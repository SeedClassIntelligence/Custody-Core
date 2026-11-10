import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { getAdminPool, getDbPool, runMigrations } from '../server/db';
import { encryptPlainSnapshots, rewrapSnapshots } from '../server/snapshots';
import {
  DEFAULT_CHUNK_LOG2, HEADER_BYTES, MAGIC, VaultError, decryptFile, decryptStream, encryptFile, keyIdOf, plaintextDigest, readHeader, rewrapFile, vaultEncrypting, vaultKeys
} from '../server/vault';
import { assertPoolTargetsTestDb } from './support/safety';
import { startHarness, Harness } from './support/apiHarness';
import { startApp } from './support/api';

/**
 * The vault (CL-16): backups are locked before they are stored, open only with the key, fail loudly when touched, and keep working through a change of key.
 */
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-vault-test-'));
const b64 = (n = 32) => crypto.randomBytes(n).toString('base64');
const sha = (b: Buffer) => crypto.createHash('sha256').update(b).digest('hex');
const KEY_A = b64();
const envA = { MFA_ENCRYPTION_KEY: KEY_A } as NodeJS.ProcessEnv;
const CHUNK_LOG2 = 12; // 4 KiB chunks keep the format tests small
const CHUNK = 2 ** CHUNK_LOG2;
const RECORD = CHUNK + 16;
let counter = 0;
const tmp = (name = 'f') => path.join(dir, `${name}-${counter++}`);
const withFile = (bytes: Buffer) => {
  const f = tmp('plain');
  fs.writeFileSync(f, bytes);
  return f;
};
async function lock(bytes: Buffer, keys = vaultKeys(envA), chunkLog2 = CHUNK_LOG2) {
  const src = withFile(bytes);
  const dst = tmp('locked');
  const r = await encryptFile(src, dst, { keys, chunkLog2 });
  return { src, dst, ...r };
}
async function unlock(file: string, keys = vaultKeys(envA)): Promise<Buffer> {
  const out: Buffer[] = [];
  for await (const c of decryptStream(file, keys)) out.push(c);
  return Buffer.concat(out);
}
const expectCorrupt = async (file: string, keys = vaultKeys(envA)) => {
  const got: Buffer[] = [];
  const err: any = await (async () => {
    for await (const c of decryptStream(file, keys)) got.push(c);
  })().then(() => null, (e) => e);
  expect(err, 'expected the file to be refused').toBeInstanceOf(VaultError);
  return { err: err as VaultError, released: Buffer.concat(got) };
};

describe('Vault: the file format', () => {
  afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

  it('round-trips every size around the chunk boundaries, including empty and exactly full chunks', async () => {
    for (const n of [0, 1, 17, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK - 1, 2 * CHUNK, 2 * CHUNK + 1, 5 * CHUNK, 5 * CHUNK + 123, 100_000]) {
      const plain = crypto.randomBytes(n);
      const r = await lock(plain);
      expect(r.bytes, `size ${n}`).toBe(n);
      expect(r.sha256).toBe(sha(plain));
      expect((await unlock(r.dst)).equals(plain), `size ${n}`).toBe(true);
      expect((await plaintextDigest(r.dst, vaultKeys(envA))).sha256).toBe(sha(plain));
      const chunks = Math.max(1, Math.ceil(n / CHUNK));
      expect(fs.statSync(r.dst).size, `size ${n}`).toBe(HEADER_BYTES + n + 16 * chunks);
    }
  });

  it('can be opened by a decryptor written only from docs/VAULT.md (so backups never depend on this code)', async () => {
    // Deliberately self-contained: node:crypto and the layout as the document states it, nothing imported from server/.
    const reference = (file: Buffer, vaultKey: Buffer): Buffer => {
      expect(file.subarray(0, 8).toString('latin1')).toBe('CCVAULT1');
      expect(file[8]).toBe(1);
      const chunk = 2 ** file[9];
      const wrap = crypto.createDecipheriv('aes-256-gcm', vaultKey, file.subarray(18, 30));
      wrap.setAAD(file.subarray(0, 18));
      wrap.setAuthTag(file.subarray(62, 78));
      const dek = Buffer.concat([wrap.update(file.subarray(30, 62)), wrap.final()]);
      const body = file.subarray(78);
      const out: Buffer[] = [];
      for (let off = 0, i = 0; off < body.length || i === 0; i++) {
        const take = Math.min(chunk + 16, body.length - off);
        const last = off + take >= body.length;
        const nonce = Buffer.alloc(12);
        nonce.writeBigUInt64BE(BigInt(i), 0);
        nonce[8] = last ? 1 : 0;
        const d = crypto.createDecipheriv('aes-256-gcm', dek, nonce);
        d.setAAD(file.subarray(0, 10));
        d.setAuthTag(body.subarray(off + take - 16, off + take));
        out.push(d.update(body.subarray(off, off + take - 16)), d.final());
        off += take;
        if (last) break;
      }
      return Buffer.concat(out);
    };
    const keys = vaultKeys(envA);
    for (const n of [0, 5, CHUNK, 3 * CHUNK + 9]) {
      const plain = crypto.randomBytes(n);
      const r = await lock(plain, keys);
      expect(reference(fs.readFileSync(r.dst), keys.current).equals(plain), `size ${n}`).toBe(true);
    }
    // and the key derivation as the document states it
    expect(Buffer.from(crypto.hkdfSync('sha256', Buffer.from(KEY_A, 'base64'), Buffer.alloc(0), 'custody-core/vault/v1', 32)).equals(keys.current)).toBe(true);
    expect(crypto.createHash('sha256').update(keys.current).digest().subarray(0, 8).toString('hex')).toBe(keys.currentId);
  });

  it('works at the default chunk size with more than one chunk', async () => {
    const plain = crypto.randomBytes(2.5 * 2 ** DEFAULT_CHUNK_LOG2);
    const r = await lock(plain, vaultKeys(envA), DEFAULT_CHUNK_LOG2);
    expect((await unlock(r.dst)).equals(plain)).toBe(true);
  });

  it('writes a readable header, no trace of the plaintext, and different bytes every time', async () => {
    const plain = Buffer.from('a recognisable sentence that must not appear in the stored file. '.repeat(200));
    const one = await lock(plain);
    const two = await lock(plain);
    const stored = fs.readFileSync(one.dst);
    expect(stored.subarray(0, 8).equals(MAGIC)).toBe(true);
    expect(stored.includes('recognisable')).toBe(false);
    expect(stored.equals(fs.readFileSync(two.dst))).toBe(false); // a fresh data key and IV for every file
    expect(await readHeader(one.dst)).toMatchObject({ version: 1, chunkLog2: CHUNK_LOG2, keyId: keyIdOf(vaultKeys(envA).current) });
    expect(await readHeader(one.src)).toBeNull(); // a plain file is not a vault file
    await expect(unlock(one.src)).rejects.toMatchObject({ code: 'not_vault_file' });
  });

  describe('anything done to a locked file is noticed, and nothing wrong is handed on', () => {
    let plain: Buffer;
    let good: string;
    beforeAll(async () => {
      plain = crypto.randomBytes(3 * CHUNK - 100); // three chunks, the last one short
      good = (await lock(plain)).dst;
    });
    const mutated = (change: (b: Buffer) => Buffer) => {
      const f = tmp('mut');
      fs.writeFileSync(f, change(Buffer.from(fs.readFileSync(good))));
      return f;
    };
    const flip = (at: number) => mutated((b) => { b[at] ^= 0x01; return b; });

    it('changing one bit anywhere in the header or in any part is refused', async () => {
      const fileSize = fs.statSync(good).size;
      const header = [10 /* key id */, 18 /* wrap iv */, 30 /* wrapped key */, 62 /* wrap tag */, 8 /* version */, 9 /* chunk size */, 0 /* magic */];
      for (const at of header) {
        const { err } = await expectCorrupt(flip(at));
        expect(['corrupt', 'no_key', 'not_vault_file'], `byte ${at}`).toContain(err.code);
      }
      for (const at of [HEADER_BYTES, HEADER_BYTES + 100, HEADER_BYTES + RECORD - 1, HEADER_BYTES + RECORD, HEADER_BYTES + RECORD + 500, HEADER_BYTES + 2 * RECORD + 1, fileSize - 1, fileSize - 17]) {
        expect((await expectCorrupt(flip(at))).err.code, `byte ${at}`).toBe('corrupt');
      }
    });

    it('stops at the damage: the parts before it are released, the damaged one and everything after never are', async () => {
      const r = await expectCorrupt(flip(HEADER_BYTES + RECORD + 5)); // second part
      expect(r.released.equals(plain.subarray(0, CHUNK))).toBe(true);
      const last = await expectCorrupt(flip(fs.statSync(good).size - 20)); // third part
      expect(last.released.equals(plain.subarray(0, 2 * CHUNK))).toBe(true);
      const first = await expectCorrupt(flip(HEADER_BYTES + 3));
      expect(first.released.length).toBe(0);
    });

    it('cutting the file short, at a part boundary or inside one, is refused', async () => {
      for (const keep of [HEADER_BYTES, HEADER_BYTES + 10, HEADER_BYTES + RECORD, HEADER_BYTES + RECORD + 40, HEADER_BYTES + 2 * RECORD, fs.statSync(good).size - 1]) {
        expect((await expectCorrupt(mutated((b) => b.subarray(0, keep)))).err.code, `kept ${keep}`).toBe('corrupt');
      }
      const inHeader = mutated((b) => b.subarray(0, 40));
      await expect(unlock(inHeader)).rejects.toMatchObject({ code: 'corrupt' });
    });

    it('adding to it, repeating a part, dropping a part or swapping two is refused', async () => {
      const part = (b: Buffer, i: number) => b.subarray(HEADER_BYTES + i * RECORD, HEADER_BYTES + (i + 1) * RECORD);
      expect((await expectCorrupt(mutated((b) => Buffer.concat([b, crypto.randomBytes(40)])))).err.code).toBe('corrupt');
      expect((await expectCorrupt(mutated((b) => Buffer.concat([b, part(b, 0)])))).err.code).toBe('corrupt');
      expect((await expectCorrupt(mutated((b) => Buffer.concat([b, b.subarray(HEADER_BYTES)])))).err.code).toBe('corrupt');
      expect((await expectCorrupt(mutated((b) => Buffer.concat([b.subarray(0, HEADER_BYTES), b.subarray(HEADER_BYTES + RECORD)])))).err.code).toBe('corrupt'); // first part dropped
      expect((await expectCorrupt(mutated((b) => Buffer.concat([b.subarray(0, HEADER_BYTES), part(b, 1), part(b, 0), part(b, 2)])))).err.code).toBe('corrupt'); // swapped
      expect((await expectCorrupt(mutated((b) => Buffer.concat([b.subarray(0, HEADER_BYTES), part(b, 0), part(b, 0), part(b, 2)])))).err.code).toBe('corrupt'); // repeated
    });

    it('a header from one file on the body of another is refused, even with the same key', async () => {
      const other = (await lock(crypto.randomBytes(3 * CHUNK - 100))).dst;
      const grafted = tmp('graft');
      fs.writeFileSync(grafted, Buffer.concat([fs.readFileSync(other).subarray(0, HEADER_BYTES), fs.readFileSync(good).subarray(HEADER_BYTES)]));
      expect((await expectCorrupt(grafted)).err.code).toBe('corrupt');
    });
  });

  describe('keys', () => {
    it('the key is derived from the server\'s other key (its own label, never the same bytes), unless one is configured', () => {
      const derived = vaultKeys(envA);
      expect(derived.source).toBe('derived');
      expect(derived.current.length).toBe(32);
      expect(derived.current.equals(Buffer.from(KEY_A, 'base64'))).toBe(false);
      expect(vaultKeys(envA).current.equals(derived.current)).toBe(true); // stable
      expect(vaultKeys({ MFA_ENCRYPTION_KEY: b64() } as any).current.equals(derived.current)).toBe(false);
      const configured = b64();
      const k = vaultKeys({ ...envA, VAULT_ENCRYPTION_KEY: configured } as any);
      expect(k.source).toBe('configured');
      expect(k.current.equals(Buffer.from(configured, 'base64'))).toBe(true);
      expect(k.all.size).toBe(2); // the derived key still opens what it locked
      expect(vaultKeys({ ...envA, VAULT_ENCRYPTION_KEY: configured, VAULT_ENCRYPTION_KEY_PREVIOUS: `${b64()}, ${b64()}` } as any).all.size).toBe(4);
    });

    it('refuses a badly configured key, and no key at all, saying so without saying the key', () => {
      for (const bad of ['', 'short', b64(16), b64(33)]) {
        if (bad === '') continue;
        expect(() => vaultKeys({ ...envA, VAULT_ENCRYPTION_KEY: bad } as any), bad).toThrowError(/VAULT_ENCRYPTION_KEY must be 32 bytes/);
      }
      expect(() => vaultKeys({ ...envA, VAULT_ENCRYPTION_KEY_PREVIOUS: 'nope' } as any)).toThrowError(/PREVIOUS must be 32 bytes/);
      expect(() => vaultKeys({} as any)).toThrowError(VaultError);
      expect(() => vaultKeys({ MFA_ENCRYPTION_KEY: 'short' } as any)).toThrowError(/no key/);
      expect(vaultEncrypting(envA)).toBe(true);
      expect(vaultEncrypting({} as any)).toBe(false);
    });

    it('a file cannot be opened without its key, and the refusal names the key by its id only', async () => {
      const r = await lock(crypto.randomBytes(1000));
      const other = vaultKeys({ MFA_ENCRYPTION_KEY: b64() } as any);
      const err: any = await unlock(r.dst, other).then(() => null, (e) => e);
      expect(err).toMatchObject({ code: 'no_key' });
      expect(err.message).toContain(keyIdOf(vaultKeys(envA).current));
      expect(err.message).not.toContain(KEY_A);
      // a key with the right id but wrong bytes cannot exist, but a forged map entry must still fail closed
      const forged = vaultKeys({ MFA_ENCRYPTION_KEY: b64() } as any);
      forged.all.set(keyIdOf(vaultKeys(envA).current), forged.current);
      await expect(unlock(r.dst, forged)).rejects.toMatchObject({ code: 'corrupt' });
    });

    it('a change of key: the data key is re-locked without touching the content, and the old key is no longer needed', async () => {
      const plain = crypto.randomBytes(3 * CHUNK + 7);
      const r = await lock(plain, vaultKeys(envA));
      const before = fs.readFileSync(r.dst);
      const newKey = b64();
      const rotated = vaultKeys({ ...envA, VAULT_ENCRYPTION_KEY: newKey } as any);
      expect((await readHeader(r.dst))!.keyId).not.toBe(rotated.currentId);
      expect(await rewrapFile(r.dst, rotated)).toBe('rewrapped');
      const after = fs.readFileSync(r.dst);
      expect(after.subarray(HEADER_BYTES).equals(before.subarray(HEADER_BYTES))).toBe(true); // the body is byte for byte the same
      expect(after.subarray(0, HEADER_BYTES).equals(before.subarray(0, HEADER_BYTES))).toBe(false);
      expect((await readHeader(r.dst))!.keyId).toBe(rotated.currentId);
      expect(await rewrapFile(r.dst, rotated)).toBe('current');
      // now only the new key is needed
      const onlyNew = { ...rotated, all: new Map([[rotated.currentId, rotated.current]]) };
      expect((await unlock(r.dst, onlyNew)).equals(plain)).toBe(true);
      await expect(unlock(r.dst, vaultKeys(envA))).rejects.toMatchObject({ code: 'no_key' });
      expect(await rewrapFile(r.src, rotated)).toBe('plain');
      expect(fs.readdirSync(dir).some((f) => f.includes('.rewrap-'))).toBe(false);
    });
  });

  it('decryptFile writes a new file, never over one, and leaves nothing behind when it fails', async () => {
    const r = await lock(crypto.randomBytes(3 * CHUNK));
    const out = tmp('out');
    expect((await decryptFile(r.dst, out, vaultKeys(envA))).sha256).toBe(r.sha256);
    await expect(decryptFile(r.dst, out, vaultKeys(envA))).rejects.toThrow(); // exists
    const bad = tmp('bad');
    const b = Buffer.from(fs.readFileSync(r.dst));
    b[b.length - 5] ^= 1;
    fs.writeFileSync(bad, b);
    const target = tmp('target');
    await expect(decryptFile(bad, target, vaultKeys(envA))).rejects.toMatchObject({ code: 'corrupt' });
    expect(fs.existsSync(target)).toBe(false);
  });
});

// ------------------------------------------------------------------------------------------------------------
describe('Vault: stored snapshots (download, check, and the move from plain backups)', () => {
  const db = getDbPool()!;
  const admin = getAdminPool()!;
  let h: Harness;
  let creator: any, other: any;
  let projectId = '', repoId = '';
  const backups = path.join(dir, 'backups');
  const saved = { ...process.env };
  const git = (args: string[], cwd?: string) => {
    const r = spawnSync('git', args, { cwd, encoding: 'utf8', env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' } });
    expect(r.status, r.stderr).toBe(0);
    return r.stdout.trim();
  };
  let realBundle: Buffer;

  /** A snapshot record (as the scheduler writes them) pointing at `bytes` stored at a path under BACKUP_DIR. */
  async function snapshot(bytes: Buffer, opts: { locked: boolean; recordedSha?: string; name?: string } = { locked: true }) {
    const rel = `${projectId}/doors/${opts.name ?? `s${counter++}`}.bundle`;
    const file = path.join(backups, ...rel.split('/'));
    fs.mkdirSync(path.dirname(file), { recursive: true });
    if (opts.locked) {
      const src = withFile(bytes);
      await encryptFile(src, file, { keys: vaultKeys(), chunkLog2: CHUNK_LOG2 });
    } else {
      fs.writeFileSync(file, bytes);
    }
    const id = (
      await admin.query(
        `INSERT INTO mirror_snapshot (repository_id, commit_sha, storage_uri, sha256, size_bytes, trigger, refs) VALUES ($1, $2, $3, $4, $5, 'door_closed', '{}'::jsonb) RETURNING id`,
        [repoId, 'a'.repeat(40), `backup-dir:${rel}`, opts.recordedSha ?? sha(bytes), bytes.length]
      )
    ).rows[0].id as string;
    return { id, file, rel };
  }
  const url = (id: string, q = '') => `${h.base}/api/v1/projects/${projectId}/snapshots/${id}/bundle${q}`;
  const get = (u: string, who = creator) => fetch(u, { headers: { 'x-test-creator': who.id } });
  const events = async () => (await db.query(`SELECT action, actor_type, actor_id, payload FROM event WHERE project_id = $1 ORDER BY seq`, [projectId])).rows;

  beforeAll(async () => {
    await assertPoolTargetsTestDb(admin);
    expect((await runMigrations()).success).toBe(true);
    process.env.BACKUP_DIR = backups;
    h = await startHarness();
    creator = await h.newCreator('owner');
    other = await h.newCreator('other');
    projectId = (await db.query(`INSERT INTO project (creator_id, name, purpose) VALUES ($1, 'Vault', 'x') RETURNING id`, [creator.id])).rows[0].id;
    repoId = (await db.query(`INSERT INTO repository (project_id, github_repo_id, full_name) VALUES ($1, '1', 'org/app') RETURNING id`, [projectId])).rows[0].id;
    // a real bundle, to prove what comes out of the vault is something git can use
    const repo = path.join(dir, 'src-repo');
    fs.mkdirSync(repo, { recursive: true });
    git(['init', '--quiet', '--initial-branch=main'], repo);
    fs.writeFileSync(path.join(repo, 'a.txt'), 'hello\n');
    git(['add', '-A'], repo);
    git(['-c', 'user.name=T', '-c', 'user.email=t@example.com', 'commit', '--quiet', '-m', 'one'], repo);
    const bundle = path.join(dir, 'real.bundle');
    git(['bundle', 'create', '--quiet', bundle, '--all'], repo);
    realBundle = fs.readFileSync(bundle);
  }, 120_000);
  afterAll(async () => {
    await h?.stop();
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved);
  });

  it('a locked snapshot downloads as the plain bundle (git can clone it), matches its record, and can also be had as stored', async () => {
    const s = await snapshot(realBundle);
    expect(fs.readFileSync(s.file).subarray(0, 8).equals(MAGIC)).toBe(true);
    expect(fs.readFileSync(s.file).includes('# v2 git bundle')).toBe(false);
    const res = await get(url(s.id));
    expect(res.status).toBe(200);
    expect(res.headers.get('x-snapshot-sha256')).toBe(sha(realBundle));
    const body = Buffer.from(await res.arrayBuffer());
    expect(body.equals(realBundle)).toBe(true);
    const f = tmp('dl');
    fs.writeFileSync(f, body);
    git(['clone', '--quiet', f, path.join(dir, `clone-${counter++}`)]);

    const raw = await get(url(s.id, '?encrypted=1'));
    expect(raw.headers.get('x-snapshot-encryption')).toBe('vault-v1');
    expect(raw.headers.get('content-disposition')).toMatch(/\.bundle\.vault"/);
    expect(Buffer.from(await raw.arrayBuffer()).equals(fs.readFileSync(s.file))).toBe(true);
    expect((await get(url(s.id), other)).status).toBe(404);
  });

  it('a snapshot of several parts downloads whole, and a damaged part cuts the download off instead of ending it', async () => {
    const big = crypto.randomBytes(5 * CHUNK + 33);
    const ok = await snapshot(big);
    const full = Buffer.from(await (await get(url(ok.id))).arrayBuffer());
    expect(full.equals(big)).toBe(true);

    const bad = await snapshot(big);
    const b = Buffer.from(fs.readFileSync(bad.file));
    b[HEADER_BYTES + 3 * RECORD + 10] ^= 1; // the fourth part
    fs.writeFileSync(bad.file, b);
    const res = await get(url(bad.id));
    expect(res.status).toBe(200); // the first parts were fine and are on their way
    let received = 0;
    const failed = await (async () => {
      for await (const c of res.body as any) received += (c as Buffer).length;
    })().then(() => false, () => true);
    expect(failed).toBe(true);
    expect(received).toBeLessThan(big.length);

    // damage in the very first part is found before anything is sent
    const early = await snapshot(big);
    const e = Buffer.from(fs.readFileSync(early.file));
    e[HEADER_BYTES + 4] ^= 1;
    fs.writeFileSync(early.file, e);
    const r2 = await get(url(early.id));
    expect(r2.status).toBe(503);
    expect(await r2.json()).toMatchObject({ code: 'vault_corrupt' });
  });

  it('a snapshot whose key is not available is refused cleanly, naming the key by id and never revealing it', async () => {
    const s = await snapshot(realBundle);
    const mfa = process.env.MFA_ENCRYPTION_KEY;
    process.env.MFA_ENCRYPTION_KEY = b64();
    try {
      const res = await get(url(s.id));
      expect(res.status).toBe(503);
      const body = await res.json();
      expect(body.code).toBe('vault_no_key');
      expect(JSON.stringify(body)).not.toContain(mfa!);
      expect(JSON.stringify(body)).not.toContain(process.env.MFA_ENCRYPTION_KEY);
    } finally {
      process.env.MFA_ENCRYPTION_KEY = mfa;
    }
    expect((await get(url(s.id))).status).toBe(200);
  });

  it('checking a snapshot opens all of it, says what it found, and writes the result to the project\'s record', async () => {
    const good = await snapshot(realBundle);
    const r = await h.api(creator, 'POST', `/projects/${projectId}/snapshots/${good.id}/verify`, {});
    expect(r.status).toBe(200);
    expect(r.body).toEqual({ ok: true, encrypted: true, bytes: realBundle.length });
    expect((await events()).filter((e) => e.action === 'mirror.verified').at(-1)).toMatchObject({ actor_type: 'creator', actor_id: creator.id, payload: { snapshot_id: good.id, encrypted: true } });

    const damaged = await snapshot(crypto.randomBytes(3 * CHUNK));
    const d = Buffer.from(fs.readFileSync(damaged.file));
    d[d.length - 3] ^= 1;
    fs.writeFileSync(damaged.file, d);
    const bad = await h.api(creator, 'POST', `/projects/${projectId}/snapshots/${damaged.id}/verify`, {});
    expect(bad.status).toBe(409);
    expect(bad.body).toMatchObject({ ok: false, problem: 'unreadable' });
    expect((await events()).filter((e) => e.action === 'mirror.corrupt').at(-1).payload).toMatchObject({ snapshot_id: damaged.id, problem: 'unreadable' });

    const wrong = await snapshot(realBundle, { locked: true, recordedSha: 'f'.repeat(64) });
    expect((await h.api(creator, 'POST', `/projects/${projectId}/snapshots/${wrong.id}/verify`, {})).body).toMatchObject({ ok: false, problem: 'mismatch' });
    const gone = await snapshot(realBundle);
    fs.rmSync(gone.file);
    expect((await h.api(creator, 'POST', `/projects/${projectId}/snapshots/${gone.id}/verify`, {})).body).toMatchObject({ ok: false, problem: 'missing' });
    expect((await get(url(gone.id))).status).toBe(410);
    expect((await h.api(other, 'POST', `/projects/${projectId}/snapshots/${good.id}/verify`, {})).status).toBe(404);
  });

  it('a download of a snapshot that is not the recorded bundle is cut off at the end', async () => {
    const s = await snapshot(realBundle, { locked: true, recordedSha: 'e'.repeat(64) });
    const res = await get(url(s.id));
    const failed = await res.arrayBuffer().then(() => false, () => true);
    expect(failed).toBe(true);
  });

  it('backups made before the vault are still readable, and can be locked in place without changing their record', async () => {
    const legacy = await snapshot(realBundle, { locked: false });
    expect(fs.readFileSync(legacy.file).equals(realBundle)).toBe(true);
    expect(Buffer.from(await (await get(url(legacy.id))).arrayBuffer()).equals(realBundle)).toBe(true);
    expect((await h.api(creator, 'POST', `/projects/${projectId}/snapshots/${legacy.id}/verify`, {})).body).toMatchObject({ ok: true, encrypted: false });

    const before = (await db.query('SELECT * FROM mirror_snapshot WHERE id = $1', [legacy.id])).rows[0];
    const done = await encryptPlainSnapshots(db);
    expect(done.encrypted).toBeGreaterThanOrEqual(1);
    expect(done.failed).toBe(0);
    expect(fs.readFileSync(legacy.file).subarray(0, 8).equals(MAGIC)).toBe(true);
    expect((await db.query('SELECT * FROM mirror_snapshot WHERE id = $1', [legacy.id])).rows[0]).toEqual(before); // the record is untouched
    expect(Buffer.from(await (await get(url(legacy.id))).arrayBuffer()).equals(realBundle)).toBe(true);
    expect((await h.api(creator, 'POST', `/projects/${projectId}/snapshots/${legacy.id}/verify`, {})).body).toMatchObject({ ok: true, encrypted: true });
    expect((await events()).some((e) => e.action === 'mirror.encrypted' && e.payload.snapshot_id === legacy.id)).toBe(true);
    expect((await encryptPlainSnapshots(db)).encrypted).toBe(0); // nothing left to lock
    expect(fs.readdirSync(path.dirname(legacy.file)).some((f) => f.endsWith('.locking'))).toBe(false);
  });

  it('after a change of key, every snapshot is re-locked with the new one and downloads exactly as before', async () => {
    const s = await snapshot(realBundle);
    const oldKeyId = (await readHeader(s.file))!.keyId;
    const configured = b64();
    process.env.VAULT_ENCRYPTION_KEY = configured;
    try {
      const out = await rewrapSnapshots(db);
      expect(out.rewrapped).toBeGreaterThanOrEqual(1);
      expect(out.failed).toBe(0);
      expect((await readHeader(s.file))!.keyId).not.toBe(oldKeyId);
      expect(Buffer.from(await (await get(url(s.id))).arrayBuffer()).equals(realBundle)).toBe(true);
      expect((await rewrapSnapshots(db)).rewrapped).toBe(0);
      // and new backups use the new key from now on
      const fresh = tmp('fresh');
      await encryptFile(withFile(Buffer.from('x')), fresh);
      expect((await readHeader(fresh))!.keyId).toBe(vaultKeys().currentId);
      expect(vaultKeys().source).toBe('configured');
    } finally {
      delete process.env.VAULT_ENCRYPTION_KEY;
    }
    // without the configured key the re-locked files need it: the derived key alone no longer opens them
    const res = await get(url(s.id));
    expect(res.status).toBe(503);
    expect((await res.json()).code).toBe('vault_no_key');
  });

  it('/health says whether backups are being locked, and nothing about the key', async () => {
    const running = await startApp();
    try {
      const health = await (await fetch(`${running.base}/api/v1/health`)).json();
      expect(health.vault).toEqual({ encrypting: true });
      const mfa = process.env.MFA_ENCRYPTION_KEY;
      delete process.env.MFA_ENCRYPTION_KEY;
      try {
        expect((await (await fetch(`${running.base}/api/v1/health`)).json()).vault).toEqual({ encrypting: false });
      } finally {
        process.env.MFA_ENCRYPTION_KEY = mfa;
      }
      expect(JSON.stringify(health)).not.toContain(vaultKeys().currentId);
    } finally {
      await running.stop();
    }
  });
});
