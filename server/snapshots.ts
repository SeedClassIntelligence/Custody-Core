import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type pg from 'pg';
import { insertEvent } from './db';
import { githubRef, providerFor } from './repositoryProvider';
import './githubProvider';
import { git } from './gateway/mirror';
import { VaultError, decryptStream, encryptFile, plaintextDigest, readHeader, rewrapFile, vaultKeys } from './vault';

/**
 * Backup snapshots of a closed door's work.
 *
 * For each repository of the door: fetch the default branch and the door's own branches (door/<door id>/...) from
 * GitHub into a temporary repository, write a git bundle, check it with `git bundle verify`, ENCRYPT it into the vault (server/vault.ts,
 * docs/VAULT.md), store it in BACKUP_DIR, and record it (mirror_snapshot, plus a mirror.written event with the SHA-256 of the bundle
 * and the exact refs). The download is the plain bundle, decrypted on the way out: it restores with plain git (`git clone <file>.bundle`).
 *
 * Storage is a directory on the server (BACKUP_DIR). Storage the creator owns (their own S3 bucket or Drive) is not
 * connected yet. Mount BACKUP_DIR on a persistent volume: the default (the system temp directory) does not survive
 * a container being replaced, and the server warns about it at start.
 */

export const MAX_SNAPSHOT_ATTEMPTS = 8;

export function backupDir(): string {
  return process.env.BACKUP_DIR || path.join(os.tmpdir(), 'custody-core-backups');
}

export function backupDirIsDefault(): boolean {
  return !process.env.BACKUP_DIR;
}

function retryDelayMs(attempt: number): number {
  // 1, 2, 4, 8 ... minutes, at most 6 hours.
  return Math.min(60_000 * 2 ** Math.max(0, attempt - 1), 6 * 3600_000);
}

const sha256File = (file: string) =>
  new Promise<string>((resolve, reject) => {
    const h = crypto.createHash('sha256');
    fs.createReadStream(file)
      .on('data', (c) => h.update(c))
      .on('end', () => resolve(h.digest('hex')))
      .on('error', reject);
  });

interface RepoSnapshot {
  repository_id: string;
  full_name: string;
  refs: Record<string, string>;
  sha256: string | null;
  size_bytes: number;
  storage_uri: string | null;
}

async function snapshotRepository(doorId: string, installationId: number, repo: { id: string; full_name: string }, projectId: string): Promise<RepoSnapshot> {
  const remote = await providerFor('github').remote(githubRef({ id: repo.id, full_name: repo.full_name, installation_id: installationId }), { readOnly: true });
  const auth = ['-c', `http.extraHeader=${remote.authHeader}`, '-c', 'credential.helper='];
  const url = remote.url;
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-snapshot-'));
  try {
    const bare = path.join(work, 'repo.git');
    const init = await git(['init', '--bare', '--quiet', bare]);
    if (init.code !== 0) throw new Error(`git init failed: ${init.stderr.trim()}`);

    const listed = await git([...auth, 'ls-remote', '--symref', url, 'HEAD', `refs/heads/door/${doorId}/*`], { cwd: bare });
    if (listed.code !== 0) throw new Error(`could not read ${repo.full_name} on GitHub: ${listed.stderr.trim().split('\n').pop()}`);
    const wanted = new Set<string>();
    for (const line of listed.stdout.split('\n')) {
      const sym = /^ref: (refs\/heads\/\S+)\tHEAD$/.exec(line);
      if (sym) wanted.add(sym[1]);
      const m = /^[0-9a-f]{40,64}\t(refs\/heads\/door\/\S+)$/.exec(line);
      if (m) wanted.add(m[1]);
    }
    if (wanted.size === 0) return { repository_id: repo.id, full_name: repo.full_name, refs: {}, sha256: null, size_bytes: 0, storage_uri: null };

    const fetched = await git([...auth, 'fetch', '--quiet', '--no-tags', '--stdin', url], {
      cwd: bare,
      input: [...wanted].map((r) => `+${r}:${r}`).join('\n') + '\n'
    });
    if (fetched.code !== 0) throw new Error(`could not fetch ${repo.full_name}: ${fetched.stderr.trim().split('\n').pop()}`);

    const refsOut = await git(['for-each-ref', '--format=%(refname) %(objectname)'], { cwd: bare });
    const refs = Object.fromEntries(refsOut.stdout.trim().split('\n').filter(Boolean).map((l) => l.split(' ')));
    const bundle = path.join(work, 'snapshot.bundle');
    const made = await git(['bundle', 'create', '--quiet', bundle, '--all'], { cwd: bare });
    if (made.code !== 0) throw new Error(`git bundle failed: ${made.stderr.trim()}`);
    const verified = await git(['bundle', 'verify', '--quiet', bundle], { cwd: bare });
    if (verified.code !== 0) throw new Error(`the bundle did not verify: ${verified.stderr.trim()}`);

    const sha256 = await sha256File(bundle);
    const size = fs.statSync(bundle).size;
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const relative = path.join(projectId, doorId, `${repo.full_name.replace('/', '__')}-${stamp}.bundle`);
    const target = path.join(backupDir(), relative);
    fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    fs.rmSync(`${target}.partial`, { force: true });
    // Locked before it is stored: what lands in BACKUP_DIR is never the readable bundle. No vault key, no snapshot (it is retried, and said so).
    try {
      await encryptFile(bundle, `${target}.partial`);
    } catch (err) {
      fs.rmSync(`${target}.partial`, { force: true });
      throw err instanceof VaultError ? new Error(err.message) : err;
    }
    fs.renameSync(`${target}.partial`, target);
    // What was stored must open and be exactly the bundle that was verified.
    const stored = await plaintextDigest(target);
    if (stored.sha256 !== sha256 || stored.bytes !== size) throw new Error('the stored bundle does not match what was written');
    return { repository_id: repo.id, full_name: repo.full_name, refs, sha256, size_bytes: size, storage_uri: `backup-dir:${relative.split(path.sep).join('/')}` };
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

/** Resolves a storage_uri to its file on this server (only inside BACKUP_DIR). */
export function snapshotFile(storageUri: string): string | null {
  const m = /^backup-dir:([A-Za-z0-9_./-]+\.bundle)$/.exec(storageUri);
  if (!m || m[1].split('/').includes('..')) return null;
  const file = path.join(backupDir(), ...m[1].split('/'));
  return file.startsWith(path.resolve(backupDir()) + path.sep) && fs.existsSync(file) ? file : null;
}

/**
 * Takes the pending snapshot of one door, if it is due. Safe with several servers: the door row is locked
 * (SKIP LOCKED), so only one takes it. Returns what happened.
 */
export async function takeDoorSnapshot(pool: pg.Pool, doorId: string): Promise<'done' | 'retry' | 'failed' | 'skipped'> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const door = (await client.query(
      `SELECT d.*, gi.installation_id FROM door d JOIN project p ON p.id = d.project_id
         LEFT JOIN github_installation gi ON gi.creator_id = p.creator_id
        WHERE d.id = $1 AND d.snapshot_status = 'pending' AND (d.snapshot_next_attempt_at IS NULL OR d.snapshot_next_attempt_at <= now())
        FOR UPDATE OF d SKIP LOCKED`,
      [doorId]
    )).rows[0];
    if (!door) {
      await client.query('ROLLBACK');
      return 'skipped';
    }
    const attempt = Number(door.snapshot_attempts) + 1;
    const repos = (await client.query(
      'SELECT r.id, r.full_name FROM door_repository dr JOIN repository r ON r.id = dr.repository_id WHERE dr.door_id = $1 ORDER BY r.full_name',
      [door.id]
    )).rows;

    let results: RepoSnapshot[] = [];
    let error: string | null = null;
    try {
      if (!door.installation_id) throw new Error('the project has no GitHub connection');
      for (const r of repos) results.push(await snapshotRepository(door.id, Number(door.installation_id), r, door.project_id));
    } catch (err: any) {
      error = String(err?.message ?? err).replace(/authorization[^\n]*/gi, '').slice(0, 500);
      results = [];
    }

    if (!error) {
      for (const r of results.filter((x) => x.sha256)) {
        await client.query(
          `INSERT INTO mirror_snapshot (repository_id, commit_sha, storage_uri, sha256, size_bytes, door_id, trigger, refs)
           VALUES ($1, $2, $3, $4, $5, $6, 'door_closed', $7::jsonb)`,
          [r.repository_id, Object.values(r.refs)[0] ?? '', r.storage_uri, r.sha256, r.size_bytes, door.id, JSON.stringify(r.refs)]
        );
      }
      await client.query(`UPDATE door SET snapshot_status = 'done', snapshot_attempts = $2, snapshot_error = NULL, snapshot_next_attempt_at = NULL WHERE id = $1`, [door.id, attempt]);
      await insertEvent({
        project_id: door.project_id,
        actor_type: 'system',
        actor_id: 'scheduler',
        action: 'mirror.written',
        subject_type: 'door',
        subject_id: door.id,
        payload: {
          trigger: 'door_closed',
          storage: 'server backup directory',
          encryption: 'vault-v1',
          snapshots: results.map((r) => ({ repository: r.full_name, refs: r.refs, sha256: r.sha256, size_bytes: r.size_bytes, storage_uri: r.storage_uri }))
        }
      }, client);
      await client.query('COMMIT');
      return 'done';
    }

    const giveUp = attempt >= MAX_SNAPSHOT_ATTEMPTS;
    await client.query(
      `UPDATE door SET snapshot_status = $2, snapshot_attempts = $3, snapshot_error = $4,
              snapshot_next_attempt_at = CASE WHEN $2 = 'pending' THEN now() + make_interval(secs => $5) ELSE NULL END WHERE id = $1`,
      [door.id, giveUp ? 'failed' : 'pending', attempt, error, retryDelayMs(attempt) / 1000]
    );
    if (giveUp || attempt === 1) {
      // Recorded on the first failure and when giving up; the retries in between only update the door.
      await insertEvent({
        project_id: door.project_id,
        actor_type: 'system',
        actor_id: 'scheduler',
        action: giveUp ? 'mirror.failed' : 'mirror.delayed',
        subject_type: 'door',
        subject_id: door.id,
        payload: { trigger: 'door_closed', attempt, max_attempts: MAX_SNAPSHOT_ATTEMPTS, error }
      }, client);
    }
    await client.query('COMMIT');
    return giveUp ? 'failed' : 'retry';
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}


// --- the vault side of snapshots -------------------------------------------------------------------------------------

export interface SnapshotRow {
  id: string;
  storage_uri: string;
  sha256: string;
  size_bytes: string | number;
}

/**
 * Checks one stored snapshot end to end: the file is there, opens (decrypting and authenticating every part, if it is locked) and is exactly the bundle
 * that was recorded. 'missing', 'unreadable' (damaged, or the key is not available) and 'mismatch' are failures; the reason never names a key.
 */
export async function checkSnapshot(row: SnapshotRow): Promise<{ ok: true; encrypted: boolean; bytes: number } | { ok: false; problem: 'missing' | 'unreadable' | 'mismatch'; detail: string }> {
  const file = snapshotFile(row.storage_uri);
  if (!file) return { ok: false, problem: 'missing', detail: 'The snapshot file is no longer in the backup directory.' };
  try {
    const d = await plaintextDigest(file);
    if (d.sha256 !== row.sha256 || d.bytes !== Number(row.size_bytes)) return { ok: false, problem: 'mismatch', detail: 'The stored snapshot is not the bundle that was recorded.' };
    return { ok: true, encrypted: d.encrypted, bytes: d.bytes };
  } catch (err: any) {
    return { ok: false, problem: 'unreadable', detail: err instanceof VaultError ? err.message : 'The snapshot file could not be read.' };
  }
}

/** The plaintext bundle of a stored snapshot as a stream (decrypted if it is locked). Throws VaultError at once if the file cannot be opened at all. */
export async function openSnapshotStream(file: string): Promise<{ stream: AsyncIterable<Buffer>; encrypted: boolean }> {
  const h = await readHeader(file);
  if (!h) return { stream: fs.createReadStream(file) as AsyncIterable<Buffer>, encrypted: false };
  const keys = vaultKeys();
  const iterator = decryptStream(file, keys);
  // Open the first part now, so a missing key or a damaged header is an error the caller can still answer, not a download that breaks half way.
  const first = await iterator.next();
  async function* again() {
    if (!first.done) yield first.value;
    yield* iterator;
  }
  return { stream: again(), encrypted: true };
}

/**
 * Locks every stored snapshot that is still a plain bundle (backups made before the vault), in place: the file keeps its name, so the record, which never
 * changes, still points at it, and its SHA-256 is still the bundle's. Each file is checked after it is locked. Returns what it did.
 */
export async function encryptPlainSnapshots(pool: pg.Pool): Promise<{ encrypted: number; already: number; missing: number; failed: number }> {
  const out = { encrypted: 0, already: 0, missing: 0, failed: 0 };
  const rows = (await pool.query(`SELECT s.id, s.storage_uri, s.sha256, s.size_bytes, p.id AS project_id FROM mirror_snapshot s JOIN repository r ON r.id = s.repository_id JOIN project p ON p.id = r.project_id ORDER BY s.created_at`)).rows;
  for (const row of rows) {
    const file = snapshotFile(row.storage_uri);
    if (!file) {
      out.missing++;
      continue;
    }
    if (await readHeader(file).catch(() => null)) {
      out.already++;
      continue;
    }
    const tmp = `${file}.locking`;
    try {
      const before = await plaintextDigest(file);
      if (before.sha256 !== row.sha256) throw new Error('the plain file is not the recorded bundle');
      fs.rmSync(tmp, { force: true });
      await encryptFile(file, tmp);
      const after = await plaintextDigest(tmp);
      if (after.sha256 !== row.sha256) throw new Error('the locked file did not match');
      fs.renameSync(tmp, file);
      out.encrypted++;
      await insertEvent({ project_id: row.project_id, actor_type: 'system', actor_id: 'vault', action: 'mirror.encrypted', subject_type: 'snapshot', subject_id: row.id, payload: { snapshot_id: row.id, sha256: row.sha256, encryption: 'vault-v1' } });
    } catch (err: any) {
      fs.rmSync(tmp, { force: true });
      out.failed++;
      console.error(`[vault] could not lock snapshot ${row.id}:`, err?.message ?? err);
    }
  }
  return out;
}

/** After a change of vault key: locks every snapshot's data key with the current key (quick: the content is not touched). */
export async function rewrapSnapshots(pool: pg.Pool): Promise<{ rewrapped: number; current: number; plain: number; missing: number; failed: number }> {
  const out = { rewrapped: 0, current: 0, plain: 0, missing: 0, failed: 0 };
  const keys = vaultKeys();
  for (const row of (await pool.query(`SELECT storage_uri FROM mirror_snapshot ORDER BY created_at`)).rows) {
    const file = snapshotFile(row.storage_uri);
    if (!file) {
      out.missing++;
      continue;
    }
    try {
      out[await rewrapFile(file, keys)]++;
    } catch (err: any) {
      out.failed++;
      console.error('[vault] could not re-lock a snapshot:', err?.message ?? err);
    }
  }
  return out;
}
