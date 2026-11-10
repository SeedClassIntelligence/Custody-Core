import crypto from 'node:crypto';
import fs from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';

/**
 * The vault: encryption of what the server keeps for the creator (docs/VAULT.md; gate CL-16).
 *
 * File format "vault-v1" (written out in full in docs/VAULT.md so anyone can write a decryptor, and the backups never depend on this code):
 *
 *   header, 78 bytes:  "CCVAULT1" | version 1 | chunk size as a power of two | key id (8) | wrap IV (12) | wrapped data key (32) | wrap tag (16)
 *   then chunks:       each the AES-256-GCM encryption of up to 2^n bytes of the file, followed by its 16-byte tag
 *
 * Every file has its own random data key, wrapped (AES-256-GCM) by the vault key. Chunks use a counter nonce, and the last chunk is marked as the last in its
 * nonce, so a chunk cannot be moved, repeated, dropped from the end or followed by another without failing its tag. Nothing is handed on before its own chunk
 * has been authenticated, so a corrupted backup stops at the damage instead of producing wrong data.
 */

export const MAGIC = Buffer.from('CCVAULT1', 'ascii');
export const HEADER_BYTES = 78;
export const DEFAULT_CHUNK_LOG2 = 20; // 1 MiB
const TAG = 16;

export type VaultErrorCode = 'no_key' | 'bad_key_config' | 'corrupt' | 'not_vault_file';
export class VaultError extends Error {
  constructor(
    readonly code: VaultErrorCode,
    message: string
  ) {
    super(message);
  }
}

// --- keys -------------------------------------------------------------------------------------------------------------------

export interface VaultKeys {
  current: Buffer;
  currentId: string;
  source: 'configured' | 'derived';
  /** Every key a file may be locked with, by id: the current one, previous ones, and the one derived from the server's other key. */
  all: Map<string, Buffer>;
}

export const keyIdOf = (key: Buffer) => crypto.createHash('sha256').update(key).digest().subarray(0, 8).toString('hex');

function parseKey(raw: string, name: string): Buffer {
  const key = Buffer.from(raw.trim(), 'base64');
  if (key.length !== 32) throw new VaultError('bad_key_config', `${name} must be 32 bytes, base64-encoded.`);
  return key;
}

/**
 * The key backups are locked with: VAULT_ENCRYPTION_KEY if it is set (32 random bytes, base64), else one derived (HKDF-SHA256, its own label) from MFA_ENCRYPTION_KEY,
 * which every server already has, so backups are encrypted without any new setting. VAULT_ENCRYPTION_KEY_PREVIOUS (comma-separated) keeps older files readable after a change;
 * the derived key is always accepted for reading, so adding a configured key later does not strand earlier backups.
 */
export function vaultKeys(env: NodeJS.ProcessEnv = process.env): VaultKeys {
  const all = new Map<string, Buffer>();
  let derived: Buffer | null = null;
  if (env.MFA_ENCRYPTION_KEY) {
    const root = Buffer.from(env.MFA_ENCRYPTION_KEY, 'base64');
    if (root.length === 32) {
      derived = Buffer.from(crypto.hkdfSync('sha256', root, Buffer.alloc(0), 'custody-core/vault/v1', 32));
      all.set(keyIdOf(derived), derived);
    }
  }
  let current = derived;
  let source: VaultKeys['source'] = 'derived';
  if (env.VAULT_ENCRYPTION_KEY) {
    current = parseKey(env.VAULT_ENCRYPTION_KEY, 'VAULT_ENCRYPTION_KEY');
    source = 'configured';
    all.set(keyIdOf(current), current);
  }
  for (const raw of (env.VAULT_ENCRYPTION_KEY_PREVIOUS ?? '').split(',').filter((s) => s.trim())) {
    const k = parseKey(raw, 'VAULT_ENCRYPTION_KEY_PREVIOUS');
    all.set(keyIdOf(k), k);
  }
  if (!current) throw new VaultError('no_key', 'The vault has no key: set VAULT_ENCRYPTION_KEY (or MFA_ENCRYPTION_KEY, from which one is derived).');
  return { current, currentId: keyIdOf(current), source, all };
}

/** What the open health check may say: whether backups are being locked, never anything about the key. */
export function vaultEncrypting(env: NodeJS.ProcessEnv = process.env): boolean {
  try {
    vaultKeys(env);
    return true;
  } catch {
    return false;
  }
}

// --- the header --------------------------------------------------------------------------------------------------------------

function aadHeader(h: Buffer): Buffer {
  return h.subarray(0, 18); // magic, version, chunk size, key id: bound into the wrapped key
}
const aadChunk = (h: Buffer): Buffer => h.subarray(0, 10); // magic, version, chunk size

function makeHeader(key: Buffer, keyId: string, chunkLog2: number, dek: Buffer): Buffer {
  const h = Buffer.alloc(HEADER_BYTES);
  MAGIC.copy(h, 0);
  h[8] = 1;
  h[9] = chunkLog2;
  Buffer.from(keyId, 'hex').copy(h, 10);
  const iv = crypto.randomBytes(12);
  iv.copy(h, 18);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: TAG });
  c.setAAD(aadHeader(h));
  const wrapped = Buffer.concat([c.update(dek), c.final()]);
  wrapped.copy(h, 30);
  c.getAuthTag().copy(h, 62);
  return h;
}

export interface Header {
  version: number;
  chunkLog2: number;
  keyId: string;
}

/** The header of a file, or null if it is not a vault file (a legacy plain bundle, for example). */
export async function readHeader(file: string): Promise<(Header & { raw: Buffer }) | null> {
  const fd = await fs.promises.open(file, 'r');
  try {
    const raw = Buffer.alloc(HEADER_BYTES);
    const { bytesRead } = await fd.read(raw, 0, HEADER_BYTES, 0);
    if (bytesRead < MAGIC.length || !raw.subarray(0, MAGIC.length).equals(MAGIC)) return null;
    if (bytesRead < HEADER_BYTES) throw new VaultError('corrupt', 'The file is cut short inside its header.');
    if (raw[8] !== 1) throw new VaultError('corrupt', `Unknown vault version ${raw[8]}.`);
    if (raw[9] < 12 || raw[9] > 24) throw new VaultError('corrupt', 'The chunk size in the header is not valid.');
    return { version: raw[8], chunkLog2: raw[9], keyId: raw.subarray(10, 18).toString('hex'), raw };
  } finally {
    await fd.close();
  }
}

function unwrap(raw: Buffer, keys: VaultKeys): Buffer {
  const id = raw.subarray(10, 18).toString('hex');
  const key = keys.all.get(id);
  if (!key) throw new VaultError('no_key', `This file is locked with key ${id}, which this server does not have (see VAULT_ENCRYPTION_KEY_PREVIOUS).`);
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', key, raw.subarray(18, 30), { authTagLength: TAG });
    d.setAAD(aadHeader(raw));
    d.setAuthTag(raw.subarray(62, 78));
    return Buffer.concat([d.update(raw.subarray(30, 62)), d.final()]);
  } catch {
    throw new VaultError('corrupt', 'The key wrapped in the file header did not authenticate: the header was changed, or this is not the right key.');
  }
}

const nonce = (index: number, final: boolean): Buffer => {
  const n = Buffer.alloc(12);
  n.writeBigUInt64BE(BigInt(index), 0);
  n[8] = final ? 1 : 0;
  return n;
};

// --- encrypting --------------------------------------------------------------------------------------------------------------

async function* sealChunks(source: AsyncIterable<Buffer>, dek: Buffer, header: Buffer, chunkSize: number): AsyncGenerator<Buffer> {
  let buf: Buffer = Buffer.alloc(0);
  let index = 0;
  const seal = (plain: Buffer, final: boolean) => {
    const c = crypto.createCipheriv('aes-256-gcm', dek, nonce(index++, final), { authTagLength: TAG });
    c.setAAD(aadChunk(header));
    return Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
  };
  for await (const piece of source) {
    buf = buf.length ? Buffer.concat([buf, piece]) : piece;
    // a chunk is only sealed as "not the last" once more data has been seen after it
    while (buf.length > chunkSize) {
      yield seal(buf.subarray(0, chunkSize), false);
      buf = buf.subarray(chunkSize);
    }
  }
  yield seal(buf, true); // the last chunk: what is left (possibly all of a full chunk, possibly nothing)
}

/** Encrypts `src` into `dst` (a new file) and says what the plaintext was. */
export async function encryptFile(src: string, dst: string, opts: { chunkLog2?: number; keys?: VaultKeys } = {}): Promise<{ sha256: string; bytes: number }> {
  const keys = opts.keys ?? vaultKeys();
  const chunkLog2 = opts.chunkLog2 ?? DEFAULT_CHUNK_LOG2;
  if (!Number.isInteger(chunkLog2) || chunkLog2 < 12 || chunkLog2 > 24) throw new Error('chunkLog2 must be a whole number from 12 to 24');
  const dek = crypto.randomBytes(32);
  const header = makeHeader(keys.current, keys.currentId, chunkLog2, dek);
  const hash = crypto.createHash('sha256');
  let bytes = 0;
  async function* plain() {
    for await (const piece of fs.createReadStream(src)) {
      hash.update(piece as Buffer);
      bytes += (piece as Buffer).length;
      yield piece as Buffer;
    }
  }
  async function* all() {
    yield header;
    yield* sealChunks(plain(), dek, header, 2 ** chunkLog2);
  }
  await pipeline(Readable.from(all(), { objectMode: false }), fs.createWriteStream(dst, { flags: 'wx', mode: 0o600 }));
  return { sha256: hash.digest('hex'), bytes };
}

// --- decrypting --------------------------------------------------------------------------------------------------------------

/** The plaintext of a vault file, chunk by chunk, each handed on only after it has authenticated. Throws VaultError at the first damage. */
export async function* decryptStream(file: string, keys: VaultKeys = vaultKeys()): AsyncGenerator<Buffer> {
  const h = await readHeader(file);
  if (!h) throw new VaultError('not_vault_file', 'This is not a vault file.');
  const dek = unwrap(h.raw, keys);
  const record = 2 ** h.chunkLog2 + TAG;
  let pending: Buffer = Buffer.alloc(0);
  let index = 0;
  const open = (rec: Buffer, final: boolean) => {
    if (rec.length < TAG) throw new VaultError('corrupt', 'The file is cut short.');
    try {
      const d = crypto.createDecipheriv('aes-256-gcm', dek, nonce(index++, final), { authTagLength: TAG });
      d.setAAD(aadChunk(h.raw));
      d.setAuthTag(rec.subarray(rec.length - TAG));
      return Buffer.concat([d.update(rec.subarray(0, rec.length - TAG)), d.final()]);
    } catch {
      throw new VaultError('corrupt', `Part ${index} of the file did not authenticate: it was changed, moved, cut off or added to.`);
    }
  };
  for await (const piece of fs.createReadStream(file, { start: HEADER_BYTES, highWaterMark: Math.max(record, 1 << 16) })) {
    pending = pending.length ? Buffer.concat([pending, piece as Buffer]) : (piece as Buffer);
    while (pending.length > record) {
      yield open(pending.subarray(0, record), false);
      pending = pending.subarray(record);
    }
  }
  yield open(pending, true);
}

/** Decrypts `src` into `dst` (a new file). Returns the SHA-256 and size of the plaintext. */
export async function decryptFile(src: string, dst: string, keys: VaultKeys = vaultKeys()): Promise<{ sha256: string; bytes: number }> {
  const hash = crypto.createHash('sha256');
  let bytes = 0;
  async function* out() {
    for await (const chunk of decryptStream(src, keys)) {
      hash.update(chunk);
      bytes += chunk.length;
      yield chunk;
    }
  }
  try {
    await pipeline(Readable.from(out(), { objectMode: false }), fs.createWriteStream(dst, { flags: 'wx', mode: 0o600 }));
  } catch (err) {
    fs.rmSync(dst, { force: true }); // never leave half a decrypted file behind
    throw err;
  }
  return { sha256: hash.digest('hex'), bytes };
}

/** Reads the whole file (a vault file is decrypted and authenticated; a plain file is just read) and returns the plaintext's SHA-256 and size. */
export async function plaintextDigest(file: string, keys: VaultKeys = vaultKeys()): Promise<{ sha256: string; bytes: number; encrypted: boolean }> {
  const hash = crypto.createHash('sha256');
  let bytes = 0;
  const h = await readHeader(file);
  const source: AsyncIterable<Buffer> = h ? decryptStream(file, keys) : (fs.createReadStream(file) as AsyncIterable<Buffer>);
  for await (const chunk of source) {
    hash.update(chunk);
    bytes += chunk.length;
  }
  return { sha256: hash.digest('hex'), bytes, encrypted: !!h };
}

// --- changing the key --------------------------------------------------------------------------------------------------------

/**
 * Locks a file's data key with the current vault key instead of the one it has (the content is not touched, so this is quick whatever the size).
 * 'current': already locked with it. 'plain': not a vault file.
 */
export async function rewrapFile(file: string, keys: VaultKeys = vaultKeys()): Promise<'rewrapped' | 'current' | 'plain'> {
  const h = await readHeader(file);
  if (!h) return 'plain';
  if (h.keyId === keys.currentId) return 'current';
  const dek = unwrap(h.raw, keys);
  const header = makeHeader(keys.current, keys.currentId, h.chunkLog2, dek);
  const tmp = `${file}.rewrap-${process.pid}`;
  try {
    await pipeline(
      Readable.from(
        (async function* () {
          yield header;
          yield* fs.createReadStream(file, { start: HEADER_BYTES });
        })(),
        { objectMode: false }
      ),
      fs.createWriteStream(tmp, { flags: 'wx', mode: 0o600 })
    );
    unwrap((await readHeader(tmp))!.raw, keys); // the new header opens with the current key
    fs.renameSync(tmp, file);
  } finally {
    fs.rmSync(tmp, { force: true });
  }
  return 'rewrapped';
}
