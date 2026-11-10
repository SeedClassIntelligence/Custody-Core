import dotenv from 'dotenv';
dotenv.config();

import fs from 'node:fs';
import { getDbPool } from '../server/db';
import { encryptPlainSnapshots, rewrapSnapshots } from '../server/snapshots';
import { VaultError, decryptFile, plaintextDigest, readHeader, vaultKeys } from '../server/vault';

/**
 * The vault from the command line (docs/VAULT.md).
 *
 *   npm run vault -- status                          which key backups are locked with (its id, never the key), and the keys that can still open older ones
 *   npm run vault -- decrypt <file> <out>            open one locked backup file with the keys in the environment (works without the database: for recovery)
 *   npm run vault -- check <file>                    open a file completely and print the SHA-256 of the bundle inside
 *   npm run vault -- encrypt-existing                lock every backup made before the vault existed (needs the database settings)
 *   npm run vault -- rewrap                          after changing VAULT_ENCRYPTION_KEY: lock every backup's data key with the new key
 */
async function main() {
  const [cmd, a, b] = process.argv.slice(2);
  switch (cmd) {
    case 'status': {
      const k = vaultKeys();
      console.log(`Backups are locked with key ${k.currentId} (${k.source === 'configured' ? 'VAULT_ENCRYPTION_KEY' : 'derived from MFA_ENCRYPTION_KEY'}).`);
      console.log(`Keys that can open older backups: ${[...k.all.keys()].filter((id) => id !== k.currentId).join(', ') || 'none'}.`);
      return;
    }
    case 'decrypt': {
      if (!a || !b) throw new Error('Usage: vault decrypt <locked file> <output file>');
      const r = await decryptFile(a, b);
      console.log(`Opened ${r.bytes} bytes. SHA-256 of the bundle: ${r.sha256}`);
      return;
    }
    case 'check': {
      if (!a) throw new Error('Usage: vault check <file>');
      const h = await readHeader(a);
      const d = await plaintextDigest(a);
      console.log(`${h ? `locked (key ${h.keyId})` : 'plain (not locked)'}; ${d.bytes} bytes; SHA-256 ${d.sha256}`);
      return;
    }
    case 'encrypt-existing':
    case 'rewrap': {
      const pool = getDbPool();
      if (!pool) throw new Error('DATABASE_URL (and APP_DB_PASSWORD) are not set.');
      console.log(JSON.stringify(cmd === 'rewrap' ? await rewrapSnapshots(pool) : await encryptPlainSnapshots(pool)));
      await pool.end();
      return;
    }
    default:
      console.log(fs.readFileSync(new URL(import.meta.url).pathname, 'utf8').split('*/')[0].split('/**')[1].replace(/^ \* ?/gm, '').trim());
  }
}

main().catch((err) => {
  console.error(err instanceof VaultError ? `${err.message}` : (err?.message ?? err));
  process.exit(1);
});
