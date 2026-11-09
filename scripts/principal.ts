import dotenv from 'dotenv';
dotenv.config();

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getDbPool } from '../server/db';
import {
  PrincipalError,
  addPrincipalKey,
  listPrincipals,
  narrowPrincipal,
  registerPrincipal,
  revokeKey,
  setPrincipalStatus,
  ALL_SCOPES
} from '../server/servicePrincipals';

/**
 * Provisioning service principals (machine callers) from the command line. There is no screen for this yet: the
 * operator creates a principal for a creator, registers its public key, and can suspend or revoke it.
 *
 *   npm run principal -- keygen --alg Ed25519|ES256 --name <file name> [--out <dir>]
 *   npm run principal -- create --creator <creator id> --name <name> --platform <type> --env development|staging|production \
 *                               --scopes a,b,c [--projects <id>,<id>] [--expires <ISO time>]
 *   npm run principal -- add-key --principal <id> --public-key <public jwk file> [--expires <ISO time>]
 *   npm run principal -- list --creator <creator id>
 *   npm run principal -- narrow --principal <id> [--scopes a,b] [--projects <id>,<id>]   (only ever removes permissions)
 *   npm run principal -- suspend|activate|revoke --principal <id>
 *   npm run principal -- revoke-key --key <key id>
 *
 * Needs the same settings as the server (DATABASE_URL, APP_DB_PASSWORD), and the server must have started once
 * against the database so the application account exists. Every change is written to the creator's account record.
 */

function args(list: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (let i = 0; i < list.length; i++) {
    const a = list[i];
    if (!a.startsWith('--')) throw new Error(`Unexpected argument "${a}".`);
    const key = a.slice(2);
    const value = list[i + 1];
    if (value === undefined || value.startsWith('--')) throw new Error(`--${key} needs a value.`);
    out[key] = value;
    i++;
  }
  return out;
}

const need = (a: Record<string, string>, k: string) => {
  if (!a[k]) throw new Error(`--${k} is required.`);
  return a[k];
};

const by = () => `cli:${os.userInfo().username}`;

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  const a = args(rest);

  if (command === 'keygen') {
    const alg = need(a, 'alg');
    const name = need(a, 'name');
    if (!/^[A-Za-z0-9._-]{1,60}$/.test(name)) throw new Error('--name may use letters, digits, dot, dash and underscore only.');
    if (alg !== 'Ed25519' && alg !== 'ES256') throw new Error('--alg must be Ed25519 or ES256.');
    const dir = path.resolve(a.out ?? '.');
    fs.mkdirSync(dir, { recursive: true });
    const { privateKey, publicKey } =
      alg === 'Ed25519' ? crypto.generateKeyPairSync('ed25519') : crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const privPath = path.join(dir, `${name}.private.jwk.json`);
    const pubPath = path.join(dir, `${name}.public.jwk.json`);
    for (const f of [privPath, pubPath]) if (fs.existsSync(f)) throw new Error(`${f} already exists; it is not overwritten.`);
    fs.writeFileSync(privPath, JSON.stringify(privateKey.export({ format: 'jwk' }), null, 2) + '\n', { mode: 0o600 });
    fs.writeFileSync(pubPath, JSON.stringify(publicKey.export({ format: 'jwk' }), null, 2) + '\n');
    console.log(`Private key (keep secret, give only to the machine caller): ${privPath}`);
    console.log(`Public key (register this one):                             ${pubPath}`);
    return;
  }

  const pool = getDbPool();
  if (!pool) throw new Error('The database is not configured (DATABASE_URL and APP_DB_PASSWORD).');
  try {
    switch (command) {
      case 'create': {
        const p = await registerPrincipal(
          pool,
          need(a, 'creator'),
          {
            name: need(a, 'name'),
            platform_type: need(a, 'platform'),
            environment: need(a, 'env'),
            allowed_scopes: need(a, 'scopes').split(',').map((s) => s.trim()).filter(Boolean),
            allowed_project_ids: a.projects ? a.projects.split(',').map((s) => s.trim()) : null,
            expires_at: a.expires ?? null
          },
          by()
        );
        console.log(`Created principal ${p.id} ("${p.name}") for creator ${p.creator_id}. Next: add-key --principal ${p.id} --public-key <file>`);
        break;
      }
      case 'add-key': {
        const jwk = JSON.parse(fs.readFileSync(need(a, 'public-key'), 'utf8'));
        const k = await addPrincipalKey(pool, need(a, 'principal'), jwk, by(), a.expires ?? null);
        console.log(`Registered ${k.algorithm} key. kid (put this in the assertion header): ${k.key_id}`);
        console.log(`Fingerprint: ${k.fingerprint}`);
        break;
      }
      case 'list': {
        const rows = await listPrincipals(pool, need(a, 'creator'));
        if (!rows.length) console.log('No principals.');
        for (const p of rows) {
          console.log(`${p.id}  ${p.status.padEnd(9)}  ${p.name}  [${p.environment}]  scopes: ${p.allowed_scopes.join(', ') || '(none)'}`);
          for (const k of p.keys) console.log(`    key ${k.id}  ${k.algorithm}  ${k.revoked_at ? 'REVOKED' : 'active'}  ${k.fingerprint}`);
        }
        break;
      }
      case 'narrow':
        await narrowPrincipal(
          pool,
          need(a, 'principal'),
          {
            ...(a.scopes !== undefined ? { allowed_scopes: a.scopes.split(',').map((x) => x.trim()).filter(Boolean) } : {}),
            ...(a.projects !== undefined ? { allowed_project_ids: a.projects.split(',').map((x) => x.trim()).filter(Boolean) } : {})
          },
          by()
        );
        console.log('Narrowed. Permissions can be removed this way, never added: for more, create a new principal.');
        break;
      case 'suspend':
        await setPrincipalStatus(pool, need(a, 'principal'), 'suspended', by());
        console.log('Suspended.');
        break;
      case 'activate':
        await setPrincipalStatus(pool, need(a, 'principal'), 'active', by());
        console.log('Active.');
        break;
      case 'revoke':
        await setPrincipalStatus(pool, need(a, 'principal'), 'revoked', by());
        console.log('Revoked. This cannot be undone.');
        break;
      case 'revoke-key':
        await revokeKey(pool, need(a, 'key'), by());
        console.log('Key revoked. This cannot be undone.');
        break;
      default:
        console.error(`Unknown command "${command ?? ''}". Commands: keygen, create, add-key, list, narrow, suspend, activate, revoke, revoke-key.`);
        console.error(`Scopes: ${ALL_SCOPES.join(', ')}`);
        process.exitCode = 2;
    }
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error(err instanceof PrincipalError ? `Refused: ${err.message}` : String(err?.message ?? err));
  process.exit(1);
});
