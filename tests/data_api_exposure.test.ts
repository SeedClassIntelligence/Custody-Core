import { describe, it, expect, beforeAll } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { authStack, createSupabaseMfaUser, signUp, uniqueEmail } from './support/authStack';

/**
 * Supabase serves every table and function in the `public` schema over its REST API (/rest/v1, /rest/v1/rpc)
 * to the roles `anon` and `authenticated`, using the public key that is in the browser. On a Supabase
 * database, a newly created table gets full rights for those roles and row-level security off.
 *
 * Custody Core never uses that API: everything goes through our server. So after our migrations and
 * server/roles.sql, those roles must have NO access to anything of ours. Otherwise someone with only a
 * password could, for example, insert their own "passed the code step" row, or read every project.
 *
 * This runs on the real Supabase Postgres image (the local stack's database), so its real default privileges
 * apply, inside a transaction that is always rolled back. It never touches a hosted project.
 */
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const migrations = fs
  .readdirSync(path.join(root, 'server', 'migrations'))
  .filter((n) => /^\d+_.+\.sql$/.test(n))
  .sort()
  .map((n) => fs.readFileSync(path.join(root, 'server', 'migrations', n), 'utf8'));
const lockdown = fs.readFileSync(path.join(root, 'server', 'lockdown.sql'), 'utf8');
// What `npm run migrate` does: each migration with the lockdown in its transaction, then roles, then lockdown.
const roles = fs.readFileSync(path.join(root, 'server', 'roles.sql'), 'utf8') + '\n' + lockdown;

const DATA_API_ROLES = ['anon', 'authenticated'];
const verifySql = fs.readFileSync(path.join(root, 'docs', 'deploy', 'verify-migrations.sql'), 'utf8');
const restRows = async (c: pg.Client) =>
  (await c.query(verifySql)).rows.filter((r: any) => /REST API roles|row-level security/.test(r.check)).map((r: any) => r.status);

async function inRolledBackTransaction<T>(fn: (c: pg.Client) => Promise<T>): Promise<T> {
  const url = authStack().dbUrl;
  if (!/@(127\.0\.0\.1|localhost):\d+\//.test(url)) throw new Error('Refusing: the auth stack database is not local.');
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    await client.query('BEGIN');
    // Our tables must not already exist here, or this would be testing something else.
    const existing = await client.query(`SELECT to_regclass('public.event') AS t`);
    if (existing.rows[0].t) throw new Error('The local stack database already has Custody Core tables; this test needs a clean public schema.');
    return await fn(client);
  } finally {
    await client.query('ROLLBACK').catch(() => undefined);
    await client.end();
  }
}

async function ourObjects(c: pg.Client) {
  const tables = (await c.query(`SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                                  WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v') ORDER BY 1`)).rows.map((r) => r.relname);
  const functions = (await c.query(`SELECT p.oid::regprocedure::text AS f FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                                     WHERE n.nspname = 'public' ORDER BY 1`)).rows.map((r) => r.f);
  return { tables, functions };
}

async function grantsFor(c: pg.Client, role: string) {
  const { tables, functions } = await ourObjects(c);
  const tableHits: string[] = [];
  for (const t of tables) {
    for (const priv of ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']) {
      const r = await c.query(`SELECT has_table_privilege($1, $2, $3) AS ok`, [role, `public.${t}`, priv]);
      if (r.rows[0].ok) tableHits.push(`${priv} ${t}`);
    }
  }
  const functionHits: string[] = [];
  for (const f of functions) {
    const r = await c.query(`SELECT has_function_privilege($1, $2::regprocedure, 'EXECUTE') AS ok`, [role, f]);
    if (r.rows[0].ok) functionHits.push(f);
  }
  return { tables, functions, tableHits, functionHits };
}

describe('Supabase REST API roles have no access to Custody Core data (real Supabase Postgres image)', () => {
  beforeAll(() => {
    authStack();
  });

  it('control: on this image, our tables WITHOUT roles.sql are open to the REST API roles (the threat is real here)', async () => {
    await inRolledBackTransaction(async (c) => {
      for (const sql of migrations) await c.query(sql);
      const g = await grantsFor(c, 'authenticated');
      expect(g.tables).toContain('mfa_session');
      expect(g.tableHits).toContain('INSERT mfa_session');
      // and the dashboard verify script (docs/deploy) reports it
      expect(await restRows(c)).toEqual(['FAIL', 'FAIL', 'FAIL']);
    });
  });

  it('after the migrations and roles.sql: anon and authenticated can touch no table, view or function of ours', async () => {
    await inRolledBackTransaction(async (c) => {
      for (const sql of migrations) await c.query(sql + '\n' + lockdown);
      await c.query(roles);
      for (const role of DATA_API_ROLES) {
        const g = await grantsFor(c, role);
        expect(g.tables.length).toBeGreaterThan(10); // we really looked at our tables
        expect(g.functions.length).toBeGreaterThan(3);
        expect(g.tableHits, `${role} table rights`).toEqual([]);
        expect(g.functionHits, `${role} function rights`).toEqual([]);
      }
      // (Looking into schema public is allowed to every role by PostgreSQL itself; without rights on any object
      // inside it, that gives nothing.) The dashboard verify script agrees:
      expect(await restRows(c)).toEqual(['PASS', 'PASS', 'PASS']);
    });
  });

  it('acting as the REST API would: a password-only user cannot mark the code step passed, unlock, read keys, or forge records', async () => {
    await inRolledBackTransaction(async (c) => {
      for (const sql of migrations) await c.query(sql + '\n' + lockdown);
      await c.query(roles);
      const factor = (await c.query(`INSERT INTO mfa_factor (identity_id, secret_ciphertext, status) VALUES ('victim', 'v1.x', 'verified') RETURNING id`)).rows[0].id;
      const attempts: Array<[string, string, unknown[]]> = [
        ['insert a passed-code-step row', `INSERT INTO public.mfa_session (session_id, identity_id, factor_id) VALUES ('s', 'victim', $1)`, [factor]],
        ['clear a lock', `UPDATE public.mfa_factor SET locked_until = NULL`, []],
        ['read stored keys', `SELECT secret_ciphertext FROM public.mfa_factor`, []],
        ['delete wrong-code attempts', `DELETE FROM public.mfa_attempt`, []],
        ['write an account event', `SELECT public.append_account_event('victim', 'system', 'x', 'forged', '{}'::jsonb)`, []],
        ['read every creator', `SELECT * FROM public.creator`, []],
        ['read every project', `SELECT * FROM public.project`, []],
        ['write a project event', `SELECT public.append_event(gen_random_uuid(), 'system', 'x', 'forged', 'project', 'x', '{}'::jsonb)`, []]
      ];
      for (const role of DATA_API_ROLES) {
        for (const [what, sql, params] of attempts) {
          await c.query('SAVEPOINT try');
          await c.query(`SET LOCAL ROLE ${role}`);
          const err = await c.query(sql, params).then(() => null, (e: Error) => e);
          await c.query('ROLLBACK TO SAVEPOINT try');
          expect(err?.message, `${role} could ${what}`).toMatch(/permission denied/);
        }
      }
    });
  });

  it('row-level security is on for every table of ours, and the app account still has its rows', async () => {
    await inRolledBackTransaction(async (c) => {
      for (const sql of migrations) await c.query(sql + '\n' + lockdown);
      await c.query(roles);
      const off = (await c.query(`SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                                   WHERE n.nspname = 'public' AND c.relkind = 'r' AND NOT c.relrowsecurity ORDER BY 1`)).rows.map((r) => r.relname);
      expect(off).toEqual([]);
      await c.query(`INSERT INTO mfa_factor (identity_id, secret_ciphertext, status) VALUES ('someone', 'v1.x', 'unverified')`);
      await c.query('GRANT custody_app TO CURRENT_USER'); // only so this test can act as the app (rolled back)
      await c.query('SET LOCAL ROLE custody_app');
      expect((await c.query(`SELECT count(*)::int AS n FROM mfa_factor WHERE identity_id = 'someone'`)).rows[0].n).toBe(1);
    });
  });

  it('no gap: right after each migration (lockdown in its own transaction), before roles.sql, nothing is open', async () => {
    await inRolledBackTransaction(async (c) => {
      for (const [i, sql] of migrations.entries()) {
        await c.query(sql + '\n' + lockdown);
        for (const role of DATA_API_ROLES) {
          const g = await grantsFor(c, role);
          expect([...g.tableHits, ...g.functionHits], `${role} after migration ${i + 1}`).toEqual([]);
        }
      }
    });
  });

  it('a table or function added later (without running anything again) is not open to the REST API roles', async () => {
    await inRolledBackTransaction(async (c) => {
      for (const sql of migrations) await c.query(sql + '\n' + lockdown);
      await c.query(roles);
      await c.query(`CREATE TABLE public.future_table (id int)`);
      await c.query(`CREATE FUNCTION public.future_fn() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'`);
      for (const role of DATA_API_ROLES) {
        const g = await grantsFor(c, role);
        expect(g.tables).toContain('future_table');
        expect([...g.tableHits, ...g.functionHits], role).toEqual([]);
      }
    });
  });

  it("migration 005 records every account that had a verified authenticator in Supabase's old code step", async () => {
    const legacy = await createSupabaseMfaUser('snapshot');
    const plain = await signUp(uniqueEmail('snapshot-plain'));
    await inRolledBackTransaction(async (c) => {
      for (const sql of migrations) await c.query(sql + '\n' + lockdown);
      const ids = (await c.query('SELECT identity_id FROM mfa_legacy_reset')).rows.map((r) => r.identity_id);
      expect(ids).toContain(legacy.session.userId);
      expect(ids).not.toContain(plain.userId);
    });
  });
});
