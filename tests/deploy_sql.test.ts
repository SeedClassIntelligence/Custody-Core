import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { applyMigrations, listMigrationFiles } from '../server/migrationRunner';
import { assertSafeTestDatabaseUrl, collectProtectedUrls } from './support/safety';
import { buildApplySql, buildVerifySql, DEPLOY_DIR, DEPLOY_FILES } from '../scripts/build-deploy-sql';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const MIGRATIONS = path.join(root, 'server', 'migrations');

/**
 * The SQL Editor scripts for deploying to a database that was set up before migrations were recorded.
 * Tested on databases built to look like that: migration 001 applied by an older app, nothing recorded.
 */
describe('Dashboard SQL Editor scripts (docs/deploy)', () => {
  const testUrl = process.env.TEST_DATABASE_URL!;
  let adminPool: pg.Pool;
  const scratch: Array<{ name: string; pool: pg.Pool }> = [];

  const applySql = () => fs.readFileSync(path.join(DEPLOY_DIR, DEPLOY_FILES.apply), 'utf8');
  const verifySql = () => fs.readFileSync(path.join(DEPLOY_DIR, DEPLOY_FILES.verify), 'utf8');

  beforeAll(() => {
    assertSafeTestDatabaseUrl(testUrl, collectProtectedUrls());
    adminPool = new pg.Pool({ connectionString: testUrl });
  });
  afterAll(async () => {
    for (const { name, pool } of scratch) {
      await pool.end();
      await adminPool.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
    }
    await adminPool.end();
  });

  async function freshDatabase(): Promise<pg.Pool> {
    const name = `custody_deploy_${Math.random().toString(36).slice(2, 10)}`;
    await adminPool.query(`CREATE DATABASE ${name}`);
    const url = new URL(testUrl);
    url.pathname = `/${name}`;
    assertSafeTestDatabaseUrl(url.toString(), collectProtectedUrls());
    const pool = new pg.Pool({ connectionString: url.toString() });
    // pool.end() can resolve before the server has closed the connections; DROP DATABASE ... WITH (FORCE) then
    // terminates them (57P01). That one is expected during cleanup; anything else still surfaces.
    pool.on('error', (err: any) => {
      if (err?.code !== '57P01') throw err;
    });
    scratch.push({ name, pool });
    return pool;
  }

  /** A database as the live one is: migration 001 applied by the old app, a legacy default and check, old-style events. */
  async function legacyDatabase(opts: { emptyTimestamp?: boolean } = {}): Promise<pg.Pool> {
    const pool = await freshDatabase();
    await pool.query(fs.readFileSync(path.join(MIGRATIONS, '001_initial_schema.sql'), 'utf8'));
    await pool.query(`ALTER TABLE event ALTER COLUMN hashed_timestamp SET DEFAULT ''`);
    await pool.query(`ALTER TABLE event DROP CONSTRAINT event_hashed_timestamp_check`);
    if (!opts.emptyTimestamp) await pool.query(`ALTER TABLE event ADD CONSTRAINT legacy_ts_check CHECK (hashed_timestamp <> '')`);
    await pool.query(`INSERT INTO creator (id, identity_id, display_name, email) VALUES ('11111111-1111-4111-8111-111111111111', 'legacy', 'Legacy', 'legacy@example.com')`);
    await pool.query(`INSERT INTO project (id, creator_id, name, purpose) VALUES ('22222222-2222-4222-8222-222222222222', '11111111-1111-4111-8111-111111111111', 'Legacy', 'old')`);
    await pool.query(
      `INSERT INTO event (seq, project_id, actor_type, actor_id, action, subject_type, subject_id, payload, prev_hash, hash, hashed_timestamp)
       VALUES (1, '22222222-2222-4222-8222-222222222222', 'creator', 'c', 'project.claimed', 'project', 'p', '{}'::jsonb, repeat('0', 64), repeat('a', 64), $1),
              (2, '22222222-2222-4222-8222-222222222222', 'system', 's', 'x', 'project', 'p', '{"n":1}'::jsonb, repeat('a', 64), repeat('b', 64), '2026-09-30T10:00:01.000Z')`,
      [opts.emptyTimestamp ? '' : '2026-09-30T10:00:00.000Z']
    );
    return pool;
  }

  async function verify(pool: pg.Pool) {
    const rows = (await pool.query(verifySql())).rows;
    return { overall: rows[0], rows };
  }

  it('the committed scripts are exactly what the generator produces from the migration files now (no drift)', () => {
    expect(applySql()).toBe(buildApplySql());
    expect(verifySql()).toBe(buildVerifySql());
  });

  it('the verify script reports clear FAILs, and does not crash, on a database that is not migrated', async () => {
    const pool = await legacyDatabase();
    const { overall, rows } = await verify(pool);
    expect(overall.status).toMatch(/FAILED$/);
    expect(rows.find((r) => r.check.startsWith('schema_migrations lists'))!.status).toBe('FAIL');
    expect(rows.find((r) => r.check.startsWith('custody_app can EXECUTE append_event'))!.status).toBe('FAIL');
  });

  it('apply: records 001 and every later migration, upgrades the legacy shape, leaves every event untouched, and verify says ALL PASS', async () => {
    const pool = await legacyDatabase();
    const eventsBefore = (await pool.query('SELECT id, seq, hash, payload, prev_hash, hashed_timestamp FROM event ORDER BY seq')).rows;

    await pool.query(applySql());

    const recorded = (await pool.query('SELECT version FROM schema_migrations ORDER BY version')).rows.map((r) => r.version);
    expect(recorded).toEqual(listMigrationFiles(MIGRATIONS));
    const col = (await pool.query(`SELECT column_default FROM information_schema.columns WHERE table_name = 'event' AND column_name = 'hashed_timestamp'`)).rows[0];
    expect(col.column_default).toBeNull();
    expect((await pool.query('SELECT conname FROM pg_constraint WHERE conrelid = $1::regclass AND conname = $2', ['event', 'chk_event_hashed_timestamp'])).rows).toHaveLength(1);
    expect((await pool.query('SELECT conname FROM pg_constraint WHERE conrelid = $1::regclass AND conname = $2', ['event', 'legacy_ts_check'])).rows).toHaveLength(0);

    const eventsAfter = (await pool.query('SELECT id, seq, hash, payload, prev_hash, hashed_timestamp FROM event ORDER BY seq')).rows;
    expect(eventsAfter).toEqual(eventsBefore);

    const { overall, rows } = await verify(pool);
    expect(rows.filter((r) => r.status === 'FAIL')).toEqual([]);
    expect(overall.status).toBe('ALL PASS');
  });

  it('apply twice: the second run changes nothing (same recorded times, same schema)', async () => {
    const pool = await legacyDatabase();
    await pool.query(applySql());
    const first = (await pool.query('SELECT version, applied_at FROM schema_migrations ORDER BY version')).rows;
    await pool.query(applySql());
    const second = (await pool.query('SELECT version, applied_at FROM schema_migrations ORDER BY version')).rows;
    expect(second).toEqual(first);
    expect((await verify(pool)).overall.status).toBe('ALL PASS');
  });

  it('afterwards the migration runner sees everything as already applied, and the database works as the app role', async () => {
    const pool = await legacyDatabase();
    await pool.query(applySql());

    const run = await applyMigrations(pool, MIGRATIONS);
    expect(run.applied).toEqual([]);
    expect(run.alreadyApplied).toEqual(listMigrationFiles(MIGRATIONS));

    // As custody_app: a direct INSERT is refused and append_event chains onto the old events.
    const appUrl = new URL(testUrl);
    appUrl.pathname = new URL((pool as any).options.connectionString).pathname;
    appUrl.username = 'custody_app';
    appUrl.password = 'CustodyAppPass702!';
    const app = new pg.Pool({ connectionString: appUrl.toString() });
    try {
      await expect(app.query(
        `INSERT INTO event (seq, project_id, actor_type, actor_id, action, subject_type, subject_id, payload, prev_hash, hash, hashed_timestamp)
         VALUES (9, '22222222-2222-4222-8222-222222222222', 'creator', 'x', 'x', 'x', 'x', '{}'::jsonb, repeat('0', 64), repeat('1', 64), '2026-01-01T00:00:00.000Z')`
      )).rejects.toThrow(/permission denied for table event/);
      const added = (await app.query(
        `SELECT * FROM append_event('22222222-2222-4222-8222-222222222222'::uuid, 'system', 'check', 'after.deploy', 'project', 'p', '{"ok":true}'::jsonb)`
      )).rows[0];
      expect(Number(added.seq)).toBe(3);
      expect(added.prev_hash).toBe('b'.repeat(64));
      expect(added.hash_version).toBe(2);
    } finally {
      await app.end();
    }
  });

  it('apply stops with a clear message and changes NOTHING if an old event makes migration 002 impossible', async () => {
    const pool = await legacyDatabase({ emptyTimestamp: true });
    await expect(pool.query(applySql())).rejects.toThrow(/chk_event_hashed_timestamp/);
    const left = (await pool.query(
      `SELECT to_regclass('public.schema_migrations') IS NOT NULL AS table_made,
              EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'append_event') AS function_made,
              EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'event' AND column_name = 'hash_version') AS column_made`
    )).rows[0];
    expect(left).toEqual({ table_made: false, function_made: false, column_made: false });
    // the database is still usable and still has its legacy default
    expect((await pool.query(`SELECT column_default FROM information_schema.columns WHERE table_name = 'event' AND column_name = 'hashed_timestamp'`)).rows[0].column_default).not.toBeNull();
  });

  it('apply stops with a clear message on a database where migration 001 was never applied', async () => {
    const pool = await freshDatabase();
    await expect(pool.query(applySql())).rejects.toThrow(/migration 001 has not been applied/);
    expect((await pool.query(`SELECT count(*)::int AS n FROM information_schema.tables WHERE table_schema = 'public'`)).rows[0].n).toBe(0);
  });

  it('verify notices when the protections are undone (INSERT re-granted to the app role)', async () => {
    const pool = await legacyDatabase();
    await pool.query(applySql());
    await pool.query('GRANT INSERT ON event TO custody_app');
    const { overall, rows } = await verify(pool);
    expect(overall.status).toBe('1 FAILED');
    expect(rows.find((r) => r.status === 'FAIL')!.check).toBe('custody_app has NO INSERT on event');
  });

  it('verify notices broken sequence numbers and previous-hash links', async () => {
    const pool = await legacyDatabase();
    await pool.query(applySql());
    await pool.query(`ALTER TABLE event DISABLE TRIGGER trg_event_append_only`);
    await pool.query(`UPDATE event SET prev_hash = repeat('9', 64) WHERE seq = 2`);
    const { overall, rows } = await verify(pool);
    expect(overall.status).toBe('1 FAILED');
    expect(rows.find((r) => r.status === 'FAIL')!.check).toMatch(/sequence number or previous-hash link is broken/);
  });

  it('the verify script changes nothing (it contains no data-changing statements)', () => {
    // Look at the SQL itself: drop comments and the text inside quotes (check names mention INSERT, DELETE, ...).
    const sql = verifySql().split('\n').filter((l) => !l.trim().startsWith('--')).join('\n').replace(/'(?:[^']|'')*'/g, "''");
    expect(sql).not.toMatch(/\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|GRANT|REVOKE)\b/i);
  });
});
