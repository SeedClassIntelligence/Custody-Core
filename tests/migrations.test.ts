import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { applyMigrations, findTransactionControl, listMigrationFiles } from '../server/migrationRunner';
import { computeEventHash, verifyHashChain, GENESIS_PREV_HASH } from '../shared/crypto';
import { assertSafeTestDatabaseUrl, collectProtectedUrls } from './support/safety';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REAL_MIGRATIONS = path.resolve(__dirname, '..', 'server', 'migrations');

function tempMigrationDir(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-migrations-'));
  for (const [name, contents] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), contents);
  }
  return dir;
}

function urlForDatabase(baseUrl: string, database: string): string {
  const u = new URL(baseUrl);
  u.pathname = `/${database}`;
  return u.toString();
}

describe('Versioned migrations (schema_migrations + 002_hashed_timestamp_constraint)', () => {
  const testUrl = process.env.TEST_DATABASE_URL!;
  const dirs: string[] = [];
  let adminPool: pg.Pool;
  const scratch: Array<{ name: string; pool: pg.Pool }> = [];

  /** A brand-new empty database, so each test starts from a known state. */
  async function freshDatabase(): Promise<pg.Pool> {
    const name = `custody_mig_${Math.random().toString(36).slice(2, 10)}`;
    await adminPool.query(`CREATE DATABASE ${name}`);
    const url = urlForDatabase(testUrl, name);
    assertSafeTestDatabaseUrl(url, collectProtectedUrls());
    const pool = new pg.Pool({ connectionString: url });
    scratch.push({ name, pool });
    return pool;
  }

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
    for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
  });

  async function eventColumnState(pool: pg.Pool) {
    const col = await pool.query(
      `SELECT column_default, is_nullable FROM information_schema.columns
       WHERE table_name = 'event' AND column_name = 'hashed_timestamp'`
    );
    const checks = await pool.query(
      `SELECT con.conname FROM pg_constraint con
       JOIN pg_attribute att ON att.attrelid = con.conrelid AND att.attnum = ANY (con.conkey)
       WHERE con.conrelid = 'event'::regclass AND con.contype = 'c' AND att.attname = 'hashed_timestamp'`
    );
    return { columnDefault: col.rows[0].column_default, nullable: col.rows[0].is_nullable, checkNames: checks.rows.map((r) => r.conname) };
  }

  it('built from 001 alone, then run through the runner: 002 removes the default and installs chk_event_hashed_timestamp', async () => {
    const pool = await freshDatabase();

    // Start from 001 only.
    const only001 = tempMigrationDir({
      '001_initial_schema.sql': fs.readFileSync(path.join(REAL_MIGRATIONS, '001_initial_schema.sql'), 'utf8')
    });
    dirs.push(only001);
    const first = await applyMigrations(pool, only001);
    expect(first.applied).toEqual(['001_initial_schema.sql']);

    // Real pre-state: 001 leaves an auto-named check, not the named one.
    const before = await eventColumnState(pool);
    expect(before.checkNames).not.toContain('chk_event_hashed_timestamp');
    expect(before.checkNames).toHaveLength(1);

    // Now run the real runner over the real migrations folder.
    const second = await applyMigrations(pool, REAL_MIGRATIONS);
    expect(second.alreadyApplied).toEqual(['001_initial_schema.sql']);
    expect(second.applied).toEqual(listMigrationFiles(REAL_MIGRATIONS).slice(1));
    expect(second.applied[0]).toBe('002_hashed_timestamp_constraint.sql');

    const after = await eventColumnState(pool);
    expect(after.columnDefault).toBeNull();
    expect(after.nullable).toBe('NO');
    expect(after.checkNames).toEqual(['chk_event_hashed_timestamp']);

    const recorded = await pool.query('SELECT version FROM schema_migrations ORDER BY version');
    expect(recorded.rows.map((r) => r.version)).toEqual(listMigrationFiles(REAL_MIGRATIONS));
  });

  it('002 also cleans up a legacy database that has DEFAULT \'\' and an oddly named check', async () => {
    const pool = await freshDatabase();
    const only001 = tempMigrationDir({
      '001_initial_schema.sql': fs.readFileSync(path.join(REAL_MIGRATIONS, '001_initial_schema.sql'), 'utf8')
    });
    dirs.push(only001);
    await applyMigrations(pool, only001);

    // Recreate the legacy shape: a default of '' and a differently named check.
    await pool.query(`ALTER TABLE event ALTER COLUMN hashed_timestamp SET DEFAULT ''`);
    await pool.query(`ALTER TABLE event DROP CONSTRAINT event_hashed_timestamp_check`);
    await pool.query(`ALTER TABLE event ADD CONSTRAINT legacy_ts_check CHECK (hashed_timestamp <> '')`);
    const legacy = await eventColumnState(pool);
    expect(legacy.columnDefault).not.toBeNull();
    expect(legacy.checkNames).toEqual(['legacy_ts_check']);

    await applyMigrations(pool, REAL_MIGRATIONS);

    const after = await eventColumnState(pool);
    expect(after.columnDefault).toBeNull();
    expect(after.checkNames).toEqual(['chk_event_hashed_timestamp']);
  });

  it('applies only new migrations: a second run changes nothing and keeps the original timestamps', async () => {
    const pool = await freshDatabase();
    const first = await applyMigrations(pool, REAL_MIGRATIONS);
    expect(first.applied).toEqual(listMigrationFiles(REAL_MIGRATIONS));
    const stamps1 = await pool.query('SELECT version, applied_at FROM schema_migrations ORDER BY version');

    const second = await applyMigrations(pool, REAL_MIGRATIONS);
    expect(second.applied).toEqual([]);
    expect(second.alreadyApplied).toEqual(listMigrationFiles(REAL_MIGRATIONS));

    const stamps2 = await pool.query('SELECT version, applied_at FROM schema_migrations ORDER BY version');
    expect(stamps2.rows).toEqual(stamps1.rows);
  });

  it('runs each migration in a transaction: a failing migration leaves no partial changes and no record', async () => {
    const pool = await freshDatabase();
    const dir = tempMigrationDir({
      '001_ok.sql': 'CREATE TABLE ok_table (id INT);',
      '002_broken.sql': 'CREATE TABLE half_done (id INT); INSERT INTO table_that_does_not_exist VALUES (1);'
    });
    dirs.push(dir);

    await expect(applyMigrations(pool, dir)).rejects.toThrow(/002_broken\.sql failed and was rolled back/);

    const tables = await pool.query(
      `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`
    );
    const names = tables.rows.map((r) => r.table_name);
    expect(names).toContain('ok_table');
    expect(names).not.toContain('half_done');

    const recorded = await pool.query('SELECT version FROM schema_migrations');
    expect(recorded.rows.map((r) => r.version)).toEqual(['001_ok.sql']);
  });

  it('rejects a migration that contains its own COMMIT, BEGIN or ROLLBACK, before applying anything', async () => {
    for (const control of ['COMMIT', 'BEGIN', 'ROLLBACK', 'commit', 'START TRANSACTION', 'END']) {
      const pool = await freshDatabase();
      const dir = tempMigrationDir({
        '001_fine.sql': 'CREATE TABLE fine_table (id INT);',
        '002_escapes.sql': `CREATE TABLE a1 (id INT);\n${control};\nSELECT 1/0;`
      });
      dirs.push(dir);

      await expect(applyMigrations(pool, dir)).rejects.toThrow(/002_escapes\.sql contains its own/);

      // Nothing was applied, not even the harmless 001 that came first.
      const tables = await pool.query(`SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`);
      const names = tables.rows.map((r) => r.table_name);
      expect(names).not.toContain('fine_table');
      expect(names).not.toContain('a1');
      const recorded = await pool.query('SELECT version FROM schema_migrations');
      expect(recorded.rows).toHaveLength(0);
    }
  });

  it('transaction-control detection ignores BEGIN/END inside function bodies, strings and comments', () => {
    const ok = [
      "DO $$ BEGIN PERFORM 1; END $$;",
      "CREATE FUNCTION f() RETURNS int LANGUAGE plpgsql AS $body$ BEGIN COMMIT_LATER(); RETURN 1; END $body$;",
      "SELECT 'COMMIT; ROLLBACK;';",
      "SELECT E'it\\'s; COMMIT;';",
      "-- COMMIT;\nSELECT 1;",
      "/* BEGIN; /* nested */ COMMIT; */ SELECT 1;",
      'SELECT 1 AS "commit";',
      "SELECT 1;"
    ];
    for (const sql of ok) expect(findTransactionControl(sql), sql).toBeNull();

    const bad: Array<[string, string]> = [
      ['BEGIN;', 'BEGIN'],
      ['  commit  ;', 'COMMIT'],
      ['SELECT 1;\nROLLBACK;', 'ROLLBACK'],
      ['start   transaction;', 'START TRANSACTION'],
      ["SELECT 'x'; BEGIN\n;", 'BEGIN'],
      ['COMMIT', 'COMMIT']
    ];
    for (const [sql, expected] of bad) expect(findTransactionControl(sql), sql).toBe(expected);
  });

  it('every real migration file passes the transaction-control check', () => {
    for (const file of listMigrationFiles(REAL_MIGRATIONS)) {
      expect(findTransactionControl(fs.readFileSync(path.join(REAL_MIGRATIONS, file), 'utf8')), file).toBeNull();
    }
  });

  it('events written before 003 (hash_version 1) still verify, and new events chain onto them', async () => {
    const pool = await freshDatabase();
    const upTo002 = tempMigrationDir({
      '001_initial_schema.sql': fs.readFileSync(path.join(REAL_MIGRATIONS, '001_initial_schema.sql'), 'utf8'),
      '002_hashed_timestamp_constraint.sql': fs.readFileSync(path.join(REAL_MIGRATIONS, '002_hashed_timestamp_constraint.sql'), 'utf8')
    });
    dirs.push(upTo002);
    await applyMigrations(pool, upTo002);

    // Two events written the old way: hashed by application code.
    const creator = (await pool.query(
      `INSERT INTO creator (identity_id, display_name, email) VALUES ('legacy', 'Legacy', 'legacy@custody.io') RETURNING id`
    )).rows[0].id;
    const projectId = (await pool.query(
      `INSERT INTO project (creator_id, name, purpose) VALUES ($1, 'Legacy', 'Old events') RETURNING id`, [creator]
    )).rows[0].id as string;
    let prev = GENESIS_PREV_HASH;
    for (let seq = 1; seq <= 2; seq++) {
      const base = {
        seq, project_id: projectId, actor_type: 'creator', actor_id: creator, action: 'legacy.event',
        subject_type: 'project', subject_id: projectId, payload: { n: seq, name: 'café' },
        prev_hash: prev, timestamp: `2026-09-30T10:00:0${seq}.000Z`
      };
      const hash = await computeEventHash(base);
      await pool.query(
        `INSERT INTO event (seq, project_id, actor_type, actor_id, action, subject_type, subject_id, payload, prev_hash, hash, hashed_timestamp)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11)`,
        [seq, projectId, base.actor_type, base.actor_id, base.action, base.subject_type, base.subject_id,
         JSON.stringify(base.payload), prev, hash, base.timestamp]
      );
      prev = hash;
    }

    // Now upgrade, and append a database-built event.
    const upgrade = await applyMigrations(pool, REAL_MIGRATIONS);
    expect(upgrade.applied).toEqual(listMigrationFiles(REAL_MIGRATIONS).slice(2));
    await pool.query(
      `SELECT * FROM append_event($1::uuid, 'system', 'upgrade_test', 'after.upgrade', 'project', $2, '{"ok":true}'::jsonb)`,
      [projectId, projectId]
    );

    const rows = (await pool.query('SELECT * FROM event WHERE project_id = $1 ORDER BY seq', [projectId])).rows;
    expect(rows.map((r) => [Number(r.seq), r.hash_version])).toEqual([[1, 1], [2, 1], [3, 2]]);
    expect(rows[2].prev_hash).toBe(rows[1].hash);

    const verified = await verifyHashChain(rows.map((r) => ({
      seq: Number(r.seq), project_id: r.project_id, actor_type: r.actor_type, actor_id: r.actor_id, action: r.action,
      subject_type: r.subject_type, subject_id: r.subject_id, payload: r.payload, prev_hash: r.prev_hash,
      hash: r.hash, timestamp: r.hashed_timestamp, hash_version: r.hash_version, canonical_payload: r.canonical_payload
    })));
    expect(verified.isValid).toBe(true);
    expect(verified.totalEvents).toBe(3);
  });
});
