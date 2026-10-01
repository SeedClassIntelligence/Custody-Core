import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { applyMigrations } from '../server/migrationRunner';
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
    assertSafeTestDatabaseUrl(url, collectProtectedUrls(testUrl));
    const pool = new pg.Pool({ connectionString: url });
    scratch.push({ name, pool });
    return pool;
  }

  beforeAll(() => {
    assertSafeTestDatabaseUrl(testUrl, collectProtectedUrls(testUrl));
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
    expect(second.applied).toEqual(['002_hashed_timestamp_constraint.sql']);

    const after = await eventColumnState(pool);
    expect(after.columnDefault).toBeNull();
    expect(after.nullable).toBe('NO');
    expect(after.checkNames).toEqual(['chk_event_hashed_timestamp']);

    const recorded = await pool.query('SELECT version FROM schema_migrations ORDER BY version');
    expect(recorded.rows.map((r) => r.version)).toEqual([
      '001_initial_schema.sql',
      '002_hashed_timestamp_constraint.sql'
    ]);
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
    expect(first.applied).toEqual(['001_initial_schema.sql', '002_hashed_timestamp_constraint.sql']);
    const stamps1 = await pool.query('SELECT version, applied_at FROM schema_migrations ORDER BY version');

    const second = await applyMigrations(pool, REAL_MIGRATIONS);
    expect(second.applied).toEqual([]);
    expect(second.alreadyApplied).toHaveLength(2);

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
});
