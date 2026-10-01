import fs from 'node:fs';
import path from 'node:path';
import type pg from 'pg';

export interface MigrationRunResult {
  applied: string[];
  alreadyApplied: string[];
}

// Arbitrary constant so two servers starting at once do not run migrations at the same time.
const MIGRATION_LOCK_ID = 7_021_001;

export function listMigrationFiles(dir: string): string[] {
  return fs
    .readdirSync(dir)
    .filter((name) => /^\d+_.+\.sql$/.test(name))
    .sort();
}

/**
 * Applies every migration in `dir` that is not yet recorded in schema_migrations, in filename
 * order. Each migration runs in its own transaction together with its bookkeeping row, so a
 * failure leaves neither partial changes nor a record behind. Must run as the admin role.
 */
export async function applyMigrations(pool: pg.Pool, dir: string): Promise<MigrationRunResult> {
  const client = await pool.connect();
  const result: MigrationRunResult = { applied: [], alreadyApplied: [] };

  try {
    await client.query('SELECT pg_advisory_lock($1)', [MIGRATION_LOCK_ID]);
    try {
      await client.query(`
        CREATE TABLE IF NOT EXISTS schema_migrations (
          version TEXT PRIMARY KEY,
          applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
      `);

      const recorded = await client.query('SELECT version FROM schema_migrations');
      const done = new Set<string>(recorded.rows.map((r) => r.version));

      for (const file of listMigrationFiles(dir)) {
        if (done.has(file)) {
          result.alreadyApplied.push(file);
          continue;
        }
        const sql = fs.readFileSync(path.join(dir, file), 'utf8');
        try {
          await client.query('BEGIN');
          await client.query(sql);
          await client.query('INSERT INTO schema_migrations (version) VALUES ($1)', [file]);
          await client.query('COMMIT');
          result.applied.push(file);
        } catch (err: any) {
          await client.query('ROLLBACK');
          throw new Error(`Migration ${file} failed and was rolled back: ${err.message}`);
        }
      }
    } finally {
      await client.query('SELECT pg_advisory_unlock($1)', [MIGRATION_LOCK_ID]);
    }
  } finally {
    client.release();
  }
  return result;
}
