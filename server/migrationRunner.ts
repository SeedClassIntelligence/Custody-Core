import fs from 'node:fs';
import path from 'node:path';
import type pg from 'pg';

export interface MigrationRunResult {
  applied: string[];
  alreadyApplied: string[];
}

// Arbitrary constant so two servers starting at once do not run migrations at the same time.
const MIGRATION_LOCK_ID = 7_021_001;

/** Replaces comments, quoted strings, quoted identifiers and dollar-quoted bodies with spaces. */
function stripNonCode(sql: string): string {
  let out = '';
  let i = 0;
  const n = sql.length;
  while (i < n) {
    const c = sql[i];
    const next = sql[i + 1];
    if (c === '-' && next === '-') {
      while (i < n && sql[i] !== '\n') i++;
      out += ' ';
    } else if (c === '/' && next === '*') {
      let depth = 1;
      i += 2;
      while (i < n && depth > 0) {
        if (sql[i] === '/' && sql[i + 1] === '*') { depth++; i += 2; }
        else if (sql[i] === '*' && sql[i + 1] === '/') { depth--; i += 2; }
        else i++;
      }
      out += ' ';
    } else if (c === "'") {
      const escapes = i > 0 && /[eE]/.test(sql[i - 1]) && !/[A-Za-z0-9_]/.test(sql[i - 2] ?? ' ');
      i++;
      while (i < n) {
        if (escapes && sql[i] === '\\') { i += 2; continue; }
        if (sql[i] === "'") {
          if (sql[i + 1] === "'") { i += 2; continue; }
          i++;
          break;
        }
        i++;
      }
      out += ' ';
    } else if (c === '"') {
      i++;
      while (i < n) {
        if (sql[i] === '"') {
          if (sql[i + 1] === '"') { i += 2; continue; }
          i++;
          break;
        }
        i++;
      }
      out += ' ';
    } else if (c === '$' && !/[A-Za-z0-9_]/.test(sql[i - 1] ?? ' ')) {
      const tag = /^\$([A-Za-z_\u0080-\uffff][A-Za-z0-9_\u0080-\uffff]*)?\$/.exec(sql.slice(i));
      if (tag) {
        const close = sql.indexOf(tag[0], i + tag[0].length);
        i = close === -1 ? n : close + tag[0].length;
        out += ' ';
      } else {
        out += c;
        i++;
      }
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

const TRANSACTION_CONTROL =
  /^(begin|commit|rollback|end|abort|start\s+transaction|prepare\s+transaction|commit\s+prepared|rollback\s+prepared)\b/i;

/**
 * Returns the first transaction-control statement (BEGIN, COMMIT, ROLLBACK, ...) in a migration,
 * or null. The runner wraps each migration in its own transaction, so a migration that ends or
 * restarts it would escape the all-or-nothing guarantee. BEGIN/END inside function bodies
 * (dollar-quoted or quoted strings) are not transaction control and are ignored.
 */
/** Removes SQL-standard function bodies (BEGIN ATOMIC ... END), whose END is not transaction control. */
function stripAtomicBlocks(code: string): string {
  const start = /\bbegin\s+atomic\b/gi;
  let out = '';
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = start.exec(code))) {
    const word = /\b(case|end)\b/gi;
    word.lastIndex = m.index + m[0].length;
    let depth = 0;
    let w: RegExpExecArray | null;
    let endAt = -1;
    while ((w = word.exec(code))) {
      if (w[1].toLowerCase() === 'case') depth++;
      else if (depth === 0) { endAt = w.index + w[0].length; break; }
      else depth--;
    }
    if (endAt === -1) break; // unterminated: leave as is, the server will reject it
    out += code.slice(last, m.index) + ' ';
    last = endAt;
    start.lastIndex = endAt;
  }
  return out + code.slice(last);
}

export function findTransactionControl(sql: string): string | null {
  for (const statement of stripAtomicBlocks(stripNonCode(sql)).split(';')) {
    const match = TRANSACTION_CONTROL.exec(statement.trim());
    if (match) return match[1].toUpperCase().replace(/\s+/g, ' ');
  }
  return null;
}

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
 *
 * `inEachTransaction` (for example server/lockdown.sql) runs inside every migration's transaction, after the
 * migration itself, so whatever a migration creates is never committed without it.
 */
export async function applyMigrations(pool: pg.Pool, dir: string, inEachTransaction?: string): Promise<MigrationRunResult> {
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

      const pending: Array<{ file: string; sql: string }> = [];
      for (const file of listMigrationFiles(dir)) {
        if (done.has(file)) {
          result.alreadyApplied.push(file);
          continue;
        }
        const sql = fs.readFileSync(path.join(dir, file), 'utf8');
        const control = findTransactionControl(sql);
        if (control) {
          throw new Error(
            `Migration ${file} contains its own ${control}. Remove it: the runner already wraps each migration in a transaction.`
          );
        }
        pending.push({ file, sql });
      }

      // Every pending file passed the check above, so nothing has been applied yet if one failed it.
      for (const { file, sql } of pending) {
        try {
          await client.query('BEGIN');
          await client.query(sql);
          if (inEachTransaction) await client.query(inEachTransaction);
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
