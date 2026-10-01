import fs from 'node:fs';
import path from 'node:path';
import dotenv from 'dotenv';

/**
 * The live database's event log is permanent by design, so test code must be
 * unable to reach it. These checks run before any test touches a database.
 */

function describeTarget(url: string): string {
  const parsed = new URL(url);
  const port = parsed.port || '5432';
  return `${parsed.hostname.toLowerCase()}:${port}${parsed.pathname}`;
}

export function assertSafeTestDatabaseUrl(
  testUrl: string | undefined,
  protectedUrls: Array<string | undefined>
): string {
  if (!testUrl) {
    throw new Error('TEST_DATABASE_URL is not set. Tests only run against a throwaway local Postgres.');
  }
  if (testUrl.toLowerCase().includes('supabase.co')) {
    throw new Error('Refusing to run tests: TEST_DATABASE_URL points at supabase.co (the live database).');
  }

  let target: string;
  try {
    target = describeTarget(testUrl);
  } catch {
    throw new Error('Refusing to run tests: TEST_DATABASE_URL is not a valid URL.');
  }

  for (const live of protectedUrls) {
    if (!live) continue;
    if (live === testUrl) {
      throw new Error('Refusing to run tests: TEST_DATABASE_URL is identical to DATABASE_URL.');
    }
    try {
      if (describeTarget(live) === target) {
        throw new Error('Refusing to run tests: TEST_DATABASE_URL targets the same host, port and database as DATABASE_URL.');
      }
    } catch (err: any) {
      if (String(err.message).startsWith('Refusing')) throw err;
      // `live` is not a parseable URL, so it cannot be the same target.
    }
  }
  return testUrl;
}

/** Every database URL the app could use for the live system: the shell's and the one in .env. */
export function collectProtectedUrls(testUrl?: string): string[] {
  const keys = ['DATABASE_URL', 'ADMIN_DATABASE_URL', 'APP_DATABASE_URL'];
  const found: string[] = [];
  for (const key of keys) {
    const value = process.env[key];
    if (value && value !== testUrl) found.push(value);
  }
  const envFile = path.resolve(process.cwd(), '.env');
  if (fs.existsSync(envFile)) {
    const parsed = dotenv.parse(fs.readFileSync(envFile));
    for (const key of keys) {
      if (parsed[key]) found.push(parsed[key]);
    }
  }
  return found;
}

/** Throws unless the pool is connected to exactly the database named by TEST_DATABASE_URL. */
export async function assertPoolTargetsTestDb(pool: {
  options?: { connectionString?: string };
  query: (sql: string) => Promise<{ rows: any[] }>;
}): Promise<void> {
  const testUrl = process.env.TEST_DATABASE_URL;
  assertSafeTestDatabaseUrl(testUrl, collectProtectedUrls(testUrl));

  const poolUrl = pool.options?.connectionString;
  if (!poolUrl) throw new Error('Cannot verify which database this pool is connected to.');
  assertSafeTestDatabaseUrl(poolUrl, collectProtectedUrls(testUrl));

  if (describeTarget(poolUrl) !== describeTarget(testUrl!)) {
    throw new Error('Refusing to continue: pool does not target the test database.');
  }
  const expectedDb = new URL(testUrl!).pathname.replace(/^\//, '');
  const actual = (await pool.query('SELECT current_database() AS db')).rows[0].db;
  if (actual !== expectedDb) {
    throw new Error(`Refusing to continue: connected to "${actual}", expected "${expectedDb}".`);
  }
}
