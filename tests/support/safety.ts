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
  return `${parsed.hostname.toLowerCase().replace(/\.$/, '')}:${port}${parsed.pathname}`;
}

function safeDecode(text: string): string {
  try {
    return decodeURIComponent(text);
  } catch {
    return text;
  }
}

const LOOPBACK = /^(localhost|127(\.\d{1,3}){3}|\[?::1\]?)$/;
const REDIRECTING_PARAMS = ['host', 'hostaddr', 'dbname', 'service', 'user', 'port'];

export function assertSafeTestDatabaseUrl(
  testUrl: string | undefined,
  protectedUrls: Array<string | undefined>
): string {
  if (!testUrl) {
    throw new Error('TEST_DATABASE_URL is not set. Tests only run against a throwaway local Postgres.');
  }
  // Check the raw text and its percent-decoded form, so "supabase%2Eco" cannot slip through.
  if (/supabase\.co/i.test(testUrl) || /supabase\.co/i.test(safeDecode(testUrl))) {
    throw new Error('Refusing to run tests: TEST_DATABASE_URL points at supabase.co (the live database).');
  }

  let parsed: URL;
  try {
    parsed = new URL(testUrl);
  } catch {
    throw new Error('Refusing to run tests: TEST_DATABASE_URL is not a valid URL.');
  }

  // A throwaway test database lives on this machine. Anything else could be the live system.
  const host = safeDecode(parsed.hostname).toLowerCase().replace(/\.$/, '');
  if (!LOOPBACK.test(host)) {
    throw new Error(`Refusing to run tests: TEST_DATABASE_URL host "${host}" is not local (localhost / 127.x / ::1).`);
  }
  // Connection-string parameters can silently point the client somewhere else.
  for (const key of REDIRECTING_PARAMS) {
    if (parsed.searchParams.has(key)) {
      throw new Error(`Refusing to run tests: TEST_DATABASE_URL must not set the "${key}" parameter.`);
    }
  }

  const target = describeTarget(testUrl);
  for (const live of protectedUrls) {
    if (!live) continue;
    if (live === testUrl) {
      throw new Error('Refusing to run tests: TEST_DATABASE_URL is identical to DATABASE_URL.');
    }
    let liveTarget: string | null = null;
    try {
      liveTarget = describeTarget(live);
    } catch {
      // not a parseable URL, so it cannot be the same target
    }
    if (liveTarget === target) {
      throw new Error('Refusing to run tests: TEST_DATABASE_URL targets the same host, port and database as DATABASE_URL.');
    }
  }
  return testUrl;
}

/**
 * Every database URL the app could use for the live system: the shell's and the one in .env.
 * The test runner records these once, before it overrides anything, in CUSTODY_PROTECTED_URLS,
 * so a later override of DATABASE_URL can never hide the original value.
 */
export function collectProtectedUrls(): string[] {
  const keys = ['DATABASE_URL', 'ADMIN_DATABASE_URL', 'APP_DATABASE_URL'];
  const found: string[] = [];

  if (process.env.CUSTODY_PROTECTED_URLS) {
    found.push(...(JSON.parse(process.env.CUSTODY_PROTECTED_URLS) as string[]));
  } else {
    for (const key of keys) {
      const value = process.env[key];
      if (value) found.push(value);
    }
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
  assertSafeTestDatabaseUrl(testUrl, collectProtectedUrls());

  const poolUrl = pool.options?.connectionString;
  if (!poolUrl) throw new Error('Cannot verify which database this pool is connected to.');
  assertSafeTestDatabaseUrl(poolUrl, collectProtectedUrls());

  if (describeTarget(poolUrl) !== describeTarget(testUrl!)) {
    throw new Error('Refusing to continue: pool does not target the test database.');
  }
  const expectedDb = new URL(testUrl!).pathname.replace(/^\//, '');
  const actual = (await pool.query('SELECT current_database() AS db')).rows[0].db;
  if (actual !== expectedDb) {
    throw new Error(`Refusing to continue: connected to "${actual}", expected "${expectedDb}".`);
  }
}
