import { assertSafeTestDatabaseUrl, collectProtectedUrls } from './support/safety';
import { startDatabaseProcess, DatabaseProcess } from './support/dbProcess';
import { ensureAuthStack } from '../scripts/auth-stack';

let database: DatabaseProcess | null = null;

export async function setup() {
  let testUrl = process.env.TEST_DATABASE_URL;
  if (!testUrl) {
    database = await startDatabaseProcess();
    testUrl = database.url;
  }

  // Record the live-database URLs now, before anything is overridden, and hand them to the workers.
  const protectedUrls = collectProtectedUrls();
  assertSafeTestDatabaseUrl(testUrl, protectedUrls);
  process.env.CUSTODY_PROTECTED_URLS = JSON.stringify(protectedUrls);
  // Test workers are started after this, so they inherit it.
  process.env.TEST_DATABASE_URL = testUrl;

  // Login tests need the local Supabase Auth stack (Docker). If it cannot start, only those tests fail,
  // loudly and with the reason; the rest of the suite still runs.
  try {
    const auth = ensureAuthStack();
    process.env.AUTH_API_URL = auth.apiUrl;
    process.env.AUTH_ANON_KEY = auth.anonKey;
  } catch (err: any) {
    process.env.AUTH_STACK_ERROR = String(err.message ?? err);
  }
}

export async function teardown() {
  if (database) {
    await database.stop();
    database = null;
  }
}
