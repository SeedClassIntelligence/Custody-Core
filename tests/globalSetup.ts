import { assertSafeTestDatabaseUrl, collectProtectedUrls } from './support/safety';
import { startDatabaseProcess, DatabaseProcess } from './support/dbProcess';

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
}

export async function teardown() {
  if (database) {
    await database.stop();
    database = null;
  }
}
