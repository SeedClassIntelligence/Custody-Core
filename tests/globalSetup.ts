import { assertSafeTestDatabaseUrl, collectProtectedUrls } from './support/safety';
import { startEmbeddedTestDb, EmbeddedTestDb } from './support/embeddedDb';

let embedded: EmbeddedTestDb | null = null;

export async function setup() {
  let testUrl = process.env.TEST_DATABASE_URL;

  if (!testUrl) {
    embedded = await startEmbeddedTestDb(process.env.TEST_PG_PORT ? Number(process.env.TEST_PG_PORT) : undefined);
    testUrl = embedded.url;
  }

  assertSafeTestDatabaseUrl(testUrl, collectProtectedUrls(testUrl));
  // Test workers are started after this, so they inherit it.
  process.env.TEST_DATABASE_URL = testUrl;
}

export async function teardown() {
  if (embedded) {
    await embedded.stop();
    embedded = null;
  }
}
