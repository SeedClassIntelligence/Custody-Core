import { startEmbeddedTestDb } from '../tests/support/embeddedDb';
import { assertSafeTestDatabaseUrl, collectProtectedUrls } from '../tests/support/safety';

// Starts a throwaway local PostgreSQL and keeps it running. `npm test` launches this as a child
// process automatically; run `npm run test:db` yourself to get a database you can also use by hand.
const port = Number(process.env.TEST_PG_PORT || 54329);
const db = await startEmbeddedTestDb(port);
assertSafeTestDatabaseUrl(db.url, collectProtectedUrls());

console.log(`TEST_DATABASE_URL=${db.url}`);
if (!process.env.TEST_DB_PARENT_PIPE) {
  console.log('Local test database is running. Press Ctrl+C to stop and delete it.');
}

let stopping = false;
const shutdown = async () => {
  if (stopping) return;
  stopping = true;
  await db.stop();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

if (process.env.TEST_DB_PARENT_PIPE) {
  // When started by the test runner, stop if the runner goes away so no database is left behind.
  process.stdin.resume();
  process.stdin.on('end', shutdown);
}
