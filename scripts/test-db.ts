import { startEmbeddedTestDb } from '../tests/support/embeddedDb';
import { assertSafeTestDatabaseUrl, collectProtectedUrls } from '../tests/support/safety';

// Starts a throwaway local PostgreSQL and keeps it running. `npm test` starts its own copy
// automatically; use this to get a database you can also poke at by hand.
const port = Number(process.env.TEST_PG_PORT || 54329);
const db = await startEmbeddedTestDb(port);
assertSafeTestDatabaseUrl(db.url, collectProtectedUrls(db.url));

console.log('Local test database is running. Press Ctrl+C to stop and delete it.');
console.log(`TEST_DATABASE_URL=${db.url}`);

const shutdown = async () => {
  await db.stop();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
