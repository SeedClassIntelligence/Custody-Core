import { assertSafeTestDatabaseUrl, collectProtectedUrls } from './support/safety';

// Runs inside every test worker before any app code is imported. Point the app at the test
// database, after confirming it is not the live one. dotenv (without override) leaves these alone.
const testUrl = process.env.TEST_DATABASE_URL;
assertSafeTestDatabaseUrl(testUrl, collectProtectedUrls());

process.env.DATABASE_URL = testUrl;
process.env.ADMIN_DATABASE_URL = '';
process.env.APP_DATABASE_URL = '';
