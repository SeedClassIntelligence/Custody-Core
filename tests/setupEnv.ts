import { assertSafeTestDatabaseUrl, collectProtectedUrls } from './support/safety';

// Runs inside every test worker before any app code is imported. Point the app at the test
// database, after confirming it is not the live one. dotenv (without override) leaves these alone.
const testUrl = process.env.TEST_DATABASE_URL;
assertSafeTestDatabaseUrl(testUrl, collectProtectedUrls());

process.env.DATABASE_URL = testUrl;
process.env.ADMIN_DATABASE_URL = '';
process.env.APP_DATABASE_URL = '';

// Login: point the app at the local Supabase Auth stack (never at a hosted project), or at nothing if
// the stack could not start, so that nothing from .env (which may hold the live project's URL) is used.
const authUrl = process.env.AUTH_API_URL || '';
if (authUrl && !/^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(authUrl)) {
  throw new Error(`Refusing to run tests: AUTH_API_URL "${authUrl}" is not a local address.`);
}
const authDbUrl = process.env.AUTH_DB_URL || '';
if (authDbUrl && !/@(127\.0\.0\.1|localhost):\d+\//.test(authDbUrl)) {
  throw new Error('Refusing to run tests: AUTH_DB_URL is not a local address.');
}
process.env.SUPABASE_URL = authUrl;
process.env.VITE_SUPABASE_URL = authUrl;
process.env.SUPABASE_ANON_KEY = process.env.AUTH_ANON_KEY || '';
process.env.VITE_SUPABASE_ANON_KEY = process.env.AUTH_ANON_KEY || '';
