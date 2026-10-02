import { describe, it, expect, afterEach } from 'vitest';
import { assertSafeTestDatabaseUrl, collectProtectedUrls } from './support/safety';

const LOCAL = 'postgresql://postgres:pw@localhost:54329/custody_test';
const LIVE = 'postgresql://postgres:secret@db.exampleproject.supabase.co:5432/postgres';

describe('test database safety guard', () => {
  it('accepts a local throwaway database', () => {
    expect(assertSafeTestDatabaseUrl(LOCAL, [LIVE])).toBe(LOCAL);
  });

  it('refuses when no test database URL is set', () => {
    expect(() => assertSafeTestDatabaseUrl(undefined, [LIVE])).toThrow(/TEST_DATABASE_URL is not set/);
  });

  it('refuses any URL containing supabase.co, however it is written', () => {
    expect(() => assertSafeTestDatabaseUrl(LIVE, [])).toThrow(/supabase\.co/);
    expect(() => assertSafeTestDatabaseUrl('postgresql://u:p@aws-0.POOLER.SUPABASE.CO:6543/postgres', [])).toThrow(/supabase\.co/);
  });

  it('refuses a URL identical to DATABASE_URL', () => {
    expect(() => assertSafeTestDatabaseUrl(LOCAL, [LOCAL])).toThrow(/identical to DATABASE_URL/);
  });

  it('refuses a URL that targets the same host, port and database with different credentials', () => {
    const sameTarget = 'postgresql://other:pw2@localhost:54329/custody_test';
    expect(() => assertSafeTestDatabaseUrl(LOCAL, [sameTarget])).toThrow(/same host, port and database/);
  });

  it('allows a different database on the same server', () => {
    const otherDb = 'postgresql://postgres:pw@localhost:54329/something_else';
    expect(assertSafeTestDatabaseUrl(LOCAL, [otherDb])).toBe(LOCAL);
  });

  it('refuses percent-encoded supabase hosts, in the host or in a host= parameter', () => {
    expect(() => assertSafeTestDatabaseUrl('postgresql://u:p@db.x.supabase%2Eco/postgres', [])).toThrow();
    expect(() => assertSafeTestDatabaseUrl('postgresql://x:y@localhost/t?host=db.x.supabase%2Eco', [])).toThrow();
  });

  it('refuses any host that is not this machine, so the live system cannot be reached by IP or custom domain', () => {
    expect(() => assertSafeTestDatabaseUrl('postgresql://u:p@203.0.113.7:5432/postgres', [])).toThrow(/not local/);
    expect(() => assertSafeTestDatabaseUrl('postgresql://u:p@db.example.com:5432/postgres', [])).toThrow(/not local/);
    expect(() => assertSafeTestDatabaseUrl('postgresql://u:p@aws-0-us.pooler.supabase.com:6543/postgres', [])).toThrow();
    expect(assertSafeTestDatabaseUrl('postgresql://u:p@127.0.0.1:5433/t', [])).toBeTruthy();
  });

  it('refuses connection parameters that could redirect the client (dbname, hostaddr, ...)', () => {
    for (const key of ['dbname', 'hostaddr', 'host', 'service']) {
      expect(() => assertSafeTestDatabaseUrl(`postgresql://u:p@localhost/t?${key}=x`, [])).toThrow(/must not set/);
    }
  });

  describe('protected URLs come from the original environment', () => {
    const saved = { ...process.env };
    afterEach(() => {
      for (const k of ['DATABASE_URL', 'ADMIN_DATABASE_URL', 'APP_DATABASE_URL', 'CUSTODY_PROTECTED_URLS']) {
        if (saved[k] === undefined) delete process.env[k];
        else process.env[k] = saved[k];
      }
    });

    it('a shell DATABASE_URL equal to the test URL is still caught (regression: it used to be dropped)', () => {
      delete process.env.CUSTODY_PROTECTED_URLS;
      process.env.DATABASE_URL = LOCAL;
      expect(() => assertSafeTestDatabaseUrl(LOCAL, collectProtectedUrls())).toThrow(/identical to DATABASE_URL/);
    });

    it('also catches ADMIN_DATABASE_URL and APP_DATABASE_URL equal to the test URL', () => {
      delete process.env.CUSTODY_PROTECTED_URLS;
      delete process.env.DATABASE_URL;
      process.env.ADMIN_DATABASE_URL = LOCAL;
      expect(() => assertSafeTestDatabaseUrl(LOCAL, collectProtectedUrls())).toThrow(/identical/);
    });

    it('uses the list recorded before the runner overrode DATABASE_URL', () => {
      process.env.CUSTODY_PROTECTED_URLS = JSON.stringify([LOCAL]);
      process.env.DATABASE_URL = 'postgresql://postgres:pw@localhost:60000/overridden';
      expect(() => assertSafeTestDatabaseUrl(LOCAL, collectProtectedUrls())).toThrow(/identical/);
    });
  });
});
