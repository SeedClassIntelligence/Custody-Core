import { describe, it, expect } from 'vitest';
import { assertSafeTestDatabaseUrl } from './support/safety';

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
});
