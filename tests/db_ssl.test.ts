import { describe, it, expect } from 'vitest';
import { usesLocalDatabase } from '../server/db';

describe('Database connections: encryption is only switched off for this computer', () => {
  it('a database on this computer is reached without SSL', () => {
    expect(usesLocalDatabase('postgresql://postgres:pw@localhost:5432/custody')).toBe(true);
    expect(usesLocalDatabase('postgresql://postgres:pw@127.0.0.1:5432/custody')).toBe(true);
    expect(usesLocalDatabase('postgresql://postgres:pw@[::1]:5432/custody')).toBe(true);
  });

  it('any other database keeps SSL, even when "localhost" appears elsewhere in the address', () => {
    expect(usesLocalDatabase('postgresql://custody_app:pw@db.abcdefgh.supabase.co:5432/postgres')).toBe(false);
    expect(usesLocalDatabase('postgresql://custody_app:localhost@db.abcdefgh.supabase.co:5432/postgres')).toBe(false);
    expect(usesLocalDatabase('postgresql://localhost:pw@db.abcdefgh.supabase.co:5432/localhost')).toBe(false);
    expect(usesLocalDatabase('postgresql://u:pw@localhost.example.com:5432/db')).toBe(false);
    expect(usesLocalDatabase('not a url')).toBe(false);
  });
});
