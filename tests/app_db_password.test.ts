import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { startApp } from './support/api';
import {
  getAdminPool,
  getAppDatabaseUrl,
  appDatabaseConfigProblem,
  runMigrations,
  scramVerifier,
  sslFor
} from '../server/db';
import { assertPoolTargetsTestDb } from './support/safety';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** Runs fn with some environment variables changed, then puts them back. */
function withEnv<T>(vars: Record<string, string | undefined>, fn: () => T): T {
  const saved: Record<string, string | undefined> = {};
  for (const k of Object.keys(vars)) {
    saved[k] = process.env[k];
    if (vars[k] === undefined) delete process.env[k];
    else process.env[k] = vars[k];
  }
  try {
    return fn();
  } finally {
    for (const k of Object.keys(saved)) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

describe('The app database account has no built-in password', () => {
  const adminDb = getAdminPool()!;

  beforeAll(async () => {
    await assertPoolTargetsTestDb(adminDb);
    const res = await runMigrations();
    expect(res.success).toBe(true);
  });

  it('no password is written anywhere in the code, the role file or the deploy script', () => {
    for (const file of ['server/db.ts', 'server/roles.sql', 'docs/deploy/apply-pending-migrations.sql']) {
      const text = fs.readFileSync(path.join(root, file), 'utf8');
      expect(text, file).not.toContain('CustodyAppPass');
      expect(text, file).not.toMatch(/CREATE ROLE custody_app[^;]*PASSWORD/i);
    }
  });

  it('without APP_DB_PASSWORD the app does not connect, and says why', () => {
    withEnv({ APP_DB_PASSWORD: undefined }, () => {
      expect(getAppDatabaseUrl()).toBeNull();
      expect(appDatabaseConfigProblem()).toMatch(/APP_DB_PASSWORD is not set/);
    });
    withEnv({ APP_DB_PASSWORD: 'short' }, () => {
      expect(getAppDatabaseUrl()).toBeNull();
      expect(appDatabaseConfigProblem()).toMatch(/shorter than 16/);
    });
    expect(appDatabaseConfigProblem()).toBeNull();
  });

  it('a Supabase pooler URL (postgres.<ref>) also becomes custody_app, keeping the project ref', () => {
    withEnv({ DATABASE_URL: 'postgresql://postgres.abcdefgh:x@aws-0-us-east-1.pooler.supabase.com:5432/postgres', APP_DB_PASSWORD: 'p'.repeat(20) }, () => {
      const u = new URL(getAppDatabaseUrl()!);
      expect(u.username).toBe('custody_app.abcdefgh');
      expect(u.password).toBe('p'.repeat(20));
    });
  });

  it('the server refuses to start without it', async () => {
    const { startServer } = await import('../server.ts');
    await withEnv({ APP_DB_PASSWORD: undefined }, () =>
      expect(startServer()).rejects.toThrow(/APP_DB_PASSWORD is not set/)
    );
  });

  it('the migration run sets custody_app to APP_DB_PASSWORD, and only that password signs in', async () => {
    const url = new URL(process.env.TEST_DATABASE_URL!);
    url.username = 'custody_app';

    url.password = process.env.APP_DB_PASSWORD!;
    const good = new pg.Pool({ connectionString: url.toString() });
    try {
      expect((await good.query('SELECT current_user AS u')).rows[0].u).toBe('custody_app');
    } finally {
      await good.end();
    }

    url.password = 'CustodyAppPass702!';
    const old = new pg.Pool({ connectionString: url.toString() });
    try {
      await expect(old.query('SELECT 1')).rejects.toThrow(/password authentication failed/);
    } finally {
      await old.end();
    }
  });

  it('the password is sent as a SCRAM verifier, which PostgreSQL accepts as the real password', async () => {
    const v = scramVerifier('a-test-password-0123456789', Buffer.alloc(16, 7));
    expect(v).toMatch(/^SCRAM-SHA-256\$4096:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$/);
    expect(v).not.toContain('a-test-password');

    const role = `custody_scram_check_${process.pid}`;
    const pw = 'a-test-password-0123456789';
    await adminDb.query(`CREATE ROLE ${role} LOGIN PASSWORD '${scramVerifier(pw)}'`);
    try {
      const url = new URL(process.env.TEST_DATABASE_URL!);
      url.username = role;
      url.password = pw;
      const p = new pg.Pool({ connectionString: url.toString() });
      try {
        expect((await p.query('SELECT current_user AS u')).rows[0].u).toBe(role);
      } finally {
        await p.end();
      }
    } finally {
      await adminDb.query(`DROP ROLE ${role}`);
    }
  });
});

describe('Database TLS settings', () => {
  afterEach(() => {
    delete process.env.DATABASE_SSL_CA;
  });

  it('local databases use no TLS; remote ones are encrypted, and checked when a CA is given', () => {
    expect(sslFor('postgresql://u:p@localhost:5432/d')).toBe(false);
    expect(sslFor('postgresql://u:p@127.0.0.1:5432/d')).toBe(false);
    expect(sslFor('postgresql://u:p@db.example.supabase.co:5432/d')).toEqual({ rejectUnauthorized: false });
    // A host merely containing "localhost" is not local.
    expect(sslFor('postgresql://u:p@localhost.attacker.example:5432/d')).toEqual({ rejectUnauthorized: false });

    const pem = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n';
    process.env.DATABASE_SSL_CA = pem;
    expect(sslFor('postgresql://u:p@db.example.supabase.co:5432/d')).toEqual({ ca: pem, rejectUnauthorized: true });
  });
});

describe('/api/v1/health', () => {
  it('does not send database error details', async () => {
    const running = await startApp();
    try {
      const r = await fetch(`${running.base}/api/v1/health`);
      expect(r.status).toBe(200);
      const body = await r.json();
      expect(body.database.status).toBe('connected');
      expect(body.database).not.toHaveProperty('error');
    } finally {
      await running.stop();
    }
  });
});
