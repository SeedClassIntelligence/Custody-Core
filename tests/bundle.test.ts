import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/**
 * The browser gets only the project URL and the public (anon) key. This builds the real bundle and
 * searches every file for secrets that must never reach a browser.
 */
describe('Built browser bundle', () => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-bundle-'));
  const files: Array<{ name: string; text: string }> = [];
  let secrets: Record<string, string> = {};

  function walk(dir: string): string[] {
    return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]));
  }

  beforeAll(() => {
    const anonKey = process.env.AUTH_ANON_KEY!;
    const apiUrl = process.env.AUTH_API_URL!;
    expect(anonKey, 'the auth stack must be running').toBeTruthy();

    // The server-only keys of the local stack, which a leaky build could pick up.
    const status = spawnSync(process.execPath, [path.join(root, 'node_modules', 'supabase', 'dist', 'supabase.js'), 'status', '-o', 'env'], {
      cwd: root, encoding: 'utf8', env: { ...process.env, DO_NOT_TRACK: '1' }
    });
    const env = Object.fromEntries(status.stdout.split('\n').filter((l) => l.includes('=')).map((l) => {
      const i = l.indexOf('=');
      return [l.slice(0, i), l.slice(i + 1).replace(/^"|"$/g, '')];
    }));
    secrets = {
      SERVICE_ROLE_KEY: env.SERVICE_ROLE_KEY,
      SECRET_KEY: env.SECRET_KEY,
      JWT_SECRET: env.JWT_SECRET,
      // The server's key for stored authenticator keys (set by tests/globalSetup.ts).
      MFA_ENCRYPTION_KEY: process.env.MFA_ENCRYPTION_KEY ?? ''
    };

    const build = spawnSync(process.execPath, [path.join(root, 'node_modules', 'vite', 'bin', 'vite.js'), 'build', '--outDir', outDir, '--emptyOutDir'], {
      cwd: root,
      encoding: 'utf8',
      env: {
        ...process.env,
        // What a real deployment would set, plus the server-only values, to prove they do not leak.
        VITE_SUPABASE_URL: apiUrl,
        VITE_SUPABASE_ANON_KEY: anonKey,
        SUPABASE_SERVICE_ROLE_KEY: secrets.SERVICE_ROLE_KEY ?? '',
        SERVICE_ROLE_KEY: secrets.SERVICE_ROLE_KEY ?? '',
        DATABASE_URL: process.env.TEST_DATABASE_URL ?? '',
        MFA_ENCRYPTION_KEY: secrets.MFA_ENCRYPTION_KEY ?? ''
      }
    });
    if (build.status !== 0) throw new Error(`vite build failed:\n${build.stdout}\n${build.stderr}`.slice(-2000));
    for (const f of walk(outDir)) files.push({ name: path.relative(outDir, f), text: fs.readFileSync(f, 'utf8') });
  }, 180_000);

  afterAll(() => fs.rmSync(outDir, { recursive: true, force: true }));

  const all = () => files.map((f) => f.text).join('\n');

  it('built real JavaScript', () => {
    expect(files.some((f) => f.name.endsWith('.js'))).toBe(true);
    expect(all().length).toBeGreaterThan(100_000);
  });

  it('contains the public anon key (so this search is not vacuous)', () => {
    expect(all()).toContain(process.env.AUTH_ANON_KEY!);
  });

  it('contains no service-role key, secret key or JWT secret value', () => {
    for (const [name, value] of Object.entries(secrets)) {
      if (!value) continue;
      expect(all().includes(value), `${name} value found in the bundle`).toBe(false);
    }
    expect(Object.values(secrets).filter(Boolean).length).toBeGreaterThan(0); // we really had secrets to look for
    expect(secrets.MFA_ENCRYPTION_KEY, 'the authenticator key must be set for this check').toBeTruthy();
  });

  it('contains no service-role variable name or app database password', () => {
    for (const needle of ['SUPABASE_SERVICE_ROLE_KEY', 'SERVICE_ROLE_KEY', 'service_role', 'CustodyAppPass', 'MFA_ENCRYPTION_KEY', 'GITHUB_APP_PRIVATE_KEY', 'GITHUB_APP_CLIENT_SECRET', 'BEGIN RSA PRIVATE KEY']) {
      const hit = files.find((f) => f.text.includes(needle));
      expect(hit?.name, `"${needle}" found in ${hit?.name}`).toBeUndefined();
    }
  });

  it('contains no real database connection string (only the [YOUR-PASSWORD] placeholder in the help text)', () => {
    const urls = [...all().matchAll(/postgres(?:ql)?:\/\/[^\s"'`<)]+/g)].map((m) => m[0]);
    expect(urls.filter((u) => !u.includes('[YOUR-PASSWORD]'))).toEqual([]);
    // The database this very build was given in its environment must not be in the output either.
    const real = process.env.TEST_DATABASE_URL!;
    expect(all().includes(real)).toBe(false);
    expect(all().includes(new URL(real).password)).toBe(false);
  });
});
