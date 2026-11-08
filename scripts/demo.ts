import { spawn, ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ensureAuthStack, readAuthStack } from './auth-stack';
import { startDatabaseProcess, freePort } from '../tests/support/dbProcess';
import { assertSafeTestDatabaseUrl, collectProtectedUrls } from '../tests/support/safety';

/**
 * Runs the real app on this computer so you can click through it:
 *   - a throwaway local PostgreSQL (deleted when you stop the demo),
 *   - the real Supabase Auth server from the Supabase CLI's local stack (needs Docker),
 *   - the real Custody Core server and UI.
 * Nothing is mocked and nothing touches a hosted project: the database URL is checked to be local, the login
 * server is the local stack, and the keys are throwaway values made for this run.
 *
 *   npm run demo                (address: http://127.0.0.1:3000, or the next free port)
 *   DEMO_PORT=4000 npm run demo
 *
 * What works: sign up (email is not confirmed locally), the authenticator-code step, claiming a project, the
 * tamper-evident event record, verify and export. What shows "Not connected yet": GitHub (needs your GitHub App,
 * docs/GITHUB_APP_SETUP.md), so doors and the git gateway cannot be exercised here.
 */
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function portIsFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.once('error', () => resolve(false));
    srv.listen(port, '127.0.0.1', () => srv.close(() => resolve(true)));
  });
}

async function choosePort(): Promise<number> {
  const wanted = Number(process.env.DEMO_PORT || 3000);
  return (await portIsFree(wanted)) ? wanted : freePort();
}

async function waitForServer(url: string, server: ChildProcess): Promise<void> {
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    if (server.exitCode !== null) throw new Error('The app server exited before it was ready (its output is above).');
    try {
      const body: any = await (await fetch(`${url}/api/v1/health`)).json();
      if (body?.database?.status === 'connected') return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error('Timed out waiting for the app server and its database connection.');
}

async function main() {
  const dockerNote = readAuthStack() ? '' : ' (the first start downloads images and can take a few minutes)';
  console.log(`Starting local Supabase Auth${dockerNote}...`);
  const auth = ensureAuthStack(); // throws a plain message if Docker is not running

  console.log('Starting a throwaway local database...');
  const database = await startDatabaseProcess();
  assertSafeTestDatabaseUrl(database.url, collectProtectedUrls());

  const port = await choosePort();
  const base = `http://127.0.0.1:${port}`;

  console.log('Starting Custody Core...');
  const server = spawn(process.execPath, ['--import', 'tsx', 'server.ts'], {
    cwd: root,
    env: {
      ...process.env,
      NODE_ENV: 'development',
      DISABLE_HMR: 'true',
      PORT: String(port),
      APP_URL: base,
      // Local database and local login only. Empty strings stop .env from supplying a live project.
      DATABASE_URL: database.url,
      ADMIN_DATABASE_URL: '',
      APP_DATABASE_URL: '',
      SUPABASE_URL: auth.apiUrl,
      SUPABASE_ANON_KEY: auth.anonKey,
      VITE_SUPABASE_URL: auth.apiUrl,
      VITE_SUPABASE_ANON_KEY: auth.anonKey,
      // Throwaway secrets for this run only.
      MFA_ENCRYPTION_KEY: randomBytes(32).toString('base64'),
      APP_DB_PASSWORD: randomBytes(24).toString('base64')
    },
    stdio: ['ignore', 'inherit', 'inherit']
  });

  let stopping = false;
  const stop = async (code: number) => {
    if (stopping) return;
    stopping = true;
    console.log('\nStopping the demo and deleting its throwaway database...');
    if (server.exitCode === null) server.kill('SIGTERM');
    await database.stop();
    console.log('Done. Local Supabase Auth is still running (it is slow to start); stop it with: npm run auth-stack:stop');
    process.exit(code);
  };
  process.on('SIGINT', () => void stop(0));
  process.on('SIGTERM', () => void stop(0));
  server.on('exit', (c) => void stop(c ?? 1));

  try {
    await waitForServer(base, server);
  } catch (err) {
    console.error(String((err as Error).message));
    await stop(1);
    return;
  }

  console.log(`
=====================================================================
  Custody Core is running:  ${base}

  1. Open that address and choose "create account" (any email, e.g. you@example.com).
  2. Set up the authenticator: scan the QR code with an authenticator app
     (Google Authenticator, 1Password, Authy...) and type the 6-digit code.
  3. Claim a project, then open "Event Chain" and press "Check This Record".

  Shows "Not connected yet": GitHub (needs your GitHub App, docs/GITHUB_APP_SETUP.md).
  Everything you create here is deleted when you press Ctrl+C.
=====================================================================
`);
}

main().catch((err) => {
  console.error(String(err?.message || err));
  process.exit(1);
});
