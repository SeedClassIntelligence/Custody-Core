import { spawn, ChildProcess } from 'node:child_process';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertSafeTestDatabaseUrl, collectProtectedUrls } from './support/safety';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
let child: ChildProcess | null = null;

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address() as net.AddressInfo;
      srv.close(() => resolve(port));
    });
  });
}

/**
 * The database runs in a child process on purpose: the embedded-postgres package installs an exit hook
 * that forces exit code 0, which would hide failing tests if it were loaded in the test runner itself.
 */
async function startDatabaseProcess(): Promise<string> {
  const port = await freePort();
  child = spawn(process.execPath, ['--import', 'tsx', path.join(root, 'scripts', 'test-db.ts')], {
    cwd: root,
    env: { ...process.env, TEST_PG_PORT: String(port), TEST_DB_PARENT_PIPE: '1' },
    stdio: ['pipe', 'pipe', 'inherit']
  });

  return new Promise<string>((resolve, reject) => {
    let output = '';
    const timer = setTimeout(() => reject(new Error('Timed out waiting for the local test database to start.')), 110_000);
    child!.stdout!.on('data', (chunk) => {
      output += chunk.toString();
      const match = output.match(/TEST_DATABASE_URL=(\S+)/);
      if (match) {
        clearTimeout(timer);
        resolve(match[1]);
      }
    });
    child!.on('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`The local test database process exited early (code ${code}). Output: ${output}`));
    });
  });
}

export async function setup() {
  let testUrl = process.env.TEST_DATABASE_URL;
  if (!testUrl) {
    testUrl = await startDatabaseProcess();
  }

  assertSafeTestDatabaseUrl(testUrl, collectProtectedUrls(testUrl));
  // Test workers are started after this, so they inherit it.
  process.env.TEST_DATABASE_URL = testUrl;
}

export async function teardown() {
  if (!child || child.exitCode !== null) return;
  const proc = child;
  child = null;
  await new Promise<void>((resolve) => {
    // Closing stdin asks the database process to stop itself cleanly (no signal, so its own cleanup finishes).
    const fallback = setTimeout(() => proc.kill('SIGKILL'), 30_000);
    proc.removeAllListeners('exit');
    proc.on('exit', () => {
      clearTimeout(fallback);
      resolve();
    });
    proc.stdin!.end();
  });
}
