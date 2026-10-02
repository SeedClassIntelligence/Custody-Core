import { spawn, ChildProcess } from 'node:child_process';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address() as net.AddressInfo;
      srv.close(() => resolve(port));
    });
  });
}

export interface DatabaseProcess {
  url: string;
  stop: () => Promise<void>;
}

/**
 * Starts the throwaway local PostgreSQL in a child process (scripts/test-db.ts) and returns its URL.
 *
 * It runs in a child on purpose: the embedded-postgres package installs an exit hook that forces exit
 * code 0, which would hide failing tests or checks if it were loaded in the process that decides the
 * exit code. Closing the child's stdin asks it to stop cleanly and delete its data.
 */
export async function startDatabaseProcess(): Promise<DatabaseProcess> {
  const port = await freePort();
  const child: ChildProcess = spawn(process.execPath, ['--import', 'tsx', path.join(root, 'scripts', 'test-db.ts')], {
    cwd: root,
    env: { ...process.env, TEST_PG_PORT: String(port), TEST_DB_PARENT_PIPE: '1' },
    stdio: ['pipe', 'pipe', 'inherit']
  });

  const url = await new Promise<string>((resolve, reject) => {
    let output = '';
    const timer = setTimeout(() => reject(new Error('Timed out waiting for the local test database to start.')), 110_000);
    child.stdout!.on('data', (chunk) => {
      output += chunk.toString();
      const match = output.match(/TEST_DATABASE_URL=(\S+)/);
      if (match) {
        clearTimeout(timer);
        resolve(match[1]);
      }
    });
    child.on('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`The local test database process exited early (code ${code}). Output: ${output}`));
    });
  });

  return {
    url,
    stop: async () => {
      if (child.exitCode !== null) return;
      await new Promise<void>((resolve) => {
        const fallback = setTimeout(() => child.kill('SIGKILL'), 30_000);
        child.removeAllListeners('exit');
        child.on('exit', () => {
          clearTimeout(fallback);
          resolve();
        });
        child.stdin!.end();
      });
    }
  };
}
