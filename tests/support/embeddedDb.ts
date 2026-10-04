import EmbeddedPostgres from 'embedded-postgres';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

export interface EmbeddedTestDb {
  url: string;
  stop: () => Promise<void>;
}

const TEST_DB_NAME = 'custody_test';
const TEST_DB_PASSWORD = 'local-test-only';

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

/** Starts a throwaway PostgreSQL in a temp directory and returns a localhost URL for it. */
export async function startEmbeddedTestDb(port?: number): Promise<EmbeddedTestDb> {
  const chosenPort = port ?? (await freePort());
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-test-pg-'));
  // Postgres cannot run as root; when we are root the package creates and uses a postgres OS user,
  // which must be able to enter this directory.
  fs.chmodSync(base, 0o755);

  const pg = new EmbeddedPostgres({
    databaseDir: path.join(base, 'data'),
    user: 'postgres',
    password: TEST_DB_PASSWORD,
    port: chosenPort,
    persistent: false,
    // Match production: UTF8 with a deterministic, non-C collation, so ordering bugs show up in tests.
    // Use ICU directly instead of an operating-system locale name: C.utf8 is available on Unix-like
    // systems but is not a valid Windows locale. PostgreSQL's bundled ICU provider accepts en-US on
    // every platform supported by embedded-postgres and preserves the locale-aware test semantics.
    initdbFlags: ['--encoding=UTF8', '--locale-provider=icu', '--icu-locale=en-US'],
    createPostgresUser: process.getuid?.() === 0,
    onLog: () => {},
    onError: () => {}
  });

  // Backstop: if the process is interrupted before a clean stop, still remove the temp directory.
  process.once('exit', () => fs.rmSync(base, { recursive: true, force: true }));

  await pg.initialise();
  await pg.start();
  await pg.createDatabase(TEST_DB_NAME);

  return {
    // "localhost" matters: server/db.ts only disables SSL for URLs containing it.
    url: `postgresql://postgres:${TEST_DB_PASSWORD}@localhost:${chosenPort}/${TEST_DB_NAME}`,
    stop: async () => {
      try {
        await pg.stop();
      } catch (err: any) {
        // On Windows, taskkill can report the process exited a moment before its files are unlocked.
        // The package then fails its own immediate removal with EBUSY even though PostgreSQL is stopped.
        if (err?.code !== 'EBUSY') throw err;
      }
      fs.rmSync(base, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
    }
  };
}
