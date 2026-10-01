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
      await pg.stop();
      fs.rmSync(base, { recursive: true, force: true });
    }
  };
}
