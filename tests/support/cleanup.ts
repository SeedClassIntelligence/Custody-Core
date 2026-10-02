import type pg from 'pg';
import { assertPoolTargetsTestDb } from './safety';

/**
 * Runs `work` on an admin connection with triggers bypassed (session_replication_role = replica),
 * which tests need to delete or tamper with append-only event rows. It refuses to run unless the
 * pool provably targets the local test database, and always restores the setting afterwards.
 */
export async function withTriggersBypassed(
  adminPool: pg.Pool,
  work: (client: pg.PoolClient) => Promise<void>
): Promise<void> {
  await assertPoolTargetsTestDb(adminPool);
  const client = await adminPool.connect();
  try {
    await client.query("SET session_replication_role = 'replica'");
    await work(client);
  } finally {
    try {
      await client.query('RESET session_replication_role');
      client.release();
    } catch (err) {
      client.release(err as Error); // connection is in an unknown state: discard it
    }
  }
}
