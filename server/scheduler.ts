import type pg from 'pg';
import { getDbPool } from './db';
import { githubConfig } from './github';
import { afterDoorClosed, closeDoorInTransaction, onDoorClosed } from './doorLifecycle';
import { applyLock } from './lockService';
import { backupDirIsDefault, takeDoorSnapshot } from './snapshots';

/**
 * Work that happens on its own, inside the server process:
 *
 *  - doors close at their end date (reason "expired"). Checked when the server starts, so a door whose end date
 *    passed while the server was down is closed right away, and then every 30 seconds. (The gateway refuses an
 *    expired door from the exact second regardless; closing also revokes the credential, withdraws invitations,
 *    records it, and starts the snapshot.)
 *  - pending backup snapshots of closed doors are taken, and retried with growing delays if GitHub or the storage
 *    is unavailable;
 *  - repository locks are read back from GitHub every LOCK_CHECK_HOURS (default 6). A lock removed or weakened on
 *    GitHub is recorded and put back; an unchanged lock only updates its check time.
 *
 * Several servers can run this at once: every door and repository is taken with SELECT ... FOR UPDATE SKIP LOCKED,
 * and every change is re-checked inside that lock, so nothing is closed or snapshotted twice.
 */

const TICK_MS = 30_000;
const BATCH = 50;

export interface SchedulerStatus {
  started_at: string | null;
  last_tick_at: string | null;
  last_error: string | null;
  doors_closed: number;
  snapshots_taken: number;
  locks_checked: number;
}

const status: SchedulerStatus = { started_at: null, last_tick_at: null, last_error: null, doors_closed: 0, snapshots_taken: 0, locks_checked: 0 };
export const schedulerStatus = (): SchedulerStatus => ({ ...status });

function lockCheckHours(): number {
  const h = Number(process.env.LOCK_CHECK_HOURS);
  return Number.isFinite(h) && h > 0 ? h : 6;
}

/** Closes every door past its end date that is not closed yet. Returns the ids closed. */
export async function closeOverdueDoors(pool: pg.Pool): Promise<string[]> {
  const closed: string[] = [];
  for (;;) {
    const client = await pool.connect();
    let doorId: string | null = null;
    try {
      await client.query('BEGIN');
      const door = (await client.query(
        `SELECT id, project_id, status, expires_at, extract(epoch FROM now() - expires_at)::int AS overdue_seconds
           FROM door WHERE status IN ('draft', 'awaiting_signature', 'open') AND expires_at <= now()
          ORDER BY expires_at LIMIT 1 FOR UPDATE SKIP LOCKED`
      )).rows[0];
      if (!door) {
        await client.query('ROLLBACK');
        break;
      }
      await closeDoorInTransaction(client, door, { type: 'system', id: 'scheduler' }, 'expired', {
        end_date: new Date(door.expires_at).toISOString(),
        closed_seconds_after_end_date: Number(door.overdue_seconds)
      });
      await client.query('COMMIT');
      doorId = door.id;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
    if (doorId) {
      closed.push(doorId);
      await afterDoorClosed(doorId);
    }
    if (closed.length >= 1000) break;
  }
  status.doors_closed += closed.length;
  return closed;
}

/** Takes every snapshot that is due now. */
export async function takeDueSnapshots(pool: pg.Pool): Promise<number> {
  const due = (await pool.query(
    `SELECT id FROM door WHERE snapshot_status = 'pending' AND (snapshot_next_attempt_at IS NULL OR snapshot_next_attempt_at <= now())
      ORDER BY snapshot_next_attempt_at NULLS FIRST LIMIT $1`,
    [BATCH]
  )).rows;
  let done = 0;
  for (const d of due) {
    try {
      if ((await takeDoorSnapshot(pool, d.id)) === 'done') done++;
    } catch (err: any) {
      console.error('[scheduler] snapshot failed:', err?.message ?? err);
    }
  }
  status.snapshots_taken += done;
  return done;
}

/** Re-checks repository locks not checked in the last LOCK_CHECK_HOURS. */
export async function checkDueLocks(pool: pg.Pool, olderThanHours = lockCheckHours()): Promise<number> {
  if (!githubConfig()) return 0;
  const repos = (await pool.query(
    `SELECT r.*, p.id AS project_id_for_lock, gi.installation_id
       FROM repository r JOIN project p ON p.id = r.project_id JOIN github_installation gi ON gi.creator_id = p.creator_id
      WHERE r.github_repo_id <> '' AND (r.lock_checked_at IS NULL OR r.lock_checked_at < now() - make_interval(secs => $1))
      ORDER BY r.lock_checked_at NULLS FIRST LIMIT $2`,
    [olderThanHours * 3600, BATCH]
  )).rows;
  let checked = 0;
  for (const r of repos) {
    try {
      // Re-read under a row lock so two servers do not check (and record) the same repository at once.
      const client = await pool.connect();
      let fresh: any;
      try {
        await client.query('BEGIN');
        fresh = (await client.query(
          `SELECT * FROM repository WHERE id = $1 AND (lock_checked_at IS NULL OR lock_checked_at < now() - make_interval(secs => $2)) FOR UPDATE SKIP LOCKED`,
          [r.id, olderThanHours * 3600]
        )).rows[0];
        if (fresh) await client.query('UPDATE repository SET lock_checked_at = now() WHERE id = $1', [r.id]);
        await client.query('COMMIT');
      } finally {
        client.release();
      }
      if (!fresh) continue;
      await applyLock(pool, r.project_id_for_lock, { type: 'system', id: 'scheduler' }, Number(r.installation_id), fresh, { quietWhenUnchanged: true });
      checked++;
    } catch (err: any) {
      console.error('[scheduler] lock check failed:', err?.message ?? err);
    }
  }
  status.locks_checked += checked;
  return checked;
}

let timer: NodeJS.Timeout | null = null;
let running: Promise<void> | null = null;

async function tick(pool: pg.Pool) {
  try {
    await closeOverdueDoors(pool);
    await takeDueSnapshots(pool);
    await checkDueLocks(pool);
    status.last_error = null;
  } catch (err: any) {
    status.last_error = String(err?.message ?? err);
    console.error('[scheduler]', status.last_error);
  } finally {
    status.last_tick_at = new Date().toISOString();
  }
}

function runTick(pool: pg.Pool): Promise<void> {
  // One tick at a time in this process; a tick asked for during one runs right after it.
  running = (running ?? Promise.resolve()).then(() => tick(pool));
  return running;
}

/**
 * Starts the scheduler. firstRun closes every door that passed its end date while the server was down; the caller
 * waits for it before serving. Snapshots and lock checks, which may wait on GitHub, then run in the background,
 * and everything repeats every 30 s.
 */
export function startScheduler(): { firstRun: Promise<void>; stop: () => void } {
  const pool = getDbPool();
  if (!pool || timer) return { firstRun: Promise.resolve(), stop: () => undefined };
  if (backupDirIsDefault()) {
    console.warn('[scheduler] BACKUP_DIR is not set: snapshots go to the system temp directory, which may not survive a restart.');
  }
  status.started_at = new Date().toISOString();
  const firstRun = closeOverdueDoors(pool)
    .then((ids) => {
      if (ids.length) console.log(`[scheduler] closed ${ids.length} door(s) that passed their end date while the server was down`);
    })
    .catch((err) => {
      status.last_error = String(err?.message ?? err);
      console.error('[scheduler] closing overdue doors at start failed:', status.last_error);
    })
    .finally(() => void runTick(pool));
  timer = setInterval(() => void runTick(pool), TICK_MS);
  timer.unref();
  const unsubscribe = onDoorClosed(() => void runTick(pool)); // snapshot promptly after a manual close
  return {
    firstRun,
    stop: () => {
      if (timer) clearInterval(timer);
      timer = null;
      unsubscribe();
    }
  };
}
