import type pg from 'pg';
import { insertEvent } from './db';
import { removeDoorMirrors } from './gateway/mirror';

/**
 * Closing a door, shared by the creator's Close button and anything else that closes doors. Runs inside the caller's
 * transaction, with the door row locked (SELECT ... FOR UPDATE): revokes every credential, withdraws open
 * invitations, marks the door closed and records it. Call afterDoorClosed() once the transaction has committed.
 */
export type CloseReason = 'creator_manual' | 'expired' | 'admin' | 'security_revocation';

export async function closeDoorInTransaction(
  client: pg.PoolClient,
  door: { id: string; project_id: string; status: string },
  actor: { type: 'creator' | 'system'; id: string },
  reason: CloseReason,
  extra: Record<string, unknown> = {}
): Promise<{ credentialsRevoked: number }> {
  const revoked = (await client.query(
    'UPDATE gateway_credential SET revoked_at = now() WHERE door_id = $1 AND revoked_at IS NULL RETURNING id, revoked_at',
    [door.id]
  )).rows;
  await client.query('UPDATE door_invite SET revoked_at = now() WHERE door_id = $1 AND revoked_at IS NULL AND accepted_at IS NULL', [door.id]);
  // A door that was open may hold work: a backup snapshot of it is now due (taken by the scheduler, never waited for here).
  const snapshotDue = door.status === 'open';
  await client.query(
    `UPDATE door SET status = 'closed', closed_at = now(), closed_reason = $2, updated_at = now(),
            snapshot_status = CASE WHEN $3 THEN 'pending' ELSE snapshot_status END,
            snapshot_next_attempt_at = CASE WHEN $3 THEN now() ELSE snapshot_next_attempt_at END
      WHERE id = $1`,
    [door.id, reason, snapshotDue]
  );
  for (const c of revoked) {
    await insertEvent({
      project_id: door.project_id,
      actor_type: actor.type,
      actor_id: actor.id,
      action: 'credential.revoked',
      subject_type: 'door',
      subject_id: door.id,
      payload: { credential_id: c.id, revoked_at: new Date(c.revoked_at).toISOString(), reason: 'door_closed' }
    }, client);
  }
  await insertEvent({
    project_id: door.project_id,
    actor_type: actor.type,
    actor_id: actor.id,
    action: 'door.closed',
    subject_type: 'door',
    subject_id: door.id,
    payload: { reason, previous_status: door.status, credentials_revoked: revoked.length, gateway_mirrors_deleted: true, snapshot_due: snapshotDue, ...extra }
  }, client);
  return { credentialsRevoked: revoked.length };
}

/**
 * After the close has committed: from here on every git request with the old credential is already refused.
 * Deletes the gateway's copies and asks the scheduler to take the snapshot now rather than at its next run.
 */
export async function afterDoorClosed(doorId: string): Promise<void> {
  try {
    removeDoorMirrors(doorId);
  } catch (err: any) {
    console.error('[doors] could not delete mirrors of a closed door:', err?.message ?? err);
  }
  closedListeners.forEach((fn) => fn(doorId));
}

const closedListeners = new Set<(doorId: string) => void>();
/** Called after every door close commits (the scheduler uses it to take snapshots promptly). */
export function onDoorClosed(fn: (doorId: string) => void): () => void {
  closedListeners.add(fn);
  return () => closedListeners.delete(fn);
}
