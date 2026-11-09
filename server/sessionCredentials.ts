import crypto from 'node:crypto';
import type pg from 'pg';
import { insertEvent } from './db';
import { removeSessionFiles } from './gateway/realMirror';

/**
 * The secret an automated session's git client sends (docs/integration/PHASE5_DESIGN.md, 4.3). Prefix `ccs_`; a door's credential
 * starts `ccg_`. They live in different tables and each gateway route accepts only its own prefix, so one kind can never be used as
 * the other. Only the SHA-256 of a credential is stored; the credential itself is shown once, when it is issued.
 */

export const SESSION_TOKEN_PREFIX = 'ccs_';
/** A session can be given a replacement credential this many times (each one revokes the last): a lost secret is fixable, a loop is not. */
export const MAX_CREDENTIALS_PER_SESSION = 10;

export function newSessionToken(): { token: string; hash: string } {
  const token = SESSION_TOKEN_PREFIX + crypto.randomBytes(32).toString('base64url');
  return { token, hash: hashSessionToken(token) };
}

export function hashSessionToken(token: string): string {
  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
}

/**
 * Revokes every active credential of a session, inside the caller's transaction, and records each revocation. Used by everything that
 * ends a session, so the credential's life is the session's life. Safe to call when there is nothing to revoke.
 */
export async function revokeSessionCredentials(
  c: pg.PoolClient,
  session: { id: string; project_id: string },
  actor: { type: 'system'; id: string },
  reason: string
): Promise<number> {
  const rows = (await c.query(`UPDATE session_credential SET revoked_at = now() WHERE work_session_id = $1 AND revoked_at IS NULL RETURNING id`, [session.id])).rows;
  for (const r of rows) {
    await insertEvent(
      {
        project_id: session.project_id,
        actor_type: actor.type,
        actor_id: actor.id,
        action: 'session_credential.revoked',
        subject_type: 'work_session',
        subject_id: session.id,
        payload: { credential_id: r.id, reason }
      },
      c
    );
  }
  return rows.length;
}

/** After the transaction that ended a session has committed: the gateway's copies of it (its view repository) are deleted. Never throws. */
export function discardSessionFiles(sessionId: string): void {
  try {
    removeSessionFiles(sessionId);
  } catch (err: any) {
    console.error(`[sessions] could not delete the files of session ${sessionId}:`, err?.message ?? err);
  }
}
