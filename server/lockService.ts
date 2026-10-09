import type pg from 'pg';
import { insertEvent } from './db';
import { LOCK_NAME, lockRepository } from './repositoryLock';

/**
 * Locks (or re-checks) one repository on GitHub, stores the outcome and records it in the project's events:
 *   repository.locked          first lock, or locked again after it was found removed or changed
 *   repository.lock_verified   a check found the lock exactly as set
 *   repository.lock_missing    a check found the lock removed or changed on GitHub (then it is put back)
 *   repository.lock_failed     GitHub would not lock it (the reason is stored and shown)
 */
export async function applyLock(
  pool: pg.Pool,
  projectId: string,
  actor: { type: 'creator' | 'system'; id: string },
  installationId: number,
  repo: any,
  opts: { quietWhenUnchanged?: boolean } = {}
) {
  const result = await lockRepository(installationId, repo.full_name);
  const wasLocked = !!repo.locked_at;
  const event = (action: string, payload: Record<string, unknown>) =>
    insertEvent({
      project_id: projectId,
      actor_type: actor.type,
      actor_id: actor.id,
      action,
      subject_type: 'repository',
      subject_id: repo.id,
      payload: { full_name: repo.full_name, ...payload }
    });

  if (wasLocked && result.previous !== 'intact') {
    await event('repository.lock_missing', {
      found: result.previous === 'changed' ? 'ruleset changed on GitHub' : 'ruleset not found on GitHub',
      locked_since: new Date(repo.locked_at).toISOString()
    });
  }
  let row;
  if (result.locked) {
    const keepSince = wasLocked && result.previous === 'intact';
    row = (await pool.query(
      `UPDATE repository SET locked_at = CASE WHEN $2 THEN locked_at ELSE now() END, lock_ruleset_id = $3,
              lock_checked_at = now(), lock_error = NULL, updated_at = now()
        WHERE id = $1 RETURNING *`,
      [repo.id, keepSince, result.ruleset_id]
    )).rows[0];
    // A scheduled check that finds the lock exactly as before only updates lock_checked_at: no event every few hours.
    if (!(keepSince && opts.quietWhenUnchanged)) await event(keepSince ? 'repository.lock_verified' : 'repository.locked', {
      ruleset_id: result.ruleset_id,
      ruleset_name: LOCK_NAME,
      rules: ['deletion', 'non_fast_forward'],
      applies_to: 'default branch',
      bypass: 'Custody Core GitHub App only',
      allow_forking: result.allow_forking
    });
  } else {
    row = (await pool.query(
      `UPDATE repository SET locked_at = NULL, lock_checked_at = now(), lock_error = $2, updated_at = now() WHERE id = $1 RETURNING *`,
      [repo.id, result.error]
    )).rows[0];
    // The same refusal again (for example the free plan, checked on schedule) is not recorded again.
    const repeated = opts.quietWhenUnchanged && !wasLocked && repo.lock_error === result.error;
    if (!repeated) await event('repository.lock_failed', { reason: result.error });
  }
  return row;
}

