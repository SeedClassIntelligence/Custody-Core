import express from 'express';
import type pg from 'pg';
import { getDbPool } from './db';
import { creatorOf } from './auth';
import { principalOf, requireScope } from './servicePrincipalAuth';

/**
 * Contribution attribution (docs/integration/PHASE7_DESIGN.md; gate CL-13): for every commit a session pushed, who the author is, who
 * committed it, who answers for it, and what the pushed commit CLAIMED. The rows are derived by the database from the session
 * (migration 016); this file only reads them.
 */

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** What the real commit's author line says, derived the same way the gateway derives it: the name is the executor's, the address is the session's. */
function gitIdentity(r: any) {
  const raw = r.author_executor_display_name || r.author_executor_external_id || [r.author_executor_provider, r.author_executor_model].filter(Boolean).join(' ') || r.author_executor_type;
  // eslint-disable-next-line no-control-regex
  const name = String(raw).replace(/[\u0000-\u001f\u007f<>]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 100) || r.author_executor_type;
  return { name, email: `session-${r.work_session_id}@sessions.custody.invalid` };
}

export function attributionView(r: any) {
  return {
    commit: r.real_sha,
    pushed_as: r.view_sha,
    author: {
      kind: 'executor',
      principal_id: r.author_principal_id,
      executor: {
        type: r.author_executor_type,
        provider: r.author_executor_provider,
        model: r.author_executor_model,
        external_id: r.author_executor_external_id,
        display_name: r.author_executor_display_name
      },
      as_written_in_git: gitIdentity(r)
    },
    committer: { kind: r.committer_kind },
    sponsor: { kind: 'creator', id: r.sponsor_id },
    // what the pushed commit said about itself: evidence of what the session claimed, never an author
    declared_author: { value: r.declared_author, trusted: false },
    recorded_at: new Date(r.created_at).toISOString()
  };
}

export async function attributionFor(c: pg.Pool | pg.PoolClient, sessionId: string) {
  const rows = (await c.query(`SELECT * FROM contribution_attribution WHERE work_session_id = $1 ORDER BY created_at, real_sha`, [sessionId])).rows;
  return { session_id: sessionId, contributions: rows.map(attributionView) };
}

/** Machine callers. Mounted at /api/v2/work-sessions. Same visibility as reading the session. */
export const attributionV2Router = express.Router();

attributionV2Router.get('/:id/attribution', requireScope('work-sessions:read'), async (req, res) => {
  const pool = getDbPool();
  if (!pool) return res.status(503).json({ error: 'Database not connected.' });
  if (!UUID.test(req.params.id)) return res.status(404).json({ error: 'No such work session.' });
  try {
    const p = principalOf(res);
    const s = (
      await pool.query(
        `SELECT s.id FROM work_session s JOIN project pr ON pr.id = s.project_id
          WHERE s.id = $1 AND s.session_type = 'automated_work_session' AND pr.creator_id = $2
            AND (s.requested_by_principal_id = $3 OR $4::boolean) AND ($5::uuid[] IS NULL OR s.project_id = ANY($5::uuid[]))`,
        [req.params.id, p.creatorId, p.id, p.scopes.includes('work-sessions:approve'), p.allowedProjectIds]
      )
    ).rows[0];
    if (!s) return res.status(404).json({ error: 'No such work session.' });
    res.json(await attributionFor(pool, s.id));
  } catch (err: any) {
    console.error('[attribution]', err?.message ?? err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

/** The project's creator. Mounted at /api/v1/projects/:id/work-sessions. */
export const attributionCreatorRouter = express.Router({ mergeParams: true });

attributionCreatorRouter.get('/:sid/attribution', async (req, res) => {
  const pool = getDbPool();
  if (!pool) return res.status(503).json({ error: 'Database not connected.' });
  try {
    const projectId = String((req.params as any).id ?? '');
    const sid = String(req.params.sid);
    const own =
      UUID.test(projectId) &&
      UUID.test(sid) &&
      (await pool.query(`SELECT 1 FROM work_session s JOIN project p ON p.id = s.project_id WHERE s.id = $1 AND s.project_id = $2 AND p.creator_id = $3 AND s.session_type = 'automated_work_session'`, [sid, projectId, creatorOf(res).id])).rowCount === 1;
    if (!own) return res.status(404).json({ error: 'No such work session.' });
    res.json(await attributionFor(pool, sid));
  } catch (err: any) {
    console.error('[attribution]', err?.message ?? err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});
