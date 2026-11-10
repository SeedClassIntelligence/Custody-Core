import express from 'express';
import type pg from 'pg';
import { getDbPool, insertEvent } from './db';
import { creatorOf } from './auth';
import { principalOf, requireScope, type AuthenticatedPrincipal } from './servicePrincipalAuth';
import { evaluateEvidence, type Evaluation } from './evidence';
import { attestationsFor } from './attestation';
import { discardSessionFiles, revokeSessionCredentials } from './sessionCredentials';
import { ProviderError, ProviderNotConfigured, githubRef, providerFor } from './repositoryProvider';
import './githubProvider';
import { gitEnv, git, withMirrorLock } from './gateway/mirror';
import { realMirrorPath, refreshRealMirror } from './gateway/realMirror';

/**
 * Promotion (docs/integration/PHASE8_DESIGN.md; gate CL-14): moving a repository's default branch forward to a commit a session produced.
 *
 *   asked for by a principal holding repositories:promote, or by the owner  ->  pending   (refused unless the evidence is ready for that commit)
 *   approved by the OWNER ONLY (never a principal)                          ->  approved  (evidence checked again)
 *   carried out by the gateway with the repository host's credentials       ->  completed | failed
 *
 * It is a fast-forward and nothing else: the default branch must still be where the session started, and everything that lands must be a commit the
 * gateway made for this session (so every line has an attribution). If the default branch has moved on, the promotion fails closed; there is no merging
 * in this platform.
 */

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX40 = /^[0-9a-f]{40}$/;

export class PromotionError extends Error {
  constructor(
    public status: number,
    message: string,
    public code: string,
    public extra: Record<string, unknown> = {}
  ) {
    super(message);
  }
}

async function inTransaction<T>(pool: pg.Pool, work: (c: pg.PoolClient) => Promise<T>): Promise<T> {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const out = await work(c);
    await c.query('COMMIT');
    return out;
  } catch (err) {
    await c.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    c.release();
  }
}

export function promotionView(r: any) {
  const iso = (v: unknown) => (v ? new Date(v as string).toISOString() : null);
  return {
    id: r.id,
    work_session_id: r.work_session_id,
    repository_id: r.repository_id,
    target_branch: r.target_branch,
    commit: r.commit_hash,
    status: r.status,
    requested_by: r.requested_by_principal_id ? { kind: 'principal', id: r.requested_by_principal_id } : { kind: 'creator', id: r.requested_by_creator_id },
    requested_at: iso(r.requested_at),
    evidence_at_request: r.evidence_at_request,
    attestations_at_request: r.attestations_at_request,
    approved_by: r.approved_by,
    approved_at: iso(r.approved_at),
    rejected_reason: r.rejected_reason,
    previous_tip: r.previous_tip,
    completed_at: iso(r.completed_at),
    failure_code: r.failure_code
  };
}

type Actor = { kind: 'principal'; principal: AuthenticatedPrincipal } | { kind: 'creator'; creatorId: string };

interface SessionInfo {
  id: string;
  project_id: string;
  repository_id: string;
  status: string;
  sponsor_id: string;
  default_branch: string | null;
}

async function loadSession(c: pg.Pool | pg.PoolClient, actor: Actor, sessionId: string, projectId?: string): Promise<SessionInfo> {
  const creatorId = actor.kind === 'principal' ? actor.principal.creatorId : actor.creatorId;
  const allowed = actor.kind === 'principal' ? actor.principal.allowedProjectIds : null;
  const s = (
    await c.query(
      `SELECT s.id, s.project_id, s.repository_id, s.status, s.sponsor_id, v.default_branch
         FROM work_session s JOIN project p ON p.id = s.project_id LEFT JOIN session_view v ON v.work_session_id = s.id
        WHERE s.id = $1 AND s.session_type = 'automated_work_session' AND p.creator_id = $2
          AND ($3::uuid[] IS NULL OR s.project_id = ANY($3::uuid[])) AND ($4::uuid IS NULL OR s.project_id = $4)`,
      [sessionId, creatorId, allowed, projectId ?? null]
    )
  ).rows[0];
  if (!s) throw new PromotionError(404, 'No such work session.', 'not_found');
  return s;
}

function notReady(e: Evaluation): PromotionError {
  const open = e.requirements.filter((r) => r.required && r.state !== 'satisfied').map((r) => `${r.evidence_type}: ${r.state}`);
  return new PromotionError(422, `The evidence for this commit is not ready (${open.join(', ') || 'no commit'}).`, 'evidence_not_ready', { evaluation: e });
}

export async function requestPromotion(pool: pg.Pool, actor: Actor, sessionId: string, commitParam: unknown, projectId?: string) {
  if (commitParam !== undefined && commitParam !== null && (typeof commitParam !== 'string' || !HEX40.test(commitParam))) {
    throw new PromotionError(400, 'commit must be a full 40-character lowercase commit id.', 'invalid');
  }
  const s = await loadSession(pool, actor, sessionId, projectId);
  if (actor.kind === 'creator' && actor.creatorId !== s.sponsor_id) throw new PromotionError(404, 'No such work session.', 'not_found');
  if (s.status !== 'active' && s.status !== 'awaiting_evidence') throw new PromotionError(409, `This session is ${s.status}; only a running session can be promoted.`, 'not_running');
  if (!s.default_branch) throw new PromotionError(409, 'This session has no recorded starting point.', 'not_running');

  let commit = (commitParam as string | null | undefined) ?? null;
  if (!commit) commit = (await pool.query(`SELECT real_sha FROM session_commit WHERE work_session_id = $1 ORDER BY created_at DESC, view_sha DESC LIMIT 1`, [s.id])).rows[0]?.real_sha ?? null;
  if (!commit) throw new PromotionError(422, 'This session has not pushed anything to promote.', 'nothing_to_promote');
  const known = (await pool.query(`SELECT 1 FROM session_commit WHERE work_session_id = $1 AND real_sha = $2`, [s.id, commit])).rowCount;
  if (!known) throw new PromotionError(422, 'That is not a commit this session produced.', 'unknown_commit');

  const evaluation = await evaluateEvidence(pool, s.id, commit);
  if (!evaluation.ready) throw notReady(evaluation);
  const attestations = (await attestationsFor(pool, s.id, commit)).attestations.filter((a) => a.authority.active).map((a) => ({ id: a.id, claim: a.claim, authority_id: a.authority.id }));

  return inTransaction(pool, async (c) => {
    let row;
    try {
      row = (
        await c.query(
          `INSERT INTO promotion_request (work_session_id, project_id, repository_id, target_branch, commit_hash, requested_by_principal_id, requested_by_creator_id, evidence_at_request, attestations_at_request)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb) RETURNING *`,
          [s.id, s.project_id, s.repository_id, s.default_branch, commit, actor.kind === 'principal' ? actor.principal.id : null, actor.kind === 'creator' ? actor.creatorId : null, JSON.stringify(evaluation), JSON.stringify(attestations)]
        )
      ).rows[0];
    } catch (err: any) {
      if (err?.code === '23505') throw new PromotionError(409, 'This commit already has a live promotion request for this branch.', 'conflict');
      throw err;
    }
    await insertEvent(
      {
        project_id: s.project_id,
        actor_type: actor.kind === 'principal' ? 'system' : 'creator',
        actor_id: actor.kind === 'principal' ? `principal:${actor.principal.id}` : actor.creatorId,
        action: 'promotion.requested',
        subject_type: 'work_session',
        subject_id: s.id,
        payload: { promotion_id: row.id, commit, target_branch: s.default_branch, evidence_ready: true, attestation_count: attestations.length }
      },
      c
    );
    return promotionView(row);
  });
}

async function loadPromotion(c: pg.Pool | pg.PoolClient, creatorId: string, projectId: string, id: string, lock: boolean) {
  const r = (
    await c.query(
      `SELECT pr.*, s.sponsor_id, s.status AS session_status FROM promotion_request pr JOIN work_session s ON s.id = pr.work_session_id JOIN project p ON p.id = pr.project_id
        WHERE pr.id = $1 AND pr.project_id = $2 AND p.creator_id = $3 ${lock ? 'FOR UPDATE OF pr' : ''}`,
      [id, projectId, creatorId]
    )
  ).rows[0];
  if (!r) throw new PromotionError(404, 'No such promotion request.', 'not_found');
  return r;
}

export async function rejectPromotion(pool: pg.Pool, creatorId: string, projectId: string, id: string, reason: string | null) {
  return inTransaction(pool, async (c) => {
    const r = await loadPromotion(c, creatorId, projectId, id, true);
    if (r.sponsor_id !== creatorId) throw new PromotionError(403, 'Only the sponsor of the session can decide this.', 'forbidden');
    if (r.status !== 'pending') throw new PromotionError(409, `This request is ${r.status}, not waiting for a decision.`, 'wrong_status');
    const row = (await c.query(`UPDATE promotion_request SET status = 'rejected', rejected_reason = $2, decided_at = now() WHERE id = $1 RETURNING *`, [id, reason])).rows[0];
    await insertEvent(
      { project_id: projectId, actor_type: 'creator', actor_id: creatorId, action: 'promotion.rejected', subject_type: 'work_session', subject_id: r.work_session_id, payload: { promotion_id: id, commit: r.commit_hash, reason } },
      c
    );
    return promotionView(row);
  });
}

/** The owner approves (evidence is checked again), then the gateway carries it out. Approving an already approved request resumes it. */
export async function approvePromotion(pool: pg.Pool, creatorId: string, projectId: string, id: string) {
  const before = await inTransaction(pool, async (c) => {
    const r = await loadPromotion(c, creatorId, projectId, id, true);
    if (r.sponsor_id !== creatorId) throw new PromotionError(403, 'Only the sponsor of the session can approve this.', 'forbidden');
    if (r.status === 'approved') return r; // resume
    if (r.status !== 'pending') throw new PromotionError(409, `This request is ${r.status}, not waiting for approval.`, 'wrong_status');
    if (r.session_status !== 'active' && r.session_status !== 'awaiting_evidence') throw new PromotionError(409, `The session is ${r.session_status}; only a running session can be promoted.`, 'not_running');
    const evaluation = await evaluateEvidence(c, r.work_session_id, r.commit_hash);
    if (!evaluation.ready) throw notReady(evaluation);
    const row = (await c.query(`UPDATE promotion_request SET status = 'approved', approved_by = $2, approved_at = now(), decided_at = now() WHERE id = $1 RETURNING *`, [id, `creator:${creatorId}`])).rows[0];
    await insertEvent(
      { project_id: projectId, actor_type: 'creator', actor_id: creatorId, action: 'promotion.approved', subject_type: 'work_session', subject_id: r.work_session_id, payload: { promotion_id: id, commit: r.commit_hash, approved_by: `creator:${creatorId}` } },
      c
    );
    return { ...r, ...row };
  });
  return executePromotion(pool, before.id);
}

async function failPromotion(pool: pg.Pool, p: any, code: string, message: string): Promise<never> {
  try {
    await inTransaction(pool, async (c) => {
      const r = await c.query(`UPDATE promotion_request SET status = 'failed', failure_code = $2 WHERE id = $1 AND status = 'approved' RETURNING id`, [p.id, code]);
      if (r.rowCount === 0) return;
      await insertEvent(
        { project_id: p.project_id, actor_type: 'gateway', actor_id: `promotion:${p.id}`, action: 'promotion.failed', subject_type: 'work_session', subject_id: p.work_session_id, payload: { promotion_id: p.id, commit: p.commit_hash, code, message: message.slice(0, 300) } },
        c
      );
    });
  } catch (err: any) {
    console.error('[promotion] could not record the failure:', err?.message ?? err);
  }
  throw new PromotionError(code === 'provider_unavailable' ? 502 : 409, message, code);
}

async function executePromotion(pool: pg.Pool, id: string) {
  const p = (
    await pool.query(
      `SELECT pr.*, s.status AS session_status, r.full_name, gi.installation_id, r.provider
         FROM promotion_request pr JOIN work_session s ON s.id = pr.work_session_id JOIN repository r ON r.id = pr.repository_id
         JOIN project pj ON pj.id = pr.project_id LEFT JOIN github_installation gi ON gi.creator_id = pj.creator_id
        WHERE pr.id = $1`,
      [id]
    )
  ).rows[0];
  if (!p || p.status !== 'approved') throw new PromotionError(409, 'This request is not approved.', 'wrong_status');
  if (p.session_status !== 'active' && p.session_status !== 'awaiting_evidence') return failPromotion(pool, p, 'session_not_running', 'The session is no longer running.');

  const evaluation = await evaluateEvidence(pool, p.work_session_id, p.commit_hash);
  if (!evaluation.ready) return failPromotion(pool, p, 'evidence_not_ready', 'The evidence is no longer ready (it may have become stale, or its issuer or key was revoked).');
  if (p.installation_id === null) return failPromotion(pool, p, 'provider_unavailable', "The project's repository connection is missing.");

  let remote;
  try {
    remote = await providerFor(p.provider).remote(githubRef({ id: p.repository_id, full_name: p.full_name, installation_id: p.installation_id }));
  } catch (err) {
    return failPromotion(pool, p, 'provider_unavailable', err instanceof ProviderNotConfigured ? err.publicMessage : err instanceof ProviderError ? 'The repository host refused access.' : 'The repository host could not be reached.');
  }
  let mirror;
  try {
    mirror = await refreshRealMirror(p.repository_id, remote.url, remote.authHeader);
  } catch (err: any) {
    return failPromotion(pool, p, 'provider_unavailable', String(err?.message ?? 'The repository could not be read.').slice(0, 200));
  }
  const dir = mirror.dir;
  const branchRef = `refs/heads/${p.target_branch}`;
  if (mirror.defaultRef !== branchRef) return failPromotion(pool, p, 'default_branch_changed', 'The repository\'s default branch is no longer the one this session was started from.');
  const tip = mirror.defaultTip;

  type Outcome = { fail: [string, string] } | { already: boolean; tip: string };
  const outcome: Outcome = await withMirrorLock(dir, async (): Promise<Outcome> => {
    const g = async (args: string[]) => git(['--git-dir', dir, ...args], { env: gitEnv() });
    if ((await g(['cat-file', '-e', `${p.commit_hash}^{commit}`])).code !== 0) return { fail: ['commit_missing', 'The gateway no longer holds that commit.'] };
    if (tip === p.commit_hash) return { already: true, tip };
    // A fast-forward only: the default branch must still be where the session started (an ancestor of the commit).
    if ((await g(['merge-base', '--is-ancestor', tip, p.commit_hash])).code !== 0) {
      return { fail: ['default_branch_moved', 'The default branch has moved on since this session started, so its work cannot be fast-forwarded. Nothing was changed; start a new session from the current code.'] };
    }
    // Everything that would land must be a commit the gateway made for this session, so every line has an attribution.
    const landing = (await g(['rev-list', `${tip}..${p.commit_hash}`])).stdout.split('\n').filter(Boolean);
    const mine = new Set((await pool.query(`SELECT real_sha FROM session_commit WHERE work_session_id = $1 AND real_sha = ANY($2::text[])`, [p.work_session_id, landing])).rows.map((r) => r.real_sha));
    if (landing.length === 0 || landing.some((c) => !mine.has(c))) return { fail: ['not_session_commits', 'Some of the commits that would land were not made by the gateway for this session.'] };
    const push = await git(
      ['--git-dir', dir, '-c', `http.extraHeader=${remote.authHeader}`, '-c', 'credential.helper=', 'push', '--porcelain', '--atomic', '--no-verify', `--force-with-lease=${branchRef}:${tip}`, remote.url, `${p.commit_hash}:${branchRef}`],
      { env: gitEnv() }
    );
    if (push.code !== 0) return { fail: ['push_refused', `The repository host did not accept the update: ${push.stderr.split('\n').filter((l) => l.trim() && !/authorization/i.test(l)).slice(-2).join(' ').slice(0, 200)}`] };
    return { already: false, tip };
  });
  if ('fail' in outcome) return failPromotion(pool, p, outcome.fail[0], outcome.fail[1]);

  const done = await inTransaction(pool, async (c) => {
    const row = (
      await c.query(
        `UPDATE promotion_request SET status = 'completed', completed_at = now(), previous_tip = $2, evaluation_at_completion = $3::jsonb WHERE id = $1 AND status = 'approved' RETURNING *`,
        [id, outcome.tip, JSON.stringify(evaluation)]
      )
    ).rows[0];
    if (!row) return null;
    const s = (await c.query(`SELECT id, project_id, status FROM work_session WHERE id = $1 FOR UPDATE`, [p.work_session_id])).rows[0];
    let ended = false;
    if (s.status === 'active' || s.status === 'awaiting_evidence') {
      await c.query(`UPDATE work_session SET status = 'completed' WHERE id = $1`, [s.id]);
      await revokeSessionCredentials(c, s, { type: 'system', id: 'promotion' }, 'session_completed');
      ended = true;
    }
    await insertEvent(
      {
        project_id: p.project_id,
        actor_type: 'gateway',
        actor_id: `promotion:${id}`,
        action: 'promotion.completed',
        subject_type: 'work_session',
        subject_id: p.work_session_id,
        payload: { promotion_id: id, commit: p.commit_hash, target_branch: p.target_branch, previous_tip: outcome.tip, already_in_place: outcome.already, approved_by: p.approved_by }
      },
      c
    );
    return { row, ended };
  });
  if (!done) throw new PromotionError(409, 'This request changed while it was being carried out.', 'changed');
  if (done.ended) discardSessionFiles(p.work_session_id);
  return promotionView(done.row);
}

// --- routes ---------------------------------------------------------------------------------------------------------------

function fail(res: express.Response, err: any, what: string) {
  if (err instanceof PromotionError) return res.status(err.status).json({ error: err.message, code: err.code, ...err.extra });
  console.error(`[promotion] ${what}:`, err?.message ?? err);
  return res.status(500).json({ error: 'Something went wrong on the server.' });
}
const db = (res: express.Response) => {
  const pool = getDbPool();
  if (!pool) res.status(503).json({ error: 'Database not connected.' });
  return pool;
};

/** Machine callers. Mounted at /api/v2/work-sessions. A principal can ask for a promotion; it can never approve one. */
export const promotionV2Router = express.Router();

promotionV2Router.post('/:id/promote', requireScope('repositories:promote'), async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  if (!UUID.test(req.params.id)) return res.status(404).json({ error: 'No such work session.' });
  const body = req.body ?? {};
  if (typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some((k) => k !== 'commit')) return res.status(400).json({ error: 'Send { "commit": <a commit id> } or nothing.' });
  try {
    const p = await requestPromotion(pool, { kind: 'principal', principal: principalOf(res) }, req.params.id.toLowerCase(), body.commit);
    res.status(202).json({ promotion: p, requires_approval: true });
  } catch (err) {
    fail(res, err, 'requesting a promotion');
  }
});

promotionV2Router.get('/:id/promotions', async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  if (!UUID.test(req.params.id)) return res.status(404).json({ error: 'No such work session.' });
  const p = principalOf(res);
  if (!p.scopes.includes('repositories:promote') && !p.scopes.includes('work-sessions:read')) return res.status(403).json({ error: 'This credential needs the work-sessions:read or repositories:promote scope.' });
  try {
    const s = (
      await pool.query(
        `SELECT s.id FROM work_session s JOIN project pr ON pr.id = s.project_id
          WHERE s.id = $1 AND s.session_type = 'automated_work_session' AND pr.creator_id = $2 AND ($3::uuid[] IS NULL OR s.project_id = ANY($3::uuid[]))
            AND (s.requested_by_principal_id = $4 OR $5::boolean)`,
        [req.params.id, p.creatorId, p.allowedProjectIds, p.id, p.scopes.includes('work-sessions:approve') || p.scopes.includes('repositories:promote')]
      )
    ).rows[0];
    if (!s) return res.status(404).json({ error: 'No such work session.' });
    const rows = (await pool.query(`SELECT * FROM promotion_request WHERE work_session_id = $1 ORDER BY requested_at`, [s.id])).rows;
    res.json({ session_id: s.id, promotions: rows.map(promotionView) });
  } catch (err) {
    fail(res, err, 'listing promotions');
  }
});

/** The owner, behind the full login. Mounted at /api/v1/projects/:id/work-sessions. */
export const promotionCreatorRouter = express.Router({ mergeParams: true });

promotionCreatorRouter.get('/:sid/promotions', async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  try {
    const projectId = String((req.params as any).id ?? '');
    if (!UUID.test(projectId) || !UUID.test(req.params.sid)) return res.status(404).json({ error: 'No such work session.' });
    const s = await loadSession(pool, { kind: 'creator', creatorId: creatorOf(res).id }, req.params.sid.toLowerCase(), projectId.toLowerCase());
    const rows = (await pool.query(`SELECT * FROM promotion_request WHERE work_session_id = $1 ORDER BY requested_at`, [s.id])).rows;
    res.json({ session_id: s.id, promotions: rows.map(promotionView) });
  } catch (err) {
    fail(res, err, 'listing promotions');
  }
});

promotionCreatorRouter.post('/:sid/promotions', async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  try {
    const projectId = String((req.params as any).id ?? '');
    if (!UUID.test(projectId) || !UUID.test(req.params.sid)) return res.status(404).json({ error: 'No such work session.' });
    const body = req.body ?? {};
    if (typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some((k) => k !== 'commit')) return res.status(400).json({ error: 'Send { "commit": <a commit id> } or nothing.' });
    const p = await requestPromotion(pool, { kind: 'creator', creatorId: creatorOf(res).id }, req.params.sid.toLowerCase(), body.commit, projectId.toLowerCase());
    res.status(201).json({ promotion: p });
  } catch (err) {
    fail(res, err, 'requesting a promotion');
  }
});

/** Mounted at /api/v1/projects/:id/promotions. Approval is a person's decision; there is no machine route for it. */
export const promotionDecisionRouter = express.Router({ mergeParams: true });

promotionDecisionRouter.get('/', async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  try {
    const projectId = String((req.params as any).id ?? '');
    if (!UUID.test(projectId)) return res.status(404).json({ error: 'No such project.' });
    const rows = (await pool.query(`SELECT pr.* FROM promotion_request pr JOIN project p ON p.id = pr.project_id WHERE pr.project_id = $1 AND p.creator_id = $2 ORDER BY pr.requested_at DESC LIMIT 200`, [projectId, creatorOf(res).id])).rows;
    res.json({ promotions: rows.map(promotionView) });
  } catch (err) {
    fail(res, err, 'listing promotions');
  }
});

promotionDecisionRouter.post('/:pid/approve', async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  try {
    const projectId = String((req.params as any).id ?? '');
    if (!UUID.test(projectId) || !UUID.test(req.params.pid)) return res.status(404).json({ error: 'No such promotion request.' });
    res.json({ promotion: await approvePromotion(pool, creatorOf(res).id, projectId.toLowerCase(), req.params.pid.toLowerCase()) });
  } catch (err) {
    fail(res, err, 'approving a promotion');
  }
});

promotionDecisionRouter.post('/:pid/reject', async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  try {
    const projectId = String((req.params as any).id ?? '');
    if (!UUID.test(projectId) || !UUID.test(req.params.pid)) return res.status(404).json({ error: 'No such promotion request.' });
    const raw = (req.body ?? {}).reason;
    if (raw !== undefined && (typeof raw !== 'string' || raw.trim().length > 500)) return res.status(400).json({ error: 'reason must be text of at most 500 characters.' });
    res.json({ promotion: await rejectPromotion(pool, creatorOf(res).id, projectId.toLowerCase(), req.params.pid.toLowerCase(), typeof raw === 'string' && raw.trim() ? raw.trim() : null) });
  } catch (err) {
    fail(res, err, 'rejecting a promotion');
  }
});
