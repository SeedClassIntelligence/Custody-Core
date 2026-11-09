import express from 'express';
import type pg from 'pg';
import { execFileSync } from 'node:child_process';
import { getDbPool, insertEvent } from './db';
import { principalOf, requireScope, type AuthenticatedPrincipal } from './servicePrincipalAuth';
import { ProviderError, ProviderNotConfigured, githubRef, providerFor } from './repositoryProvider';
import './githubProvider';
import { gatewayBase } from './doors';
import { refreshRealMirror, sessionViewPath } from './gateway/realMirror';
import { UpstreamError } from './gateway/mirror';
import { PathRules } from './pathRules';
import { ViewBuildError, buildView, verifyBaseCommit, viewLimits, type ViewResult } from './viewBuilder';
import { MAX_CREDENTIALS_PER_SESSION, discardSessionFiles, newSessionToken, revokeSessionCredentials } from './sessionCredentials';

/**
 * Provisioning: what turns an APPROVED automated session into one that can actually work (docs/integration/PHASE5_DESIGN.md, 4.4).
 *
 *   POST /api/v2/work-sessions/:id/credential   (scope repositories:push-session; only the principal that requested the session)
 *     approved  -> provisioning -> active : fetch the real repository, check the base commit, build the filtered view, issue ONE credential
 *     active                              : a replacement credential (the old one stops working at once)
 *   GET  /api/v2/work-sessions/:id/commits      (scope work-sessions:read) which real commit each pushed commit became
 *
 * A failure at any step puts the session back to approved and leaves no credential and no view, so it can simply be tried again.
 */

export const PROVISIONING_STUCK_AFTER_MINUTES = 15;

class ProvisionError extends Error {
  constructor(
    public status: number,
    message: string,
    public code: string
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

interface SessionRow {
  id: string;
  project_id: string;
  repository_id: string;
  status: string;
  base_commit: string;
  repository_access: 'read' | 'read_and_push';
  allowed_read_paths: string[];
  allowed_write_paths: string[];
  prohibited_paths: string[];
  expires_at: Date;
  full_name: string;
  provider: 'github';
  installation_id: number | null;
}

const SELECT_FOR_PROVISIONING = `
  SELECT s.id, s.project_id, s.repository_id, s.status, s.base_commit, s.repository_access,
         s.allowed_read_paths, s.allowed_write_paths, s.prohibited_paths, s.expires_at,
         r.full_name, r.provider, gi.installation_id
    FROM work_session s
    JOIN repository r ON r.id = s.repository_id
    JOIN project p ON p.id = s.project_id
    LEFT JOIN github_installation gi ON gi.creator_id = p.creator_id
   WHERE s.id = $1 AND s.session_type = 'automated_work_session' AND s.requested_by_principal_id = $2
     AND p.creator_id = $3 AND ($4::uuid[] IS NULL OR s.project_id = ANY($4::uuid[]))`;

function paramsFor(principal: AuthenticatedPrincipal, sessionId: string) {
  return [sessionId, principal.id, principal.creatorId, principal.allowedProjectIds];
}

export interface Provisioned {
  session_id: string;
  repository: string;
  read_only: boolean;
  git_url: string;
  credential: { token: string; expires_at: string };
  branch_prefix: string;
  view: { commit: string; tree: string; file_count: number; base_commit: string };
  replaced: boolean;
}

function gitVersion(): string {
  try {
    return execFileSync('git', ['--version'], { encoding: 'utf8' }).trim();
  } catch {
    return 'unknown';
  }
}

/** The credential request. `baseUrl` is the app's public address (for the git address). */
export async function provisionSession(pool: pg.Pool, principal: AuthenticatedPrincipal, sessionId: string, baseUrl: string): Promise<Provisioned> {
  // 1. Decide, and claim the session so only one provisioning runs for it.
  const claim = await inTransaction(pool, async (c) => {
    const s = (await c.query<SessionRow>(`${SELECT_FOR_PROVISIONING} FOR UPDATE OF s`, paramsFor(principal, sessionId))).rows[0];
    if (!s) throw new ProvisionError(404, 'No such work session.', 'not_found');
    if (new Date(s.expires_at).getTime() <= Date.now()) throw new ProvisionError(409, 'This session has expired.', 'expired');
    if (s.status === 'approved') {
      await c.query(`UPDATE work_session SET status = 'provisioning', provisioning_started_at = now() WHERE id = $1`, [s.id]);
      return { s, replacement: false };
    }
    if (s.status === 'active') return { s, replacement: true };
    if (s.status === 'provisioning') throw new ProvisionError(409, 'This session is being prepared. Try again in a moment.', 'in_progress');
    if (s.status === 'requested') throw new ProvisionError(409, 'This session has not been approved yet.', 'not_approved');
    throw new ProvisionError(409, `This session is ${s.status}; it cannot be given a credential.`, 'wrong_status');
  });
  const s = claim.s;

  if (claim.replacement) return issueReplacement(pool, principal, s, baseUrl);

  // 2. Build (no database transaction is held while git works).
  let view: ViewResult;
  let tip: string;
  let defaultRef: string;
  try {
    const provider = providerFor(s.provider);
    if (s.installation_id === null) throw new ProvisionError(503, "The project's GitHub connection is missing. Ask the creator to reconnect GitHub.", 'not_connected');
    let remote;
    try {
      remote = await provider.remote(githubRef({ id: s.repository_id, full_name: s.full_name, installation_id: s.installation_id }));
    } catch (err: any) {
      if (err instanceof ProviderNotConfigured) throw new ProvisionError(503, err.publicMessage, 'provider_not_configured');
      throw new ProvisionError(502, err instanceof ProviderError ? `${provider.label} refused access to the repository.` : `${provider.label} could not be reached.`, 'provider_unavailable');
    }
    let mirror;
    try {
      mirror = await refreshRealMirror(s.repository_id, remote.url, remote.authHeader);
    } catch (err: any) {
      if (err instanceof UpstreamError) throw new ProvisionError(502, err.message, 'repository_unavailable');
      throw err;
    }
    tip = mirror.defaultTip;
    defaultRef = mirror.defaultRef;
    const rules = new PathRules({ allowedRead: s.allowed_read_paths, allowedWrite: s.allowed_write_paths, prohibited: s.prohibited_paths });
    const base = await verifyBaseCommit(mirror.dir, s.base_commit, defaultRef);
    if (!base.ok) throw new ProvisionError(422, `The base commit cannot be used: ${base.detail}.`, `base_${base.reason}`);
    view = await buildView({ mirrorDir: mirror.dir, baseCommit: s.base_commit, rules, outDir: sessionViewPath(s.id), limits: viewLimits() });
  } catch (err: any) {
    discardSessionFiles(s.id);
    await failProvisioning(pool, principal, s, err);
    if (err instanceof ProvisionError) throw err;
    if (err instanceof ViewBuildError) throw new ProvisionError(err.code === 'git_failed' || err.code === 'not_exact' ? 500 : 422, err.message, `view_${err.code}`);
    console.error('[provisioning] failed:', err?.message ?? err);
    throw new ProvisionError(500, 'The session could not be prepared. Nothing was changed; try again.', 'internal');
  }

  // 3. Commit: the view, the credential and the new status, together.
  try {
    const issued = await inTransaction(pool, async (c) => {
      const cur = (await c.query(`SELECT status, expires_at FROM work_session WHERE id = $1 FOR UPDATE`, [s.id])).rows[0];
      if (!cur || cur.status !== 'provisioning') throw new ProvisionError(409, 'The session changed while it was being prepared (it may have been closed). Nothing was issued.', 'changed');
      if (new Date(cur.expires_at).getTime() <= Date.now()) throw new ProvisionError(409, 'This session expired while it was being prepared.', 'expired');
      await c.query(
        `INSERT INTO session_view (work_session_id, base_commit, default_branch, default_branch_tip, view_commit, view_tree, file_count, total_bytes, excluded_count)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [s.id, s.base_commit, defaultRef.replace(/^refs\/heads\//, ''), tip, view.viewCommit, view.viewTree, view.fileCount, view.totalBytes, view.excludedCount]
      );
      const cred = await insertCredential(c, principal, s, []);
      await c.query(`UPDATE work_session SET status = 'active', provisioning_started_at = NULL WHERE id = $1`, [s.id]);
      await insertEvent(
        {
          project_id: s.project_id,
          actor_type: 'system',
          actor_id: `principal:${principal.id}`,
          action: 'work_session.provisioned',
          subject_type: 'work_session',
          subject_id: s.id,
          // Counts only for what was left out: the names, sizes and number of unreadable paths are not the session's to learn.
          payload: {
            repository_id: s.repository_id,
            base_commit: s.base_commit,
            default_branch: defaultRef.replace(/^refs\/heads\//, ''),
            default_branch_tip: tip,
            view_commit: view.viewCommit,
            view_tree: view.viewTree,
            file_count: view.fileCount,
            total_bytes: view.totalBytes,
            excluded_count: view.excludedCount,
            read_only: s.repository_access === 'read',
            git: gitVersion()
          }
        },
        c
      );
      return cred;
    });
    return describe(s, baseUrl, view, issued.token, false);
  } catch (err: any) {
    discardSessionFiles(s.id);
    if (!(err instanceof ProvisionError && err.code === 'changed')) await failProvisioning(pool, principal, s, err);
    if (err instanceof ProvisionError) throw err;
    console.error('[provisioning] could not finish:', err?.message ?? err);
    throw new ProvisionError(500, 'The session could not be prepared. Nothing was changed; try again.', 'internal');
  }
}

async function insertCredential(c: pg.PoolClient, principal: AuthenticatedPrincipal, s: SessionRow, replacing: string[]) {
  const { token, hash } = newSessionToken();
  const row = (await c.query(`INSERT INTO session_credential (work_session_id, token_hash) VALUES ($1, $2) RETURNING id`, [s.id, hash])).rows[0];
  await insertEvent(
    {
      project_id: s.project_id,
      actor_type: 'system',
      actor_id: `principal:${principal.id}`,
      action: 'session_credential.issued',
      subject_type: 'work_session',
      subject_id: s.id,
      payload: { credential_id: row.id, principal_id: principal.id, expires_at: new Date(s.expires_at).toISOString(), replaced_credential_ids: replacing }
    },
    c
  );
  return { token, id: row.id as string };
}

async function issueReplacement(pool: pg.Pool, principal: AuthenticatedPrincipal, s: SessionRow, baseUrl: string): Promise<Provisioned> {
  return inTransaction(pool, async (c) => {
    const cur = (await c.query(`SELECT status, expires_at FROM work_session WHERE id = $1 FOR UPDATE`, [s.id])).rows[0];
    if (!cur || cur.status !== 'active') throw new ProvisionError(409, 'This session is no longer active.', 'wrong_status');
    if (new Date(cur.expires_at).getTime() <= Date.now()) throw new ProvisionError(409, 'This session has expired.', 'expired');
    const issuedBefore = (await c.query(`SELECT count(*)::int AS n FROM session_credential WHERE work_session_id = $1`, [s.id])).rows[0].n;
    if (issuedBefore >= MAX_CREDENTIALS_PER_SESSION) throw new ProvisionError(429, `This session has already been given ${issuedBefore} credentials. Close it and request a new one.`, 'too_many_credentials');
    const old = (await c.query(`SELECT id FROM session_credential WHERE work_session_id = $1 AND revoked_at IS NULL`, [s.id])).rows.map((r) => r.id as string);
    await revokeSessionCredentials(c, s, { type: 'system', id: `principal:${principal.id}` }, 'replaced');
    const fresh = await insertCredential(c, principal, s, old);
    const v = (await c.query(`SELECT view_commit, view_tree, file_count, base_commit FROM session_view WHERE work_session_id = $1`, [s.id])).rows[0];
    if (!v) throw new ProvisionError(500, 'The session has no recorded view.', 'internal');
    return describe(s, baseUrl, { viewCommit: v.view_commit, viewTree: v.view_tree, fileCount: v.file_count, baseCommit: v.base_commit } as ViewResult, fresh.token, true);
  });
}

function describe(s: SessionRow, baseUrl: string, view: ViewResult, token: string, replaced: boolean): Provisioned {
  return {
    session_id: s.id,
    repository: s.full_name,
    read_only: s.repository_access === 'read',
    git_url: `${baseUrl}/git/sessions/${s.id}/${s.full_name}.git`,
    credential: { token, expires_at: new Date(s.expires_at).toISOString() },
    branch_prefix: `session/${s.id}/`,
    view: { commit: view.viewCommit, tree: view.viewTree, file_count: view.fileCount, base_commit: view.baseCommit },
    replaced
  };
}

/** A build that did not finish: the session goes back to approved (if it is still provisioning) and the record says why, in words that name no file. */
async function failProvisioning(pool: pg.Pool, principal: AuthenticatedPrincipal, s: SessionRow, err: any): Promise<void> {
  const code = err instanceof ProvisionError ? err.code : err instanceof ViewBuildError ? `view_${err.code}` : 'internal';
  try {
    await inTransaction(pool, async (c) => {
      const r = await c.query(`UPDATE work_session SET status = 'approved', provisioning_started_at = NULL WHERE id = $1 AND status = 'provisioning' RETURNING id`, [s.id]);
      if (r.rowCount === 0) return;
      await insertEvent(
        {
          project_id: s.project_id,
          actor_type: 'system',
          actor_id: `principal:${principal.id}`,
          action: 'work_session.provisioning_failed',
          subject_type: 'work_session',
          subject_id: s.id,
          payload: { reason: code, message: err instanceof ProvisionError || err instanceof ViewBuildError ? String(err.message).slice(0, 300) : 'internal error' }
        },
        c
      );
    });
  } catch (e: any) {
    console.error('[provisioning] could not put the session back to approved:', e?.message ?? e); // the scheduler's recovery will
  }
}

/** Scheduler: a session left in 'provisioning' by a crash goes back to approved so it can be provisioned again. Never touches a recent one. */
export async function recoverStuckProvisioning(pool: pg.Pool): Promise<string[]> {
  const out: string[] = [];
  for (;;) {
    const id = await inTransaction(pool, async (c) => {
      const s = (
        await c.query(
          `SELECT id, project_id FROM work_session
            WHERE status = 'provisioning' AND provisioning_started_at < now() - make_interval(mins => $1)
            ORDER BY provisioning_started_at LIMIT 1 FOR UPDATE SKIP LOCKED`,
          [PROVISIONING_STUCK_AFTER_MINUTES]
        )
      ).rows[0];
      if (!s) return null;
      await c.query(`UPDATE work_session SET status = 'approved', provisioning_started_at = NULL WHERE id = $1`, [s.id]);
      await insertEvent(
        {
          project_id: s.project_id,
          actor_type: 'system',
          actor_id: 'scheduler',
          action: 'work_session.provisioning_failed',
          subject_type: 'work_session',
          subject_id: s.id,
          payload: { reason: 'interrupted', message: 'Preparing the session did not finish; it was put back so it can be prepared again.' }
        },
        c
      );
      return s.id as string;
    });
    if (!id) break;
    discardSessionFiles(id);
    out.push(id);
    if (out.length >= 100) break;
  }
  return out;
}

// --- routes ----------------------------------------------------------------------------------------------------------

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Mounted at /api/v2/work-sessions after workSessionsV2Router. */
export const sessionProvisioningRouter = express.Router();

sessionProvisioningRouter.post('/:id/credential', requireScope('repositories:push-session'), async (req, res) => {
  const pool = getDbPool();
  if (!pool) return res.status(503).json({ error: 'Database not connected.' });
  if (!UUID.test(req.params.id)) return res.status(404).json({ error: 'No such work session.' });
  try {
    const out = await provisionSession(pool, principalOf(res), req.params.id.toLowerCase(), gatewayBase(req));
    res.setHeader('Cache-Control', 'no-store');
    res.status(out.replaced ? 200 : 201).json(out);
  } catch (err: any) {
    if (err instanceof ProvisionError) return res.status(err.status).json({ error: err.message, code: err.code });
    console.error('[provisioning]', err?.message ?? err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

sessionProvisioningRouter.get('/:id/commits', requireScope('work-sessions:read'), async (req, res) => {
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
    const rows = (await pool.query(`SELECT view_sha, real_sha, parent_view_sha, declared_author, created_at FROM session_commit WHERE work_session_id = $1 ORDER BY created_at, view_sha`, [s.id])).rows;
    res.json({
      session_id: s.id,
      commits: rows.map((r) => ({ view_sha: r.view_sha, real_sha: r.real_sha, parent_view_sha: r.parent_view_sha, declared_author: r.declared_author, created_at: new Date(r.created_at).toISOString() }))
    });
  } catch (err: any) {
    console.error('[provisioning] commits:', err?.message ?? err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});
