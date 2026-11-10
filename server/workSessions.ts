import express from 'express';
import type pg from 'pg';
import crypto from 'node:crypto';
import { getDbPool, insertEvent } from './db';
import { creatorOf } from './auth';
import { principalOf, projectAccessible, requireScope, type AuthenticatedPrincipal } from './servicePrincipalAuth';
import { externalContextProblem, externalContextSha256, type ExternalContext } from './externalContext';
import { scanTextForSecrets } from './textScan';
import { discardSessionFiles, revokeSessionCredentials } from './sessionCredentials';
import { PathRules, PatternError, patternProblem } from './pathRules';
import { insertRequirements, issuerProblems, parseEvidenceRequirements, type EvidenceRequirementInput } from './evidence';

/**
 * Work sessions (docs/integration/PHASE0_SPEC.md, Phase 3).
 *
 * A work session is one bounded piece of work on one repository of one project. A human developer's door is a session
 * too (the database mirrors every door into one; nothing here touches doors). This file is the other kind: an
 * AUTOMATED session, which a service principal requests and a person approves.
 *
 *   machine caller (/api/v2/work-sessions, scopes: work-sessions:request / :read / :close-own)
 *       POST    request a session           -> 'requested'. Nothing can happen to it until a person approves.
 *       GET     read the ones it requested
 *       POST    :id/close                   -> 'closed'
 *   the project's creator (/api/v1/projects/:id/work-sessions, full login with the code step)
 *       GET     list
 *       POST    :sid/approve                -> 'approved'
 *       POST    :sid/reject                 -> 'rejected'
 *
 * There is deliberately no machine route that approves, and the database refuses a session that is created already
 * approved or an approval that names anyone but the sponsoring creator, so a principal cannot approve its own request.
 *
 * What approval does NOT do yet: an approved session gets no git credential and no checkout. That arrives with
 * controlled materialization, together with enforcement of the allowed and prohibited paths. Issuing a credential before
 * the paths can be enforced would hand out more access than the request asked for, so it waits.
 */

export const SESSION_TTL_MIN_SECONDS = 60;
export const SESSION_TTL_MAX_SECONDS = 24 * 3600;
export const SESSION_TTL_DEFAULT_SECONDS = 3600;
/** A principal cannot bury its creator's approval queue: this many requests waiting at once, no more. */
export const MAX_PENDING_PER_PRINCIPAL = 25;
export const MAX_PATHS_PER_LIST = 50;
export const MAX_PATH_LENGTH = 200;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const COMMIT = /^[0-9a-f]{40}$/;
const MACHINE_EXECUTORS = ['ai_assistant', 'ide_runtime', 'ci_runtime', 'platform_service'];
const FINAL = ['rejected', 'closed', 'expired'];
export const SESSION_STATUSES = ['requested', 'approved', 'provisioning', 'active', 'awaiting_evidence', 'completed', 'rejected', 'closed', 'expired'];

const TOP_LEVEL_FIELDS = ['project_id', 'repository_id', 'executor', 'sponsor', 'objective', 'base_commit', 'access', 'expires_in_seconds', 'external_context', 'evidence_requirements'];
/** Part of the planned request, not accepted yet. Said plainly instead of being silently ignored. */
const LATER_FIELDS: string[] = [];

export interface SessionRequest {
  project_id: string;
  repository_id: string;
  executor: { type: string; provider: string | null; model: string | null; external_id: string | null; display_name: string | null };
  sponsor_id: string;
  objective: string;
  base_commit: string;
  repository_access: 'read' | 'read_and_push';
  allowed_read_paths: string[];
  allowed_write_paths: string[];
  prohibited_paths: string[];
  expires_in_seconds: number;
  external_context: ExternalContext | null;
  evidence_requirements: EvidenceRequirementInput[];
}

type Parsed = { ok: true; value: SessionRequest } | { ok: false; error: string };
const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

function optionalText(v: unknown, label: string): string | null | { error: string } {
  if (v === undefined || v === null) return null;
  if (typeof v !== 'string' || !v.trim() || v.trim().length > 200) return { error: `${label} must be 1 to 200 characters.` };
  return v.trim();
}

/** Why a path pattern is not acceptable, or null. How patterns are matched is decided where they are enforced. */
export function pathProblem(p: unknown): string | null {
  if (typeof p !== 'string' || !p) return 'every path must be non-empty text';
  if (p.length > MAX_PATH_LENGTH) return `a path is longer than ${MAX_PATH_LENGTH} characters`;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f\\]/.test(p)) return 'a path contains a control character or a backslash';
  if (p.startsWith('/') || p.startsWith('~')) return 'paths are relative to the repository root and cannot start with / or ~';
  const segments = p.split('/');
  if (segments.some((s) => s === '..')) return 'a path cannot contain ..';
  if (segments.some((s) => s === '' || s === '.')) return 'a path cannot contain empty or . segments';
  // The rules that enforce a pattern (the filtered view and the push check) must accept it, so a request that is accepted here can
  // always be provisioned: this adds invisible, bidirectional and line-separator characters to what is refused.
  const enforceable = patternProblem(p);
  if (enforceable) return enforceable;
  return null;
}

function pathList(v: unknown, label: string, required: boolean): string[] | { error: string } {
  if (v === undefined || v === null) return required ? { error: `${label} is required.` } : [];
  if (!Array.isArray(v)) return { error: `${label} must be a list of paths.` };
  if (v.length > MAX_PATHS_PER_LIST) return { error: `${label} can have at most ${MAX_PATHS_PER_LIST} paths.` };
  for (const p of v) {
    const problem = pathProblem(p);
    if (problem) return { error: `${label}: ${problem}.` };
  }
  return [...new Set(v as string[])];
}

export function parseSessionRequest(body: unknown): Parsed {
  if (!isObject(body)) return { ok: false, error: 'The request must be a JSON object.' };
  const later = LATER_FIELDS.filter((f) => f in body);
  if (later.length) return { ok: false, error: `${later.join(', ')} is not accepted yet.` };
  const unknown = Object.keys(body).filter((k) => !TOP_LEVEL_FIELDS.includes(k));
  if (unknown.length) return { ok: false, error: `Unknown field(s): ${unknown.join(', ')}.` };

  const projectId = body.project_id;
  const repositoryId = body.repository_id;
  if (typeof projectId !== 'string' || !UUID.test(projectId)) return { ok: false, error: 'project_id must be a project id.' };
  if (typeof repositoryId !== 'string' || !UUID.test(repositoryId)) return { ok: false, error: 'repository_id must be a repository id.' };

  const ex = body.executor;
  if (!isObject(ex)) return { ok: false, error: 'executor is required.' };
  const exUnknown = Object.keys(ex).filter((k) => !['type', 'provider', 'model', 'external_id', 'display_name'].includes(k));
  if (exUnknown.length) return { ok: false, error: `Unknown executor field(s): ${exUnknown.join(', ')}.` };
  if (typeof ex.type !== 'string' || !MACHINE_EXECUTORS.includes(ex.type)) {
    return { ok: false, error: `executor.type must be one of ${MACHINE_EXECUTORS.join(', ')}. A human developer works through a door.` };
  }
  const parts: Record<string, string | null> = {};
  for (const k of ['provider', 'model', 'external_id', 'display_name']) {
    const r = optionalText(ex[k], `executor.${k}`);
    if (r && typeof r === 'object') return { ok: false, error: r.error };
    parts[k] = r as string | null;
  }

  const sp = body.sponsor;
  if (!isObject(sp) || sp.type !== 'creator' || typeof sp.id !== 'string' || !UUID.test(sp.id)) {
    return { ok: false, error: 'sponsor must be { "type": "creator", "id": <the creator\'s id> }.' };
  }

  const objective = typeof body.objective === 'string' ? body.objective.trim() : '';
  if (!objective || objective.length > 2000) return { ok: false, error: 'objective must be 1 to 2000 characters.' };

  if (typeof body.base_commit !== 'string' || !COMMIT.test(body.base_commit)) return { ok: false, error: 'base_commit must be a full 40-character lowercase commit id.' };

  const access = body.access;
  if (!isObject(access)) return { ok: false, error: 'access is required.' };
  const accUnknown = Object.keys(access).filter((k) => !['repository', 'allowed_read_paths', 'allowed_write_paths', 'prohibited_paths'].includes(k));
  if (accUnknown.length) return { ok: false, error: `Unknown access field(s): ${accUnknown.join(', ')}.` };
  if (access.repository !== 'read' && access.repository !== 'read_and_push') return { ok: false, error: 'access.repository must be "read" or "read_and_push".' };
  const read = pathList(access.allowed_read_paths, 'access.allowed_read_paths', true);
  if ('error' in read) return { ok: false, error: read.error };
  if (read.length === 0) return { ok: false, error: 'access.allowed_read_paths must name at least one path: nothing is allowed unless listed.' };
  const write = pathList(access.allowed_write_paths, 'access.allowed_write_paths', false);
  if ('error' in write) return { ok: false, error: write.error };
  const prohibited = pathList(access.prohibited_paths, 'access.prohibited_paths', false);
  if ('error' in prohibited) return { ok: false, error: prohibited.error };
  if (access.repository === 'read_and_push' && write.length === 0) return { ok: false, error: 'read_and_push needs access.allowed_write_paths.' };
  if (access.repository === 'read' && write.length > 0) return { ok: false, error: 'access.allowed_write_paths must be empty for read-only access.' };
  // Every pattern must also compile for the rules that will enforce it.
  try {
    new PathRules({ allowedRead: read, allowedWrite: write, prohibited });
  } catch (err) {
    if (err instanceof PatternError) return { ok: false, error: err.message };
    throw err;
  }

  let ttl = SESSION_TTL_DEFAULT_SECONDS;
  if (body.expires_in_seconds !== undefined) {
    const t = body.expires_in_seconds;
    if (typeof t !== 'number' || !Number.isInteger(t) || t < SESSION_TTL_MIN_SECONDS || t > SESSION_TTL_MAX_SECONDS) {
      return { ok: false, error: `expires_in_seconds must be a whole number from ${SESSION_TTL_MIN_SECONDS} to ${SESSION_TTL_MAX_SECONDS}.` };
    }
    ttl = t;
  }

  let externalContext: ExternalContext | null = null;
  if (body.external_context !== undefined && body.external_context !== null) {
    const problem = externalContextProblem(body.external_context);
    if (problem) return { ok: false, error: problem };
    externalContext = { namespace: (body.external_context as any).namespace, context: (body.external_context as any).context };
  }

  let evidenceRequirements: EvidenceRequirementInput[] = [];
  if (body.evidence_requirements !== undefined && body.evidence_requirements !== null) {
    const er = parseEvidenceRequirements(body.evidence_requirements);
    if (!er.ok) return { ok: false, error: er.error };
    evidenceRequirements = er.value;
  }

  return {
    ok: true,
    value: {
      project_id: projectId.toLowerCase(),
      repository_id: repositoryId.toLowerCase(),
      executor: { type: ex.type, provider: parts.provider, model: parts.model, external_id: parts.external_id, display_name: parts.display_name },
      sponsor_id: sp.id.toLowerCase(),
      objective,
      base_commit: body.base_commit,
      repository_access: access.repository,
      allowed_read_paths: read,
      allowed_write_paths: write,
      prohibited_paths: prohibited,
      expires_in_seconds: ttl,
      external_context: externalContext,
      evidence_requirements: evidenceRequirements
    }
  };
}

// --- reading -----------------------------------------------------------------------------------------------------

const SELECT_SESSION = `
  SELECT s.id, s.project_id, s.repository_id, s.session_type, s.door_id, s.requested_by_principal_id, sp.name AS requested_by_name,
         s.executor_type, s.executor_provider, s.executor_model, s.executor_external_id, s.executor_display_name,
         s.sponsor_id, s.objective, s.base_commit, s.branch_name, s.repository_access,
         s.allowed_read_paths, s.allowed_write_paths, s.prohibited_paths,
         s.status, s.created_at, s.approved_at, s.approved_by, s.expires_at, s.closed_at, s.closed_reason,
         s.external_context_namespace, s.external_context_payload, s.external_context_sha256,
         (SELECT COALESCE(jsonb_agg(jsonb_build_object('type', er.evidence_type, 'issuer_principal_id', er.issuer_principal_id, 'required', er.is_required,
                 'tied_to_commit', er.tied_to_commit, 'specification_hash', er.specification_hash, 'max_age_seconds', er.max_age_seconds,
                 'issuer_is_requester', er.issuer_principal_id = s.requested_by_principal_id) ORDER BY er.evidence_type), '[]'::jsonb)
            FROM evidence_requirement er WHERE er.work_session_id = s.id) AS evidence_requirements
    FROM work_session s LEFT JOIN service_principal sp ON sp.id = s.requested_by_principal_id`;

export function sessionView(r: any) {
  const iso = (v: unknown) => (v ? new Date(v as string).toISOString() : null);
  return {
    id: r.id,
    project_id: r.project_id,
    repository_id: r.repository_id,
    session_type: r.session_type,
    door_id: r.door_id,
    status: r.status,
    requested_by: r.requested_by_principal_id ? { principal_id: r.requested_by_principal_id, name: r.requested_by_name } : null,
    executor: { type: r.executor_type, provider: r.executor_provider, model: r.executor_model, external_id: r.executor_external_id, display_name: r.executor_display_name },
    sponsor_id: r.sponsor_id,
    objective: r.objective,
    base_commit: r.base_commit,
    branch_name: r.branch_name,
    access: r.repository_access
      ? { repository: r.repository_access, allowed_read_paths: r.allowed_read_paths, allowed_write_paths: r.allowed_write_paths, prohibited_paths: r.prohibited_paths }
      : null,
    external_context: r.external_context_namespace
      ? { namespace: r.external_context_namespace, context: r.external_context_payload, sha256: r.external_context_sha256 }
      : null,
    evidence_requirements: r.evidence_requirements ?? [],
    created_at: iso(r.created_at),
    approved_at: iso(r.approved_at),
    approved_by: r.approved_by,
    expires_at: iso(r.expires_at),
    closed_at: iso(r.closed_at),
    closed_reason: r.closed_reason
  };
}

/**
 * Which automated sessions a principal may see: its own, and, if it holds work-sessions:approve, any in the projects
 * it may reach. Always inside its creator's projects and its project list, whatever else is true.
 */
function visibleTo(p: AuthenticatedPrincipal): { where: string; params: unknown[] } {
  const params: unknown[] = [p.creatorId, p.id, p.scopes.includes('work-sessions:approve')];
  let where = `s.session_type = 'automated_work_session'
    AND s.project_id IN (SELECT id FROM project WHERE creator_id = $1)
    AND (s.requested_by_principal_id = $2 OR $3::boolean)`;
  if (p.allowedProjectIds) {
    params.push(p.allowedProjectIds);
    where += ` AND s.project_id = ANY($${params.length}::uuid[])`;
  }
  return { where, params };
}

// --- writing -----------------------------------------------------------------------------------------------------

export class SessionError extends Error {
  constructor(public status: number, message: string) {
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

export async function requestSession(pool: pg.Pool, principal: AuthenticatedPrincipal, req: SessionRequest) {
  // The sponsor is the person who will be asked to approve this, and who is accountable for it: it must be the owner.
  if (req.sponsor_id !== principal.creatorId) throw new SessionError(403, 'The sponsor must be the owner of the project.');
  if (!(await projectAccessible(pool, principal, req.project_id))) throw new SessionError(404, 'No such project.');

  // Everything the caller wrote goes into the project's permanent record, so it is checked for secrets first (the same
  // scanner as the git gateway; no scanner means no recording).
  const scan = await scanTextForSecrets(
    JSON.stringify(
      { objective: req.objective, executor: req.executor, paths: [req.allowed_read_paths, req.allowed_write_paths, req.prohibited_paths], external_context: req.external_context, evidence_requirements: req.evidence_requirements },
      null,
      2
    )
  );
  if (scan.status === 'found') {
    throw new SessionError(400, `The request appears to contain a secret (${scan.rules.join(', ') || 'unnamed rule'}). Nothing was recorded, because the project's record is permanent. Remove it and send the request again.`);
  }
  if (scan.status !== 'clean') throw new SessionError(503, 'The secret scanner is not available, so the request cannot be recorded. Try again later.');

  const ctx = req.external_context;
  const ctxHash = ctx ? externalContextSha256(ctx) : null;

  return inTransaction(pool, async (c) => {
    const repo = (await c.query('SELECT id FROM repository WHERE id = $1 AND project_id = $2', [req.repository_id, req.project_id])).rows[0];
    if (!repo) throw new SessionError(404, 'No such repository in this project.');
    const issuerProblem = await issuerProblems(c, principal.creatorId, req.project_id, req.evidence_requirements);
    if (issuerProblem) throw new SessionError(422, issuerProblem);

    // One request at a time per principal while counting, so the limit holds under concurrent requests.
    await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`work_session_pending:${principal.id}`]);
    const pending = (await c.query(`SELECT count(*)::int AS n FROM work_session WHERE requested_by_principal_id = $1 AND status = 'requested'`, [principal.id])).rows[0].n;
    if (pending >= MAX_PENDING_PER_PRINCIPAL) {
      throw new SessionError(429, `This principal already has ${pending} requests waiting for approval. Wait for them to be decided.`);
    }

    const id = crypto.randomUUID();
    const branch = `session/${id}/work`;
    const row = (
      await c.query(
        `INSERT INTO work_session (id, project_id, repository_id, session_type, requested_by_principal_id,
                executor_type, executor_provider, executor_model, executor_external_id, executor_display_name,
                sponsor_id, objective, base_commit, branch_name, repository_access,
                allowed_read_paths, allowed_write_paths, prohibited_paths, expires_at,
                external_context_namespace, external_context_payload, external_context_sha256)
         VALUES ($1, $2, $3, 'automated_work_session', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                 now() + make_interval(secs => $18), $19, $20::jsonb, $21)
         RETURNING id, status, expires_at`,
        [
          id, req.project_id, req.repository_id, principal.id,
          req.executor.type, req.executor.provider, req.executor.model, req.executor.external_id, req.executor.display_name,
          req.sponsor_id, req.objective, req.base_commit, branch, req.repository_access,
          req.allowed_read_paths, req.allowed_write_paths, req.prohibited_paths, req.expires_in_seconds,
          ctx ? ctx.namespace : null, ctx ? JSON.stringify(ctx.context) : null, ctxHash
        ]
      )
    ).rows[0];

    await insertRequirements(c, id, req.evidence_requirements);

    const event = await insertEvent(
      {
        project_id: req.project_id,
        actor_type: 'system',
        actor_id: `principal:${principal.id}`,
        action: 'work_session.requested',
        subject_type: 'work_session',
        subject_id: id,
        payload: {
          principal_id: principal.id,
          principal_name: principal.name,
          executor: req.executor,
          sponsor_id: req.sponsor_id,
          repository_id: req.repository_id,
          objective: req.objective,
          base_commit: req.base_commit,
          branch_name: branch,
          repository_access: req.repository_access,
          allowed_read_paths: req.allowed_read_paths,
          allowed_write_paths: req.allowed_write_paths,
          prohibited_paths: req.prohibited_paths,
          expires_at: new Date(row.expires_at).toISOString(),
          ...(req.evidence_requirements.length ? { evidence_requirements: req.evidence_requirements } : {}),
          ...(ctx ? { external_context: { namespace: ctx.namespace, context: ctx.context, sha256: ctxHash } } : {})
        }
      },
      c
    );
    return { id, status: row.status as string, expires_at: new Date(row.expires_at).toISOString(), branch_prefix: `session/${id}/`, event_hash: event.hash };
  });
}

/** The principal closes a session it requested. Closing one that is already closed is not an error. */
export async function closeOwnSession(pool: pg.Pool, principal: AuthenticatedPrincipal, sessionId: string) {
  const out = await closeOwnSessionInTransaction(pool, principal, sessionId);
  if (out.changed) discardSessionFiles(out.id); // after the commit: the credential is already revoked, so nothing can reach the files
  return out;
}

async function closeOwnSessionInTransaction(pool: pg.Pool, principal: AuthenticatedPrincipal, sessionId: string) {
  return inTransaction(pool, async (c) => {
    const vis = visibleTo(principal);
    const s = (
      await c.query(
        `SELECT s.id, s.project_id, s.status FROM work_session s
          WHERE s.id = $${vis.params.length + 1} AND s.requested_by_principal_id = $2 AND ${vis.where} FOR UPDATE OF s`,
        [...vis.params, sessionId]
      )
    ).rows[0];
    if (!s) throw new SessionError(404, 'No such work session.');
    if (s.status === 'closed') return { id: s.id, status: 'closed' as const, changed: false };
    if (FINAL.includes(s.status)) throw new SessionError(409, `This session is already ${s.status}.`);
    await c.query(`UPDATE work_session SET status = 'closed', closed_at = now(), closed_reason = 'closed_by_requester' WHERE id = $1`, [s.id]);
    await revokeSessionCredentials(c, s, { type: 'system', id: `principal:${principal.id}` }, 'session_closed');
    await insertEvent(
      {
        project_id: s.project_id,
        actor_type: 'system',
        actor_id: `principal:${principal.id}`,
        action: 'work_session.closed',
        subject_type: 'work_session',
        subject_id: s.id,
        payload: { reason: 'closed_by_requester', previous_status: s.status }
      },
      c
    );
    return { id: s.id, status: 'closed' as const, changed: true };
  });
}

/** The project's creator approves a request. Only 'requested' sessions, and only before they expire. */
export async function approveSession(pool: pg.Pool, creatorId: string, projectId: string, sessionId: string) {
  return inTransaction(pool, async (c) => {
    const s = (
      await c.query(
        `SELECT id, project_id, status, sponsor_id, expires_at, requested_by_principal_id, external_context_namespace, external_context_sha256 FROM work_session
          WHERE id = $1 AND project_id = $2 AND session_type = 'automated_work_session' FOR UPDATE`,
        [sessionId, projectId]
      )
    ).rows[0];
    if (!s) throw new SessionError(404, 'No such work session.');
    if (s.sponsor_id !== creatorId) throw new SessionError(403, 'Only the sponsor of a session can approve it.');
    if (s.status !== 'requested') throw new SessionError(409, `This session is ${s.status}, not waiting for approval.`);
    if (new Date(s.expires_at).getTime() <= Date.now()) throw new SessionError(409, 'This session has already expired.');
    await c.query(`UPDATE work_session SET status = 'approved', approved_at = now(), approved_by = $2 WHERE id = $1`, [s.id, `creator:${creatorId}`]);
    await insertEvent(
      {
        project_id: projectId,
        actor_type: 'creator',
        actor_id: creatorId,
        action: 'work_session.approved',
        subject_type: 'work_session',
        subject_id: s.id,
        payload: {
          principal_id: s.requested_by_principal_id,
          approved_by: `creator:${creatorId}`,
          // what was approved includes the context, by its hash, so the two records can be matched
          ...(s.external_context_namespace ? { external_context: { namespace: s.external_context_namespace, sha256: s.external_context_sha256 } } : {})
        }
      },
      c
    );
    return { id: s.id, status: 'approved' as const };
  });
}

export async function rejectSession(pool: pg.Pool, creatorId: string, projectId: string, sessionId: string, reason: string | null) {
  return inTransaction(pool, async (c) => {
    const s = (
      await c.query(
        `SELECT id, status, sponsor_id, requested_by_principal_id FROM work_session
          WHERE id = $1 AND project_id = $2 AND session_type = 'automated_work_session' FOR UPDATE`,
        [sessionId, projectId]
      )
    ).rows[0];
    if (!s) throw new SessionError(404, 'No such work session.');
    if (s.sponsor_id !== creatorId) throw new SessionError(403, 'Only the sponsor of a session can reject it.');
    if (s.status !== 'requested') throw new SessionError(409, `This session is ${s.status}, not waiting for approval.`);
    const closedReason = reason ? `rejected: ${reason}` : 'rejected';
    await c.query(`UPDATE work_session SET status = 'rejected', closed_at = now(), closed_reason = $2 WHERE id = $1`, [s.id, closedReason]);
    await insertEvent(
      {
        project_id: projectId,
        actor_type: 'creator',
        actor_id: creatorId,
        action: 'work_session.rejected',
        subject_type: 'work_session',
        subject_id: s.id,
        payload: { principal_id: s.requested_by_principal_id, reason }
      },
      c
    );
    return { id: s.id, status: 'rejected' as const };
  });
}

/** Called by the scheduler: automated sessions that passed their end time are expired, and the record says so. */
export async function expireOverdueSessions(pool: pg.Pool): Promise<string[]> {
  const expired: string[] = [];
  for (;;) {
    const done = await inTransaction(pool, async (c) => {
      const s = (
        await c.query(
          `SELECT id, project_id, status, expires_at, extract(epoch FROM now() - expires_at)::int AS overdue_seconds
             FROM work_session
            WHERE session_type = 'automated_work_session' AND status NOT IN ('rejected', 'closed', 'expired') AND expires_at <= now()
            ORDER BY expires_at LIMIT 1 FOR UPDATE SKIP LOCKED`
        )
      ).rows[0];
      if (!s) return null;
      await c.query(`UPDATE work_session SET status = 'expired', closed_at = now(), closed_reason = 'expired' WHERE id = $1`, [s.id]);
      await revokeSessionCredentials(c, s, { type: 'system', id: 'scheduler' }, 'session_expired');
      await insertEvent(
        {
          project_id: s.project_id,
          actor_type: 'system',
          actor_id: 'scheduler',
          action: 'work_session.closed',
          subject_type: 'work_session',
          subject_id: s.id,
          payload: { reason: 'expired', previous_status: s.status, end_time: new Date(s.expires_at).toISOString(), closed_seconds_after_end_time: Number(s.overdue_seconds) }
        },
        c
      );
      return s.id as string;
    });
    if (!done) break;
    discardSessionFiles(done);
    expired.push(done);
    if (expired.length >= 1000) break;
  }
  return expired;
}

// --- routes --------------------------------------------------------------------------------------------------------

function db(res: express.Response): pg.Pool | null {
  const pool = getDbPool();
  if (!pool) res.status(503).json({ error: 'Database not connected.' });
  return pool;
}

function fail(res: express.Response, err: any, what: string) {
  if (err instanceof SessionError) return res.status(err.status).json({ error: err.message });
  console.error(`[work-sessions] ${what}:`, err?.message ?? err);
  return res.status(500).json({ error: 'Something went wrong on the server.' });
}

/** Machine callers. Mounted at /api/v2/work-sessions, after authenticatePrincipal. */
export const workSessionsV2Router = express.Router();

workSessionsV2Router.post('/', requireScope('work-sessions:request'), async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  const parsed = parseSessionRequest(req.body);
  if (!parsed.ok) return res.status(400).json({ error: parsed.error });
  try {
    const out = await requestSession(pool, principalOf(res), parsed.value);
    res.status(202).json({
      session_id: out.id,
      status: out.status,
      requires_approval: true,
      sponsor_id: parsed.value.sponsor_id,
      branch_prefix: out.branch_prefix,
      expires_at: out.expires_at,
      event_hash: out.event_hash
    });
  } catch (err) {
    fail(res, err, 'requesting a session');
  }
});

workSessionsV2Router.get('/', requireScope('work-sessions:read'), async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  try {
    const vis = visibleTo(principalOf(res));
    let where = vis.where;
    const params = [...vis.params];
    if (req.query.project_id !== undefined) {
      const pid = String(req.query.project_id);
      if (!UUID.test(pid)) return res.status(400).json({ error: 'project_id must be a project id.' });
      params.push(pid);
      where += ` AND s.project_id = $${params.length}`;
    }
    if (req.query.status !== undefined) {
      const st = String(req.query.status);
      if (!SESSION_STATUSES.includes(st)) return res.status(400).json({ error: `status must be one of ${SESSION_STATUSES.join(', ')}.` });
      params.push(st);
      where += ` AND s.status = $${params.length}`;
    }
    const rows = (await pool.query(`${SELECT_SESSION} WHERE ${where} ORDER BY s.created_at DESC LIMIT 100`, params)).rows;
    res.json({ work_sessions: rows.map(sessionView) });
  } catch (err) {
    fail(res, err, 'listing sessions');
  }
});

workSessionsV2Router.get('/:id', requireScope('work-sessions:read'), async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  try {
    if (!UUID.test(req.params.id)) return res.status(404).json({ error: 'No such work session.' });
    const vis = visibleTo(principalOf(res));
    const row = (await pool.query(`${SELECT_SESSION} WHERE s.id = $${vis.params.length + 1} AND ${vis.where}`, [...vis.params, req.params.id])).rows[0];
    if (!row) return res.status(404).json({ error: 'No such work session.' });
    res.json({ work_session: sessionView(row) });
  } catch (err) {
    fail(res, err, 'reading a session');
  }
});

workSessionsV2Router.post('/:id/close', requireScope('work-sessions:close-own'), async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  try {
    if (!UUID.test(req.params.id)) return res.status(404).json({ error: 'No such work session.' });
    const out = await closeOwnSession(pool, principalOf(res), req.params.id);
    res.json({ session_id: out.id, status: out.status });
  } catch (err) {
    fail(res, err, 'closing a session');
  }
});

/** The project's creator. Mounted at /api/v1/projects/:id/work-sessions, after the full login. */
export const workSessionsCreatorRouter = express.Router({ mergeParams: true });

async function ownProjectOr404(pool: pg.Pool, req: express.Request, res: express.Response): Promise<string | null> {
  const projectId = String((req.params as any).id ?? '');
  const ok = UUID.test(projectId) && (await pool.query('SELECT 1 FROM project WHERE id = $1 AND creator_id = $2', [projectId, creatorOf(res).id])).rowCount === 1;
  if (!ok) {
    res.status(404).json({ error: 'No such project.' });
    return null;
  }
  return projectId;
}

workSessionsCreatorRouter.get('/', async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  try {
    const projectId = await ownProjectOr404(pool, req, res);
    if (!projectId) return;
    const rows = (await pool.query(`${SELECT_SESSION} WHERE s.project_id = $1 ORDER BY s.created_at DESC LIMIT 200`, [projectId])).rows;
    res.json({ work_sessions: rows.map(sessionView) });
  } catch (err) {
    fail(res, err, 'listing a project\'s sessions');
  }
});

workSessionsCreatorRouter.post('/:sid/approve', async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  try {
    const projectId = await ownProjectOr404(pool, req, res);
    if (!projectId) return;
    if (!UUID.test(req.params.sid)) return res.status(404).json({ error: 'No such work session.' });
    res.json(await approveSession(pool, creatorOf(res).id, projectId, req.params.sid));
  } catch (err) {
    fail(res, err, 'approving a session');
  }
});

workSessionsCreatorRouter.post('/:sid/reject', async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  try {
    const projectId = await ownProjectOr404(pool, req, res);
    if (!projectId) return;
    if (!UUID.test(req.params.sid)) return res.status(404).json({ error: 'No such work session.' });
    const raw = (req.body ?? {}).reason;
    if (raw !== undefined && (typeof raw !== 'string' || raw.trim().length > 500)) return res.status(400).json({ error: 'reason must be text of at most 500 characters.' });
    const reason = typeof raw === 'string' && raw.trim() ? raw.trim() : null;
    res.json(await rejectSession(pool, creatorOf(res).id, projectId, req.params.sid, reason));
  } catch (err) {
    fail(res, err, 'rejecting a session');
  }
});
