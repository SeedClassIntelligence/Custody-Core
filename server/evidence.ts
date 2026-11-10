import crypto from 'node:crypto';
import express from 'express';
import type pg from 'pg';
import { canonicalJsonV2 } from '../shared/crypto';
import { getDbPool, insertEvent } from './db';
import { creatorOf } from './auth';
import { contextProblem } from './externalContext';
import { principalOf, requireScope, verifySignature, type AuthenticatedPrincipal } from './servicePrincipalAuth';
import { scanTextForSecrets } from './textScan';

/**
 * Evidence (docs/integration/PHASE6_DESIGN.md; gate CL-12).
 *
 * A session request can say what must be shown before its work is trusted, and WHICH registered principal may show it
 * ("evidence_requirements"). That principal later submits a SIGNED statement about one commit the session produced. Custody Core
 * records it, never alters it, and can say at any time whether a requirement is met for a commit. It does not decide anything
 * from that (promotion, a later phase, will).
 *
 * What a statement is bound to (TM-09): the session, the commit, the evidence type, the issuer's key, the specification hash and a
 * hash of the attached payload. A pass on one commit never satisfies another; a statement older than the requirement allows does not count.
 */

export const EVIDENCE_FORMAT = 'custody-core.evidence.v1';
export const MAX_REQUIREMENTS = 10;
export const MAX_SUBMISSIONS_PER_SESSION = 500;
export const MIN_MAX_AGE_SECONDS = 60;
export const MAX_MAX_AGE_SECONDS = 365 * 24 * 3600;
const CLOCK_SKEW_MS = 30_000;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX40 = /^[0-9a-f]{40}$/;
const TYPE = /^[a-z][a-z0-9_.-]{0,63}$/;
const ISSUED_AT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const STATUSES = ['pass', 'fail', 'inconclusive'] as const;
const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

// --- requirements in a session request ------------------------------------------------------------------------------

export interface EvidenceRequirementInput {
  evidence_type: string;
  issuer_principal_id: string;
  is_required: boolean;
  tied_to_commit: boolean;
  specification_hash: string | null;
  max_age_seconds: number | null;
}

/** Shape check of `evidence_requirements` (pure). Who the issuers are is checked against the database by checkIssuers. */
export function parseEvidenceRequirements(v: unknown): { ok: true; value: EvidenceRequirementInput[] } | { ok: false; error: string } {
  if (!Array.isArray(v)) return { ok: false, error: 'evidence_requirements must be a list.' };
  if (v.length > MAX_REQUIREMENTS) return { ok: false, error: `evidence_requirements can have at most ${MAX_REQUIREMENTS} entries.` };
  const out: EvidenceRequirementInput[] = [];
  const seen = new Set<string>();
  for (const [i, r] of v.entries()) {
    const where = `evidence_requirements[${i}]`;
    if (!isObject(r)) return { ok: false, error: `${where} must be an object.` };
    const extra = Object.keys(r).filter((k) => !['type', 'issuer_principal_id', 'required', 'tied_to_commit', 'specification_hash', 'max_age_seconds'].includes(k));
    if (extra.length) return { ok: false, error: `${where}: unknown field(s): ${extra.join(', ')}.` };
    if (typeof r.type !== 'string' || !TYPE.test(r.type)) return { ok: false, error: `${where}.type must be lowercase letters, digits, "_", "." or "-", starting with a letter, at most 64 characters.` };
    if (seen.has(r.type)) return { ok: false, error: `${where}: evidence type "${r.type}" is listed twice.` };
    seen.add(r.type);
    if (typeof r.issuer_principal_id !== 'string' || !UUID.test(r.issuer_principal_id)) return { ok: false, error: `${where}.issuer_principal_id must be the id of a registered principal.` };
    for (const k of ['required', 'tied_to_commit'] as const) {
      if (r[k] !== undefined && typeof r[k] !== 'boolean') return { ok: false, error: `${where}.${k} must be true or false.` };
    }
    if (r.specification_hash !== undefined && r.specification_hash !== null && (typeof r.specification_hash !== 'string' || !HEX64.test(r.specification_hash))) {
      return { ok: false, error: `${where}.specification_hash must be 64 lowercase hex characters (a SHA-256).` };
    }
    if (r.max_age_seconds !== undefined && r.max_age_seconds !== null) {
      const m = r.max_age_seconds;
      if (typeof m !== 'number' || !Number.isInteger(m) || m < MIN_MAX_AGE_SECONDS || m > MAX_MAX_AGE_SECONDS) {
        return { ok: false, error: `${where}.max_age_seconds must be a whole number from ${MIN_MAX_AGE_SECONDS} to ${MAX_MAX_AGE_SECONDS}.` };
      }
    }
    out.push({
      evidence_type: r.type,
      issuer_principal_id: r.issuer_principal_id.toLowerCase(),
      is_required: r.required !== false,
      tied_to_commit: r.tied_to_commit !== false,
      specification_hash: (r.specification_hash as string | null | undefined) ?? null,
      max_age_seconds: (r.max_age_seconds as number | null | undefined) ?? null
    });
  }
  return { ok: true, value: out };
}

/** Every issuer must be an active principal of the same owner that may submit evidence and may act on the project. Said plainly: an unsatisfiable requirement is refused now. */
export async function issuerProblems(c: pg.Pool | pg.PoolClient, creatorId: string, projectId: string, reqs: EvidenceRequirementInput[]): Promise<string | null> {
  for (const r of reqs) {
    const p = (
      await c.query(`SELECT status, allowed_scopes, allowed_project_ids, expires_at FROM service_principal WHERE id = $1 AND creator_id = $2`, [r.issuer_principal_id, creatorId])
    ).rows[0];
    if (!p) return `The issuer of "${r.evidence_type}" is not a principal of this owner.`;
    if (p.status !== 'active' || (p.expires_at && new Date(p.expires_at).getTime() <= Date.now())) return `The issuer of "${r.evidence_type}" is not active.`;
    if (!p.allowed_scopes.includes('evidence:submit')) return `The issuer of "${r.evidence_type}" does not hold the evidence:submit scope.`;
    if (p.allowed_project_ids && !p.allowed_project_ids.includes(projectId)) return `The issuer of "${r.evidence_type}" cannot act on this project.`;
  }
  return null;
}

export async function insertRequirements(c: pg.PoolClient, sessionId: string, reqs: EvidenceRequirementInput[]): Promise<void> {
  for (const r of reqs) {
    await c.query(
      `INSERT INTO evidence_requirement (work_session_id, evidence_type, is_required, issuer_principal_id, tied_to_commit, specification_hash, max_age_seconds)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [sessionId, r.evidence_type, r.is_required, r.issuer_principal_id, r.tied_to_commit, r.specification_hash, r.max_age_seconds]
    );
  }
}

// --- the signed statement -----------------------------------------------------------------------------------------------

export interface StatementFields {
  work_session_id: string;
  evidence_type: string;
  subject_commit: string;
  status: string;
  specification_hash: string;
  evidence_hash: string;
  payload_sha256: string;
  issued_at: string;
}

/**
 * The exact text that is signed: canonical JSON (docs/EVENT_HASH_FORMAT.md) of these fields plus the format name, so a signature made for
 * anything else cannot be replayed as evidence. Signature: Ed25519 over the UTF-8 bytes, or ES256 in the raw 64-byte r||s form; base64url, no padding.
 */
export function evidenceSigningInput(f: StatementFields): string {
  return canonicalJsonV2({
    format: EVIDENCE_FORMAT,
    work_session_id: f.work_session_id,
    evidence_type: f.evidence_type,
    subject_commit: f.subject_commit,
    status: f.status,
    specification_hash: f.specification_hash,
    evidence_hash: f.evidence_hash,
    payload_sha256: f.payload_sha256,
    issued_at: f.issued_at
  });
}

export function payloadSha256(payload: Record<string, unknown>): string {
  return crypto.createHash('sha256').update(canonicalJsonV2(payload), 'utf8').digest('hex');
}

export class EvidenceError extends Error {
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

function submissionView(r: any) {
  return {
    id: r.id,
    evidence_type: r.evidence_type,
    issuer_principal_id: r.issuer_principal_id,
    signature_key_id: r.signature_key_id,
    subject_commit: r.subject_commit,
    status: r.status,
    specification_hash: r.specification_hash,
    evidence_hash: r.evidence_hash,
    payload_sha256: r.payload_sha256,
    issued_at: new Date(r.issued_at).toISOString().replace('.000Z', 'Z'),
    signature: { algorithm: r.signature_algorithm, value: r.signature_value },
    created_at: new Date(r.created_at).toISOString()
  };
}

export async function submitEvidence(pool: pg.Pool, principal: AuthenticatedPrincipal, sessionId: string, body: unknown) {
  if (!isObject(body)) throw new EvidenceError(400, 'The request must be a JSON object.', 'invalid');
  const extra = Object.keys(body).filter((k) => !['evidence_type', 'subject_commit', 'status', 'specification_hash', 'evidence_hash', 'issued_at', 'payload', 'signature'].includes(k));
  if (extra.length) throw new EvidenceError(400, `Unknown field(s): ${extra.join(', ')}.`, 'invalid');
  const { evidence_type, subject_commit, status, specification_hash, evidence_hash, issued_at } = body as Record<string, unknown>;
  if (typeof evidence_type !== 'string' || !TYPE.test(evidence_type)) throw new EvidenceError(400, 'evidence_type is not a valid evidence type.', 'invalid');
  if (typeof subject_commit !== 'string' || !HEX40.test(subject_commit)) throw new EvidenceError(400, 'subject_commit must be a full 40-character lowercase commit id.', 'invalid');
  if (typeof status !== 'string' || !(STATUSES as readonly string[]).includes(status)) throw new EvidenceError(400, `status must be one of ${STATUSES.join(', ')}.`, 'invalid');
  if (typeof specification_hash !== 'string' || !HEX64.test(specification_hash)) throw new EvidenceError(400, 'specification_hash must be 64 lowercase hex characters.', 'invalid');
  if (typeof evidence_hash !== 'string' || !HEX64.test(evidence_hash)) throw new EvidenceError(400, 'evidence_hash must be 64 lowercase hex characters.', 'invalid');
  if (typeof issued_at !== 'string' || !ISSUED_AT.test(issued_at) || Number.isNaN(Date.parse(issued_at))) throw new EvidenceError(400, 'issued_at must be a UTC time like 2026-01-31T12:00:00Z (whole seconds).', 'invalid');
  const payload = (body as any).payload ?? {};
  const pp = contextProblem(payload);
  if (pp) throw new EvidenceError(400, pp.replace(/^context/, 'payload'), 'invalid');
  const sig = (body as any).signature;
  if (!isObject(sig) || Object.keys(sig).some((k) => !['key_id', 'algorithm', 'value'].includes(k))) throw new EvidenceError(400, 'signature must be { "key_id", "algorithm", "value" }.', 'invalid');
  if (typeof sig.key_id !== 'string' || !UUID.test(sig.key_id)) throw new EvidenceError(400, 'signature.key_id must be the id of one of your keys.', 'invalid');
  if (sig.algorithm !== 'Ed25519' && sig.algorithm !== 'ES256') throw new EvidenceError(400, 'signature.algorithm must be Ed25519 or ES256.', 'invalid');
  if (typeof sig.value !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(sig.value)) throw new EvidenceError(400, 'signature.value must be the 64-byte signature in base64url.', 'invalid');

  const sigKeyId = sig.key_id;
  const sigAlgorithm = sig.algorithm;
  const sigValue = sig.value;
  const issuedMs = Date.parse(issued_at);
  if (issuedMs > Date.now() + CLOCK_SKEW_MS) throw new EvidenceError(422, 'issued_at is in the future.', 'issued_in_future');

  // Everything written to the permanent record is checked for secrets first (the payload is kept; the event carries hashes only).
  const scan = await scanTextForSecrets(JSON.stringify({ payload }, null, 2));
  if (scan.status === 'found') throw new EvidenceError(400, `The payload appears to contain a secret (${scan.rules.join(', ') || 'unnamed rule'}). Nothing was recorded. Remove it and send the evidence again.`, 'secret_found');
  if (scan.status !== 'clean') throw new EvidenceError(503, 'The secret scanner is not available, so the evidence cannot be recorded. Try again later.', 'scanner_unavailable');

  const fields: StatementFields = {
    work_session_id: sessionId,
    evidence_type,
    subject_commit,
    status,
    specification_hash,
    evidence_hash,
    payload_sha256: payloadSha256(payload),
    issued_at
  };

  return inTransaction(pool, async (c) => {
    // Only the issuer the request named can even see that the session wants this kind of evidence (anyone else gets 404).
    const s = (
      await c.query(
        `SELECT s.id, s.project_id, s.status FROM work_session s JOIN project p ON p.id = s.project_id
          WHERE s.id = $1 AND s.session_type = 'automated_work_session' AND p.creator_id = $2
            AND ($3::uuid[] IS NULL OR s.project_id = ANY($3::uuid[]))
            AND EXISTS (SELECT 1 FROM evidence_requirement er WHERE er.work_session_id = s.id AND er.evidence_type = $4 AND er.issuer_principal_id = $5)
          FOR UPDATE OF s`,
        [sessionId, principal.creatorId, principal.allowedProjectIds, evidence_type, principal.id]
      )
    ).rows[0];
    if (!s) throw new EvidenceError(404, 'No such work session, or it did not ask you for this kind of evidence.', 'not_found');
    const req = (await c.query(`SELECT specification_hash FROM evidence_requirement WHERE work_session_id = $1 AND evidence_type = $2`, [s.id, evidence_type])).rows[0];
    if (s.status !== 'active' && s.status !== 'awaiting_evidence') throw new EvidenceError(409, `This session is ${s.status}; evidence is only accepted while it is running.`, 'not_running');
    if (req.specification_hash && req.specification_hash !== specification_hash) throw new EvidenceError(422, 'This is not the specification the request pinned for this kind of evidence.', 'wrong_specification');

    // The key: one of the caller's own, usable now, and the signature must verify over exactly this statement.
    const key = (
      await c.query(`SELECT id, algorithm, public_key_jwk, expires_at, revoked_at FROM service_principal_key WHERE id = $1 AND principal_id = $2`, [sig.key_id, principal.id])
    ).rows[0];
    if (!key || key.revoked_at || (key.expires_at && new Date(key.expires_at).getTime() <= Date.now())) throw new EvidenceError(422, 'The signing key is not a usable key of this principal.', 'bad_key');
    if (key.algorithm !== sigAlgorithm) throw new EvidenceError(422, 'signature.algorithm is not the algorithm of that key.', 'bad_key');
    let verified = false;
    try {
      verified = verifySignature(key.algorithm, key.public_key_jwk, evidenceSigningInput(fields), Buffer.from(sigValue, 'base64url'));
    } catch {
      verified = false;
    }
    if (!verified) throw new EvidenceError(422, 'The signature does not verify over this statement.', 'bad_signature');

    // The commit must be one this session produced, and cannot have been vouched for before it existed.
    const commit = (await c.query(`SELECT created_at FROM session_commit WHERE work_session_id = $1 AND real_sha = $2`, [s.id, subject_commit])).rows[0];
    if (!commit) throw new EvidenceError(422, 'That is not a commit this session produced.', 'unknown_commit');
    if (issuedMs < Math.floor(new Date(commit.created_at).getTime() / 1000) * 1000) throw new EvidenceError(422, 'issued_at is before that commit existed.', 'issued_before_commit');

    const existing = (
      await c.query(`SELECT * FROM evidence_submission WHERE work_session_id = $1 AND evidence_type = $2 AND subject_commit = $3 AND evidence_hash = $4`, [s.id, evidence_type, subject_commit, evidence_hash])
    ).rows[0];
    if (existing) {
      const same = existing.status === status && existing.specification_hash === specification_hash && existing.payload_sha256 === fields.payload_sha256 && new Date(existing.issued_at).getTime() === issuedMs;
      if (!same) throw new EvidenceError(409, 'Different evidence with this evidence_hash is already recorded for this commit. A recorded statement is never replaced; issue a new one with a new evidence_hash.', 'conflict');
      return { created: false, submission: submissionView(existing) };
    }
    const count = (await c.query(`SELECT count(*)::int AS n FROM evidence_submission WHERE work_session_id = $1`, [s.id])).rows[0].n;
    if (count >= MAX_SUBMISSIONS_PER_SESSION) throw new EvidenceError(429, `This session already has ${count} evidence submissions.`, 'too_many');

    const row = (
      await c.query(
        `INSERT INTO evidence_submission (work_session_id, evidence_type, issuer_principal_id, signature_key_id, subject_commit, status, specification_hash, evidence_hash,
                                          payload_sha256, issued_at, signature_algorithm, signature_value, raw_payload)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb) RETURNING *`,
        [s.id, evidence_type, principal.id, key.id, subject_commit, status, specification_hash, evidence_hash, fields.payload_sha256, new Date(issuedMs), key.algorithm, sigValue, JSON.stringify(payload)]
      )
    ).rows[0];
    const requester = (await c.query(`SELECT requested_by_principal_id FROM work_session WHERE id = $1`, [s.id])).rows[0].requested_by_principal_id;
    await insertEvent(
      {
        project_id: s.project_id,
        actor_type: 'system',
        actor_id: `principal:${principal.id}`,
        action: 'evidence.submitted',
        subject_type: 'work_session',
        subject_id: s.id,
        payload: {
          submission_id: row.id,
          evidence_type,
          subject_commit,
          status,
          specification_hash,
          evidence_hash,
          payload_sha256: fields.payload_sha256,
          issued_at,
          signature_key_id: key.id,
          signature_algorithm: key.algorithm,
          // the approver can see at a glance when the one who did the work also vouches for it
          issuer_is_requester: requester === principal.id
        }
      },
      c
    );
    return { created: true, submission: submissionView(row) };
  });
}

// --- evaluation: is a requirement met for a commit? ---------------------------------------------------------------------

export type RequirementState = 'satisfied' | 'failed' | 'inconclusive' | 'missing' | 'stale' | 'issuer_unavailable';

export interface Evaluation {
  commit: string | null;
  ready: boolean;
  requirements: Array<{
    evidence_type: string;
    issuer_principal_id: string;
    required: boolean;
    tied_to_commit: boolean;
    specification_hash: string | null;
    max_age_seconds: number | null;
    state: RequirementState;
    submission_id: string | null;
    issued_at: string | null;
  }>;
}

/**
 * Whether each requirement is met for one commit (default: the session's newest). Rules, all of them:
 *  - only statements by the named issuer, about this commit (or, if the requirement is not tied to a commit, about any commit of the session);
 *  - a statement older than max_age_seconds does not count (state "stale");
 *  - the issuer must still be usable: an active principal and a key that is not revoked or expired (otherwise "issuer_unavailable"; a revoked key
 *    invalidates what it signed, because a revocation cannot say whether the key was already compromised);
 *  - of the statements that count, the newest decides: a later fail overrides an earlier pass, and a later pass overrides an earlier fail;
 *  - `ready` means every required requirement is satisfied. Optional requirements are reported but never block.
 * This is the one function the promotion gate will use.
 */
export async function evaluateEvidence(c: pg.Pool | pg.PoolClient, sessionId: string, commit: string | null, now = new Date()): Promise<Evaluation> {
  if (commit === null) {
    commit = (await c.query(`SELECT real_sha FROM session_commit WHERE work_session_id = $1 ORDER BY created_at DESC, view_sha DESC LIMIT 1`, [sessionId])).rows[0]?.real_sha ?? null;
  }
  const reqs = (await c.query(`SELECT * FROM evidence_requirement WHERE work_session_id = $1 ORDER BY evidence_type`, [sessionId])).rows;
  const out: Evaluation['requirements'] = [];
  for (const r of reqs) {
    const subs = (
      await c.query(
        `SELECT e.id, e.status, e.issued_at, e.created_at, k.revoked_at AS key_revoked_at, k.expires_at AS key_expires_at,
                p.status AS principal_status, p.expires_at AS principal_expires_at
           FROM evidence_submission e
           JOIN service_principal_key k ON k.id = e.signature_key_id
           JOIN service_principal p ON p.id = e.issuer_principal_id
          WHERE e.work_session_id = $1 AND e.evidence_type = $2 AND e.issuer_principal_id = $3
            AND ($4::boolean = false OR e.subject_commit = $5)
          ORDER BY e.issued_at DESC, e.created_at DESC`,
        [sessionId, r.evidence_type, r.issuer_principal_id, r.tied_to_commit, commit]
      )
    ).rows;
    let state: RequirementState = 'missing';
    let chosen: any = null;
    if (r.tied_to_commit && commit === null) {
      state = 'missing';
    } else if (subs.length > 0) {
      const fresh = subs.filter((s) => r.max_age_seconds === null || now.getTime() - new Date(s.issued_at).getTime() <= r.max_age_seconds * 1000);
      if (fresh.length === 0) {
        state = 'stale';
      } else {
        const usable = fresh.filter(
          (s) =>
            !s.key_revoked_at &&
            !(s.key_expires_at && new Date(s.key_expires_at).getTime() <= now.getTime()) &&
            s.principal_status === 'active' &&
            !(s.principal_expires_at && new Date(s.principal_expires_at).getTime() <= now.getTime())
        );
        if (usable.length === 0) {
          state = 'issuer_unavailable';
        } else {
          chosen = usable[0];
          state = chosen.status === 'pass' ? 'satisfied' : chosen.status === 'fail' ? 'failed' : 'inconclusive';
        }
      }
    }
    out.push({
      evidence_type: r.evidence_type,
      issuer_principal_id: r.issuer_principal_id,
      required: r.is_required,
      tied_to_commit: r.tied_to_commit,
      specification_hash: r.specification_hash,
      max_age_seconds: r.max_age_seconds,
      state,
      submission_id: chosen?.id ?? null,
      issued_at: chosen ? new Date(chosen.issued_at).toISOString().replace('.000Z', 'Z') : null
    });
  }
  return { commit, ready: out.every((x) => !x.required || x.state === 'satisfied'), requirements: out };
}

async function evidenceReport(c: pg.Pool, sessionId: string, commitParam: unknown) {
  let commit: string | null = null;
  if (commitParam !== undefined) {
    if (typeof commitParam !== 'string' || !HEX40.test(commitParam)) throw new EvidenceError(400, 'commit must be a full 40-character lowercase commit id.', 'invalid');
    const known = (await c.query(`SELECT 1 FROM session_commit WHERE work_session_id = $1 AND real_sha = $2`, [sessionId, commitParam])).rowCount;
    if (!known) throw new EvidenceError(422, 'That is not a commit this session produced.', 'unknown_commit');
    commit = commitParam;
  }
  const evaluation = await evaluateEvidence(c, sessionId, commit);
  const subs = (await c.query(`SELECT * FROM evidence_submission WHERE work_session_id = $1 ORDER BY issued_at, created_at`, [sessionId])).rows;
  return { session_id: sessionId, evaluation, submissions: subs.map((r) => ({ ...submissionView(r), payload: r.raw_payload })) };
}

// --- routes ---------------------------------------------------------------------------------------------------------------

function fail(res: express.Response, err: any, what: string) {
  if (err instanceof EvidenceError) return res.status(err.status).json({ error: err.message, code: err.code });
  console.error(`[evidence] ${what}:`, err?.message ?? err);
  return res.status(500).json({ error: 'Something went wrong on the server.' });
}

/** Machine callers. Mounted at /api/v2/work-sessions. */
export const evidenceV2Router = express.Router();

evidenceV2Router.post('/:id/evidence', requireScope('evidence:submit'), async (req, res) => {
  const pool = getDbPool();
  if (!pool) return res.status(503).json({ error: 'Database not connected.' });
  if (!UUID.test(req.params.id)) return res.status(404).json({ error: 'No such work session.' });
  try {
    const out = await submitEvidence(pool, principalOf(res), req.params.id.toLowerCase(), req.body);
    res.status(out.created ? 201 : 200).json({ ...out.submission, recorded: out.created });
  } catch (err) {
    fail(res, err, 'submitting evidence');
  }
});

evidenceV2Router.get('/:id/evidence', requireScope('work-sessions:read'), async (req, res) => {
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
    res.json(await evidenceReport(pool, s.id, req.query.commit));
  } catch (err) {
    fail(res, err, 'reading evidence');
  }
});

/** The project's creator, behind the full login. Mounted at /api/v1/projects/:id/work-sessions. */
export const evidenceCreatorRouter = express.Router({ mergeParams: true });

evidenceCreatorRouter.get('/:sid/evidence', async (req, res) => {
  const pool = getDbPool();
  if (!pool) return res.status(503).json({ error: 'Database not connected.' });
  try {
    const projectId = String((req.params as any).id ?? '');
    const sid = String(req.params.sid);
    const own = UUID.test(projectId) && UUID.test(sid) && (await pool.query(
      `SELECT 1 FROM work_session s JOIN project p ON p.id = s.project_id WHERE s.id = $1 AND s.project_id = $2 AND p.creator_id = $3 AND s.session_type = 'automated_work_session'`,
      [sid, projectId, creatorOf(res).id]
    )).rowCount === 1;
    if (!own) return res.status(404).json({ error: 'No such work session.' });
    res.json(await evidenceReport(pool, sid, req.query.commit));
  } catch (err) {
    fail(res, err, 'reading evidence');
  }
});
