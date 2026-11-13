import crypto from 'node:crypto';
import express from 'express';
import type pg from 'pg';
import { canonicalJsonV2 } from '../shared/crypto';
import { getDbPool, insertEvent } from './db';
import { creatorOf } from './auth';
import { contextProblem } from './externalContext';
import { payloadSha256 } from './evidence';
import { principalOf, requireScope, verifySignature } from './servicePrincipalAuth';
import { PrincipalError, jwkFingerprint, readPublicJwk } from './servicePrincipals';
import { scanTextForSecrets } from './textScan';

/**
 * Attestation by an external signing authority (docs/integration/PHASE7_DESIGN.md; gate CL-13).
 *
 * The owner registers the PUBLIC KEY of a signer they choose to trust (an "attestation authority"). That signer can then make a detached signature
 * over a canonical statement ("this authority makes this claim about this commit of this session"); the owner delivers it here. It is verified against
 * the registered key BEFORE it is stored, and kept unchanged. Anyone can re-verify it offline from the stored fields and the authority's public key.
 *
 * This is deliberately protocol-neutral: it defines no particular signing service. A named service (for example Seed Signature) would be one authority,
 * with whatever transport it uses delivering the same signed statement.
 */

export const ATTESTATION_FORMAT = 'custody-core.attestation.v1';
export const MAX_ATTESTATIONS_PER_SESSION = 200;
/** The only claim a machine submission (scope attestations:submit) may carry. The owner's own route accepts any claim, as before. */
export const ATTRIBUTION_CLAIM = 'commit.attribution';
/** Published in the API description (info.x-custody-contracts) so an integrator can tell whether this server supports the submission route. */
export const SUBMISSION_CONTRACT = { name: 'commit-attribution-submission', version: '1' } as const;
const CLOCK_SKEW_MS = 30_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX40 = /^[0-9a-f]{40}$/;
const CLAIM = /^[a-z][a-z0-9_.-]{0,63}$/;
const ISSUED_AT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

export interface AttestationStatement {
  authority_id: string;
  work_session_id: string;
  claim: string;
  subject_commit: string;
  payload_sha256: string;
  issued_at: string;
}

/** The exact text that is signed (canonical JSON, docs/EVENT_HASH_FORMAT.md). Ed25519 over the UTF-8 bytes, or ES256 as raw r||s; base64url. */
export function attestationSigningInput(s: AttestationStatement): string {
  return canonicalJsonV2({
    format: ATTESTATION_FORMAT,
    authority_id: s.authority_id,
    work_session_id: s.work_session_id,
    claim: s.claim,
    subject_commit: s.subject_commit,
    payload_sha256: s.payload_sha256,
    issued_at: s.issued_at
  });
}

export class AttestationError extends Error {
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

async function accountEvent(c: pg.PoolClient, creatorId: string, action: string, payload: Record<string, unknown>) {
  const who = (await c.query('SELECT identity_id FROM creator WHERE id = $1', [creatorId])).rows[0];
  await c.query('SELECT append_account_event($1, $2, $3, $4, $5::jsonb)', [who.identity_id, 'creator', creatorId, action, JSON.stringify(payload)]);
}

// --- authorities ----------------------------------------------------------------------------------------------------------

const authorityView = (r: any) => ({
  id: r.id,
  name: r.name,
  algorithm: r.algorithm,
  public_key: r.public_key_jwk,
  fingerprint: r.fingerprint,
  created_at: new Date(r.created_at).toISOString(),
  revoked_at: r.revoked_at ? new Date(r.revoked_at).toISOString() : null
});

export async function registerAuthority(pool: pg.Pool, creatorId: string, input: unknown) {
  if (!isObject(input) || Object.keys(input).some((k) => !['name', 'public_key'].includes(k))) throw new AttestationError(400, 'Send { "name", "public_key" }.', 'invalid');
  const name = typeof input.name === 'string' ? input.name.trim() : '';
  if (!name || name.length > 100) throw new AttestationError(400, 'The name must be 1 to 100 characters.', 'invalid');
  let key;
  try {
    key = readPublicJwk(input.public_key);
  } catch (err) {
    if (err instanceof PrincipalError) throw new AttestationError(400, err.message, 'invalid');
    throw err;
  }
  const fingerprint = jwkFingerprint(key.jwk);
  return inTransaction(pool, async (c) => {
    let row;
    try {
      row = (await c.query(`INSERT INTO attestation_authority (creator_id, name, algorithm, public_key_jwk, fingerprint) VALUES ($1, $2, $3, $4::jsonb, $5) RETURNING *`, [creatorId, name, key.algorithm, JSON.stringify(key.jwk), fingerprint])).rows[0];
    } catch (err: any) {
      if (err?.code === '23505') throw new AttestationError(409, 'An authority with this name or this key is already registered.', 'conflict');
      throw err;
    }
    await accountEvent(c, creatorId, 'attestation_authority.registered', { authority_id: row.id, name, algorithm: key.algorithm, fingerprint });
    return authorityView(row);
  });
}

export async function revokeAuthority(pool: pg.Pool, creatorId: string, id: string) {
  return inTransaction(pool, async (c) => {
    const a = (await c.query(`SELECT * FROM attestation_authority WHERE id = $1 AND creator_id = $2 FOR UPDATE`, [id, creatorId])).rows[0];
    if (!a) throw new AttestationError(404, 'No such authority.', 'not_found');
    if (a.revoked_at) return authorityView(a);
    const row = (await c.query(`UPDATE attestation_authority SET revoked_at = now() WHERE id = $1 RETURNING *`, [id])).rows[0];
    await accountEvent(c, creatorId, 'attestation_authority.revoked', { authority_id: id, fingerprint: a.fingerprint });
    return authorityView(row);
  });
}

// --- attestations -----------------------------------------------------------------------------------------------------------

const attestationView = (r: any) => ({
  id: r.id,
  authority: { id: r.authority_id, name: r.authority_name, active: !r.authority_revoked_at },
  claim: r.claim,
  subject_commit: r.subject_commit,
  payload_sha256: r.payload_sha256,
  payload: r.raw_payload,
  issued_at: new Date(r.issued_at).toISOString().replace('.000Z', 'Z'),
  signature: { algorithm: r.signature_algorithm, value: r.signature_value },
  recorded_at: new Date(r.created_at).toISOString()
});

export async function attestationsFor(c: pg.Pool | pg.PoolClient, sessionId: string, commit?: string | null) {
  const rows = (
    await c.query(
      `SELECT t.*, a.name AS authority_name, a.revoked_at AS authority_revoked_at
         FROM attestation t JOIN attestation_authority a ON a.id = t.authority_id
        WHERE t.work_session_id = $1 AND ($2::text IS NULL OR t.subject_commit = $2) ORDER BY t.issued_at, t.created_at`,
      [sessionId, commit ?? null]
    )
  ).rows;
  return { session_id: sessionId, attestations: rows.map(attestationView) };
}

/** Who carries the statement when it is not the owner: a service principal, whose owner, sponsor and project all come from our records, never from the request. */
export interface SubmissionVia {
  principalId: string;
}

export async function submitAttestation(pool: pg.Pool, creatorId: string, projectId: string, sessionId: string, body: unknown, via?: SubmissionVia) {
  if (!isObject(body) || Object.keys(body).some((k) => !['authority_id', 'claim', 'subject_commit', 'issued_at', 'payload', 'signature'].includes(k))) {
    throw new AttestationError(400, 'Send { "authority_id", "claim", "subject_commit", "issued_at", "payload"?, "signature" }.', 'invalid');
  }
  const { authority_id, claim, subject_commit, issued_at } = body as Record<string, unknown>;
  if (typeof authority_id !== 'string' || !UUID.test(authority_id)) throw new AttestationError(400, 'authority_id must be the id of a registered authority.', 'invalid');
  if (typeof claim !== 'string' || !CLAIM.test(claim)) throw new AttestationError(400, 'claim must be lowercase letters, digits, "_", "." or "-", starting with a letter, at most 64 characters.', 'invalid');
  if (typeof subject_commit !== 'string' || !HEX40.test(subject_commit)) throw new AttestationError(400, 'subject_commit must be a full 40-character lowercase commit id.', 'invalid');
  if (typeof issued_at !== 'string' || !ISSUED_AT.test(issued_at) || Number.isNaN(Date.parse(issued_at))) throw new AttestationError(400, 'issued_at must be a UTC time like 2026-01-31T12:00:00Z (whole seconds).', 'invalid');
  if (via && claim !== ATTRIBUTION_CLAIM) throw new AttestationError(422, `A machine submission may only carry the "${ATTRIBUTION_CLAIM}" claim.`, 'claim_not_allowed');
  const payload = (body as any).payload ?? {};
  const pp = contextProblem(payload);
  if (pp) throw new AttestationError(400, pp.replace(/^context/, 'payload'), 'invalid');
  const sig = (body as any).signature;
  if (!isObject(sig) || Object.keys(sig).some((k) => !['algorithm', 'value'].includes(k)) || (sig.algorithm !== 'Ed25519' && sig.algorithm !== 'ES256') || typeof sig.value !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(sig.value)) {
    throw new AttestationError(400, 'signature must be { "algorithm": "Ed25519" | "ES256", "value": <64-byte signature, base64url> }.', 'invalid');
  }
  const sigAlgorithm = sig.algorithm;
  const sigValue = sig.value;
  const issuedMs = Date.parse(issued_at);
  if (issuedMs > Date.now() + CLOCK_SKEW_MS) throw new AttestationError(422, 'issued_at is in the future.', 'issued_in_future');

  const scan = await scanTextForSecrets(JSON.stringify({ payload }, null, 2));
  if (scan.status === 'found') throw new AttestationError(400, `The payload appears to contain a secret (${scan.rules.join(', ') || 'unnamed rule'}). Nothing was recorded.`, 'secret_found');
  if (scan.status !== 'clean') throw new AttestationError(503, 'The secret scanner is not available, so the attestation cannot be recorded. Try again later.', 'scanner_unavailable');

  const statement: AttestationStatement = { authority_id: authority_id.toLowerCase(), work_session_id: sessionId, claim, subject_commit, payload_sha256: payloadSha256(payload), issued_at };
  const statementSha256 = crypto.createHash('sha256').update(attestationSigningInput(statement), 'utf8').digest('hex');

  return inTransaction(pool, async (c) => {
    const s = (
      await c.query(`SELECT s.id, s.requested_by_principal_id FROM work_session s JOIN project p ON p.id = s.project_id WHERE s.id = $1 AND s.project_id = $2 AND p.creator_id = $3 AND s.session_type = 'automated_work_session' FOR UPDATE OF s`, [sessionId, projectId, creatorId])
    ).rows[0];
    if (!s) throw new AttestationError(404, 'No such work session.', 'not_found');
    if (via) {
      // Before anything about the authority is looked at, so a caller learns nothing about authorities it was not granted.
      if (s.requested_by_principal_id !== via.principalId) throw new AttestationError(404, 'No such work session.', 'not_found');
      const grant = (
        await c.query(`SELECT 1 FROM attestation_submission_grant WHERE principal_id = $1 AND authority_id = $2 AND project_id = $3 AND revoked_at IS NULL`, [via.principalId, statement.authority_id, projectId])
      ).rows[0];
      if (!grant) throw new AttestationError(403, 'The owner has not granted this credential the right to deliver statements by that authority for this project.', 'not_granted');
    }
    const auth = (await c.query(`SELECT * FROM attestation_authority WHERE id = $1 AND creator_id = $2`, [statement.authority_id, creatorId])).rows[0];
    if (!auth) throw new AttestationError(404, 'No such authority.', 'not_found');
    if (auth.revoked_at) throw new AttestationError(422, 'This authority has been revoked.', 'authority_revoked');
    if (auth.algorithm !== sigAlgorithm) throw new AttestationError(422, 'signature.algorithm is not the algorithm of that authority\'s key.', 'bad_signature');
    // Verified BEFORE anything is stored.
    let ok = false;
    try {
      ok = verifySignature(auth.algorithm, auth.public_key_jwk, attestationSigningInput(statement), Buffer.from(sigValue, 'base64url'));
    } catch {
      ok = false;
    }
    if (!ok) throw new AttestationError(422, 'The signature does not verify over this statement with the authority\'s registered key.', 'bad_signature');

    const commit = (await c.query(`SELECT created_at FROM session_commit WHERE work_session_id = $1 AND real_sha = $2`, [sessionId, subject_commit])).rows[0];
    if (!commit) throw new AttestationError(422, 'That is not a commit this session produced.', 'unknown_commit');
    if (issuedMs < Math.floor(new Date(commit.created_at).getTime() / 1000) * 1000) throw new AttestationError(422, 'issued_at is before that commit existed.', 'issued_before_commit');

    const existing = (
      await c.query(
        `SELECT t.*, a.name AS authority_name, a.revoked_at AS authority_revoked_at FROM attestation t JOIN attestation_authority a ON a.id = t.authority_id
          WHERE t.work_session_id = $1 AND t.authority_id = $2 AND t.claim = $3 AND t.subject_commit = $4 AND t.issued_at = $5 AND t.payload_sha256 = $6`,
        [sessionId, statement.authority_id, claim, subject_commit, new Date(issuedMs), statement.payload_sha256]
      )
    ).rows[0];
    if (existing) return { created: false, attestation: attestationView(existing), statementSha256 };
    const count = (await c.query(`SELECT count(*)::int AS n FROM attestation WHERE work_session_id = $1`, [sessionId])).rows[0].n;
    if (count >= MAX_ATTESTATIONS_PER_SESSION) throw new AttestationError(429, `This session already has ${count} attestations.`, 'too_many');

    const row = (
      await c.query(
        `INSERT INTO attestation (work_session_id, authority_id, claim, subject_commit, payload_sha256, raw_payload, issued_at, signature_algorithm, signature_value, submitted_by_creator_id, submitted_by_principal_id)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10, $11) RETURNING *`,
        [sessionId, statement.authority_id, claim, subject_commit, statement.payload_sha256, JSON.stringify(payload), new Date(issuedMs), auth.algorithm, sigValue, creatorId, via?.principalId ?? null]
      )
    ).rows[0];
    await insertEvent(
      {
        project_id: projectId,
        actor_type: via ? 'system' : 'creator',
        actor_id: via ? `principal:${via.principalId}` : creatorId,
        action: 'attestation.recorded',
        subject_type: 'work_session',
        subject_id: sessionId,
        payload: { attestation_id: row.id, authority_id: statement.authority_id, authority_fingerprint: auth.fingerprint, claim, subject_commit, payload_sha256: statement.payload_sha256, issued_at, signature_algorithm: auth.algorithm, ...(via ? { submitted_by_principal_id: via.principalId } : {}) }
      },
      c
    );
    return { created: true, attestation: attestationView({ ...row, authority_name: auth.name, authority_revoked_at: null }), statementSha256 };
  });
}

// --- routes ------------------------------------------------------------------------------------------------------------------

function fail(res: express.Response, err: any, what: string) {
  if (err instanceof AttestationError) return res.status(err.status).json({ error: err.message, code: err.code });
  console.error(`[attestation] ${what}:`, err?.message ?? err);
  return res.status(500).json({ error: 'Something went wrong on the server.' });
}

// --- submission grants -------------------------------------------------------------------------------------------------------------

const grantView = (r: any) => ({
  id: r.id,
  principal_id: r.principal_id,
  authority_id: r.authority_id,
  project_id: r.project_id,
  created_at: new Date(r.created_at).toISOString(),
  revoked_at: r.revoked_at ? new Date(r.revoked_at).toISOString() : null
});

/** The owner lets one service principal deliver statements by one of their authorities for one of their projects. The principal must already hold attestations:submit (that is set when it is registered and can never be added later). */
export async function createSubmissionGrant(pool: pg.Pool, creatorId: string, input: unknown) {
  if (!isObject(input) || Object.keys(input).some((k) => !['principal_id', 'authority_id', 'project_id'].includes(k))) {
    throw new AttestationError(400, 'Send { "principal_id", "authority_id", "project_id" }.', 'invalid');
  }
  for (const k of ['principal_id', 'authority_id', 'project_id']) if (typeof input[k] !== 'string' || !UUID.test(input[k] as string)) throw new AttestationError(400, `${k} must be an id.`, 'invalid');
  const [principalId, authorityId, projectId] = ['principal_id', 'authority_id', 'project_id'].map((k) => (input[k] as string).toLowerCase());
  return inTransaction(pool, async (c) => {
    const sp = (await c.query(`SELECT id, status, allowed_scopes, allowed_project_ids FROM service_principal WHERE id = $1 AND creator_id = $2`, [principalId, creatorId])).rows[0];
    if (!sp) throw new AttestationError(404, 'No such service principal.', 'not_found');
    if (!(await c.query(`SELECT 1 FROM attestation_authority WHERE id = $1 AND creator_id = $2`, [authorityId, creatorId])).rowCount) throw new AttestationError(404, 'No such authority.', 'not_found');
    if (!(await c.query(`SELECT 1 FROM project WHERE id = $1 AND creator_id = $2`, [projectId, creatorId])).rowCount) throw new AttestationError(404, 'No such project.', 'not_found');
    if (sp.status !== 'active') throw new AttestationError(422, 'That service principal is not active.', 'principal_inactive');
    if (!sp.allowed_scopes.includes('attestations:submit')) throw new AttestationError(422, 'That service principal does not hold the attestations:submit scope. Scopes cannot be added to a principal: register a new one.', 'scope_missing');
    if (sp.allowed_project_ids && !sp.allowed_project_ids.includes(projectId)) throw new AttestationError(422, "That project is not on the service principal's project list.", 'project_not_allowed');
    let row;
    try {
      row = (await c.query(`INSERT INTO attestation_submission_grant (creator_id, principal_id, authority_id, project_id) VALUES ($1, $2, $3, $4) RETURNING *`, [creatorId, principalId, authorityId, projectId])).rows[0];
    } catch (err: any) {
      if (err?.code === '23505') throw new AttestationError(409, 'That grant already exists (a revoked grant stays revoked).', 'conflict');
      if (err?.code === '23514') throw new AttestationError(422, 'The authority must not be revoked.', 'authority_revoked');
      throw err;
    }
    await accountEvent(c, creatorId, 'attestation_submission_grant.created', { grant_id: row.id, principal_id: principalId, authority_id: authorityId, project_id: projectId });
    return grantView(row);
  });
}

export async function revokeSubmissionGrant(pool: pg.Pool, creatorId: string, id: string) {
  return inTransaction(pool, async (c) => {
    const g = (await c.query(`SELECT * FROM attestation_submission_grant WHERE id = $1 AND creator_id = $2 FOR UPDATE`, [id, creatorId])).rows[0];
    if (!g) throw new AttestationError(404, 'No such grant.', 'not_found');
    if (g.revoked_at) return grantView(g);
    const row = (await c.query(`UPDATE attestation_submission_grant SET revoked_at = now() WHERE id = $1 RETURNING *`, [id])).rows[0];
    await accountEvent(c, creatorId, 'attestation_submission_grant.revoked', { grant_id: id, principal_id: g.principal_id, authority_id: g.authority_id, project_id: g.project_id });
    return grantView(row);
  });
}

/** Mounted at /api/v1/attestation-submission-grants, behind the full login. */
export const submissionGrantsRouter = express.Router();

submissionGrantsRouter.get('/', async (_req, res) => {
  const pool = getDbPool();
  if (!pool) return res.status(503).json({ error: 'Database not connected.' });
  try {
    res.json({ grants: (await pool.query(`SELECT * FROM attestation_submission_grant WHERE creator_id = $1 ORDER BY created_at`, [creatorOf(res).id])).rows.map(grantView) });
  } catch (err) {
    fail(res, err, 'listing grants');
  }
});

submissionGrantsRouter.post('/', async (req, res) => {
  const pool = getDbPool();
  if (!pool) return res.status(503).json({ error: 'Database not connected.' });
  try {
    res.status(201).json({ grant: await createSubmissionGrant(pool, creatorOf(res).id, req.body) });
  } catch (err) {
    fail(res, err, 'creating a grant');
  }
});

submissionGrantsRouter.post('/:id/revoke', async (req, res) => {
  const pool = getDbPool();
  if (!pool) return res.status(503).json({ error: 'Database not connected.' });
  if (!UUID.test(req.params.id)) return res.status(404).json({ error: 'No such grant.' });
  try {
    res.json({ grant: await revokeSubmissionGrant(pool, creatorOf(res).id, req.params.id.toLowerCase()) });
  } catch (err) {
    fail(res, err, 'revoking a grant');
  }
});

/** Mounted at /api/v1/attestation-authorities, behind the full login. */
export const authoritiesRouter = express.Router();

authoritiesRouter.get('/', async (_req, res) => {
  const pool = getDbPool();
  if (!pool) return res.status(503).json({ error: 'Database not connected.' });
  try {
    const rows = (await pool.query(`SELECT * FROM attestation_authority WHERE creator_id = $1 ORDER BY created_at`, [creatorOf(res).id])).rows;
    res.json({ authorities: rows.map(authorityView) });
  } catch (err) {
    fail(res, err, 'listing authorities');
  }
});

authoritiesRouter.post('/', async (req, res) => {
  const pool = getDbPool();
  if (!pool) return res.status(503).json({ error: 'Database not connected.' });
  try {
    res.status(201).json({ authority: await registerAuthority(pool, creatorOf(res).id, req.body) });
  } catch (err) {
    fail(res, err, 'registering an authority');
  }
});

authoritiesRouter.post('/:id/revoke', async (req, res) => {
  const pool = getDbPool();
  if (!pool) return res.status(503).json({ error: 'Database not connected.' });
  if (!UUID.test(req.params.id)) return res.status(404).json({ error: 'No such authority.' });
  try {
    res.json({ authority: await revokeAuthority(pool, creatorOf(res).id, req.params.id.toLowerCase()) });
  } catch (err) {
    fail(res, err, 'revoking an authority');
  }
});

/** Mounted at /api/v1/projects/:id/work-sessions, behind the full login. */
export const attestationCreatorRouter = express.Router({ mergeParams: true });

async function ownSession(pool: pg.Pool, req: express.Request, res: express.Response): Promise<{ projectId: string; sid: string } | null> {
  const projectId = String((req.params as any).id ?? '');
  const sid = String(req.params.sid);
  const ok = UUID.test(projectId) && UUID.test(sid) && (await pool.query(`SELECT 1 FROM work_session s JOIN project p ON p.id = s.project_id WHERE s.id = $1 AND s.project_id = $2 AND p.creator_id = $3 AND s.session_type = 'automated_work_session'`, [sid, projectId, creatorOf(res).id])).rowCount === 1;
  if (!ok) {
    res.status(404).json({ error: 'No such work session.' });
    return null;
  }
  return { projectId, sid: sid.toLowerCase() };
}

attestationCreatorRouter.get('/:sid/attestations', async (req, res) => {
  const pool = getDbPool();
  if (!pool) return res.status(503).json({ error: 'Database not connected.' });
  try {
    const own = await ownSession(pool, req, res);
    if (!own) return;
    const commit = req.query.commit === undefined ? null : String(req.query.commit);
    if (commit !== null && !HEX40.test(commit)) return res.status(400).json({ error: 'commit must be a full 40-character lowercase commit id.' });
    res.json(await attestationsFor(pool, own.sid, commit));
  } catch (err) {
    fail(res, err, 'listing attestations');
  }
});

attestationCreatorRouter.post('/:sid/attestations', async (req, res) => {
  const pool = getDbPool();
  if (!pool) return res.status(503).json({ error: 'Database not connected.' });
  try {
    const own = await ownSession(pool, req, res);
    if (!own) return;
    const out = await submitAttestation(pool, creatorOf(res).id, own.projectId, own.sid, req.body);
    res.status(out.created ? 201 : 200).json({ ...out.attestation, recorded: out.created });
  } catch (err) {
    fail(res, err, 'recording an attestation');
  }
});

/** Machine callers, read only. Mounted at /api/v2/work-sessions. */
export const attestationV2Router = express.Router();

attestationV2Router.get('/:id/attestations', requireScope('work-sessions:read'), async (req, res) => {
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
    const commit = req.query.commit === undefined ? null : String(req.query.commit);
    if (commit !== null && !HEX40.test(commit)) return res.status(400).json({ error: 'commit must be a full 40-character lowercase commit id.' });
    res.json(await attestationsFor(pool, s.id, commit));
  } catch (err) {
    fail(res, err, 'reading attestations');
  }
});

/**
 * Contract "commit-attribution-submission" v1. A service principal that holds attestations:submit, for a session it requested, delivers a detached signed
 * statement by an authority the owner granted it for this project. The owner, sponsor, requester, repository and project come from our records.
 */
attestationV2Router.post('/:id/attestations', requireScope('attestations:submit'), async (req, res) => {
  const pool = getDbPool();
  if (!pool) return res.status(503).json({ error: 'Database not connected.' });
  if (!UUID.test(req.params.id)) return res.status(404).json({ error: 'No such work session.' });
  try {
    const p = principalOf(res);
    const s = (
      await pool.query(
        `SELECT s.id, s.project_id FROM work_session s JOIN project pr ON pr.id = s.project_id
          WHERE s.id = $1 AND s.session_type = 'automated_work_session' AND pr.creator_id = $2 AND s.requested_by_principal_id = $3
            AND ($4::uuid[] IS NULL OR s.project_id = ANY($4::uuid[]))`,
        [req.params.id, p.creatorId, p.id, p.allowedProjectIds]
      )
    ).rows[0];
    if (!s) return res.status(404).json({ error: 'No such work session.' });
    const out = await submitAttestation(pool, p.creatorId, s.project_id, s.id, req.body, { principalId: p.id });
    const a = out.attestation;
    res.status(out.created ? 201 : 200).json({
      ...a,
      recorded: out.created,
      receipt: {
        contract: `${SUBMISSION_CONTRACT.name}/${SUBMISSION_CONTRACT.version}`,
        attestation_id: a.id,
        work_session_id: s.id,
        authority_id: a.authority.id,
        claim: a.claim,
        subject_commit: a.subject_commit,
        statement_sha256: out.statementSha256,
        recorded_at: a.recorded_at
      }
    });
  } catch (err) {
    fail(res, err, 'submitting an attestation');
  }
});
