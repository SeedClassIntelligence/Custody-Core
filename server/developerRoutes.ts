import crypto from 'node:crypto';
import express from 'express';
import type pg from 'pg';
import { getDbPool, insertEvent } from './db';
import { creatorOf } from './auth';
import { newGatewayToken } from './gateway/router';
import { gatewayBase, remotesFor } from './doors';
import { CONSENT_TEXT, SIGNATURE_PURPOSE, SignedStatement, canonicalStatement, readPublicKey, verifyStatement } from './agreements';

/**
 * The developer's side (mounted at /api/v1/developer, after the full login: the same email-and-password step,
 * confirmed email, and server-side authenticator-code step with its wrong-code lockout as creators).
 *
 *   GET  /invites/:token          what the invitation is for, and the agreement text (only for the invited address)
 *   POST /invites/:token/accept   links the door to this login
 *   POST /keys                    registers this device's signing key (public half only)
 *   GET  /doors                   doors this login has accepted
 *   POST /doors/:doorId/sign      signs the agreement; the door opens
 *   POST /doors/:doorId/credential   issues the gateway credential (shown once; a new one replaces the old)
 */

export const developerRouter = express.Router();

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SIGNING_WINDOW_MS = 10 * 60 * 1000;

function db(res: express.Response): pg.Pool | null {
  const pool = getDbPool();
  if (!pool) res.status(503).json({ error: 'Database not connected.' });
  return pool;
}

function fail(res: express.Response, err: any, what: string) {
  console.error(`[developer] ${what}:`, err?.message ?? err);
  return res.status(500).json({ error: 'Something went wrong on the server.' });
}

const sameEmail = (a: string, b: string) => a.trim().toLowerCase() === b.trim().toLowerCase();

function maskEmail(email: string): string {
  const [user, domain] = email.split('@');
  return `${user.slice(0, 1)}${'*'.repeat(Math.max(1, user.length - 1))}@${domain}`;
}

async function developerId(pool: pg.Pool | pg.PoolClient, userId: string): Promise<string | null> {
  const r = await pool.query('SELECT id FROM developer WHERE identity_id = $1', [userId]);
  return r.rows[0]?.id ?? null;
}

async function findInvite(pool: pg.Pool | pg.PoolClient, token: string, lock = false) {
  if (!/^cci_[A-Za-z0-9_-]{32}$/.test(token)) return null;
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  return (await pool.query(
    `SELECT i.*, d.status AS door_status, d.project_id, d.expires_at AS door_expires_at, d.developer_id AS door_developer_id
       FROM door_invite i JOIN door d ON d.id = i.door_id WHERE i.token_hash = $1 ${lock ? 'FOR UPDATE OF i, d' : ''}`,
    [hash]
  )).rows[0] ?? null;
}

/** Why an invitation cannot be used by this login, or null. */
function inviteProblem(invite: any, email: string, myDeveloperId: string | null): { status: number; error: string } | null {
  if (!invite) return { status: 404, error: 'This invitation link is not valid.' };
  if (invite.revoked_at) return { status: 410, error: 'This invitation was withdrawn or replaced by a newer one. Ask the creator for a new link.' };
  if (!sameEmail(invite.email, email)) {
    return { status: 403, error: `This invitation is for ${maskEmail(invite.email)}. Sign in with that address.` };
  }
  if (invite.accepted_at && invite.accepted_by_developer !== myDeveloperId) return { status: 409, error: 'This invitation was already accepted.' };
  if (!invite.accepted_at && new Date(invite.expires_at).getTime() <= Date.now()) {
    return { status: 410, error: 'This invitation has expired. Ask the creator for a new link.' };
  }
  if (invite.door_status === 'closed') return { status: 410, error: 'This door was closed.' };
  return null;
}

developerRouter.get('/invites/:token', async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  const me = creatorOf(res);
  try {
    const invite = await findInvite(pool, req.params.token);
    const problem = inviteProblem(invite, me.email, await developerId(pool, me.userId));
    if (problem) return res.status(problem.status).json({ error: problem.error });
    const door = (await pool.query(
      `SELECT d.id, d.job_description, d.rights_type, d.expires_at, d.status, d.agreement_version, d.agreement_text, d.agreement_sha256,
              p.name AS project_name, c.display_name AS creator_name, c.email AS creator_email,
              COALESCE((SELECT json_agg(json_build_object('full_name', r.full_name, 'access', dr.access) ORDER BY r.full_name)
                          FROM door_repository dr JOIN repository r ON r.id = dr.repository_id WHERE dr.door_id = d.id), '[]') AS repositories
         FROM door d JOIN project p ON p.id = d.project_id JOIN creator c ON c.id = p.creator_id WHERE d.id = $1`,
      [invite.door_id]
    )).rows[0];
    res.json({ invite: { door, accepted: !!invite.accepted_at } });
  } catch (err) {
    fail(res, err, 'reading an invitation');
  }
});

developerRouter.post('/invites/:token/accept', async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  const me = creatorOf(res);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const invite = await findInvite(client, req.params.token, true);
    const existingDev = await developerId(client, me.userId);
    const problem = inviteProblem(invite, me.email, existingDev);
    if (problem) {
      await client.query('ROLLBACK');
      return res.status(problem.status).json({ error: problem.error });
    }
    if (invite.door_developer_id && invite.door_developer_id !== existingDev) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Another account already accepted this door.' });
    }
    const dev = (await client.query(
      `INSERT INTO developer (identity_id, display_name, email) VALUES ($1, $2, $3)
       ON CONFLICT (identity_id) DO UPDATE SET email = EXCLUDED.email, updated_at = now() RETURNING id`,
      [me.userId, me.email.split('@')[0], me.email]
    )).rows[0].id as string;
    if (!invite.accepted_at) {
      await client.query('UPDATE door_invite SET accepted_at = now(), accepted_by_developer = $2 WHERE id = $1', [invite.id, dev]);
      await client.query('UPDATE door SET developer_id = $2, updated_at = now() WHERE id = $1', [invite.door_id, dev]);
      await insertEvent({
        project_id: invite.project_id,
        actor_type: 'developer',
        actor_id: dev,
        action: 'door.invite_accepted',
        subject_type: 'door',
        subject_id: invite.door_id,
        payload: { invite_id: invite.id, developer_id: dev, developer_email: me.email, developer_identity: me.userId }
      }, client);
    }
    await client.query('COMMIT');
    res.json({ door_id: invite.door_id });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    fail(res, err, 'accepting an invitation');
  } finally {
    client.release();
  }
});

developerRouter.post('/keys', async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  const me = creatorOf(res);
  const key = readPublicKey(req.body?.public_key_spki);
  if (!key) return res.status(400).json({ error: 'public_key_spki must be an ECDSA P-256 public key (base64 DER SubjectPublicKeyInfo).' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const dev = await developerId(client, me.userId);
    if (!dev) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Accept an invitation first.' });
    }
    const current = (await client.query('SELECT id, fingerprint FROM developer_key WHERE developer_id = $1 AND retired_at IS NULL FOR UPDATE', [dev])).rows[0];
    if (current?.fingerprint === key.fingerprint) {
      await client.query('COMMIT');
      return res.json({ key: { id: current.id, fingerprint: key.fingerprint } });
    }
    if (current) await client.query('UPDATE developer_key SET retired_at = now() WHERE id = $1', [current.id]);
    const row = (await client.query(
      `INSERT INTO developer_key (developer_id, algorithm, public_key_spki, fingerprint) VALUES ($1, 'ECDSA-P256-SHA256', $2, $3) RETURNING id`,
      [dev, key.spki, key.fingerprint]
    )).rows[0];
    // On the developer's own account record: a new key (a new device) is visible later.
    await client.query(
      `SELECT * FROM append_account_event($1, 'developer', $2, 'developer.key_registered', $3::jsonb)`,
      [me.userId, dev, JSON.stringify({ key_id: row.id, fingerprint: key.fingerprint, replaced_key_id: current?.id ?? null })]
    );
    await client.query('COMMIT');
    res.status(201).json({ key: { id: row.id, fingerprint: key.fingerprint } });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    fail(res, err, 'registering a key');
  } finally {
    client.release();
  }
});

developerRouter.get('/doors', async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  const me = creatorOf(res);
  try {
    const dev = await developerId(pool, me.userId);
    if (!dev) return res.json({ doors: [], key: null });
    const doors = (await pool.query(
      `SELECT d.id, d.project_id, d.job_description, d.rights_type, d.status, d.expires_at, d.opens_at, d.closed_at, d.closed_reason,
              d.agreement_version, d.agreement_text, d.agreement_sha256, d.agreement_signed_at, d.developer_email,
              p.name AS project_name, c.display_name AS creator_name,
              COALESCE((SELECT json_agg(json_build_object('full_name', r.full_name, 'access', dr.access) ORDER BY r.full_name)
                          FROM door_repository dr JOIN repository r ON r.id = dr.repository_id WHERE dr.door_id = d.id), '[]') AS repositories,
              (SELECT json_build_object('id', gc.id, 'created_at', gc.created_at, 'last_used_at', gc.last_used_at)
                 FROM gateway_credential gc WHERE gc.door_id = d.id AND gc.revoked_at IS NULL ORDER BY gc.created_at DESC LIMIT 1) AS credential
         FROM door d JOIN project p ON p.id = d.project_id JOIN creator c ON c.id = p.creator_id
        WHERE d.developer_id = $1 ORDER BY d.created_at DESC`,
      [dev]
    )).rows;
    const key = (await pool.query('SELECT id, fingerprint, created_at FROM developer_key WHERE developer_id = $1 AND retired_at IS NULL', [dev])).rows[0] ?? null;
    res.json({
      developer_identity: me.userId,
      key,
      doors: doors.map((d) => ({ ...d, branch_prefix: `door/${d.id}/`, remotes: d.status === 'open' ? remotesFor(req, d.id, d.repositories) : [] }))
    });
  } catch (err) {
    fail(res, err, 'listing doors');
  }
});

developerRouter.post('/doors/:doorId/sign', async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  const me = creatorOf(res);
  if (!UUID.test(req.params.doorId)) return res.status(404).json({ error: 'Door not found.' });
  const { statement, signature } = req.body ?? {};
  if (typeof statement !== 'string' || statement.length > 4000 || typeof signature !== 'string' || !/^[A-Za-z0-9+/=]{80,100}$/.test(signature)) {
    return res.status(400).json({ error: 'statement (text) and signature (base64) are required.' });
  }
  let parsed: SignedStatement;
  try {
    parsed = JSON.parse(statement);
  } catch {
    return res.status(400).json({ error: 'statement must be JSON.' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const dev = await developerId(client, me.userId);
    const door = dev
      ? (await client.query('SELECT * FROM door WHERE id = $1 AND developer_id = $2 FOR UPDATE', [req.params.doorId, dev])).rows[0]
      : null;
    if (!door) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Door not found.' });
    }
    if (door.status !== 'awaiting_signature') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: door.agreement_signed_at ? 'This agreement is already signed.' : `This door is ${door.status}.` });
    }
    if (new Date(door.expires_at).getTime() <= Date.now()) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'This door has passed its end date.' });
    }
    const key = (await client.query('SELECT * FROM developer_key WHERE developer_id = $1 AND retired_at IS NULL', [dev])).rows[0];
    if (!key) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Register this device\'s signing key first.' });
    }

    // The statement must be exactly the canonical form of exactly these fields, naming this agreement and this login.
    const problems: string[] = [];
    const expectedKeys = ['agreement_sha256', 'consent', 'developer_email', 'developer_identity', 'door_id', 'project_id', 'purpose', 'signed_at', 'signer_name'];
    if (!parsed || typeof parsed !== 'object' || Object.keys(parsed).sort().join() !== expectedKeys.join()) problems.push('fields');
    else {
      if (canonicalStatement(parsed) !== statement) problems.push('not in canonical form');
      if (parsed.purpose !== SIGNATURE_PURPOSE) problems.push('purpose');
      if (parsed.agreement_sha256 !== door.agreement_sha256) problems.push('agreement_sha256 (not this agreement)');
      if (parsed.door_id !== door.id || parsed.project_id !== door.project_id) problems.push('door');
      if (!sameEmail(String(parsed.developer_email), door.developer_email) || !sameEmail(String(parsed.developer_email), me.email)) problems.push('developer_email');
      if (parsed.developer_identity !== me.userId) problems.push('developer_identity');
      if (parsed.consent !== CONSENT_TEXT) problems.push('consent');
      if (typeof parsed.signer_name !== 'string' || parsed.signer_name.trim().length < 2 || parsed.signer_name.length > 200) problems.push('signer_name');
      const at = Date.parse(String(parsed.signed_at));
      if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/.test(String(parsed.signed_at)) || Number.isNaN(at) || Math.abs(at - Date.now()) > SIGNING_WINDOW_MS) {
        problems.push('signed_at (more than 10 minutes from the server clock)');
      }
    }
    if (problems.length) {
      await client.query('ROLLBACK');
      return res.status(422).json({ error: `The signed statement does not match this agreement: ${problems.join(', ')}.` });
    }
    if (!verifyStatement(key.public_key_spki, statement, signature)) {
      await client.query('ROLLBACK');
      return res.status(422).json({ error: 'The signature does not verify with your registered key.' });
    }

    await client.query(
      `UPDATE door SET agreement_signed_at = now(), agreement_signed_message = $2, agreement_signature = $3, agreement_key_id = $4,
              status = 'open', opens_at = now(), updated_at = now() WHERE id = $1`,
      [door.id, statement, signature, key.id]
    );
    await insertEvent({
      project_id: door.project_id,
      actor_type: 'developer',
      actor_id: dev!,
      action: 'agreement.signed',
      subject_type: 'agreement',
      subject_id: door.id,
      // Everything needed to check the signature later, without trusting this server: the exact signed bytes,
      // the signature and the public key. The agreement text is on the door, and its SHA-256 is in the statement.
      payload: {
        agreement_version: door.agreement_version,
        agreement_sha256: door.agreement_sha256,
        signer_name: parsed.signer_name,
        developer_email: me.email,
        developer_identity: me.userId,
        algorithm: 'ECDSA-P256-SHA256',
        public_key_spki: key.public_key_spki,
        key_fingerprint: key.fingerprint,
        signed_statement: statement,
        signature
      }
    }, client);
    await insertEvent({
      project_id: door.project_id,
      actor_type: 'system',
      actor_id: 'door-lifecycle',
      action: 'door.opened',
      subject_type: 'door',
      subject_id: door.id,
      payload: { opened_because: 'agreement signed', expires_at: new Date(door.expires_at).toISOString(), branch_prefix: `door/${door.id}/` }
    }, client);
    await client.query('COMMIT');
    res.json({ signed: true, door_id: door.id });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    fail(res, err, 'signing an agreement');
  } finally {
    client.release();
  }
});

developerRouter.post('/doors/:doorId/credential', async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  const me = creatorOf(res);
  if (!UUID.test(req.params.doorId)) return res.status(404).json({ error: 'Door not found.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const dev = await developerId(client, me.userId);
    const door = dev
      ? (await client.query('SELECT * FROM door WHERE id = $1 AND developer_id = $2 FOR UPDATE', [req.params.doorId, dev])).rows[0]
      : null;
    if (!door) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Door not found.' });
    }
    if (door.status !== 'open' || new Date(door.expires_at).getTime() <= Date.now()) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: door.status === 'awaiting_signature' ? 'Sign the agreement first.' : 'This door is not open.' });
    }
    const replaced = (await client.query(
      'UPDATE gateway_credential SET revoked_at = now() WHERE door_id = $1 AND revoked_at IS NULL RETURNING id', [door.id]
    )).rows;
    for (const c of replaced) {
      await insertEvent({
        project_id: door.project_id, actor_type: 'developer', actor_id: dev!, action: 'credential.revoked',
        subject_type: 'door', subject_id: door.id, payload: { credential_id: c.id, reason: 'replaced_by_developer' }
      }, client);
    }
    const { token, hash } = newGatewayToken();
    const credential = (await client.query('INSERT INTO gateway_credential (door_id, token_hash) VALUES ($1, $2) RETURNING id', [door.id, hash])).rows[0];
    await insertEvent({
      project_id: door.project_id, actor_type: 'developer', actor_id: dev!, action: 'credential.issued',
      subject_type: 'door', subject_id: door.id, payload: { credential_id: credential.id, issued_to: me.email }
    }, client);
    await client.query('COMMIT');
    const repos = (await pool.query(
      'SELECT r.full_name FROM door_repository dr JOIN repository r ON r.id = dr.repository_id WHERE dr.door_id = $1 ORDER BY r.full_name', [door.id]
    )).rows;
    res.json({ credential: { username: 'door', token }, remotes: remotesFor(req, door.id, repos), branch_prefix: `door/${door.id}/`, base: gatewayBase(req) });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    fail(res, err, 'issuing a credential');
  } finally {
    client.release();
  }
});
