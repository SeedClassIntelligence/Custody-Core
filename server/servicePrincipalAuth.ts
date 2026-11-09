import crypto from 'node:crypto';
import express from 'express';
import type pg from 'pg';
import { getDbPool } from './db';
import { ALL_SCOPES, type KeyAlgorithm, type PublicJwk } from './servicePrincipals';

/**
 * Login for machine callers on /api/v2. Not the person login (that is /api/v1, untouched).
 *
 * Every request carries `Authorization: Bearer <client assertion>`: a JWT the caller signs with a key registered
 * for its principal (docs/integration/PHASE0_SPEC.md, section 4.1). All of this must hold, or the answer is 401:
 *   1. The header names an algorithm (EdDSA or ES256) that is the registered algorithm of the key `kid` names.
 *      The key is looked up by `kid` in our database; keys carried in the token's own header are never used.
 *   2. The signature verifies with that registered public key.
 *   3. iss and sub are the principal's id; the principal is active and unexpired; the key is not revoked or expired.
 *   4. aud is exactly "custody-core".
 *   5. iat is not in the future (30 s of clock difference allowed), exp is in the future, exp - iat <= 300 s.
 *   6. jti is present and has not been used by this principal. It is recorded in the same statement that checks it.
 *
 * Order matters: a token with a bad signature is turned away before anything is written, so nobody without the key
 * can use up a principal's jti values. What the caller may do (its scopes) comes from our database, never from the token.
 * The response never says which check failed; the reason goes to the server log (not the token).
 */

export const ASSERTION_AUDIENCE = 'custody-core';
export const MAX_ASSERTION_LIFETIME_SECONDS = 300;
const CLOCK_SKEW_SECONDS = 30;

const JWT_ALG_FOR_KEY: Record<string, KeyAlgorithm> = { EdDSA: 'Ed25519', ES256: 'ES256' };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface AuthenticatedPrincipal {
  id: string;
  creatorId: string;
  name: string;
  platformType: string;
  environment: string;
  scopes: string[];
  allowedProjectIds: string[] | null;
  expiresAt: string | null;
}

/** The assertion was refused. `reason` is for the server log only. */
export class AssertionRejected extends Error {
  constructor(public reason: string) {
    super(reason);
  }
}

function parseSegment(segment: string): Record<string, unknown> {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) throw new AssertionRejected('malformed segment');
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
  } catch {
    throw new AssertionRejected('segment is not JSON');
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new AssertionRejected('segment is not an object');
  return value as Record<string, unknown>;
}

function verifySignature(algorithm: KeyAlgorithm, jwk: PublicJwk, signingInput: string, signature: Buffer): boolean {
  const key = crypto.createPublicKey({ key: jwk as any, format: 'jwk' });
  if (algorithm === 'Ed25519') {
    if (signature.length !== 64) return false;
    return crypto.verify(null, Buffer.from(signingInput), key, signature);
  }
  if (signature.length !== 64) return false; // JWS ES256 is the raw 64-byte r || s form
  return crypto.verify('sha256', Buffer.from(signingInput), { key, dsaEncoding: 'ieee-p1363' }, signature);
}

export async function verifyClientAssertion(pool: pg.Pool, token: string, nowMs = Date.now()): Promise<AuthenticatedPrincipal> {
  const parts = token.split('.');
  if (parts.length !== 3) throw new AssertionRejected('not a compact JWT');
  const [h, p, s] = parts;
  const header = parseSegment(h);
  const claims = parseSegment(p);
  if (!/^[A-Za-z0-9_-]+$/.test(s)) throw new AssertionRejected('malformed signature');
  const signature = Buffer.from(s, 'base64url');

  // 1. algorithm and key
  const alg = header.alg;
  if (typeof alg !== 'string' || !(alg in JWT_ALG_FOR_KEY)) throw new AssertionRejected(`algorithm not allowed: ${String(alg).slice(0, 20)}`);
  const kid = header.kid;
  if (typeof kid !== 'string' || !UUID.test(kid)) throw new AssertionRejected('kid missing or not an id');

  const found = (
    await pool.query(
      `SELECT k.algorithm AS key_algorithm, k.public_key_jwk, k.expires_at AS key_expires_at, k.revoked_at AS key_revoked_at,
              p.id, p.creator_id, p.name, p.platform_type, p.environment, p.status, p.allowed_scopes, p.allowed_project_ids,
              p.expires_at, p.revoked_at
         FROM service_principal_key k JOIN service_principal p ON p.id = k.principal_id WHERE k.id = $1`,
      [kid]
    )
  ).rows[0];
  if (!found) throw new AssertionRejected('unknown key');
  if (JWT_ALG_FOR_KEY[alg] !== found.key_algorithm) throw new AssertionRejected('algorithm does not match the registered key');

  // 2. signature (before any claim is trusted, and before anything is written)
  let ok = false;
  try {
    ok = verifySignature(found.key_algorithm, found.public_key_jwk, `${h}.${p}`, signature);
  } catch {
    ok = false;
  }
  if (!ok) throw new AssertionRejected('signature does not verify');

  // 3. who and whether still allowed
  if (claims.iss !== found.id || claims.sub !== found.id) throw new AssertionRejected('iss/sub is not the key\'s principal');
  if (found.status !== 'active' || found.revoked_at) throw new AssertionRejected(`principal is ${found.status}`);
  if (found.expires_at && new Date(found.expires_at).getTime() <= nowMs) throw new AssertionRejected('principal expired');
  if (found.key_revoked_at) throw new AssertionRejected('key revoked');
  if (found.key_expires_at && new Date(found.key_expires_at).getTime() <= nowMs) throw new AssertionRejected('key expired');

  // 4. audience (a single string, exactly)
  if (claims.aud !== ASSERTION_AUDIENCE) throw new AssertionRejected('wrong audience');

  // 5. times
  const { iat, exp } = claims;
  if (typeof iat !== 'number' || typeof exp !== 'number' || !Number.isInteger(iat) || !Number.isInteger(exp)) throw new AssertionRejected('iat/exp missing or not whole seconds');
  const nowS = Math.floor(nowMs / 1000);
  if (iat > nowS + CLOCK_SKEW_SECONDS) throw new AssertionRejected('iat is in the future');
  if (exp <= nowS) throw new AssertionRejected('expired');
  if (exp <= iat || exp - iat > MAX_ASSERTION_LIFETIME_SECONDS) throw new AssertionRejected('lifetime longer than allowed');

  // 6. replay: record the jti and learn in one statement whether it was new
  const jti = claims.jti;
  if (typeof jti !== 'string' || jti.length < 1 || jti.length > 128) throw new AssertionRejected('jti missing or invalid');
  const recorded = await pool.query(
    `INSERT INTO used_client_assertion (principal_id, jti, expires_at) VALUES ($1, $2, to_timestamp($3))
     ON CONFLICT (principal_id, jti) DO NOTHING RETURNING 1`,
    [found.id, jti, exp + CLOCK_SKEW_SECONDS]
  );
  if (recorded.rowCount === 0) throw new AssertionRejected('replayed assertion (jti already used)');

  return {
    id: found.id,
    creatorId: found.creator_id,
    name: found.name,
    platformType: found.platform_type,
    environment: found.environment,
    scopes: found.allowed_scopes,
    allowedProjectIds: found.allowed_project_ids,
    expiresAt: found.expires_at ? new Date(found.expires_at).toISOString() : null
  };
}

export function principalOf(res: express.Response): AuthenticatedPrincipal {
  return res.locals.principal as AuthenticatedPrincipal;
}

/** Express middleware for /api/v2. */
export const authenticatePrincipal: express.RequestHandler = async (req, res, next) => {
  const pool = getDbPool();
  if (!pool) return res.status(503).json({ error: 'Database not connected.' });
  const header = req.header('authorization') ?? '';
  const match = /^Bearer ([^\s]+)$/.exec(header);
  const refuse = (reason: string) => {
    console.warn(`[principal-auth] refused: ${reason}`);
    res.setHeader('WWW-Authenticate', 'Bearer');
    return res.status(401).json({ error: 'Invalid or missing credentials.' });
  };
  if (!match) return refuse('no bearer token');
  try {
    res.locals.principal = await verifyClientAssertion(pool, match[1]);
    next();
  } catch (err: any) {
    if (err instanceof AssertionRejected) return refuse(err.reason);
    console.error('[principal-auth] failed:', err?.message ?? err);
    return res.status(500).json({ error: 'Something went wrong on the server.' });
  }
};

/**
 * For routes that need a scope: 403 unless this principal's stored scopes include it. The scopes are read from the
 * database on every request (see verifyClientAssertion), so narrowing, suspending or revoking is effective at once.
 * Put it after authenticatePrincipal: a caller with no valid credential is a 401 before it is ever a 403.
 */
export function requireScope(scope: string): express.RequestHandler {
  // A typo in a route would otherwise make it unreachable for everyone, or worse, read as "no scope needed".
  if (!ALL_SCOPES.includes(scope)) throw new Error(`requireScope: "${scope}" is not a known scope.`);
  return (_req, res, next) => {
    if (!principalOf(res).scopes.includes(scope)) return res.status(403).json({ error: `This credential does not have the ${scope} scope.` });
    next();
  };
}

/** Whether this principal may act on this project: the creator's own project, and on the principal's list if it has one. */
export async function projectAccessible(pool: pg.Pool, principal: AuthenticatedPrincipal, projectId: string): Promise<boolean> {
  if (!UUID.test(projectId)) return false;
  if (principal.allowedProjectIds && !principal.allowedProjectIds.includes(projectId)) return false;
  // Always checked against the creator, even when the list names the project: a list is not proof of ownership.
  const r = await pool.query('SELECT 1 FROM project WHERE id = $1 AND creator_id = $2', [projectId, principal.creatorId]);
  return r.rowCount === 1;
}

/**
 * For routes with a project id in the path. A project that does not exist, belongs to another creator, or is
 * outside this principal's project list all answer 404, so a caller cannot find out which projects exist.
 * Order scope checks before this one: a caller without the scope gets 403 whatever the project.
 */
export function requireProjectAccess(param = 'projectId'): express.RequestHandler {
  return async (req, res, next) => {
    const pool = getDbPool();
    if (!pool) return res.status(503).json({ error: 'Database not connected.' });
    try {
      if (!(await projectAccessible(pool, principalOf(res), String(req.params[param] ?? '')))) {
        return res.status(404).json({ error: 'No such project.' });
      }
      next();
    } catch (err: any) {
      console.error('[principal-auth] project access check failed:', err?.message ?? err);
      return res.status(500).json({ error: 'Something went wrong on the server.' });
    }
  };
}

// --- /api/v2 ------------------------------------------------------------------------------------------------------

export const v2Router = express.Router();
v2Router.use(authenticatePrincipal);

/** Who the caller is, as we know it. Everything here comes from our records, not from the token. */
v2Router.get('/whoami', (_req, res) => {
  const p = principalOf(res);
  res.json({
    principal: {
      id: p.id,
      name: p.name,
      platform_type: p.platformType,
      environment: p.environment,
      scopes: p.scopes,
      allowed_project_ids: p.allowedProjectIds,
      expires_at: p.expiresAt
    }
  });
});
