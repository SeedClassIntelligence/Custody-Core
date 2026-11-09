import crypto from 'node:crypto';
import type pg from 'pg';

/**
 * Service principals: machine callers that authenticate with a key they hold (docs/integration/PHASE0_SPEC.md).
 * This file is the registry: scopes, key handling, and registering / suspending / revoking, each recorded on the
 * creator's account record (append_account_event) in the same transaction as the change.
 * Verifying an assertion is in servicePrincipalAuth.ts.
 */

// --- Scopes -----------------------------------------------------------------------------------------------------

/** What an ordinary automated caller may hold. */
export const EXECUTION_SCOPES = [
  'work-sessions:request',
  'work-sessions:read',
  'work-sessions:close-own',
  'evidence:submit',
  'repositories:push-session'
] as const;

/**
 * Consequential scopes: approving work, promoting to a default branch, managing principals or webhooks. Separation
 * from the execution scopes is enforced when those features are built (spec section 3.3); they are named now so
 * that a registration cannot invent scopes.
 */
export const HIGH_CONSEQUENCE_SCOPES = ['work-sessions:approve', 'repositories:promote', 'principals:manage', 'webhooks:manage'] as const;

export const ALL_SCOPES: readonly string[] = [...EXECUTION_SCOPES, ...HIGH_CONSEQUENCE_SCOPES];

export const ENVIRONMENTS = ['development', 'staging', 'production'] as const;

// --- Keys -------------------------------------------------------------------------------------------------------

export type KeyAlgorithm = 'Ed25519' | 'ES256';

export interface PublicJwk {
  kty: 'OKP' | 'EC';
  crv: 'Ed25519' | 'P-256';
  x: string;
  y?: string;
}

export class PrincipalError extends Error {
  constructor(public code: 'invalid' | 'not_found' | 'conflict', message: string) {
    super(message);
  }
}

const B64URL = /^[A-Za-z0-9_-]+$/;
const fixedBytes = (v: unknown, n: number) => typeof v === 'string' && B64URL.test(v) && Buffer.from(v, 'base64url').length === n;

/**
 * Checks a submitted public key and returns it in canonical form (only the members that define the key).
 * A private key (a `d` member) is refused outright: it must never be sent here, and is not stored.
 */
export function readPublicJwk(input: unknown): { jwk: PublicJwk; algorithm: KeyAlgorithm } {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new PrincipalError('invalid', 'The public key must be a JWK object.');
  const j = input as Record<string, unknown>;
  if ('d' in j) throw new PrincipalError('invalid', 'That JWK contains a private key (a "d" member). Send only the public key.');
  let jwk: PublicJwk;
  let algorithm: KeyAlgorithm;
  if (j.kty === 'OKP' && j.crv === 'Ed25519' && fixedBytes(j.x, 32)) {
    jwk = { kty: 'OKP', crv: 'Ed25519', x: j.x as string };
    algorithm = 'Ed25519';
  } else if (j.kty === 'EC' && j.crv === 'P-256' && fixedBytes(j.x, 32) && fixedBytes(j.y, 32)) {
    jwk = { kty: 'EC', crv: 'P-256', x: j.x as string, y: j.y as string };
    algorithm = 'ES256';
  } else {
    throw new PrincipalError('invalid', 'The public key must be an Ed25519 key (kty OKP, crv Ed25519) or a P-256 key (kty EC, crv P-256).');
  }
  try {
    crypto.createPublicKey({ key: jwk as any, format: 'jwk' });
  } catch {
    throw new PrincipalError('invalid', 'That is not a valid public key (the point is not on the curve).');
  }
  return { jwk, algorithm };
}

/** SHA-256 (hex) of the RFC 7638 thumbprint input: the key's required members, in alphabetical order. */
export function jwkFingerprint(jwk: PublicJwk): string {
  const members = jwk.kty === 'OKP' ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x } : { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  return crypto.createHash('sha256').update(JSON.stringify(members)).digest('hex');
}

// --- Registry ---------------------------------------------------------------------------------------------------

export interface PrincipalInput {
  name: string;
  platform_type: string;
  environment: string;
  allowed_scopes: string[];
  allowed_project_ids?: string[] | null;
  expires_at?: string | null;
}

export interface PrincipalRow {
  id: string;
  creator_id: string;
  name: string;
  platform_type: string;
  environment: string;
  status: string;
  allowed_scopes: string[];
  allowed_project_ids: string[] | null;
  created_by: string;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

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

/**
 * Records a principal event on the creator's own account record (the chain for things that are not one project's).
 * Registration is done by an operator script for now, so the actor is the platform (`system`) and `by` names who ran it.
 * (append_account_event accepts creator, developer, system or gateway as actor types.)
 */
async function recordAccountEvent(c: pg.PoolClient, creatorId: string, by: string, action: string, payload: Record<string, unknown>) {
  const who = (await c.query('SELECT identity_id FROM creator WHERE id = $1', [creatorId])).rows[0];
  if (!who) throw new PrincipalError('not_found', 'No such creator.');
  await c.query('SELECT append_account_event($1, $2, $3, $4, $5::jsonb)', [who.identity_id, 'system', by, action, JSON.stringify(payload)]);
}

export async function registerPrincipal(pool: pg.Pool, creatorId: string, input: PrincipalInput, createdBy: string): Promise<PrincipalRow> {
  const name = (input.name ?? '').trim();
  if (!name || name.length > 100) throw new PrincipalError('invalid', 'The name must be 1 to 100 characters.');
  const platform = (input.platform_type ?? '').trim();
  if (!platform || platform.length > 50) throw new PrincipalError('invalid', 'The platform type must be 1 to 50 characters.');
  if (!(ENVIRONMENTS as readonly string[]).includes(input.environment)) throw new PrincipalError('invalid', `The environment must be one of ${ENVIRONMENTS.join(', ')}.`);
  const scopes = [...new Set(input.allowed_scopes ?? [])];
  const unknown = scopes.filter((s) => !ALL_SCOPES.includes(s));
  if (unknown.length) throw new PrincipalError('invalid', `Unknown scope(s): ${unknown.join(', ')}.`);
  let expires: string | null = null;
  if (input.expires_at) {
    const t = Date.parse(input.expires_at);
    if (!Number.isFinite(t) || t <= Date.now()) throw new PrincipalError('invalid', 'expires_at must be a time in the future.');
    expires = new Date(t).toISOString();
  }
  const projects = input.allowed_project_ids ?? null;
  if (projects && projects.some((p) => !UUID.test(p))) throw new PrincipalError('invalid', 'allowed_project_ids must be project ids.');

  return inTransaction(pool, async (c) => {
    if (projects?.length) {
      const owned = (await c.query('SELECT id FROM project WHERE creator_id = $1 AND id = ANY($2::uuid[])', [creatorId, projects])).rows.length;
      if (owned !== new Set(projects).size) throw new PrincipalError('invalid', 'allowed_project_ids may only name this creator\'s own projects.');
    }
    let row: PrincipalRow;
    try {
      row = (
        await c.query(
          `INSERT INTO service_principal (creator_id, name, platform_type, environment, allowed_scopes, allowed_project_ids, created_by, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
          [creatorId, name, platform, input.environment, scopes, projects, createdBy, expires]
        )
      ).rows[0];
    } catch (err: any) {
      if (err?.code === '23505') throw new PrincipalError('conflict', `This creator already has a principal named "${name}".`);
      if (err?.code === '23503') throw new PrincipalError('not_found', 'No such creator.');
      throw err;
    }
    await recordAccountEvent(c, creatorId, createdBy, 'service_principal.registered', {
      principal_id: row.id,
      name,
      platform_type: platform,
      environment: input.environment,
      scopes,
      project_ids: projects,
      expires_at: expires
    });
    return row;
  });
}

export async function addPrincipalKey(
  pool: pg.Pool,
  principalId: string,
  publicKey: unknown,
  by: string,
  expiresAt?: string | null
): Promise<{ key_id: string; algorithm: KeyAlgorithm; fingerprint: string }> {
  const { jwk, algorithm } = readPublicJwk(publicKey);
  const fingerprint = jwkFingerprint(jwk);
  let expires: string | null = null;
  if (expiresAt) {
    const t = Date.parse(expiresAt);
    if (!Number.isFinite(t) || t <= Date.now()) throw new PrincipalError('invalid', 'expires_at must be a time in the future.');
    expires = new Date(t).toISOString();
  }
  return inTransaction(pool, async (c) => {
    const p = (await c.query('SELECT id, creator_id, status FROM service_principal WHERE id = $1 FOR UPDATE', [principalId])).rows[0];
    if (!p) throw new PrincipalError('not_found', 'No such principal.');
    if (p.status === 'revoked') throw new PrincipalError('conflict', 'A revoked principal cannot be given keys.');
    let keyId: string;
    try {
      keyId = (
        await c.query(
          `INSERT INTO service_principal_key (principal_id, algorithm, public_key_jwk, fingerprint, expires_at)
           VALUES ($1, $2, $3::jsonb, $4, $5) RETURNING id`,
          [principalId, algorithm, JSON.stringify(jwk), fingerprint, expires]
        )
      ).rows[0].id;
    } catch (err: any) {
      if (err?.code === '23505') throw new PrincipalError('conflict', 'This key is already registered.');
      throw err;
    }
    await recordAccountEvent(c, p.creator_id, by, 'service_principal.key_added', { principal_id: principalId, key_id: keyId, algorithm, fingerprint, expires_at: expires });
    return { key_id: keyId, algorithm, fingerprint };
  });
}

export async function revokeKey(pool: pg.Pool, keyId: string, by: string): Promise<void> {
  await inTransaction(pool, async (c) => {
    const k = (
      await c.query(
        `SELECT k.id, k.principal_id, k.revoked_at, p.creator_id FROM service_principal_key k
         JOIN service_principal p ON p.id = k.principal_id WHERE k.id = $1 FOR UPDATE OF k`,
        [keyId]
      )
    ).rows[0];
    if (!k) throw new PrincipalError('not_found', 'No such key.');
    if (k.revoked_at) return; // already revoked: nothing to do, nothing to record twice
    await c.query('UPDATE service_principal_key SET revoked_at = now() WHERE id = $1', [keyId]);
    await recordAccountEvent(c, k.creator_id, by, 'service_principal.key_revoked', { principal_id: k.principal_id, key_id: keyId });
  });
}

/** 'suspended' can be lifted back to 'active'; 'revoked' is final (the database refuses to undo it). */
export async function setPrincipalStatus(pool: pg.Pool, principalId: string, status: 'active' | 'suspended' | 'revoked', by: string): Promise<void> {
  await inTransaction(pool, async (c) => {
    const p = (await c.query('SELECT id, creator_id, status FROM service_principal WHERE id = $1 FOR UPDATE', [principalId])).rows[0];
    if (!p) throw new PrincipalError('not_found', 'No such principal.');
    if (p.status === status) return;
    if (p.status === 'revoked') throw new PrincipalError('conflict', 'A revoked principal cannot be changed.');
    await c.query(`UPDATE service_principal SET status = $2, revoked_at = CASE WHEN $2 = 'revoked' THEN now() ELSE NULL END, updated_at = now() WHERE id = $1`, [principalId, status]);
    const action = status === 'revoked' ? 'service_principal.revoked' : status === 'suspended' ? 'service_principal.suspended' : 'service_principal.reactivated';
    await recordAccountEvent(c, p.creator_id, by, action, { principal_id: principalId, from: p.status, to: status });
  });
}

export async function listPrincipals(pool: pg.Pool, creatorId: string) {
  const rows = (
    await pool.query(
      `SELECT p.*, COALESCE(json_agg(json_build_object('id', k.id, 'algorithm', k.algorithm, 'fingerprint', k.fingerprint,
                'expires_at', k.expires_at, 'revoked_at', k.revoked_at) ORDER BY k.created_at) FILTER (WHERE k.id IS NOT NULL), '[]') AS keys
         FROM service_principal p LEFT JOIN service_principal_key k ON k.principal_id = p.id
        WHERE p.creator_id = $1 GROUP BY p.id ORDER BY p.created_at`,
      [creatorId]
    )
  ).rows;
  return rows;
}
