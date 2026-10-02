import type { NextFunction, Request, Response } from 'express';
import { getDbPool } from './db';

/**
 * Login for the API. Identity comes only from a verified Supabase Auth session token, never from a
 * header, query parameter or body field the client chooses.
 *
 * Every request must carry `Authorization: Bearer <access token>`. The server asks Supabase Auth to
 * validate the token (signature, expiry, revocation), then reads the assurance level from it:
 *   - missing, malformed, invalid or expired token  -> 401
 *   - valid token, but not multifactor (below aal2) -> 403
 *   - valid aal2 token                              -> the request runs as that creator
 *
 * Only the project URL and the public (anon) key are needed. The service-role key is not used.
 */

export interface AuthenticatedCreator {
  /** creator.id in our database */
  id: string;
  /** Supabase Auth user id (creator.identity_id) */
  userId: string;
  email: string;
}

export function getAuthConfig(): { url: string; anonKey: string } | null {
  const url = (process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL || '').replace(/\/+$/, '');
  const anonKey = process.env.SUPABASE_ANON_KEY || process.env.VITE_SUPABASE_ANON_KEY || '';
  if (!url || !anonKey) return null;
  return { url, anonKey };
}

function tokenPayload(token: string): Record<string, any> | null {
  try {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

// creator.id never changes for a given login, so remember it instead of asking the database each time.
// The email is remembered too, so a changed email is written through to the creator row once.
const creatorByUser = new Map<string, { id: string; email: string }>();

async function ensureCreator(userId: string, email: string, displayName: string): Promise<string> {
  const known = creatorByUser.get(userId);
  if (known && known.email === email) return known.id;

  const db = getDbPool();
  if (!db) throw new Error('Database not connected.');
  // First verified login creates the creator row; later logins find it by identity_id (never by email,
  // which people change and which Supabase may hand to someone else later) and keep its email current.
  const res = await db.query(
    `INSERT INTO creator (identity_id, display_name, email)
     VALUES ($1, $2, $3)
     ON CONFLICT (identity_id) DO UPDATE SET email = EXCLUDED.email, updated_at = now()
     RETURNING id`,
    [userId, displayName, email]
  );
  const id = res.rows[0].id as string;
  creatorByUser.set(userId, { id, email });
  return id;
}

export async function authenticate(req: Request, res: Response, next: NextFunction) {
  const config = getAuthConfig();
  if (!config) {
    return res.status(503).json({ error: 'Login is not configured on the server (SUPABASE_URL and SUPABASE_ANON_KEY are missing).' });
  }

  const header = req.get('authorization') || '';
  const match = /^Bearer\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/.exec(header);
  if (!match) {
    return res.status(401).json({ error: 'Sign in required.' });
  }
  const token = match[1];

  let user: any;
  try {
    const authRes = await fetch(`${config.url}/auth/v1/user`, {
      headers: { apikey: config.anonKey, Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(8000)
    });
    if (authRes.status === 401 || authRes.status === 403) {
      return res.status(401).json({ error: 'Your session is not valid. Sign in again.' });
    }
    if (!authRes.ok) {
      return res.status(503).json({ error: 'The login service could not check your session. Try again.' });
    }
    user = await authRes.json();
  } catch {
    // Fail closed: if we cannot confirm who this is, nobody gets in.
    return res.status(503).json({ error: 'The login service is unreachable. Try again.' });
  }

  const claims = tokenPayload(token);
  // Every real login token belongs to a session. A token without one was not issued by a sign-in.
  if (!user?.id || !claims || claims.sub !== user.id || typeof claims.session_id !== 'string' || !claims.session_id) {
    return res.status(401).json({ error: 'Your session is not valid. Sign in again.' });
  }

  if (claims.aal !== 'aal2') {
    return res.status(403).json({
      error: 'Multifactor authentication is required. Enter the code from your authenticator app.',
      required: 'aal2',
      current: claims.aal ?? 'unknown'
    });
  }

  // The email is how a creator is shown and contacted, so it must belong to this person.
  if (!user.email || !user.email_confirmed_at) {
    return res.status(403).json({
      error: 'Confirm your email address before using Custody Core.',
      required: 'confirmed_email'
    });
  }

  try {
    const email = String(user.email || '');
    const displayName = String(user.user_metadata?.full_name || user.user_metadata?.name || email.split('@')[0] || 'Creator');
    const id = await ensureCreator(user.id, email, displayName);
    res.locals.creator = { id, userId: user.id, email } satisfies AuthenticatedCreator;
    next();
  } catch (err: any) {
    console.error('[auth] could not load the creator record:', err?.message ?? err);
    return res.status(500).json({ error: 'Could not load your creator record.' });
  }
}

export function creatorOf(res: Response): AuthenticatedCreator {
  return res.locals.creator as AuthenticatedCreator;
}
