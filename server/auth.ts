import type { NextFunction, Request, Response } from 'express';
import { getDbPool } from './db';

/**
 * Login for the API. Identity comes only from a verified Supabase Auth session token, never from a
 * header, query parameter or body field the client chooses.
 *
 * Every request must carry `Authorization: Bearer <access token>`. The server asks Supabase Auth to
 * validate the token (signature, expiry, revocation), then checks the code step was passed on this server:
 *   - missing, malformed, invalid or expired token          -> 401
 *   - valid session, but the code step not passed here      -> 403
 *   - valid session that passed the code step on this server -> the request runs as that creator
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

export interface AuthenticatedSession {
  /** Supabase Auth user id */
  userId: string;
  email: string;
  /** Supabase session id: stays the same when the access token is refreshed */
  sessionId: string;
}

/**
 * Step 1: a real, current Supabase session (email and password) for a confirmed email address.
 * Enough to set up or enter the authenticator code, and nothing else.
 */
export async function authenticateSession(req: Request, res: Response, next: NextFunction) {
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

  // The email is how a creator is shown and contacted, so it must belong to this person.
  if (!user.email || !user.email_confirmed_at) {
    return res.status(403).json({
      error: 'Confirm your email address before using Custody Core.',
      required: 'confirmed_email'
    });
  }

  res.locals.session = { userId: user.id, email: String(user.email), sessionId: claims.session_id } satisfies AuthenticatedSession;
  res.locals.displayName = String(user.user_metadata?.full_name || user.user_metadata?.name || String(user.email).split('@')[0] || 'Creator');
  next();
}

/**
 * Step 2: this session has passed the authenticator-code step on THIS server (see server/mfa.ts).
 * Supabase's own multifactor result (the token's aal claim) is deliberately not trusted: Supabase's
 * code-check endpoint cannot be rate limited on every plan, so codes are checked only here.
 */
export async function requireSecondFactor(_req: Request, res: Response, next: NextFunction) {
  const session = res.locals.session as AuthenticatedSession;
  const db = getDbPool();
  if (!db) return res.status(503).json({ error: 'Database not connected.' });

  try {
    const passed = await db.query('SELECT 1 FROM mfa_session WHERE session_id = $1 AND identity_id = $2', [session.sessionId, session.userId]);
    if (passed.rowCount !== 1) {
      return res.status(403).json({
        error: 'Enter the code from your authenticator app.',
        required: 'second_factor'
      });
    }
    const id = await ensureCreator(session.userId, session.email, String(res.locals.displayName));
    res.locals.creator = { id, userId: session.userId, email: session.email } satisfies AuthenticatedCreator;
    next();
  } catch (err: any) {
    console.error('[auth] could not check the second factor or load the creator record:', err?.message ?? err);
    return res.status(500).json({ error: 'Could not load your creator record.' });
  }
}

/** A full login: real session, confirmed email, and the code step passed on this server. */
export const authenticate = [authenticateSession, requireSecondFactor];

export function sessionOf(res: Response): AuthenticatedSession {
  return res.locals.session as AuthenticatedSession;
}

export function creatorOf(res: Response): AuthenticatedCreator {
  return res.locals.creator as AuthenticatedCreator;
}
