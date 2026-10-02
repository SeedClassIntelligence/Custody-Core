import { generateSync } from 'otplib';

/**
 * Helpers for tests that talk to a real Supabase Auth server (the local stack). Nothing here is
 * mocked: users are really created, factors really enrolled, and codes really verified.
 */
export function authStack(): { apiUrl: string; anonKey: string } {
  if (process.env.AUTH_STACK_ERROR) {
    throw new Error(`The local Supabase Auth stack is not available: ${process.env.AUTH_STACK_ERROR}`);
  }
  const apiUrl = process.env.AUTH_API_URL;
  const anonKey = process.env.AUTH_ANON_KEY;
  if (!apiUrl || !anonKey) throw new Error('AUTH_API_URL / AUTH_ANON_KEY are not set; the auth stack was not started.');
  return { apiUrl, anonKey };
}

export interface AuthSession {
  accessToken: string;
  refreshToken: string;
  userId: string;
  email: string;
  aal: 'aal1' | 'aal2';
}

export function tokenClaims(token: string): Record<string, any> {
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
}

async function call(path: string, init: { method?: string; token?: string; body?: unknown } = {}) {
  const { apiUrl, anonKey } = authStack();
  const res = await fetch(`${apiUrl}${path}`, {
    method: init.method ?? 'GET',
    headers: { 'Content-Type': 'application/json', apikey: anonKey, Authorization: `Bearer ${init.token ?? anonKey}` },
    body: init.body === undefined ? undefined : JSON.stringify(init.body)
  });
  const body: any = await res.json().catch(() => ({}));
  return { status: res.status, body };
}

function toSession(body: any, email: string): AuthSession {
  return {
    accessToken: body.access_token,
    refreshToken: body.refresh_token,
    userId: body.user.id,
    email,
    aal: tokenClaims(body.access_token).aal
  };
}

export function uniqueEmail(label: string): string {
  return `${label}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}@example.com`;
}

export const TEST_PASSWORD = 'Test-Passw0rd!-local';

/** Creates a user. The returned session is aal1 (password only). */
export async function signUp(email: string, password = TEST_PASSWORD): Promise<AuthSession> {
  const r = await call('/auth/v1/signup', { method: 'POST', body: { email, password } });
  if (r.status !== 200 || !r.body.access_token) throw new Error(`sign up failed (${r.status}): ${JSON.stringify(r.body)}`);
  return toSession(r.body, email);
}

/** Signs in with the password. The session is aal1 until a TOTP code is verified. */
export async function signIn(email: string, password = TEST_PASSWORD): Promise<AuthSession> {
  const r = await call('/auth/v1/token?grant_type=password', { method: 'POST', body: { email, password } });
  if (r.status !== 200) throw new Error(`sign in failed (${r.status}): ${JSON.stringify(r.body)}`);
  return toSession(r.body, email);
}

export interface EnrolledFactor {
  factorId: string;
  secret: string;
}

/** Starts TOTP enrollment. The factor stays unverified until a code is verified. */
export async function enrollTotp(session: AuthSession, name = 'authenticator'): Promise<EnrolledFactor> {
  const r = await call('/auth/v1/factors', {
    method: 'POST',
    token: session.accessToken,
    body: { factor_type: 'totp', friendly_name: `${name}-${Math.random().toString(36).slice(2, 7)}` }
  });
  if (r.status !== 200) throw new Error(`TOTP enrollment failed (${r.status}): ${JSON.stringify(r.body)}`);
  return { factorId: r.body.id, secret: r.body.totp.secret };
}

export function currentCode(secret: string): string {
  return generateSync({ secret });
}

/** Challenges a factor and verifies a code. Returns the raw result so tests can check refusals. */
export async function verifyTotp(session: AuthSession, factor: EnrolledFactor, code: string) {
  const challenge = await call(`/auth/v1/factors/${factor.factorId}/challenge`, { method: 'POST', token: session.accessToken, body: {} });
  if (challenge.status !== 200) throw new Error(`challenge failed (${challenge.status}): ${JSON.stringify(challenge.body)}`);
  const r = await call(`/auth/v1/factors/${factor.factorId}/verify`, {
    method: 'POST',
    token: session.accessToken,
    body: { challenge_id: challenge.body.id, code }
  });
  return { status: r.status, body: r.body, session: r.status === 200 ? toSession(r.body, session.email) : null };
}

/** Full happy path: sign up, enroll an authenticator, verify a real code. Returns an aal2 session. */
export async function createMfaUser(label: string): Promise<{ session: AuthSession; factor: EnrolledFactor; email: string }> {
  const email = uniqueEmail(label);
  const aal1 = await signUp(email);
  const factor = await enrollTotp(aal1);
  const verified = await verifyTotp(aal1, factor, currentCode(factor.secret));
  if (!verified.session) throw new Error(`TOTP verification failed (${verified.status}): ${JSON.stringify(verified.body)}`);
  return { session: verified.session, factor, email };
}

/** The auth server's own opinion of a token. */
export async function getUser(token: string) {
  return call('/auth/v1/user', { token });
}
