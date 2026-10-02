import { createHmac } from 'node:crypto';
import pg from 'pg';
import { generateSync } from 'otplib';

/**
 * Helpers for tests that talk to a real Supabase Auth server (the local stack). Nothing here is
 * mocked: users are really created, factors really enrolled, and codes really verified.
 */
export function authStack(): { apiUrl: string; anonKey: string; jwtSecret: string; dbUrl: string } {
  if (process.env.AUTH_STACK_ERROR) {
    throw new Error(`The local Supabase Auth stack is not available: ${process.env.AUTH_STACK_ERROR}`);
  }
  const apiUrl = process.env.AUTH_API_URL;
  const anonKey = process.env.AUTH_ANON_KEY;
  if (!apiUrl || !anonKey) throw new Error('AUTH_API_URL / AUTH_ANON_KEY are not set; the auth stack was not started.');
  return { apiUrl, anonKey, jwtSecret: process.env.AUTH_JWT_SECRET ?? '', dbUrl: process.env.AUTH_DB_URL ?? '' };
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

/** Supabase's OWN authenticator enrollment (no longer used by the app; kept to prove it grants nothing). */
export async function supabaseEnrollTotp(session: AuthSession, name = 'authenticator'): Promise<EnrolledFactor> {
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

/** Supabase's OWN code check (no longer used by the app). Returns the raw result. */
export async function supabaseVerifyTotp(session: AuthSession, factor: EnrolledFactor, code: string) {
  const challenge = await call(`/auth/v1/factors/${factor.factorId}/challenge`, { method: 'POST', token: session.accessToken, body: {} });
  if (challenge.status !== 200) throw new Error(`challenge failed (${challenge.status}): ${JSON.stringify(challenge.body)}`);
  const r = await call(`/auth/v1/factors/${factor.factorId}/verify`, {
    method: 'POST',
    token: session.accessToken,
    body: { challenge_id: challenge.body.id, code }
  });
  return { status: r.status, body: r.body, session: r.status === 200 ? toSession(r.body, session.email) : null };
}

/** Supabase's own multifactor flow to aal2. The app ignores it; tests use it to prove that. */
export async function createSupabaseMfaUser(label: string): Promise<{ session: AuthSession; factor: EnrolledFactor; email: string }> {
  const email = uniqueEmail(label);
  const aal1 = await signUp(email);
  const factor = await supabaseEnrollTotp(aal1);
  const verified = await supabaseVerifyTotp(aal1, factor, currentCode(factor.secret));
  if (!verified.session) throw new Error(`TOTP verification failed (${verified.status}): ${JSON.stringify(verified.body)}`);
  return { session: verified.session, factor, email };
}

// ------------------------------------------------------------------ Custody Core's own code step

/** A code for `secret` at the current time step plus `stepOffset`, computed by otplib (independent of server/totp.ts). */
export function codeAt(secret: string, stepOffset = 0): string {
  return generateSync({ secret, epoch: Math.floor(Date.now() / 1000) + stepOffset * 30 });
}

async function appCall(base: string, session: { accessToken: string } | null, path: string, body?: unknown) {
  const res = await fetch(`${base}/api/v1${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { 'Content-Type': 'application/json', ...(session ? { Authorization: `Bearer ${session.accessToken}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  return { status: res.status, body: (await res.json().catch(() => ({}))) as any, headers: res.headers };
}

/** Starts setting up an authenticator on the Custody Core server. Returns the key the app would show. */
export async function enrollCode(base: string, session: AuthSession): Promise<{ secret: string; factorId: string; otpauthUri: string }> {
  const r = await appCall(base, session, '/mfa/enroll', {});
  if (r.status !== 201) throw new Error(`enroll failed (${r.status}): ${JSON.stringify(r.body)}`);
  return { secret: r.body.secret, factorId: r.body.factor_id, otpauthUri: r.body.otpauth_uri };
}

/** Sends a code to the Custody Core server. Returns the raw answer so tests can check refusals. */
export function verifyCode(base: string, session: { accessToken: string }, code: string) {
  return appCall(base, session, '/mfa/verify', { code });
}

export function mfaStatus(base: string, session: { accessToken: string }) {
  return appCall(base, session, '/mfa/status');
}

/** Full login the way the app does it: sign up, set up the authenticator on our server, enter a real code. */
export async function createMfaUser(label: string, base: string): Promise<{ session: AuthSession; secret: string; email: string }> {
  const email = uniqueEmail(label);
  const session = await signUp(email);
  const { secret } = await enrollCode(base, session);
  const r = await verifyCode(base, session, codeAt(secret));
  if (r.status !== 200) throw new Error(`code step failed (${r.status}): ${JSON.stringify(r.body)}`);
  return { session, secret, email };
}

/** Signs in again with the password and passes the code step with the NEXT code (the current one may be used). */
export async function signInWithCode(base: string, email: string, secret: string): Promise<AuthSession> {
  const session = await signIn(email);
  const r = await verifyCode(base, session, codeAt(secret, 1));
  if (r.status !== 200) throw new Error(`code step failed (${r.status}): ${JSON.stringify(r.body)}`);
  return session;
}

/** The auth server's own opinion of a token. */
export async function getUser(token: string) {
  return call('/auth/v1/user', { token });
}

const b64 = (value: object | Buffer) => Buffer.from(value instanceof Buffer ? value : JSON.stringify(value)).toString('base64url');

/** Signs a token with the local stack's secret, to test how the server treats tokens it did not hand out itself. */
export function mintToken(claims: Record<string, unknown>, header: Record<string, unknown> = { alg: 'HS256', typ: 'JWT' }): string {
  const { jwtSecret } = authStack();
  const signingInput = `${b64(header)}.${b64(claims)}`;
  return `${signingInput}.${b64(createHmac('sha256', jwtSecret).update(signingInput).digest())}`;
}

/** Runs `work` against the local stack's own database (its auth tables), to set up states a real flow cannot reach. */
export async function withAuthDb<T>(work: (client: pg.Client) => Promise<T>): Promise<T> {
  const client = new pg.Client({ connectionString: authStack().dbUrl });
  await client.connect();
  try {
    return await work(client);
  } finally {
    await client.end();
  }
}

/** Ends a session on the auth server (what Sign out does). */
export async function signOut(session: AuthSession) {
  return call('/auth/v1/logout?scope=global', { method: 'POST', token: session.accessToken, body: {} });
}
