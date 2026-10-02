import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { getAdminPool, runMigrations } from '../server/db';
import { assertPoolTargetsTestDb } from './support/safety';
import { withTriggersBypassed } from './support/cleanup';
import { api, startApp, RunningApp } from './support/api';
import {
  authStack, createMfaUser, mintToken, signOut, signUp, tokenClaims, uniqueEmail, withAuthDb, enrollTotp, currentCode, verifyTotp, TEST_PASSWORD
} from './support/authStack';

/**
 * The cases a lazy implementation gets wrong: failing OPEN when the login service is down, believing
 * identity the client chooses, trusting tokens the login service would not hand out, and locking people out.
 */
describe('Login hardening', () => {
  const adminDb = getAdminPool()!;
  let running: RunningApp;
  const userIds: string[] = [];
  const realUrl = () => authStack().apiUrl;

  beforeAll(async () => {
    authStack();
    await assertPoolTargetsTestDb(adminDb);
    const res = await runMigrations();
    if (!res.success) throw new Error(res.message);
    running = await startApp();
  });

  afterAll(async () => {
    await running.stop();
    await withTriggersBypassed(adminDb, async (admin) => {
      const creators = (await admin.query('SELECT id FROM creator WHERE identity_id = ANY($1::text[])', [userIds])).rows.map((r) => r.id);
      const projects = (await admin.query('SELECT id FROM project WHERE creator_id = ANY($1::uuid[])', [creators])).rows.map((r) => r.id);
      await admin.query('DELETE FROM event WHERE project_id = ANY($1::uuid[])', [projects]);
      await admin.query('DELETE FROM project WHERE id = ANY($1::uuid[])', [projects]);
      await admin.query('DELETE FROM creator WHERE id = ANY($1::uuid[])', [creators]);
    });
  });

  async function newCreator(label: string) {
    const made = await createMfaUser(label);
    userIds.push(made.session.userId);
    return made;
  }

  /** Runs `work` while the server believes the login service lives at `url` (and holds `key`). */
  async function withAuthService<T>(url: string, key: string, work: () => Promise<T>): Promise<T> {
    const saved = { a: process.env.SUPABASE_URL, b: process.env.SUPABASE_ANON_KEY, c: process.env.VITE_SUPABASE_URL, d: process.env.VITE_SUPABASE_ANON_KEY };
    process.env.SUPABASE_URL = url; process.env.VITE_SUPABASE_URL = url;
    process.env.SUPABASE_ANON_KEY = key; process.env.VITE_SUPABASE_ANON_KEY = key;
    try {
      return await work();
    } finally {
      process.env.SUPABASE_URL = saved.a; process.env.SUPABASE_ANON_KEY = saved.b;
      process.env.VITE_SUPABASE_URL = saved.c; process.env.VITE_SUPABASE_ANON_KEY = saved.d;
    }
  }

  async function fakeAuthServer(handler: http.RequestListener) {
    const server = http.createServer(handler);
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, close: () => { server.closeAllConnections(); return new Promise<void>((r) => server.close(() => r())); } };
  }

  // ------------------------------------------------------------ fail closed

  describe('fails closed: if the login service cannot confirm who this is, nobody gets in', () => {
    it('a valid aal2 token is refused (503, no data) while the login service is unreachable', async () => {
      const { session } = await newCreator('down');
      const dead = await fakeAuthServer((_q, r) => r.end());
      const url = dead.url;
      await dead.close(); // nothing listens there any more
      const r = await withAuthService(url, authStack().anonKey, () => api(running.base, session, '/projects'));
      expect(r.status).toBe(503);
      expect(r.body.projects).toBeUndefined();
    });

    it('a valid aal2 token is refused (503) when the login service answers with an error', async () => {
      const { session } = await newCreator('err500');
      const broken = await fakeAuthServer((_q, r) => { r.statusCode = 500; r.end('{"error":"boom"}'); });
      try {
        const r = await withAuthService(broken.url, authStack().anonKey, () => api(running.base, session, '/projects'));
        expect(r.status).toBe(503);
      } finally { await broken.close(); }
    });

    it('junk answers from the login service never let anyone in', async () => {
      const { session } = await newCreator('junk');
      const answers: Array<[string, string]> = [['{}', 'application/json'], ['null', 'application/json'], ['<html>ok</html>', 'text/html'], ['{"id":"someone-else"}', 'application/json'], ['', 'application/json']];
      for (const [body, type] of answers) {
        const srv = await fakeAuthServer((_q, r) => { r.setHeader('content-type', type); r.statusCode = 200; r.end(body); });
        try {
          const r = await withAuthService(srv.url, authStack().anonKey, () => api(running.base, session, '/projects'));
          expect([401, 503], `login service answered ${body.slice(0, 20)}`).toContain(r.status);
          expect(r.body.projects).toBeUndefined();
        } finally { await srv.close(); }
      }
    });

    it('a login service that never answers is given up on after about 8 seconds (503), not waited for forever', async () => {
      const { session } = await newCreator('hang');
      const hanging = await fakeAuthServer(() => { /* never respond */ });
      try {
        const started = Date.now();
        const r = await withAuthService(hanging.url, authStack().anonKey, () => api(running.base, session, '/projects'));
        const took = Date.now() - started;
        expect(r.status).toBe(503);
        expect(took).toBeGreaterThanOrEqual(7500);
        expect(took).toBeLessThan(15000);
      } finally { await hanging.close(); }
    }, 30_000);

    it('with login not configured on the server, every protected route is 503, even with no token', async () => {
      const { session } = await newCreator('unconf');
      for (const [url, key] of [['', ''], [realUrl(), ''], ['', authStack().anonKey]]) {
        for (const who of [session, null]) {
          const r = await withAuthService(url, key, () => api(running.base, who, '/projects'));
          expect(r.status).toBe(503);
        }
      }
      // /health stays open and the server stays up
      expect((await withAuthService('', '', () => api(running.base, null, '/health'))).status).toBe(200);
    });
  });

  // ------------------------------------------------------------ identity comes only from the session

  it('identity-looking headers, query parameters and body fields from the client change nothing', async () => {
    const alice = await newCreator('idA');
    const bob = await newCreator('idB');
    const aliceId = (await api(running.base, alice.session, '/me')).body.creator.id;
    const bobId = (await api(running.base, bob.session, '/me')).body.creator.id;
    expect(aliceId).not.toBe(bobId);

    const spoof = { 'x-user-id': bob.session.userId, 'x-creator-id': bobId, 'x-forwarded-user': bob.session.userId, 'x-supabase-user': bob.session.userId, 'x-auth-user': bobId };
    expect((await api(running.base, alice.session, '/me', { headers: spoof })).body.creator.id).toBe(aliceId);
    expect((await api(running.base, alice.session, `/me?user_id=${bob.session.userId}&creator_id=${bobId}`, { headers: spoof })).body.creator.id).toBe(aliceId);

    const claim = await api(running.base, alice.session, '/projects', {
      method: 'POST', headers: spoof,
      body: { name: 'Spoof test', purpose: 'p', creator_id: bobId, user_id: bob.session.userId, owner: bobId }
    });
    expect(claim.status).toBe(201);
    expect(claim.body.project.creator_id).toBe(aliceId);
  });

  it('the event recorded by a claim has its actor and chain fields set by the server, whatever the body says', async () => {
    const alice = await newCreator('actor');
    const bob = await newCreator('actorB');
    const aliceId = (await api(running.base, alice.session, '/me')).body.creator.id;
    const bobId = (await api(running.base, bob.session, '/me')).body.creator.id;
    const claim = await api(running.base, alice.session, '/projects', {
      method: 'POST',
      body: {
        name: 'Actor test', purpose: 'p', actor_id: bobId, actor_type: 'system', subject_id: 'forged', subject_type: 'door',
        action: 'door.opened', seq: 99, hash: 'f'.repeat(64), prev_hash: 'e'.repeat(64), hashed_timestamp: '2000-01-01T00:00:00.000Z', payload: { forged: true }
      }
    });
    expect(claim.status).toBe(201);
    const ev = claim.body.event;
    expect(ev.actor_id).toBe(aliceId);
    expect(ev.actor_type).toBe('creator');
    expect(ev.action).toBe('project.claimed');
    expect(ev.subject_id).toBe(claim.body.project.id);
    expect(ev.seq).toBe(1);
    expect(ev.hash).not.toBe('f'.repeat(64));
    expect(ev.hashed_timestamp).not.toBe('2000-01-01T00:00:00.000Z');
    expect(ev.payload.forged).toBeUndefined();
  });

  it('asking for someone else\'s project looks exactly like asking for one that does not exist: status, body and headers, on both routes', async () => {
    const alice = await newCreator('ghostA');
    const bob = await newCreator('ghostB');
    const bobProject = (await api(running.base, bob.session, '/projects', { method: 'POST', body: { name: 'Bob', purpose: 'p' } })).body.project.id;
    const missing = '00000000-0000-4000-8000-0000000000bb';
    const raw = async (id: string, suffix: string) => {
      const res = await fetch(`${running.base}/api/v1/projects/${id}${suffix}`, { headers: { Authorization: `Bearer ${alice.session.accessToken}` } });
      return { status: res.status, type: res.headers.get('content-type'), length: res.headers.get('content-length'), text: await res.text() };
    };
    for (const suffix of ['/events', '/events/verify']) {
      const foreign = await raw(bobProject, suffix);
      const absent = await raw(missing, suffix);
      expect(foreign.status).toBe(404);
      expect(foreign).toEqual(absent);
    }
  });

  // ------------------------------------------------------------ tokens the login service did not hand out

  it('a signed-out session no longer works', async () => {
    const { session } = await newCreator('signout');
    expect((await api(running.base, session, '/projects')).status).toBe(200);
    expect((await signOut(session)).status).toBeLessThan(300);
    expect((await api(running.base, session, '/projects')).status).toBe(401);
  });

  it('an expired token is 401 (even one signed with the right secret, for a real session)', async () => {
    const { session } = await newCreator('expired');
    const claims = tokenClaims(session.accessToken);
    const expired = mintToken({ ...claims, iat: claims.iat - 7200, exp: Math.floor(Date.now() / 1000) - 60 });
    expect((await api(running.base, { accessToken: expired }, '/projects')).status).toBe(401);
    // the same claims with a future expiry are accepted, so the 401 above is about expiry and nothing else
    const fresh = mintToken({ ...claims, exp: Math.floor(Date.now() / 1000) + 600 });
    expect((await api(running.base, { accessToken: fresh }, '/projects')).status).toBe(200);
  });

  it('a token that does not belong to any session is 401, even with aal2 and a real user id', async () => {
    const { session } = await newCreator('nosession');
    const claims = tokenClaims(session.accessToken);
    const { session_id: _dropped, ...withoutSession } = claims;
    const noSession = mintToken({ ...withoutSession, aal: 'aal2', amr: [{ method: 'totp', timestamp: claims.iat }] });
    expect((await api(running.base, { accessToken: noSession }, '/projects')).status).toBe(401);
    const bogusSession = mintToken({ ...claims, session_id: '00000000-0000-4000-8000-000000000000' });
    expect((await api(running.base, { accessToken: bogusSession }, '/projects')).status).toBe(401);
  });

  it('an account whose email is not confirmed is refused (403), and gets in once it is', async () => {
    const { session } = await newCreator('unconfirmed');
    await withAuthDb((c) => c.query('UPDATE auth.users SET email_confirmed_at = NULL WHERE id = $1', [session.userId]));
    const refused = await api(running.base, session, '/projects');
    expect(refused.status).toBe(403);
    expect(refused.body.required).toBe('confirmed_email');
    expect((await adminDb.query('SELECT COUNT(*)::int AS n FROM creator WHERE identity_id = $1', [session.userId])).rows[0].n).toBe(0);
    await withAuthDb((c) => c.query('UPDATE auth.users SET email_confirmed_at = now() WHERE id = $1', [session.userId]));
    expect((await api(running.base, session, '/projects')).status).toBe(200);
  });

  // ------------------------------------------------------------ people change and reuse email addresses

  it('when someone changes their email and another person takes the old address, nobody is locked out and the record follows the change', async () => {
    const first = await newCreator('reuseA');
    const oldEmail = first.email.toLowerCase(); // the login service stores addresses in lower case
    const firstCreator = (await api(running.base, first.session, '/me')).body.creator.id;
    expect((await adminDb.query('SELECT email FROM creator WHERE id = $1', [firstCreator])).rows[0].email).toBe(oldEmail);

    const newEmail = uniqueEmail('moved').toLowerCase();
    // What a confirmed email change updates in the login service: the user and its email identity.
    await withAuthDb(async (c) => {
      await c.query('UPDATE auth.users SET email = $2 WHERE id = $1', [first.session.userId, newEmail]);
      await c.query(
        `UPDATE auth.identities SET provider_id = $2, identity_data = identity_data || jsonb_build_object('email', $2::text)
          WHERE user_id = $1 AND provider = 'email'`,
        [first.session.userId, newEmail]
      );
    });

    // The first person has not used the app since, so their creator row still holds the OLD address.
    // A different person registers with that address, sets up their authenticator, and must get in.
    expect((await adminDb.query('SELECT email FROM creator WHERE id = $1', [firstCreator])).rows[0].email).toBe(oldEmail);
    const aal1 = await signUp(oldEmail);
    userIds.push(aal1.userId);
    const factor = await enrollTotp(aal1);
    const verified = await verifyTotp(aal1, factor, currentCode(factor.secret));
    expect(verified.session).not.toBeNull();
    const second = await api(running.base, verified.session!, '/me');
    expect(second.status).toBe(200);
    expect(second.body.creator.id).not.toBe(firstCreator);
    expect((await adminDb.query('SELECT identity_id FROM creator WHERE id = $1', [second.body.creator.id])).rows[0].identity_id).toBe(aal1.userId);

    // When the first person comes back, their record follows the change and is still theirs.
    expect((await api(running.base, first.session, '/me')).body.creator.id).toBe(firstCreator);
    expect((await adminDb.query('SELECT email FROM creator WHERE id = $1', [firstCreator])).rows[0].email).toBe(newEmail);
    void TEST_PASSWORD;
  });

  // ------------------------------------------------------------ input checks and error answers

  it('bad project input is a clear 400 and writes nothing', async () => {
    const { session } = await newCreator('input');
    const before = (await adminDb.query('SELECT COUNT(*)::int AS n FROM project')).rows[0].n;
    const bad: unknown[] = [
      { name: 'x', purpose: 'y', repositories: 'not a list' },
      { name: 'x', purpose: 'y', repositories: [null] },
      { name: 'x', purpose: 'y', repositories: [{ default_branch: 'main' }] },
      { name: 'x', purpose: 'y', repositories: [{ full_name: 42 }] },
      { name: 'x', purpose: 'y', repositories: Array.from({ length: 21 }, (_, i) => ({ full_name: `o/r${i}` })) },
      { name: 123, purpose: 'y' },
      { name: 'x', purpose: { text: 'y' } },
      { name: 'n'.repeat(201), purpose: 'y' },
      { name: 'x', purpose: 'p'.repeat(5001) }
    ];
    for (const body of bad) {
      const r = await api(running.base, session, '/projects', { method: 'POST', body });
      expect(r.status, JSON.stringify(body).slice(0, 80)).toBe(400);
    }
    expect((await adminDb.query('SELECT COUNT(*)::int AS n FROM project')).rows[0].n).toBe(before);
  });

  it('a request body that is not JSON gets a short 400, with no stack trace or file paths', async () => {
    const { session } = await newCreator('badjson');
    const res = await fetch(`${running.base}/api/v1/projects`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${session.accessToken}` },
      body: '{"name": '
    });
    const text = await res.text();
    expect(res.status).toBe(400);
    expect(JSON.parse(text).error).toBe('The request body is not valid JSON.');
    expect(text).not.toMatch(/\bat \S+\(|node_modules|\.ts:\d+|SyntaxError/);
  });
});
