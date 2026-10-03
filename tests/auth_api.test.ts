import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { getAdminPool, runMigrations } from '../server/db';
import { assertPoolTargetsTestDb } from './support/safety';
import { withTriggersBypassed } from './support/cleanup';
import { api, startApp, RunningApp } from './support/api';
import {
  authStack, createMfaUser, createSupabaseMfaUser, enrollCode, signIn, signUp, tokenClaims, uniqueEmail, codeAt, verifyCode, AuthSession
} from './support/authStack';

/**
 * Login on the API, tested against a real Supabase Auth server and a real database:
 * no token or a bad token is 401, a session that has not passed the code step ON THIS SERVER is 403,
 * a session that has gets in, and the logged-in creator, not the client, decides who owns what.
 */
describe('API login: 401 without a valid session, 403 without the code step, creator linked on first full login', () => {
  const adminDb = getAdminPool()!;
  let running: RunningApp;
  const userIds: string[] = [];

  beforeAll(async () => {
    authStack(); // fails with the reason if the stack is not available
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
      await admin.query('DELETE FROM repository WHERE project_id = ANY($1::uuid[])', [projects]);
      await admin.query('DELETE FROM project WHERE id = ANY($1::uuid[])', [projects]);
      await admin.query('DELETE FROM creator WHERE id = ANY($1::uuid[])', [creators]);
    });
  });

  async function newCreator(label: string) {
    const made = await createMfaUser(label, running.base);
    userIds.push(made.session.userId);
    return made;
  }

  const protectedRoutes: Array<[string, string, unknown?]> = [
    ['GET', '/me'],
    ['GET', '/projects'],
    ['POST', '/projects', { name: 'x', purpose: 'y' }],
    ['GET', '/projects/00000000-0000-4000-8000-000000000000/events'],
    ['GET', '/projects/00000000-0000-4000-8000-000000000000/events/verify'],
    ['GET', '/projects/not-a-uuid/events']
  ];

  it('/health is open to everyone', async () => {
    expect((await api(running.base, null, '/health')).status).toBe(200);
  });

  it.each(protectedRoutes)('%s %s with no token is 401', async (method, path, body) => {
    const r = await api(running.base, null, path, { method, body });
    expect(r.status).toBe(401);
    expect(r.body.error).toBeTruthy();
  });

  it('malformed, garbage, forged and wrong-scheme credentials are all 401', async () => {
    const { session } = await newCreator('forge');
    const [h, p, s] = session.accessToken.split('.');
    const forgedPayload = Buffer.from(JSON.stringify({ ...tokenClaims(session.accessToken), sub: '00000000-0000-0000-0000-000000000000' })).toString('base64url');
    const attempts: Array<Record<string, string>> = [
      { Authorization: 'Bearer garbage' },
      { Authorization: 'Bearer a.b.c' },
      { Authorization: `Bearer ${h}.${forgedPayload}.${s}` }, // payload edited, signature no longer matches
      { Authorization: `Bearer ${h}.${p}.` },
      { Authorization: `Basic ${session.accessToken}` },
      { Authorization: session.accessToken }, // no scheme
      { Authorization: '' },
      { 'x-creator-id': '00000000-0000-0000-0000-000000000000' } // the old, client-chosen identity
    ];
    for (const headers of attempts) {
      const r = await api(running.base, null, '/projects', { headers });
      expect(r.status, JSON.stringify(headers).slice(0, 80)).toBe(401);
    }
    // A client-supplied creator in the URL or body never works as a credential either.
    expect((await api(running.base, null, `/projects?creator_id=${session.userId}`)).status).toBe(401);
    expect((await api(running.base, null, '/projects', { method: 'POST', body: { name: 'x', purpose: 'y', creator_id: session.userId } })).status).toBe(401);
  });

  it('a password-only session is 403 on every protected route, for a user who has no authenticator yet', async () => {
    const pw = await signUp(uniqueEmail('pwonly'));
    userIds.push(pw.userId);
    for (const [method, path, body] of protectedRoutes) {
      const r = await api(running.base, pw, path, { method, body });
      expect(r.status, `${method} ${path}`).toBe(403);
      expect(r.body.required).toBe('second_factor');
    }
  });

  it("Supabase's own multifactor result (an aal2 token) does NOT get in: codes count only when checked by this server", async () => {
    const viaSupabase = await createSupabaseMfaUser('supabase-aal2');
    userIds.push(viaSupabase.session.userId);
    expect(tokenClaims(viaSupabase.session.accessToken).aal).toBe('aal2');
    for (const [method, path, body] of protectedRoutes) {
      const r = await api(running.base, viaSupabase.session, path, { method, body });
      expect(r.status, `${method} ${path}`).toBe(403);
      expect(r.body.required).toBe('second_factor');
    }
  });

  it('a password-only session is 403 even for a user who has already set up the code step, and a half-finished setup does not count', async () => {
    const { email, session } = await newCreator('pwagain');
    const again = await signIn(email);
    expect((await api(running.base, again, '/projects')).status).toBe(403);

    // Set up but never confirmed with a code: still no access.
    const half = await signUp(uniqueEmail('half'));
    userIds.push(half.userId);
    await enrollCode(running.base, half);
    expect((await api(running.base, half, '/projects')).status).toBe(403);

    // The session that passed the code step does work.
    expect((await api(running.base, session, '/projects')).status).toBe(200);
  });

  it('a wrong authenticator code does not open the API', async () => {
    const pw = await signUp(uniqueEmail('wrong'));
    userIds.push(pw.userId);
    const { secret } = await enrollCode(running.base, pw);
    const right = codeAt(secret);
    const wrong = right === '000000' ? '000001' : '000000';
    const r = await verifyCode(running.base, pw, wrong);
    expect(r.status).toBe(422);
    expect((await api(running.base, pw, '/projects')).status).toBe(403);
  });

  it('passing the code step in one session does not unlock another session of the same person', async () => {
    const { email, session } = await newCreator('persession');
    expect((await api(running.base, session, '/projects')).status).toBe(200);
    const other = await signIn(email);
    expect((await api(running.base, other, '/projects')).status).toBe(403);
  });

  it('no creator row is created for a session that has not passed the code step', async () => {
    const pw = await signUp(uniqueEmail('nocreator'));
    userIds.push(pw.userId);
    await api(running.base, pw, '/projects');
    await api(running.base, pw, '/projects', { method: 'POST', body: { name: 'x', purpose: 'y' } });
    const n = (await adminDb.query('SELECT COUNT(*)::int AS n FROM creator WHERE identity_id = $1', [pw.userId])).rows[0].n;
    expect(n).toBe(0);
  });

  it('the first verified login creates the creator row linked to the Supabase user; later logins reuse it', async () => {
    // newCreator signs up and passes the code step: that first verified login creates the row (and records the
    // setup with that creator as actor). A login that has not passed the code step gets none (tested below).
    const { session, email } = await newCreator('first');
    expect((await adminDb.query('SELECT COUNT(*)::int AS n FROM creator WHERE identity_id = $1', [session.userId])).rows[0].n).toBe(1);

    const me = await api(running.base, session, '/me');
    expect(me.status).toBe(200);
    const row = (await adminDb.query('SELECT id, identity_id, email FROM creator WHERE identity_id = $1', [session.userId])).rows;
    expect(row).toHaveLength(1);
    expect(row[0].id).toBe(me.body.creator.id);
    expect(row[0].email).toBe(email);

    // A brand-new verified session for the same person (sign in, verify again) maps to the same creator.
    const second = await api(running.base, session, '/me');
    expect(second.body.creator.id).toBe(me.body.creator.id);
    expect((await adminDb.query('SELECT COUNT(*)::int AS n FROM creator WHERE identity_id = $1', [session.userId])).rows[0].n).toBe(1);
  });

  it('claiming a project: the logged-in creator owns it and is the actor of the event, whatever the body says', async () => {
    const alice = await newCreator('claimA');
    const bob = await newCreator('claimB');
    const bobCreatorId = (await api(running.base, bob.session, '/me')).body.creator.id;
    const aliceCreatorId = (await api(running.base, alice.session, '/me')).body.creator.id;

    // Alice tries to file the project under Bob by naming him in the body.
    const claim = await api(running.base, alice.session, '/projects', {
      method: 'POST',
      body: { name: 'Alice project', purpose: 'Owned by whoever is logged in', creator_id: bobCreatorId }
    });
    expect(claim.status).toBe(201);
    expect(claim.body.project.creator_id).toBe(aliceCreatorId);
    expect(claim.body.event.actor_id).toBe(aliceCreatorId);
    expect(claim.body.event.actor_type).toBe('creator');

    const bobs = await api(running.base, bob.session, '/projects');
    expect(bobs.body.projects.map((p: any) => p.id)).not.toContain(claim.body.project.id);
  });

  it('there is no default creator: claiming never invents one', async () => {
    const before = (await adminDb.query(`SELECT COUNT(*)::int AS n FROM creator WHERE identity_id = 'default_creator' OR email = 'creator@custodycore.internal'`)).rows[0].n;
    const { session } = await newCreator('nodefault');
    const claim = await api(running.base, session, '/projects', { method: 'POST', body: { name: 'P', purpose: 'Q' } });
    expect(claim.status).toBe(201);
    const after = (await adminDb.query(`SELECT COUNT(*)::int AS n FROM creator WHERE identity_id = 'default_creator' OR email = 'creator@custodycore.internal'`)).rows[0].n;
    expect(after).toBe(before);
    const owner = (await adminDb.query('SELECT identity_id FROM creator WHERE id = $1', [claim.body.project.creator_id])).rows[0];
    expect(owner.identity_id).toBe(session.userId);
  });

  it('a project id that is not a UUID is 404 for a logged-in creator, 401 for everyone else', async () => {
    const { session } = await newCreator('badid');
    for (const id of ['not-a-uuid', '123', "1'%20OR%20'1'='1"]) {
      expect((await api(running.base, session, `/projects/${id}/events`)).status).toBe(404);
      expect((await api(running.base, session, `/projects/${id}/events/verify`)).status).toBe(404);
      expect((await api(running.base, null, `/projects/${id}/events`)).status).toBe(401);
    }
  });
});
