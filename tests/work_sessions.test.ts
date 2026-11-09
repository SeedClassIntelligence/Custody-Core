import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getAdminPool, getDbPool, runMigrations, verifyServerProjectEvents } from '../server/db';
import { addPrincipalKey, registerPrincipal } from '../server/servicePrincipals';
import { MAX_PENDING_PER_PRINCIPAL, expireOverdueSessions } from '../server/workSessions';
import { closeOverdueDoors } from '../server/scheduler';
import { assertPoolTargetsTestDb } from './support/safety';
import { withTriggersBypassed } from './support/cleanup';
import { startHarness, Harness } from './support/apiHarness';
import { startApp, RunningApp } from './support/api';
import { acceptSignAndGetCredential } from './support/developerFlow';
import { assertion, newKey, TestKey } from './support/principalKeys';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/**
 * Universal work sessions (CL-09) and the guarantee that human doors are untouched (CL-20): the door tests
 * (developer_signing, git_gateway, scheduler) run unchanged next to this file. Real database, real HTTP for machine
 * callers (the real app), the real creator routes behind the test login step.
 */
describe('Work sessions', () => {
  const db = getDbPool()!;
  const admin = getAdminPool()!;
  let h: Harness;
  let app: RunningApp;
  let creator: any, other: any, dev: any;
  let projectId = '', projectId2 = '', otherProjectId = '';
  let repoId = '', repoId2 = '', otherRepoId = '';

  interface Caller { id: string; keyId: string; key: TestKey }
  const callers: Record<string, Caller> = {};
  async function caller(label: string, scopes: string[], over: Record<string, unknown> = {}, who = creator): Promise<Caller> {
    const p = await registerPrincipal(db, who.id, { name: `${label}-${crypto.randomUUID().slice(0, 6)}`, platform_type: 'agent', environment: 'development', allowed_scopes: scopes, ...over } as any, 'test');
    const key = newKey('Ed25519');
    return (callers[label] = { id: p.id, keyId: (await addPrincipalKey(db, p.id, key.publicJwk, 'test')).key_id, key });
  }
  const v2 = async (c: Caller | null, method: string, p: string, body?: unknown) => {
    const res = await fetch(`${app.base}/api/v2${p}`, {
      method,
      headers: { ...(c ? { Authorization: `Bearer ${assertion(c.key, c.keyId, c.id)}` } : {}), ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    return { status: res.status, body: await res.json().catch(() => ({})) };
  };
  const v1 = (who: any, method: string, p: string, body?: unknown) => h.api(who, method, p, body);

  const baseRequest = (over: Record<string, unknown> = {}) => ({
    project_id: projectId,
    repository_id: repoId,
    executor: { type: 'ai_assistant', provider: 'example-ai', model: 'model-1', external_id: 'agent_99', display_name: 'Refactor Engine' },
    sponsor: { type: 'creator', id: creator.id },
    objective: 'Harden the authorization routes',
    base_commit: 'a'.repeat(40),
    access: { repository: 'read_and_push', allowed_read_paths: ['server/**', 'shared/**'], allowed_write_paths: ['server/gateway/**'], prohibited_paths: ['server/migrations/**', '.env*'] },
    expires_in_seconds: 3600,
    ...over
  });
  const access = (over: Record<string, unknown>) => ({ ...baseRequest().access, ...over });
  const sessionRow = async (id: string) => (await db.query('SELECT * FROM work_session WHERE id = $1', [id])).rows[0];
  const events = async (pid = projectId) => (await db.query('SELECT action, actor_type, actor_id, subject_id, payload, hash FROM event WHERE project_id = $1 ORDER BY seq', [pid])).rows;
  const sessionCount = async () => (await db.query('SELECT count(*)::int AS n FROM work_session WHERE session_type = $1', ['automated_work_session'])).rows[0].n;
  let requester: Caller, reader: Caller, approver: Caller;

  async function request(c = requester, over: Record<string, unknown> = {}) {
    const r = await v2(c, 'POST', '/work-sessions', baseRequest(over));
    expect(r.status, JSON.stringify(r.body)).toBe(202);
    return r.body.session_id as string;
  }

  beforeAll(async () => {
    await assertPoolTargetsTestDb(admin);
    expect((await runMigrations()).success).toBe(true);
    h = await startHarness();
    app = await startApp();
    creator = await h.newCreator('owner');
    other = await h.newCreator('other');
    dev = await h.newCreator('dana');
    await db.query(`INSERT INTO github_installation (creator_id, installation_id, account_login, account_type, connected_by_github_login) VALUES ($1, 11, 'org', 'Organization', 'octo')`, [creator.id]);
    const project = async (c: any, name: string) => (await db.query(`INSERT INTO project (creator_id, name, purpose) VALUES ($1, $2, 'x') RETURNING id`, [c.id, name])).rows[0].id as string;
    const repo = async (pid: string, n: string) => (await db.query(`INSERT INTO repository (project_id, github_repo_id, full_name) VALUES ($1, $2, $3) RETURNING id`, [pid, n, `org/${n}`])).rows[0].id as string;
    projectId = await project(creator, 'P1');
    projectId2 = await project(creator, 'P2');
    otherProjectId = await project(other, 'Q1');
    repoId = await repo(projectId, 'app');
    repoId2 = await repo(projectId2, 'lib');
    otherRepoId = await repo(otherProjectId, 'theirs');
    requester = await caller('requester', ['work-sessions:request', 'work-sessions:read', 'work-sessions:close-own']);
    reader = await caller('reader', ['work-sessions:request', 'work-sessions:read']);
    approver = await caller('approver', ['work-sessions:approve', 'work-sessions:read']);
  });
  afterAll(async () => {
    await app?.stop();
    await h?.stop();
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('human doors are sessions too, and doors themselves are untouched (CL-20)', () => {
    let doorId = '';
    let sessionOf = async (id: string) => (await db.query('SELECT * FROM work_session WHERE door_id = $1', [id])).rows[0];

    it('creating a door creates its session: same project, sponsor, objective and end date; human executor; no repository, commit or branch of its own', async () => {
      const expires = new Date(Date.now() + 5 * 86400_000).toISOString();
      const r = await v1(creator, 'POST', `/projects/${projectId}/doors`, {
        developer_email: `dana_${Date.now()}@example.com`, job_description: 'Build the export page', rights_type: 'contribute', expires_at: expires,
        repositories: [{ repository_id: repoId, access: 'write' }]
      });
      expect(r.status).toBe(201);
      doorId = r.body.door.id;
      const s = await sessionOf(doorId);
      expect(s).toMatchObject({ project_id: projectId, session_type: 'human_door', executor_type: 'human_developer', sponsor_id: creator.id, objective: 'Build the export page', status: 'requested' });
      expect(new Date(s.expires_at).toISOString()).toBe(new Date(expires).toISOString());
      expect(s.repository_id).toBeNull();
      expect(s.base_commit).toBeNull();
      expect(s.branch_name).toBeNull();
      expect(s.requested_by_principal_id).toBeNull();
    });

    it('the session follows the door through invitation, signing, opening and closing', async () => {
      const dana = { ...dev, email: (await db.query('SELECT developer_email FROM door WHERE id = $1', [doorId])).rows[0].developer_email };
      await db.query('UPDATE creator SET email = $2 WHERE id = $1', [dev.id, dana.email]);
      const invite = await v1(creator, 'POST', `/projects/${projectId}/doors/${doorId}/invite`);
      expect(invite.status).toBe(200);
      expect((await sessionOf(doorId)).status).toBe('approved'); // awaiting_signature
      await acceptSignAndGetCredential((w, m, p, b) => v1(w, m, p, b), dana, invite.body.invite.url);
      expect((await sessionOf(doorId)).status).toBe('active'); // open
      expect((await v1(creator, 'POST', `/projects/${projectId}/doors/${doorId}/close`)).status).toBe(200);
      const closed = await sessionOf(doorId);
      expect(closed.status).toBe('closed');
      expect(closed.closed_reason).toBe('creator_manual');
      expect(closed.closed_at).toBeTruthy();
    });

    it('a door that reaches its end date is closed by the scheduler, and its session shows expired', async () => {
      const r = await v1(creator, 'POST', `/projects/${projectId}/doors`, {
        developer_email: 'late@example.com', job_description: 'Late', rights_type: 'contribute', expires_at: new Date(Date.now() + 86400_000).toISOString(),
        repositories: [{ repository_id: repoId, access: 'read' }]
      });
      const id = r.body.door.id;
      await withTriggersBypassed(admin, async (c) => {
        await c.query(`UPDATE door SET expires_at = now() - interval '1 minute', created_at = now() - interval '2 days' WHERE id = $1`, [id]);
      });
      expect(await closeOverdueDoors(db)).toContain(id);
      expect(await sessionOf(id)).toMatchObject({ status: 'expired', closed_reason: 'expired' });
    });

    it('the status mapping covers every door status', async () => {
      const m = async (s: string, reason: string | null = null) => (await db.query('SELECT work_session_status_for_door($1, $2) AS s', [s, reason])).rows[0].s;
      expect([await m('draft'), await m('awaiting_signature'), await m('opening'), await m('open'), await m('closing')]).toEqual(['requested', 'approved', 'provisioning', 'active', 'active']);
      expect([await m('closed', 'expired'), await m('closed', 'creator_manual'), await m('closed'), await m('failed')]).toEqual(['expired', 'closed', 'closed', 'closed']);
    });

    it('a door that already existed before the migration gets its session from the migration\'s own backfill statement', async () => {
      const r = await v1(creator, 'POST', `/projects/${projectId}/doors`, {
        developer_email: 'old@example.com', job_description: 'Predates sessions', rights_type: 'contribute', expires_at: new Date(Date.now() + 86400_000).toISOString(),
        repositories: [{ repository_id: repoId, access: 'read' }]
      });
      const id = r.body.door.id;
      // Put the database back in the state it was in before this migration: a door with no session.
      await withTriggersBypassed(admin, async (c) => {
        await c.query('DELETE FROM work_session WHERE door_id = $1', [id]);
      });
      expect(await sessionOf(id)).toBeUndefined();
      const sql = fs.readFileSync(path.join(root, 'server', 'migrations', '012_universal_work_sessions.sql'), 'utf8');
      const backfill = sql.slice(sql.indexOf('INSERT INTO work_session', sql.indexOf('Every door that already exists')));
      await admin.query(backfill.replace(/;\s*$/, ' ON CONFLICT (door_id) DO NOTHING;'));
      expect(await sessionOf(id)).toMatchObject({ session_type: 'human_door', status: 'requested', objective: 'Predates sessions', sponsor_id: creator.id });
      // and the backfill wrote no events
      expect((await events()).filter((e) => e.subject_id === id && String(e.action).startsWith('work_session.'))).toHaveLength(0);
    });

    it('human sessions are never visible to machine callers, even by id, even to an approver', async () => {
      const sid = (await sessionOf(doorId)).id;
      for (const c of [requester, approver]) expect((await v2(c, 'GET', `/work-sessions/${sid}`)).status).toBe(404);
      const listed = await v2(approver, 'GET', '/work-sessions');
      expect(listed.body.work_sessions.every((s: any) => s.session_type === 'automated_work_session')).toBe(true);
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('requesting an automated session', () => {
    it('is accepted as "requested", needs approval, and gets a branch prefix of its own', async () => {
      const before = (await events()).length;
      const r = await v2(requester, 'POST', '/work-sessions', baseRequest());
      expect(r.status).toBe(202);
      expect(r.body).toMatchObject({ status: 'requested', requires_approval: true, sponsor_id: creator.id });
      expect(r.body.branch_prefix).toBe(`session/${r.body.session_id}/`);
      expect(new Date(r.body.expires_at).getTime()).toBeGreaterThan(Date.now() + 3500_000);
      expect(new Date(r.body.expires_at).getTime()).toBeLessThan(Date.now() + 3700_000);

      const s = await sessionRow(r.body.session_id);
      expect(s).toMatchObject({
        project_id: projectId, repository_id: repoId, session_type: 'automated_work_session', requested_by_principal_id: requester.id,
        executor_type: 'ai_assistant', executor_provider: 'example-ai', executor_model: 'model-1', executor_external_id: 'agent_99', executor_display_name: 'Refactor Engine',
        sponsor_id: creator.id, objective: 'Harden the authorization routes', base_commit: 'a'.repeat(40), repository_access: 'read_and_push', status: 'requested',
        approved_at: null, approved_by: null, closed_at: null
      });
      expect(s.branch_name).toBe(`session/${s.id}/work`);
      expect(s.allowed_write_paths).toEqual(['server/gateway/**']);
      expect(s.prohibited_paths.sort()).toEqual(['.env*', 'server/migrations/**']);

      const ev = (await events()).slice(before);
      expect(ev).toHaveLength(1);
      expect(ev[0]).toMatchObject({ action: 'work_session.requested', actor_type: 'system', actor_id: `principal:${requester.id}`, subject_id: s.id });
      expect(ev[0].hash).toBe(r.body.event_hash);
      expect(ev[0].payload).toMatchObject({ principal_id: requester.id, repository_id: repoId, base_commit: 'a'.repeat(40), allowed_write_paths: ['server/gateway/**'] });
    });

    it('read-only access, shorter lifetimes and optional fields work', async () => {
      const r = await v2(requester, 'POST', '/work-sessions', baseRequest({
        access: { repository: 'read', allowed_read_paths: ['docs/**'] }, expires_in_seconds: 60,
        executor: { type: 'ci_runtime' }, objective: '  Check the docs  '
      }));
      expect(r.status, JSON.stringify(r.body)).toBe(202);
      const s = await sessionRow(r.body.session_id);
      expect(s).toMatchObject({ repository_access: 'read', objective: 'Check the docs', executor_type: 'ci_runtime', executor_provider: null });
      expect(s.allowed_write_paths).toEqual([]);
    });

    it('refuses what is not a valid request, naming the problem, and writes nothing', async () => {
      const n = await sessionCount();
      const ev = (await events()).length;
      const bad: Array<[string, unknown, RegExp]> = [
        ['not an object', [1], /JSON object/],
        ['unknown field', { ...baseRequest(), priority: 1 }, /Unknown field/],
        ['context not accepted yet', baseRequest({ external_context: { namespace: 'com.example', context: {} } }), /external_context is not accepted yet/],
        ['evidence not accepted yet', baseRequest({ evidence_requirements: [] }), /evidence_requirements is not accepted yet/],
        ['project id', baseRequest({ project_id: 'nope' }), /project_id/],
        ['repository id', baseRequest({ repository_id: 5 }), /repository_id/],
        ['no executor', baseRequest({ executor: undefined }), /executor is required/],
        ['human executor', baseRequest({ executor: { type: 'human_developer' } }), /executor.type/],
        ['executor extra', baseRequest({ executor: { type: 'ai_assistant', secret: 'x' } }), /Unknown executor/],
        ['executor long', baseRequest({ executor: { type: 'ai_assistant', model: 'x'.repeat(201) } }), /executor.model/],
        ['sponsor type', baseRequest({ sponsor: { type: 'organization_member', id: creator.id } }), /sponsor/],
        ['sponsor id', baseRequest({ sponsor: { type: 'creator', id: 'me' } }), /sponsor/],
        ['no objective', baseRequest({ objective: '   ' }), /objective/],
        ['long objective', baseRequest({ objective: 'x'.repeat(2001) }), /objective/],
        ['short commit', baseRequest({ base_commit: 'abc123' }), /base_commit/],
        ['uppercase commit', baseRequest({ base_commit: 'A'.repeat(40) }), /base_commit/],
        ['no access', baseRequest({ access: undefined }), /access is required/],
        ['access mode', baseRequest({ access: access({ repository: 'admin' }) }), /access.repository/],
        ['access extra', baseRequest({ access: access({ network: true }) }), /Unknown access/],
        ['no read paths', baseRequest({ access: access({ allowed_read_paths: [] }) }), /at least one path/],
        ['read paths missing', baseRequest({ access: access({ allowed_read_paths: undefined }) }), /required/],
        ['push without write paths', baseRequest({ access: access({ allowed_write_paths: [] }) }), /needs access.allowed_write_paths/],
        ['read with write paths', baseRequest({ access: { repository: 'read', allowed_read_paths: ['a'], allowed_write_paths: ['b'] } }), /must be empty/],
        ['parent path', baseRequest({ access: access({ allowed_read_paths: ['a/../../etc'] }) }), /\.\./],
        ['absolute path', baseRequest({ access: access({ allowed_read_paths: ['/etc/passwd'] }) }), /cannot start with/],
        ['home path', baseRequest({ access: access({ allowed_read_paths: ['~/x'] }) }), /cannot start with/],
        ['backslash path', baseRequest({ access: access({ allowed_read_paths: ['a\\b'] }) }), /backslash/],
        ['control character', baseRequest({ access: access({ allowed_read_paths: ['a\u0000b'] }) }), /control character/],
        ['empty segment', baseRequest({ access: access({ allowed_read_paths: ['a//b'] }) }), /empty or \. segments/],
        ['dot segment', baseRequest({ access: access({ allowed_read_paths: ['./a'] }) }), /empty or \. segments/],
        ['long path', baseRequest({ access: access({ allowed_read_paths: ['x'.repeat(201)] }) }), /longer than/],
        ['path not text', baseRequest({ access: access({ allowed_read_paths: [5] }) }), /non-empty text/],
        ['too many paths', baseRequest({ access: access({ allowed_read_paths: Array.from({ length: 51 }, (_, i) => `p${i}`) }) }), /at most 50/],
        ['prohibited bad', baseRequest({ access: access({ prohibited_paths: ['../x'] }) }), /prohibited_paths/],
        ['ttl too short', baseRequest({ expires_in_seconds: 59 }), /expires_in_seconds/],
        ['ttl too long', baseRequest({ expires_in_seconds: 86401 }), /expires_in_seconds/],
        ['ttl fraction', baseRequest({ expires_in_seconds: 90.5 }), /expires_in_seconds/],
        ['ttl text', baseRequest({ expires_in_seconds: '3600' }), /expires_in_seconds/]
      ];
      for (const [label, body, why] of bad) {
        const r = await v2(requester, 'POST', '/work-sessions', body);
        expect(r.status, label).toBe(400);
        expect(r.body.error, label).toMatch(why);
      }
      expect(await sessionCount()).toBe(n);
      expect((await events()).length).toBe(ev);
    });

    it('401 without a valid credential; 403 without the scope; nothing is written either way', async () => {
      const n = await sessionCount();
      expect((await v2(null, 'POST', '/work-sessions', baseRequest())).status).toBe(401);
      const noScope = await caller('read-only', ['work-sessions:read']);
      const r = await v2(noScope, 'POST', '/work-sessions', baseRequest());
      expect(r.status).toBe(403);
      expect(r.body.error).toMatch(/work-sessions:request/);
      expect(await sessionCount()).toBe(n);
    });

    it('the sponsor must be the project\'s owner (403); a project or repository that is not reachable is 404; nothing is written', async () => {
      const n = await sessionCount();
      const ev = (await events()).length;
      expect((await v2(requester, 'POST', '/work-sessions', baseRequest({ sponsor: { type: 'creator', id: other.id } }))).status).toBe(403);
      expect((await v2(requester, 'POST', '/work-sessions', baseRequest({ project_id: otherProjectId, repository_id: otherRepoId }))).status).toBe(404);
      expect((await v2(requester, 'POST', '/work-sessions', baseRequest({ project_id: crypto.randomUUID() }))).status).toBe(404);
      // a repository of another project, even the same creator's
      expect((await v2(requester, 'POST', '/work-sessions', baseRequest({ repository_id: repoId2 }))).status).toBe(404);
      expect((await v2(requester, 'POST', '/work-sessions', baseRequest({ repository_id: otherRepoId }))).status).toBe(404);
      expect((await v2(requester, 'POST', '/work-sessions', baseRequest({ repository_id: crypto.randomUUID() }))).status).toBe(404);
      expect(await sessionCount()).toBe(n);
      expect((await events()).length).toBe(ev);
    });

    it('a principal limited to some projects cannot request in the others', async () => {
      const limited = await caller('limited', ['work-sessions:request'], { allowed_project_ids: [projectId2] });
      expect((await v2(limited, 'POST', '/work-sessions', baseRequest())).status).toBe(404); // project 1
      expect((await v2(limited, 'POST', '/work-sessions', baseRequest({ project_id: projectId2, repository_id: repoId2 }))).status).toBe(202);
    });

    it(`at most ${MAX_PENDING_PER_PRINCIPAL} requests can wait for approval at once, even when they arrive together`, async () => {
      const flood = await caller('flood', ['work-sessions:request']);
      const results = await Promise.all(Array.from({ length: MAX_PENDING_PER_PRINCIPAL + 10 }, () => v2(flood, 'POST', '/work-sessions', baseRequest())));
      expect(results.filter((r) => r.status === 202)).toHaveLength(MAX_PENDING_PER_PRINCIPAL);
      expect(results.filter((r) => r.status === 429)).toHaveLength(10);
      expect((await db.query(`SELECT count(*)::int AS n FROM work_session WHERE requested_by_principal_id = $1`, [flood.id])).rows[0].n).toBe(MAX_PENDING_PER_PRINCIPAL);
      // deciding one frees a place
      const waiting = (await db.query(`SELECT id FROM work_session WHERE requested_by_principal_id = $1 LIMIT 1`, [flood.id])).rows[0].id;
      expect((await v1(creator, 'POST', `/projects/${projectId}/work-sessions/${waiting}/reject`, {})).status).toBe(200);
      expect((await v2(flood, 'POST', '/work-sessions', baseRequest())).status).toBe(202);
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('approval is a person\'s decision', () => {
    it('the creator approves: approved, by creator:<id>, recorded; approving again is refused', async () => {
      const id = await request();
      const before = (await events()).length;
      const r = await v1(creator, 'POST', `/projects/${projectId}/work-sessions/${id}/approve`, {});
      expect(r.status).toBe(200);
      expect(r.body).toEqual({ id, status: 'approved' });
      const s = await sessionRow(id);
      expect(s.status).toBe('approved');
      expect(s.approved_by).toBe(`creator:${creator.id}`);
      expect(s.approved_at).toBeTruthy();
      const ev = (await events()).slice(before);
      expect(ev).toHaveLength(1);
      expect(ev[0]).toMatchObject({ action: 'work_session.approved', actor_type: 'creator', actor_id: creator.id, subject_id: id });
      expect((await v1(creator, 'POST', `/projects/${projectId}/work-sessions/${id}/approve`, {})).status).toBe(409);
      expect((await v1(creator, 'POST', `/projects/${projectId}/work-sessions/${id}/reject`, {})).status).toBe(409);
      expect((await events()).length).toBe(before + 1);
    });

    it('the creator rejects, with or without a reason; a rejected session is final', async () => {
      const a = await request();
      const b = await request();
      expect((await v1(creator, 'POST', `/projects/${projectId}/work-sessions/${a}/reject`, { reason: 'Too broad' })).status).toBe(200);
      expect((await v1(creator, 'POST', `/projects/${projectId}/work-sessions/${b}/reject`)).status).toBe(200);
      expect(await sessionRow(a)).toMatchObject({ status: 'rejected', closed_reason: 'rejected: Too broad' });
      expect(await sessionRow(b)).toMatchObject({ status: 'rejected', closed_reason: 'rejected' });
      expect((await sessionRow(a)).closed_at).toBeTruthy();
      expect((await v1(creator, 'POST', `/projects/${projectId}/work-sessions/${a}/approve`, {})).status).toBe(409);
      expect((await events()).some((e) => e.action === 'work_session.rejected' && e.subject_id === a && e.payload.reason === 'Too broad')).toBe(true);
      expect((await v1(creator, 'POST', `/projects/${projectId}/work-sessions/${await request()}/reject`, { reason: 'x'.repeat(501) })).status).toBe(400);
    });

    it('no machine route approves: not for the requester, and not even for a principal that holds work-sessions:approve', async () => {
      const id = await request();
      for (const c of [requester, approver]) {
        for (const verb of ['approve', 'reject', 'promote']) {
          const r = await v2(c, 'POST', `/work-sessions/${id}/${verb}`, {});
          expect([404, 405], `${verb}`).toContain(r.status);
        }
      }
      expect((await sessionRow(id)).status).toBe('requested');
    });

    it('only the project\'s owner can decide: another creator gets 404, and other projects\' sessions are not reachable through this one', async () => {
      const id = await request();
      expect((await v1(other, 'POST', `/projects/${projectId}/work-sessions/${id}/approve`, {})).status).toBe(404);
      expect((await v1(other, 'GET', `/projects/${projectId}/work-sessions`)).status).toBe(404);
      expect((await v1(creator, 'POST', `/projects/${projectId2}/work-sessions/${id}/approve`, {})).status).toBe(404); // right owner, wrong project
      expect((await v1(creator, 'POST', `/projects/${projectId}/work-sessions/not-an-id/approve`, {})).status).toBe(404);
      expect((await sessionRow(id)).status).toBe('requested');
    });

    it('an expired request cannot be approved', async () => {
      const id = await request(requester, { expires_in_seconds: 60 });
      await withTriggersBypassed(admin, async (c) => {
        await c.query(`UPDATE work_session SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' WHERE id = $1`, [id]);
      });
      const r = await v1(creator, 'POST', `/projects/${projectId}/work-sessions/${id}/approve`, {});
      expect(r.status).toBe(409);
      expect(r.body.error).toMatch(/expired/);
      expect((await sessionRow(id)).status).toBe('requested');
    });

    it('the creator lists a project\'s sessions, with who asked', async () => {
      const id = await request();
      const r = await v1(creator, 'GET', `/projects/${projectId}/work-sessions`);
      expect(r.status).toBe(200);
      const found = r.body.work_sessions.find((s: any) => s.id === id);
      expect(found).toMatchObject({ status: 'requested', session_type: 'automated_work_session', objective: 'Harden the authorization routes' });
      expect(found.requested_by.principal_id).toBe(requester.id);
      expect(found.requested_by.name).toMatch(/^requester-/);
      expect(r.body.work_sessions.some((s: any) => s.session_type === 'human_door')).toBe(true); // doors are listed too
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('who can see a session', () => {
    it('the principal that asked sees it; another principal of the same creator does not', async () => {
      const id = await request(requester);
      const mine = await v2(requester, 'GET', `/work-sessions/${id}`);
      expect(mine.status).toBe(200);
      expect(mine.body.work_session).toMatchObject({ id, status: 'requested', requested_by: { principal_id: requester.id }, branch_name: `session/${id}/work` });
      expect(mine.body.work_session.access).toMatchObject({ repository: 'read_and_push', allowed_write_paths: ['server/gateway/**'] });
      expect((await v2(reader, 'GET', `/work-sessions/${id}`)).status).toBe(404);
      expect((await v2(reader, 'GET', '/work-sessions')).body.work_sessions.map((s: any) => s.id)).not.toContain(id);
    });

    it('a principal that can approve sees sessions in the projects it can reach, and no others', async () => {
      const id = await request(requester);
      expect((await v2(approver, 'GET', `/work-sessions/${id}`)).status).toBe(200);
      const narrow = await caller('approver-p2', ['work-sessions:approve', 'work-sessions:read'], { allowed_project_ids: [projectId2] });
      expect((await v2(narrow, 'GET', `/work-sessions/${id}`)).status).toBe(404);
      const foreign = await caller('foreign', ['work-sessions:approve', 'work-sessions:read'], {}, other);
      expect((await v2(foreign, 'GET', `/work-sessions/${id}`)).status).toBe(404);
      expect((await v2(foreign, 'GET', '/work-sessions')).body.work_sessions).toEqual([]);
    });

    it('reading needs the read scope; ids are checked; filters work', async () => {
      const noRead = await caller('noread', ['work-sessions:request']);
      expect((await v2(noRead, 'GET', '/work-sessions')).status).toBe(403);
      expect((await v2(requester, 'GET', '/work-sessions/not-an-id')).status).toBe(404);
      expect((await v2(requester, 'GET', `/work-sessions/${crypto.randomUUID()}`)).status).toBe(404);
      expect((await v2(requester, 'GET', '/work-sessions?project_id=x')).status).toBe(400);
      expect((await v2(requester, 'GET', '/work-sessions?status=nonsense')).status).toBe(400);
      const id = await request(requester);
      await v1(creator, 'POST', `/projects/${projectId}/work-sessions/${id}/approve`, {});
      const approved = await v2(requester, 'GET', '/work-sessions?status=approved');
      expect(approved.body.work_sessions.map((s: any) => s.id)).toContain(id);
      expect(approved.body.work_sessions.every((s: any) => s.status === 'approved')).toBe(true);
      const inP2 = await v2(requester, 'GET', `/work-sessions?project_id=${projectId2}`);
      expect(inP2.body.work_sessions.every((s: any) => s.project_id === projectId2)).toBe(true);
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('closing and expiry', () => {
    it('the requester closes its own session; closing again is harmless and records nothing more', async () => {
      const id = await request();
      const before = (await events()).length;
      const r = await v2(requester, 'POST', `/work-sessions/${id}/close`);
      expect(r.status).toBe(200);
      expect(r.body).toEqual({ session_id: id, status: 'closed' });
      expect(await sessionRow(id)).toMatchObject({ status: 'closed', closed_reason: 'closed_by_requester' });
      const ev = (await events()).slice(before);
      expect(ev).toHaveLength(1);
      expect(ev[0]).toMatchObject({ action: 'work_session.closed', actor_id: `principal:${requester.id}`, payload: { reason: 'closed_by_requester', previous_status: 'requested' } });
      expect((await v2(requester, 'POST', `/work-sessions/${id}/close`)).status).toBe(200);
      expect((await events()).length).toBe(before + 1);
    });

    it('only the requester can close it (another principal gets 404), and it needs the close-own scope', async () => {
      const id = await request();
      expect((await v2(reader, 'POST', `/work-sessions/${id}/close`)).status).toBe(403); // no close-own
      const closer = await caller('closer', ['work-sessions:close-own', 'work-sessions:read']);
      expect((await v2(closer, 'POST', `/work-sessions/${id}/close`)).status).toBe(404); // not its session
      expect((await v2(approver, 'POST', `/work-sessions/${id}/close`)).status).toBe(403);
      expect((await sessionRow(id)).status).toBe('requested');
    });

    it('an approved session can be closed; a rejected or expired one cannot be closed again (409)', async () => {
      const a = await request();
      await v1(creator, 'POST', `/projects/${projectId}/work-sessions/${a}/approve`, {});
      expect((await v2(requester, 'POST', `/work-sessions/${a}/close`)).status).toBe(200);
      const b = await request();
      await v1(creator, 'POST', `/projects/${projectId}/work-sessions/${b}/reject`, {});
      expect((await v2(requester, 'POST', `/work-sessions/${b}/close`)).status).toBe(409);
      expect((await v2(requester, 'POST', `/work-sessions/${crypto.randomUUID()}/close`)).status).toBe(404);
    });

    it('the scheduler expires overdue sessions, approved or not, once each, and leaves finished and current ones alone', async () => {
      const waiting = await request();
      const approved = await request();
      await v1(creator, 'POST', `/projects/${projectId}/work-sessions/${approved}/approve`, {});
      const closed = await request();
      await v2(requester, 'POST', `/work-sessions/${closed}/close`);
      const current = await request();
      await withTriggersBypassed(admin, async (c) => {
        await c.query(`UPDATE work_session SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' WHERE id = ANY($1::uuid[])`, [[waiting, approved, closed]]);
      });
      const before = (await events()).length;
      const expired = await expireOverdueSessions(db);
      // (an earlier test left one aged, still-requested session behind: it is overdue too, and is expired too)
      expect(expired).toEqual(expect.arrayContaining([waiting, approved]));
      expect(expired).not.toContain(closed);
      expect(expired).not.toContain(current);
      expect(new Set(expired).size).toBe(expired.length);
      expect(await sessionRow(waiting)).toMatchObject({ status: 'expired', closed_reason: 'expired' });
      expect(await sessionRow(approved)).toMatchObject({ status: 'expired' });
      expect((await sessionRow(closed)).status).toBe('closed');
      expect((await sessionRow(current)).status).toBe('requested');
      const ev = (await events()).slice(before);
      expect(ev.map((e) => e.action)).toEqual(expired.map(() => 'work_session.closed'));
      expect(ev.every((e) => e.actor_type === 'system' && e.actor_id === 'scheduler' && e.payload.reason === 'expired')).toBe(true);
      expect(await expireOverdueSessions(db)).toEqual([]);
      expect((await events()).length).toBe(before + expired.length);
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('what the database refuses, whoever asks', () => {
    const insert = (over: Record<string, string | null> = {}) => {
      const id = crypto.randomUUID();
      const v: Record<string, any> = {
        id, project_id: projectId, repository_id: repoId, session_type: 'automated_work_session', executor_type: 'ai_assistant', sponsor_id: creator.id,
        objective: 'x', base_commit: 'b'.repeat(40), branch_name: `session/${id}/work`, repository_access: 'read', allowed_read_paths: ['a'],
        expires_at: new Date(Date.now() + 3600_000).toISOString(), ...over
      };
      const cols = Object.keys(v);
      return db.query(`INSERT INTO work_session (${cols.join(', ')}) VALUES (${cols.map((_, i) => `$${i + 1}`).join(', ')}) RETURNING id`, cols.map((c) => v[c])).then((r) => r.rows[0].id as string);
    };

    it('a session cannot be created already approved, closed or with an approver', async () => {
      const t = new Date().toISOString();
      await expect(insert({ status: 'approved', approved_at: t, approved_by: `creator:${creator.id}` })).rejects.toThrow(/must be created as requested/);
      await expect(insert({ status: 'closed', closed_at: t })).rejects.toThrow(/must be created as requested/);
      await expect(insert({ approved_by: `creator:${creator.id}` })).rejects.toThrow(/must be created as requested/);
    });

    it('it has to be complete: repository, commit, branch under its own id, expiry, read paths, and consistent write paths', async () => {
      await expect(insert({ repository_id: null })).rejects.toThrow(/chk_session_automated_fields/);
      await expect(insert({ base_commit: null })).rejects.toThrow();
      await expect(insert({ expires_at: null })).rejects.toThrow(/chk_session_automated_fields/);
      await expect(insert({ branch_name: 'session/someone-else/work' })).rejects.toThrow(/chk_session_branch/);
      await expect(insert({ branch_name: 'main' })).rejects.toThrow(/chk_session_branch/);
      await expect(insert({ allowed_read_paths: [] as any })).rejects.toThrow(/chk_session_automated_fields/);
      await expect(insert({ repository_access: 'read', allowed_write_paths: ['a'] as any })).rejects.toThrow(/chk_session_automated_fields/);
      await expect(insert({ repository_access: 'read_and_push' })).rejects.toThrow(/chk_session_automated_fields/);
      await expect(insert({ objective: '' })).rejects.toThrow(/chk_session_automated_fields/);
      await expect(insert({ executor_type: 'human_developer' })).rejects.toThrow(/chk_session_executor/);
      await expect(insert({ session_type: 'human_door' })).rejects.toThrow(/chk_session_door/);
      await expect(insert({ expires_at: new Date(Date.now() - 1000).toISOString() })).rejects.toThrow(/chk_session_automated_fields/);
    });

    it('approval needs the sponsoring creator named as approver: not nobody, not the requesting principal', async () => {
      const id = await insert();
      const t = new Date().toISOString();
      await expect(db.query(`UPDATE work_session SET status = 'approved', approved_at = $2 WHERE id = $1`, [id, t])).rejects.toThrow(/chk_session_approved_has_approval/);
      await expect(db.query(`UPDATE work_session SET status = 'approved', approved_at = $2, approved_by = $3 WHERE id = $1`, [id, t, `principal:${requester.id}`])).rejects.toThrow(/chk_session_approver/);
      await expect(db.query(`UPDATE work_session SET status = 'approved', approved_at = $2, approved_by = $3 WHERE id = $1`, [id, t, `creator:${other.id}`])).rejects.toThrow(/chk_session_approver/);
      await expect(db.query(`UPDATE work_session SET status = 'approved', approved_at = $2, approved_by = $3 WHERE id = $1`, [id, t, `creator:${creator.id}`])).resolves.toBeTruthy();
    });

    it('the request cannot be rewritten after it is made, and an approval cannot be rewritten after it is given', async () => {
      const id = await insert();
      const refuses = (set: string, ...args: unknown[]) => expect(db.query(`UPDATE work_session SET ${set} WHERE id = $1`, [id, ...args])).rejects.toThrow(/cannot be changed|cannot change/);
      await refuses(`objective = 'something else'`);
      await refuses(`base_commit = '${'c'.repeat(40)}'`);
      await refuses(`allowed_read_paths = ARRAY['everything']`);
      await refuses(`allowed_write_paths = ARRAY['everything']`);
      await refuses(`prohibited_paths = ARRAY['somewhere/else']`);
      await refuses(`repository_access = 'read_and_push'`);
      await refuses(`expires_at = now() + interval '90 days'`);
      await refuses(`sponsor_id = $2`, other.id);
      await refuses(`repository_id = $2`, repoId2);
      await refuses(`executor_type = 'ci_runtime'`);
      await refuses(`project_id = $2`, projectId2);
      await refuses(`session_type = 'human_door'`);
      await refuses(`requested_by_principal_id = $2`, approver.id);
      await db.query(`UPDATE work_session SET status = 'approved', approved_at = now(), approved_by = $2 WHERE id = $1`, [id, `creator:${creator.id}`]);
      await expect(db.query(`UPDATE work_session SET approved_by = 'policy:abc' WHERE id = $1`, [id])).rejects.toThrow(/approval cannot be changed/);
      await expect(db.query(`UPDATE work_session SET approved_at = now() WHERE id = $1`, [id])).rejects.toThrow(/approval cannot be changed/);
    });

    it('status moves only along allowed steps, and rejected, closed and expired are final', async () => {
      const id = await insert();
      const go = (s: string, extra = '') => db.query(`UPDATE work_session SET status = '${s}' ${extra} WHERE id = $1`, [id]);
      await expect(go('active')).rejects.toThrow(/cannot go from requested to active/);
      await expect(go('completed')).rejects.toThrow(/cannot go from requested to completed/);
      await go('approved', `, approved_at = now(), approved_by = 'creator:${creator.id}'`);
      await expect(go('requested')).rejects.toThrow(/cannot go from approved to requested/);
      await go('active');
      await go('awaiting_evidence');
      await go('completed');
      await expect(go('active')).rejects.toThrow(/cannot go from completed to active/);
      await go('closed', ', closed_at = now()');
      for (const s of ['requested', 'approved', 'active', 'expired', 'rejected']) {
        await expect(go(s, s === 'requested' ? '' : ''), s).rejects.toThrow();
      }
    });

    it('a session cannot be deleted by the application, and a closed or expired one is not reopened by touching its end time', async () => {
      expect((await db.query(`SELECT has_table_privilege(current_user, 'public.work_session', 'DELETE') AS ok`)).rows[0].ok).toBe(false);
      await expect(db.query('DELETE FROM work_session')).rejects.toThrow(/permission denied/);
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  it('everything above is in the projects\' tamper-evident records, and the records still verify', async () => {
    for (const pid of [projectId, projectId2]) {
      const check = await verifyServerProjectEvents(pid);
      expect(check.isValid, check.reason).toBe(true);
    }
    const actions = new Set((await events()).map((e) => e.action));
    for (const a of ['work_session.requested', 'work_session.approved', 'work_session.rejected', 'work_session.closed']) expect(actions.has(a)).toBe(true);
  });
});
