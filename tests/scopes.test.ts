import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import http from 'node:http';
import express from 'express';
import { getAdminPool, getDbPool, runMigrations } from '../server/db';
import {
  ALL_SCOPES,
  EXECUTION_SCOPES,
  HIGH_CONSEQUENCE_SCOPES,
  PrincipalError,
  WORK_PRODUCING_SCOPES,
  addPrincipalKey,
  narrowPrincipal,
  registerPrincipal,
  scopeSetProblem,
  setPrincipalStatus
} from '../server/servicePrincipals';
import { authenticatePrincipal, requireProjectAccess, requireScope } from '../server/servicePrincipalAuth';
import { verifyAccountChain } from '../shared/crypto';
import { assertPoolTargetsTestDb } from './support/safety';
import { withTriggersBypassed } from './support/cleanup';
import { assertion, newKey, TestKey } from './support/principalKeys';

/**
 * Scope enforcement (CL-08): who may be given which scopes (checked by the code and by the database), permissions
 * that can only shrink, and the middleware that turns scopes and project access into 403 / 404 on real HTTP requests.
 */
describe('Scopes: separation of duties, narrowing, and enforcement', () => {
  const db = getDbPool()!;
  const admin = getAdminPool()!;
  let creatorA: { id: string; userId: string };
  let creatorB: { id: string; userId: string };
  let projectA1 = '';
  let projectA2 = '';
  let projectB1 = '';

  async function newCreator(label: string) {
    const userId = `user-${crypto.randomUUID()}`;
    const id = (await db.query('INSERT INTO creator (identity_id, display_name, email) VALUES ($1, $2, $3) RETURNING id', [userId, label, `${label}_${Date.now()}@example.com`])).rows[0].id;
    return { id, userId };
  }
  const project = async (creatorId: string, name: string) => (await db.query(`INSERT INTO project (creator_id, name, purpose) VALUES ($1, $2, 'x') RETURNING id`, [creatorId, name])).rows[0].id as string;
  const register = (scopes: string[], over: Record<string, unknown> = {}, who = creatorA) =>
    registerPrincipal(db, who.id, { name: `p-${crypto.randomUUID().slice(0, 8)}`, platform_type: 'ci', environment: 'development', allowed_scopes: scopes, ...over } as any, 'test');
  const rejects = async (p: Promise<unknown>, code: string, text?: RegExp) => {
    const err: any = await p.then(() => null, (e) => e);
    expect(err, 'expected a rejection').toBeInstanceOf(PrincipalError);
    expect(err.code).toBe(code);
    if (text) expect(err.message).toMatch(text);
  };
  const rawInsert = (scopes: string[], name = `raw-${crypto.randomUUID().slice(0, 8)}`) =>
    db.query(`INSERT INTO service_principal (creator_id, name, platform_type, environment, allowed_scopes, created_by) VALUES ($1, $2, 'ci', 'development', $3, 'raw')`, [creatorA.id, name, scopes]);

  beforeAll(async () => {
    await assertPoolTargetsTestDb(admin);
    expect((await runMigrations()).success).toBe(true);
    creatorA = await newCreator('a');
    creatorB = await newCreator('b');
    projectA1 = await project(creatorA.id, 'A1');
    projectA2 = await project(creatorA.id, 'A2');
    projectB1 = await project(creatorB.id, 'B1');
  });

  describe('which scopes can be held together', () => {
    it('the registry: every scope is either an execution scope or a high-consequence scope, never both', () => {
      expect(new Set(ALL_SCOPES).size).toBe(ALL_SCOPES.length);
      for (const s of HIGH_CONSEQUENCE_SCOPES) expect((EXECUTION_SCOPES as readonly string[]).includes(s)).toBe(false);
      for (const s of WORK_PRODUCING_SCOPES) expect((EXECUTION_SCOPES as readonly string[]).includes(s)).toBe(true);
    });

    it('a worker (request, evidence, push) can never also approve, promote or manage: every pair is refused', async () => {
      for (const high of HIGH_CONSEQUENCE_SCOPES) {
        for (const worker of WORK_PRODUCING_SCOPES) {
          expect(scopeSetProblem([high, worker]), `${high} + ${worker}`).toMatch(/Use two principals/);
          await rejects(register([high, worker]), 'invalid', /Use two principals/);
        }
      }
    });

    it('a scope set that is allowed: workers with read and close-own; approvers with read; promote alone; none at all', async () => {
      await expect(register(['work-sessions:request', 'evidence:submit', 'repositories:push-session', 'work-sessions:close-own', 'work-sessions:read'])).resolves.toBeTruthy();
      await expect(register(['work-sessions:approve', 'work-sessions:read'])).resolves.toBeTruthy();
      await expect(register(['repositories:promote'])).resolves.toBeTruthy();
      await expect(register(['principals:manage', 'webhooks:manage', 'work-sessions:approve'])).resolves.toBeTruthy();
      await expect(register([])).resolves.toBeTruthy();
    });

    it('the database refuses the same combinations, whatever code wrote them', async () => {
      await expect(rawInsert(['work-sessions:approve', 'work-sessions:request'])).rejects.toThrow(/chk_principal_scope_separation/);
      await expect(rawInsert(['repositories:promote', 'evidence:submit'])).rejects.toThrow(/chk_principal_scope_separation/);
      await expect(rawInsert(['principals:manage', 'repositories:push-session'])).rejects.toThrow(/chk_principal_scope_separation/);
      await expect(rawInsert(['work-sessions:approve', 'work-sessions:read'])).resolves.toBeTruthy();
    });

    it('the database refuses unknown scopes, and its list is exactly the registry', async () => {
      await expect(rawInsert(['everything'])).rejects.toThrow(/chk_principal_known_scopes/);
      await expect(rawInsert(['work-sessions:read', 'admin'])).rejects.toThrow(/chk_principal_known_scopes/);
      const def = (await db.query(`SELECT pg_get_constraintdef(oid) AS d FROM pg_constraint WHERE conname = 'chk_principal_known_scopes'`)).rows[0].d as string;
      const inDb = [...new Set([...def.matchAll(/'([a-z-]+:[a-z-]+)'/g)].map((m) => m[1]))].sort();
      expect(inDb).toEqual([...ALL_SCOPES].sort());
    });

    it('an existing principal cannot be given a conflicting scope by a direct update either', async () => {
      const p = await register(['work-sessions:request']);
      await expect(db.query(`UPDATE service_principal SET allowed_scopes = allowed_scopes || 'work-sessions:approve' WHERE id = $1`, [p.id])).rejects.toThrow();
    });
  });

  describe('permissions only shrink', () => {
    it('narrowPrincipal removes scopes, records before and after on the creator\'s account record, and the chain still verifies', async () => {
      const p = await register(['work-sessions:request', 'evidence:submit', 'work-sessions:read']);
      await narrowPrincipal(db, p.id, { allowed_scopes: ['work-sessions:read'] }, 'op');
      expect((await db.query('SELECT allowed_scopes FROM service_principal WHERE id = $1', [p.id])).rows[0].allowed_scopes).toEqual(['work-sessions:read']);
      const events = (await db.query('SELECT * FROM account_event WHERE account_id = $1 ORDER BY seq', [creatorA.userId])).rows;
      const e = events.find((x) => x.action === 'service_principal.narrowed' && x.payload.principal_id === p.id);
      expect([...e.payload.scopes_before].sort()).toEqual(['evidence:submit', 'work-sessions:read', 'work-sessions:request']);
      expect(e.payload.scopes_after).toEqual(['work-sessions:read']);
      expect((await verifyAccountChain(events.map((x) => ({ ...x, seq: Number(x.seq), timestamp: x.hashed_timestamp })))).isValid).toBe(true);
    });

    it('can narrow to nothing, and a principal with no scopes is still a valid principal', async () => {
      const p = await register(['work-sessions:request']);
      await narrowPrincipal(db, p.id, { allowed_scopes: [] }, 'op');
      expect((await db.query('SELECT allowed_scopes FROM service_principal WHERE id = $1', [p.id])).rows[0].allowed_scopes).toEqual([]);
    });

    it('adding a scope is refused by the code and by the database', async () => {
      const p = await register(['work-sessions:read']);
      await rejects(narrowPrincipal(db, p.id, { allowed_scopes: ['work-sessions:read', 'work-sessions:request'] }, 'op'), 'invalid', /only be narrowed/);
      await expect(db.query(`UPDATE service_principal SET allowed_scopes = ARRAY['work-sessions:read','evidence:submit'] WHERE id = $1`, [p.id])).rejects.toThrow(/scopes can only be removed/);
      // swapping one scope for another is adding one
      await expect(db.query(`UPDATE service_principal SET allowed_scopes = ARRAY['evidence:submit'] WHERE id = $1`, [p.id])).rejects.toThrow(/scopes can only be removed/);
    });

    it('the project list: from "all" to a set is narrowing; a set can shrink but never grow or return to "all"', async () => {
      const p = await register(['work-sessions:read']);
      await narrowPrincipal(db, p.id, { allowed_project_ids: [projectA1, projectA2] }, 'op');
      await narrowPrincipal(db, p.id, { allowed_project_ids: [projectA1] }, 'op');
      await rejects(narrowPrincipal(db, p.id, { allowed_project_ids: [projectA1, projectA2] }, 'op'), 'invalid', /cannot gain projects/);
      await expect(db.query(`UPDATE service_principal SET allowed_project_ids = NULL WHERE id = $1`, [p.id])).rejects.toThrow(/project list can only be made smaller/);
      await expect(db.query(`UPDATE service_principal SET allowed_project_ids = ARRAY[$2::uuid, $3::uuid] WHERE id = $1`, [p.id, projectA1, projectA2])).rejects.toThrow(/project list can only be made smaller/);
    });

    it('narrowing to another creator\'s project is refused', async () => {
      const p = await register(['work-sessions:read']);
      await rejects(narrowPrincipal(db, p.id, { allowed_project_ids: [projectB1] }, 'op'), 'invalid', /own projects/);
    });

    it('the environment can never change (development to production would be a widening)', async () => {
      const p = await register(['work-sessions:read']);
      await expect(db.query(`UPDATE service_principal SET environment = 'production' WHERE id = $1`, [p.id])).rejects.toThrow(/environment cannot change/);
    });

    it('narrowing needs a change, a real principal, and one that is not revoked', async () => {
      const p = await register(['work-sessions:read']);
      await rejects(narrowPrincipal(db, p.id, {}, 'op'), 'invalid', /Nothing to change/);
      await rejects(narrowPrincipal(db, crypto.randomUUID(), { allowed_scopes: [] }, 'op'), 'not_found');
      await setPrincipalStatus(db, p.id, 'revoked', 'op');
      await rejects(narrowPrincipal(db, p.id, { allowed_scopes: [] }, 'op'), 'conflict', /revoked/);
    });

    it('suspending, reactivating and revoking still work (the guard did not break them)', async () => {
      const p = await register(['work-sessions:read']);
      await setPrincipalStatus(db, p.id, 'suspended', 'op');
      await setPrincipalStatus(db, p.id, 'active', 'op');
      await setPrincipalStatus(db, p.id, 'revoked', 'op');
    });
  });

  describe('enforcement on real HTTP requests', () => {
    let server: http.Server;
    let base = '';

    // A small app that uses only the production middleware, with routes that need particular scopes.
    beforeAll(async () => {
      const app = express();
      const v2 = express.Router();
      v2.use(authenticatePrincipal);
      v2.get('/request-only', requireScope('work-sessions:request'), (_q, r) => r.json({ ok: true }));
      v2.get('/approve-only', requireScope('work-sessions:approve'), (_q, r) => r.json({ ok: true }));
      v2.get('/projects/:projectId/read', requireScope('work-sessions:read'), requireProjectAccess(), (_q, r) => r.json({ ok: true }));
      v2.get('/projects/:projectId/open', requireProjectAccess(), (_q, r) => r.json({ ok: true }));
      app.use('/api/v2', v2);
      server = http.createServer(app);
      await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
      base = `http://127.0.0.1:${(server.address() as any).port}`;
    });
    afterAll(async () => {
      await new Promise((r) => server?.close(r));
    });

    interface Caller { id: string; keyId: string; key: TestKey }
    async function caller(scopes: string[], over: Record<string, unknown> = {}, who = creatorA): Promise<Caller> {
      const p = await register(scopes, over, who);
      const key = newKey('Ed25519');
      return { id: p.id, keyId: (await addPrincipalKey(db, p.id, key.publicJwk, 'test')).key_id, key };
    }
    const call = async (c: Caller | null, path: string) => {
      const res = await fetch(`${base}/api/v2${path}`, { headers: c ? { Authorization: `Bearer ${assertion(c.key, c.keyId, c.id)}` } : {} });
      return { status: res.status, body: await res.json().catch(() => ({})) };
    };

    it('a caller with the scope gets through; without it, 403; with no valid credential, 401 (never 403)', async () => {
      const worker = await caller(['work-sessions:request']);
      const approver = await caller(['work-sessions:approve']);
      expect((await call(worker, '/request-only')).status).toBe(200);
      expect((await call(approver, '/request-only')).status).toBe(403);
      expect((await call(approver, '/approve-only')).status).toBe(200);
      expect((await call(worker, '/approve-only')).status).toBe(403);
      expect((await call(null, '/approve-only')).status).toBe(401);
      expect((await call(null, '/request-only')).status).toBe(401);
      expect((await call(worker, '/request-only')).body).toEqual({ ok: true });
      expect((await call(worker, '/approve-only')).body.error).toMatch(/work-sessions:approve/);
    });

    it('a principal with no scopes can reach nothing that needs one', async () => {
      const none = await caller([]);
      expect((await call(none, '/request-only')).status).toBe(403);
      expect((await call(none, '/approve-only')).status).toBe(403);
      expect((await call(none, `/projects/${projectA1}/read`)).status).toBe(403);
    });

    it('narrowing takes effect on the very next request', async () => {
      const c = await caller(['work-sessions:request', 'evidence:submit']);
      expect((await call(c, '/request-only')).status).toBe(200);
      await narrowPrincipal(db, c.id, { allowed_scopes: ['evidence:submit'] }, 'op');
      expect((await call(c, '/request-only')).status).toBe(403);
    });

    it('suspension and revocation take effect on the very next request', async () => {
      const c = await caller(['work-sessions:request']);
      expect((await call(c, '/request-only')).status).toBe(200);
      await setPrincipalStatus(db, c.id, 'suspended', 'op');
      expect((await call(c, '/request-only')).status).toBe(401);
      await setPrincipalStatus(db, c.id, 'active', 'op');
      expect((await call(c, '/request-only')).status).toBe(200);
      await setPrincipalStatus(db, c.id, 'revoked', 'op');
      expect((await call(c, '/request-only')).status).toBe(401);
    });

    it('a token that claims scopes it was not given gets nothing', async () => {
      const c = await caller(['work-sessions:request']);
      const token = assertion(c.key, c.keyId, c.id, { claims: { scope: 'work-sessions:approve', scopes: ['work-sessions:approve'], permissions: ['*'] } });
      const res = await fetch(`${base}/api/v2/approve-only`, { headers: { Authorization: `Bearer ${token}` } });
      expect(res.status).toBe(403);
    });

    it('requireScope refuses a scope name it does not know, when the route is defined (a typo is not silently "no scope")', () => {
      expect(() => requireScope('work-sessions:aprove')).toThrow(/not a known scope/);
      expect(() => requireScope('')).toThrow(/not a known scope/);
    });
  });

  describe('projects: tenant isolation', () => {
    let server: http.Server;
    let base = '';
    beforeAll(async () => {
      const app = express();
      const v2 = express.Router();
      v2.use(authenticatePrincipal);
      v2.get('/projects/:projectId/read', requireScope('work-sessions:read'), requireProjectAccess(), (_q, r) => r.json({ ok: true }));
      v2.get('/projects/:projectId/open', requireProjectAccess(), (_q, r) => r.json({ ok: true }));
      app.use('/api/v2', v2);
      server = http.createServer(app);
      await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
      base = `http://127.0.0.1:${(server.address() as any).port}`;
    });
    afterAll(async () => {
      await new Promise((r) => server?.close(r));
    });

    async function caller(scopes: string[], over: Record<string, unknown> = {}, who = creatorA) {
      const p = await register(scopes, over, who);
      const key = newKey('ES256');
      return { id: p.id, keyId: (await addPrincipalKey(db, p.id, key.publicJwk, 'test')).key_id, key };
    }
    const call = async (c: { id: string; keyId: string; key: TestKey }, path: string) => {
      const res = await fetch(`${base}/api/v2${path}`, { headers: { Authorization: `Bearer ${assertion(c.key, c.keyId, c.id)}` } });
      return { status: res.status, body: await res.json().catch(() => ({})) };
    };

    it('a principal with no project list reaches all of its own creator\'s projects, and none of another creator\'s', async () => {
      const c = await caller(['work-sessions:read']);
      expect((await call(c, `/projects/${projectA1}/read`)).status).toBe(200);
      expect((await call(c, `/projects/${projectA2}/read`)).status).toBe(200);
      expect((await call(c, `/projects/${projectB1}/read`)).status).toBe(404);
    });

    it('a project list limits it to those projects', async () => {
      const c = await caller(['work-sessions:read'], { allowed_project_ids: [projectA1] });
      expect((await call(c, `/projects/${projectA1}/read`)).status).toBe(200);
      expect((await call(c, `/projects/${projectA2}/read`)).status).toBe(404);
    });

    it('a project that does not exist, another creator\'s, and one outside the list all look the same (404, same body)', async () => {
      const c = await caller(['work-sessions:read'], { allowed_project_ids: [projectA1] });
      const missing = await call(c, `/projects/${crypto.randomUUID()}/read`);
      const foreign = await call(c, `/projects/${projectB1}/read`);
      const outside = await call(c, `/projects/${projectA2}/read`);
      const garbage = await call(c, `/projects/not-an-id/read`);
      for (const r of [missing, foreign, outside, garbage]) expect(r.status).toBe(404);
      expect(foreign.body).toEqual(missing.body);
      expect(outside.body).toEqual(missing.body);
      expect(garbage.body).toEqual(missing.body);
    });

    it('creator B\'s principal cannot see creator A\'s projects, and the reverse', async () => {
      const b = await caller(['work-sessions:read'], {}, creatorB);
      expect((await call(b, `/projects/${projectB1}/read`)).status).toBe(200);
      expect((await call(b, `/projects/${projectA1}/read`)).status).toBe(404);
    });

    it('a caller without the scope is told 403 whatever the project: it learns nothing about which projects exist', async () => {
      const c = await caller(['evidence:submit']);
      const own = await call(c, `/projects/${projectA1}/read`);
      const foreign = await call(c, `/projects/${projectB1}/read`);
      const missing = await call(c, `/projects/${crypto.randomUUID()}/read`);
      for (const r of [own, foreign, missing]) expect(r.status).toBe(403);
    });

    it('defense in depth: even if a project list were tampered to name another creator\'s project, ownership is still checked', async () => {
      const c = await caller(['work-sessions:read'], { allowed_project_ids: [projectA1] });
      // Only possible with the guard triggers off (the database refuses it otherwise, tested above).
      await withTriggersBypassed(admin, async (client) => {
        await client.query('UPDATE service_principal SET allowed_project_ids = ARRAY[$2::uuid, $3::uuid] WHERE id = $1', [c.id, projectA1, projectB1]);
      });
      expect((await call(c, `/projects/${projectA1}/read`)).status).toBe(200);
      expect((await call(c, `/projects/${projectB1}/read`)).status).toBe(404);
    });

    it('a route that needs no scope but names a project still checks project access', async () => {
      const c = await caller([]);
      expect((await call(c, `/projects/${projectA1}/open`)).status).toBe(200);
      expect((await call(c, `/projects/${projectB1}/open`)).status).toBe(404);
    });
  });
});
