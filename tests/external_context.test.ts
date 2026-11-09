import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getAdminPool, getDbPool, runMigrations, verifyServerProjectEvents } from '../server/db';
import { addPrincipalKey, registerPrincipal } from '../server/servicePrincipals';
import { MAX_CONTEXT_BYTES, contextProblem, externalContextProblem, externalContextSha256, namespaceProblem } from '../server/externalContext';
import { scanTextForSecrets } from '../server/textScan';
import { canonicalJsonV2 } from '../shared/crypto';
import { assertPoolTargetsTestDb } from './support/safety';
import { withTriggersBypassed } from './support/cleanup';
import { startHarness, Harness } from './support/apiHarness';
import { startApp, RunningApp } from './support/api';
import { assertion, newKey, TestKey } from './support/principalKeys';
import { installGitleaks } from '../scripts/install-gitleaks';

/**
 * External context on work sessions (CL-10): a namespace and plain JSON that a caller's own platform can use to find
 * its way back. The platform must treat it as opaque (platform neutrality), validate it strictly (it goes into a
 * permanent record whose hashes anyone must be able to re-derive), keep secrets out of it, and record it so that the
 * copy in the tamper-evident ledger can be checked.
 */
describe('External context', () => {
  const db = getDbPool()!;
  const admin = getAdminPool()!;
  let h: Harness;
  let app: RunningApp;
  let creator: any, other: any;
  let projectId = '', ledgerProjectId = '', otherProjectId = '';
  let repoId = '', ledgerRepoId = '';
  interface Caller { id: string; keyId: string; key: TestKey }
  let requester: Caller, reader: Caller, approver: Caller;

  async function caller(label: string, scopes: string[]): Promise<Caller> {
    const p = await registerPrincipal(db, creator.id, { name: `${label}-${crypto.randomUUID().slice(0, 6)}`, platform_type: 'agent', environment: 'development', allowed_scopes: scopes } as any, 'test');
    const key = newKey('Ed25519');
    return { id: p.id, keyId: (await addPrincipalKey(db, p.id, key.publicJwk, 'test')).key_id, key };
  }
  const call = async (c: Caller | null, method: string, p: string, body?: unknown, raw?: string) => {
    const res = await fetch(`${app.base}/api/v2${p}`, {
      method,
      headers: { ...(c ? { Authorization: `Bearer ${assertion(c.key, c.keyId, c.id)}` } : {}), ...(body !== undefined || raw !== undefined ? { 'Content-Type': 'application/json' } : {}) },
      body: raw ?? (body === undefined ? undefined : JSON.stringify(body))
    });
    return { status: res.status, body: await res.json().catch(() => ({})), text: '' };
  };
  const baseRequest = (over: Record<string, unknown> = {}, pid = projectId, rid = repoId) => ({
    project_id: pid,
    repository_id: rid,
    executor: { type: 'ai_assistant', display_name: 'Worker' },
    sponsor: { type: 'creator', id: creator.id },
    objective: 'Do the work',
    base_commit: 'a'.repeat(40),
    access: { repository: 'read', allowed_read_paths: ['src/**'] },
    ...over
  });
  const withContext = (namespace: unknown, context: unknown, extra: Record<string, unknown> = {}) => baseRequest({ external_context: { namespace, context }, ...extra });
  const row = async (id: string) => (await db.query('SELECT * FROM work_session WHERE id = $1', [id])).rows[0];
  const events = async (pid = projectId) => (await db.query('SELECT seq, action, actor_type, actor_id, subject_id, payload, canonical_payload FROM event WHERE project_id = $1 ORDER BY seq', [pid])).rows;
  const count = async () => (await db.query(`SELECT count(*)::int AS n FROM work_session WHERE session_type = 'automated_work_session'`)).rows[0].n;
  const sha = (s: string) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
  const dbHash = async (ns: string, context: unknown) =>
    (await admin.query(`SELECT encode(sha256(convert_to(canonical_jsonb(jsonb_build_object('namespace', $1::text, 'context', $2::jsonb)), 'UTF8')), 'hex') AS h`, [ns, JSON.stringify(context)])).rows[0].h as string;

  async function ok(body: unknown) {
    const r = await call(requester, 'POST', '/work-sessions', body);
    expect(r.status, JSON.stringify(r.body)).toBe(202);
    return r.body.session_id as string;
  }

  beforeAll(async () => {
    await assertPoolTargetsTestDb(admin);
    expect((await runMigrations()).success).toBe(true);
    await installGitleaks();
    h = await startHarness();
    app = await startApp();
    creator = await h.newCreator('owner');
    other = await h.newCreator('other');
    const project = async (c: any, n: string) => (await db.query(`INSERT INTO project (creator_id, name, purpose) VALUES ($1, $2, 'x') RETURNING id`, [c.id, n])).rows[0].id as string;
    const repo = async (pid: string, n: string) => (await db.query(`INSERT INTO repository (project_id, github_repo_id, full_name) VALUES ($1, $2, $3) RETURNING id`, [pid, n, `org/${n}`])).rows[0].id as string;
    projectId = await project(creator, 'P');
    ledgerProjectId = await project(creator, 'Ledger');
    otherProjectId = await project(other, 'Q');
    repoId = await repo(projectId, 'app');
    ledgerRepoId = await repo(ledgerProjectId, 'ledger-app');
    requester = await caller('requester', ['work-sessions:request', 'work-sessions:read']);
    reader = await caller('reader', ['work-sessions:read']);
    approver = await caller('approver', ['work-sessions:approve', 'work-sessions:read']);
  });
  afterAll(async () => {
    await app?.stop();
    await h?.stop();
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('the namespace', () => {
    it('accepts lowercase reverse-DNS names with two or more labels', () => {
      for (const ns of ['com.seedclass.srt1', 'io.github.someone.tool', 'a.b', 'x1.y-z', 'org.example.orchestrator-v2', 'a0.b0.c0.d0', 'com.example.' + 'x'.repeat(60)]) {
        expect(namespaceProblem(ns), ns).toBeNull();
      }
    });

    it('refuses everything else, and the names the platform keeps for itself', () => {
      const bad: unknown[] = [
        'srt1', 'COM.example', 'com.Example', 'com..example', '.com.example', 'com.example.', '-com.example', 'com.-example', 'com.example-', 'com.exa_mple',
        'com.exa mple', 'com.exämple', '', ' com.example', 'com.example ', 'com/example', 'x'.repeat(101) + '.com', 'com.example\n', 5, null, undefined, {}, ['com.example'],
        'custody.core', 'custody.anything.else'
      ];
      for (const ns of bad) expect(namespaceProblem(ns), JSON.stringify(ns)).toEqual(expect.any(String));
      expect(namespaceProblem('custody.core')).toMatch(/reserved/);
      // only the FIRST label is reserved
      expect(namespaceProblem('com.custody.core')).toBeNull();
      expect(namespaceProblem('custodyx.core')).toBeNull();
    });
  });

  describe('the context data', () => {
    const nest = (levels: number): Record<string, unknown> => {
      let v: Record<string, unknown> = { leaf: 1 };
      for (let i = 1; i < levels; i++) v = { n: v };
      return v;
    };

    it('accepts plain data: text, whole numbers, booleans, null, lists, nested objects, any unicode', () => {
      const good = [
        {},
        { project_id: 'srt1_proj_44', workcell_id: 'cell_09' },
        { n: 0, negative: -42, big: Number.MAX_SAFE_INTEGER, small: -Number.MAX_SAFE_INTEGER, t: true, f: false, nothing: null },
        { list: [1, 'two', { three: [3] }, [[]], null], empty: {}, emptyList: [] },
        { unicode: 'héllo wörld · 日本語 · العربية · 😀🚀 · é', 'ключ': 'значение' },
        { decimal_as_text: '123456789.123456789', huge_as_text: '12345678901234567890123' }
      ];
      for (const c of good) expect(contextProblem(c), JSON.stringify(c).slice(0, 60)).toBeNull();
    });

    it('allows exactly 8 levels, not 9', () => {
      expect(contextProblem(nest(8))).toBeNull();
      expect(contextProblem(nest(9))).toMatch(/deeper than 8/);
      expect(contextProblem({ a: [[[[[[[[1]]]]]]]] })).toMatch(/deeper than 8/); // lists count as levels too
    });

    it('allows 1000 values, not 1001', () => {
      const make = (n: number) => Object.fromEntries(Array.from({ length: n - 1 }, (_, i) => [`k${i}`, i])); // the object itself is one value
      expect(contextProblem(make(1000))).toBeNull();
      expect(contextProblem(make(1001))).toMatch(/more than 1000 values/);
    });

    it('limits keys, text, lists and total size, and gives the same answer at the edge', () => {
      expect(contextProblem({ ['k'.repeat(100)]: 1 })).toBeNull();
      expect(contextProblem({ ['k'.repeat(101)]: 1 })).toMatch(/key is longer than 100/);
      expect(contextProblem({ '': 1 })).toMatch(/key cannot be empty/);
      expect(contextProblem({ t: 'x'.repeat(2000) })).toBeNull();
      expect(contextProblem({ t: 'x'.repeat(2001) })).toMatch(/longer than 2000/);
      expect(contextProblem({ l: Array.from({ length: 200 }, () => 0) })).toBeNull();
      expect(contextProblem({ l: Array.from({ length: 201 }, () => 0) })).toMatch(/at most 200/);
      // total size: build exactly MAX bytes, then one more
      const entries: Record<string, string> = {};
      let i = 0;
      while (Buffer.byteLength(canonicalJsonV2({ ...entries, [`k${String(i).padStart(2, '0')}`]: 'x'.repeat(2000) })) < MAX_CONTEXT_BYTES) entries[`k${String(i++).padStart(2, '0')}`] = 'x'.repeat(2000);
      const room = MAX_CONTEXT_BYTES - Buffer.byteLength(canonicalJsonV2({ ...entries, [`k${String(i).padStart(2, '0')}`]: '' }));
      const exact = { ...entries, [`k${String(i).padStart(2, '0')}`]: 'x'.repeat(room) };
      expect(Buffer.byteLength(canonicalJsonV2(exact))).toBe(MAX_CONTEXT_BYTES);
      expect(contextProblem(exact)).toBeNull();
      const over = { ...entries, [`k${String(i).padStart(2, '0')}`]: 'x'.repeat(room + 1) };
      expect(contextProblem(over)).toMatch(/larger than 16384 bytes/);
    });

    it('refuses what the ledger could not hash identically: decimals and numbers beyond 2^53 - 1', () => {
      for (const n of [1.5, 0.1, -2.25, 1e21, 1e-7, Number.MAX_SAFE_INTEGER + 1, 2 ** 60, NaN, Infinity]) {
        expect(contextProblem({ n }), String(n)).toMatch(/whole numbers|not allowed/);
      }
    });

    it('refuses values the database cannot store and keys that mean something to other software', () => {
      expect(contextProblem({ t: 'a\u0000b' })).toMatch(/NUL/);
      expect(contextProblem({ ['a\u0000b']: 1 })).toMatch(/NUL/);
      expect(contextProblem({ t: '\ud800' })).toMatch(/unpaired surrogate/);
      expect(contextProblem({ t: 'x\udc00y' })).toMatch(/unpaired surrogate/);
      expect(contextProblem({ t: '😀' })).toBeNull(); // a proper pair is fine
      expect(contextProblem(JSON.parse('{"__proto__": 1}'))).toMatch(/__proto__/);
      expect(contextProblem(JSON.parse('{"a": {"__proto__": {"x": 1}}}'))).toMatch(/__proto__/);
    });

    it('must be an object, inside external_context with exactly a namespace and a context', () => {
      for (const c of [[], [1], 'text', 5, true, null, undefined]) expect(contextProblem(c), String(c)).toMatch(/JSON object/);
      expect(externalContextProblem({ namespace: 'com.example' })).toMatch(/context is required/);
      expect(externalContextProblem({ context: {} })).toMatch(/namespace is required/);
      expect(externalContextProblem({ namespace: 'com.example', context: {}, extra: 1 })).toMatch(/Unknown external_context field/);
      expect(externalContextProblem('com.example')).toMatch(/must be/);
      expect(externalContextProblem([])).toMatch(/must be/);
      expect(externalContextProblem({ namespace: 'com.example', context: {} })).toBeNull();
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('requesting a session with context', () => {
    const ctx = { project_id: 'srt1_proj_44', workcell_id: 'cell_09', attempt: 3, tags: ['a', 'b'], nested: { deeper: { ok: true } }, note: 'héllo 😀' };

    it('is recorded with the session: namespace, data and a hash, none of which can change afterwards', async () => {
      const id = await ok(withContext('com.seedclass.srt1', ctx));
      const s = await row(id);
      expect(s.external_context_namespace).toBe('com.seedclass.srt1');
      expect(s.external_context_payload).toEqual(ctx);
      expect(s.external_context_sha256).toBe(externalContextSha256({ namespace: 'com.seedclass.srt1', context: ctx }));
      for (const set of [`external_context_namespace = 'com.other.platform'`, `external_context_payload = '{}'::jsonb`, `external_context_sha256 = '${'0'.repeat(64)}'`, `external_context_namespace = NULL, external_context_payload = NULL, external_context_sha256 = NULL`]) {
        await expect(db.query(`UPDATE work_session SET ${set} WHERE id = $1`, [id]), set).rejects.toThrow(/cannot be changed/);
      }
    });

    it('a request without context still works exactly as before, and records no context', async () => {
      const before = (await events()).length;
      const a = await ok(baseRequest());
      const b = await ok(baseRequest({ external_context: null }));
      for (const id of [a, b]) {
        const s = await row(id);
        expect([s.external_context_namespace, s.external_context_payload, s.external_context_sha256]).toEqual([null, null, null]);
      }
      const ev = (await events()).slice(before);
      expect(ev.every((e) => !('external_context' in e.payload))).toBe(true);
    });

    it('the hash is the same whoever computes it: this code, a plain SHA-256 of the canonical text, and the database itself', async () => {
      const cases: Array<[string, Record<string, unknown>]> = [
        ['com.example.one', {}],
        ['com.example.two', ctx],
        ['com.example.three', { b: 1, a: 2, c: { z: null, y: [true, false] } }], // key order is not significant
        ['com.example.four', { text: 'Zürich · 日本語 · 😀🚀 · é · "quoted" · back\\slash · tab\t · line\nbreak ·  ', 'ключ': 'значение' }],
        ['com.example.five', { max: Number.MAX_SAFE_INTEGER, min: -Number.MAX_SAFE_INTEGER, zero: 0 }]
      ];
      for (const [ns, c] of cases) {
        const id = await ok(withContext(ns, c));
        const stored = (await row(id)).external_context_sha256;
        expect(stored, ns).toBe(sha(canonicalJsonV2({ namespace: ns, context: c })));
        expect(stored, ns).toBe(await dbHash(ns, c));
        expect((await row(id)).external_context_payload, ns).toEqual(c);
      }
    });

    it('is shown on reading: to the principal that asked, to a principal that can approve, to the creator; to no one else', async () => {
      const id = await ok(withContext('com.seedclass.srt1', ctx));
      const expected = { namespace: 'com.seedclass.srt1', context: ctx, sha256: externalContextSha256({ namespace: 'com.seedclass.srt1', context: ctx }) };
      expect((await call(requester, 'GET', `/work-sessions/${id}`)).body.work_session.external_context).toEqual(expected);
      expect((await call(approver, 'GET', `/work-sessions/${id}`)).body.work_session.external_context).toEqual(expected);
      expect((await call(reader, 'GET', `/work-sessions/${id}`)).status).toBe(404);
      const listed = await h.api(creator, 'GET', `/projects/${projectId}/work-sessions`);
      expect(listed.body.work_sessions.find((s: any) => s.id === id).external_context).toEqual(expected);
      expect((await call(requester, 'GET', '/work-sessions')).body.work_sessions.find((s: any) => s.id === id).external_context).toEqual(expected);
    });

    it('a request that has no usable context is refused, with the reason, and nothing is written', async () => {
      const n = await count();
      const ev = (await events()).length;
      const bad: Array<[string, unknown, RegExp]> = [
        ['no context', baseRequest({ external_context: { namespace: 'com.example' } }), /context is required/],
        ['no namespace', baseRequest({ external_context: { context: {} } }), /namespace is required/],
        ['extra field', baseRequest({ external_context: { namespace: 'com.example', context: {}, extra: 1 } }), /Unknown external_context/],
        ['list context', withContext('com.example', [1]), /JSON object/],
        ['text context', withContext('com.example', 'x'), /JSON object/],
        ['null context', withContext('com.example', null), /JSON object/],
        ['text instead of object', baseRequest({ external_context: 'com.example' }), /must be/],
        ['uppercase namespace', withContext('Com.Example', {}), /reverse-DNS/],
        ['one label', withContext('srt1', {}), /reverse-DNS/],
        ['reserved namespace', withContext('custody.core', {}), /reserved/],
        ['decimal', withContext('com.example', { x: 1.5 }), /whole numbers/],
        ['big number', withContext('com.example', { x: 2 ** 53 }), /whole numbers/],
        ['deep', withContext('com.example', { a: { b: { c: { d: { e: { f: { g: { h: { i: 1 } } } } } } } } }), /deeper than 8/],
        ['long text', withContext('com.example', { t: 'x'.repeat(2001) }), /longer than 2000/]
      ];
      for (const [label, body, why] of bad) {
        const r = await call(requester, 'POST', '/work-sessions', body);
        expect(r.status, label).toBe(400);
        expect(r.body.error, label).toMatch(why);
      }
      // values a JavaScript object literal cannot carry are sent as raw JSON
      const raws: Array<[string, string, RegExp]> = [
        ['proto key', JSON.stringify(baseRequest()).replace(/}$/, ',"external_context":{"namespace":"com.example","context":{"__proto__":1}}}'), /__proto__/],
        ['NUL', JSON.stringify(baseRequest()).replace(/}$/, ',"external_context":{"namespace":"com.example","context":{"t":"a\\u0000b"}}}'), /NUL/],
        ['lone surrogate', JSON.stringify(baseRequest()).replace(/}$/, ',"external_context":{"namespace":"com.example","context":{"t":"\\ud800"}}}'), /unpaired surrogate/],
        ['huge integer', JSON.stringify(baseRequest()).replace(/}$/, ',"external_context":{"namespace":"com.example","context":{"n":9007199254740993}}}'), /whole numbers/],
        ['exponent', JSON.stringify(baseRequest()).replace(/}$/, ',"external_context":{"namespace":"com.example","context":{"n":1e21}}}'), /whole numbers/]
      ];
      for (const [label, raw, why] of raws) {
        const r = await call(requester, 'POST', '/work-sessions', undefined, raw);
        expect(r.status, label).toBe(400);
        expect(r.body.error, label).toMatch(why);
      }
      expect(await count()).toBe(n);
      expect((await events()).length).toBe(ev);
    });

    it('the other checks still come first: no credential is 401, no scope is 403, an unreachable project is 404', async () => {
      expect((await call(null, 'POST', '/work-sessions', withContext('com.example', {}))).status).toBe(401);
      expect((await call(reader, 'POST', '/work-sessions', withContext('com.example', {}))).status).toBe(403);
      expect((await call(requester, 'POST', '/work-sessions', withContext('com.example', {}, { project_id: otherProjectId }))).status).toBe(404);
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('the platform treats context as opaque (platform neutrality)', () => {
    it('different platforms, different data, the same behavior: nothing but the context itself differs', async () => {
      const shapes: Array<[string, Record<string, unknown>]> = [
        ['com.seedclass.srt1', { project_id: 'srt1_proj_44', workcell_id: 'cell_09' }],
        ['org.example.ci', { pipeline: 12, branch: 'main', labels: ['x'] }],
        ['io.github.someone.ide', { workspace: { folder: '/home/u/app', tabs: [1, 2, 3] } }],
        ['net.example.unknown-platform', { anything: 'at all', 'even a key with spaces': { and: [] } }]
      ];
      const norm = (s: any) => {
        const { id, created_at, expires_at, branch_name, external_context_namespace, external_context_payload, external_context_sha256, ...rest } = s;
        return rest;
      };
      const results = [];
      for (const [ns, c] of shapes) {
        const before = (await events()).length;
        const id = await ok(withContext(ns, c));
        const s = await row(id);
        const ev = (await events()).slice(before);
        expect(ev).toHaveLength(1);
        const { external_context, ...payload } = ev[0].payload;
        const { branch_name, expires_at, ...payloadRest } = payload;
        results.push({ s: norm(s), ev: { action: ev[0].action, actor_type: ev[0].actor_type, actor_id: ev[0].actor_id, payload: payloadRest } });
        expect(external_context).toMatchObject({ namespace: ns, context: c });
      }
      for (const r of results.slice(1)) expect(r).toEqual(results[0]);
    });

    it('context never changes who may do what: content that looks like authority is just data', async () => {
      const hostile = {
        status: 'approved', approved_by: `creator:${creator.id}`, sponsor_id: other.id, project_id: otherProjectId, repository_id: crypto.randomUUID(),
        scopes: ['work-sessions:approve', 'repositories:promote'], permissions: ['*'], role: 'admin', requested_by_principal_id: approver.id,
        action: 'work_session.approved', actor_type: 'creator', actor_id: creator.id, subject_id: crypto.randomUUID(), hash: 'f'.repeat(64), seq: 1,
        executor: { type: 'human_developer' }, expires_in_seconds: 86400, base_commit: 'b'.repeat(40), allowed_write_paths: ['**'], prohibited_paths: []
      };
      const before = (await events()).length;
      const id = await ok(withContext('com.attacker.example', hostile));
      const s = await row(id);
      expect(s).toMatchObject({ status: 'requested', project_id: projectId, sponsor_id: creator.id, requested_by_principal_id: requester.id, executor_type: 'ai_assistant', approved_by: null, approved_at: null });
      expect(s.base_commit).toBe('a'.repeat(40));
      expect(s.allowed_write_paths).toEqual([]);
      const ev = (await events()).slice(before);
      expect(ev).toHaveLength(1);
      expect(ev[0]).toMatchObject({ action: 'work_session.requested', actor_type: 'system', actor_id: `principal:${requester.id}`, subject_id: id });
      expect(ev[0].payload.external_context.context).toEqual(hostile); // kept as data, one level down
      // and it grants nothing to read either
      expect((await call(reader, 'GET', `/work-sessions/${id}`)).status).toBe(404);
      expect((await call(approver, 'GET', `/work-sessions/${id}`)).status).toBe(200); // by its own scope, not by what the context says
    });

    it('the namespace is a label, not an identity: the session records which principal sent it, whatever namespace it claims', async () => {
      const other2 = await caller('another-requester', ['work-sessions:request', 'work-sessions:read']);
      const r = await call(other2, 'POST', '/work-sessions', withContext('com.seedclass.srt1', { claims: 'to be srt1' }));
      expect(r.status).toBe(202);
      expect((await row(r.body.session_id)).requested_by_principal_id).toBe(other2.id);
      const requestedEvent = (await events()).find((e) => e.subject_id === r.body.session_id)!;
      expect(requestedEvent.actor_id).toBe(`principal:${other2.id}`);
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('the permanent record', () => {
    it('the request and the approval carry the context, and the project\'s record verifies', async () => {
      const ctx = { job: 'j-77', retry: 0, parts: ['x', 'y'] };
      const before = (await events(ledgerProjectId)).length;
      const r = await call(requester, 'POST', '/work-sessions', withContext('com.seedclass.srt1', ctx, { project_id: ledgerProjectId, repository_id: ledgerRepoId }));
      expect(r.status).toBe(202);
      const id = r.body.session_id as string;
      expect((await h.api(creator, 'POST', `/projects/${ledgerProjectId}/work-sessions/${id}/approve`, {})).status).toBe(200);
      const hash = externalContextSha256({ namespace: 'com.seedclass.srt1', context: ctx });
      const ev = (await events(ledgerProjectId)).slice(before);
      expect(ev.map((e) => e.action)).toEqual(['work_session.requested', 'work_session.approved']);
      expect(ev[0].payload.external_context).toEqual({ namespace: 'com.seedclass.srt1', context: ctx, sha256: hash });
      expect(ev[1].payload.external_context).toEqual({ namespace: 'com.seedclass.srt1', sha256: hash }); // what was approved, by hash
      // the hash in the record is the hash of the stored copy, which is the hash the database computes
      expect((await row(id)).external_context_sha256).toBe(hash);
      expect(hash).toBe(await dbHash('com.seedclass.srt1', ctx));
      const check = await verifyServerProjectEvents(ledgerProjectId);
      expect(check.isValid, check.reason).toBe(true);
    });

    it('changing the context in the record is detected', async () => {
      // an isolated project, so the damage done here is not shared with the other tests
      const pid = (await db.query(`INSERT INTO project (creator_id, name, purpose) VALUES ($1, 'Tamper', 'x') RETURNING id`, [creator.id])).rows[0].id as string;
      const rid = (await db.query(`INSERT INTO repository (project_id, github_repo_id, full_name) VALUES ($1, 'tamper', 'org/tamper') RETURNING id`, [pid])).rows[0].id as string;
      const r = await call(requester, 'POST', '/work-sessions', withContext('com.seedclass.srt1', { account: 'alice' }, { project_id: pid, repository_id: rid }));
      expect(r.status).toBe(202);
      expect((await verifyServerProjectEvents(pid)).isValid).toBe(true);
      await withTriggersBypassed(admin, async (c) => {
        const e = (await c.query(`SELECT id, canonical_payload FROM event WHERE project_id = $1 AND action = 'work_session.requested'`, [pid])).rows[0];
        const forged = e.canonical_payload.replace('alice', 'mallory');
        expect(forged).not.toBe(e.canonical_payload);
        // a careful forger keeps the two stored copies consistent with each other; only the hash gives it away
        await c.query(`UPDATE event SET canonical_payload = $2::text, payload = ($2::text)::jsonb WHERE id = $1`, [e.id, forged]);
      });
      const after = await verifyServerProjectEvents(pid);
      expect(after.isValid).toBe(false);
      expect(after.brokenAtSeq).toBe(1);
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('secrets never reach the record', () => {
    const pem = () => crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs1', format: 'pem' }).toString();
    const awsKey = () => 'AKIA' + Array.from(crypto.randomBytes(16), (b) => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[b % 32]).join('');
    const githubToken = () => 'ghp_' + Array.from(crypto.randomBytes(36), (b) => 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'[b % 62]).join('');

    it('a key in the context is refused, the rules are named, the key is not echoed, and nothing is written', async () => {
      const n = await count();
      const ev = (await events()).length;
      for (const [label, secret] of [['private key', pem()], ['aws key', awsKey()], ['github token', githubToken()]] as const) {
        const r = await call(requester, 'POST', '/work-sessions', withContext('com.example', { deploy: { credentials: secret } }));
        expect(r.status, label).toBe(400);
        expect(r.body.error, label).toMatch(/appears to contain a secret/);
        expect(r.body.error, label).toMatch(/permanent/);
        const fragment = secret.includes('\n') ? secret.split('\n')[1] : secret.slice(4, 16); // a piece of the secret itself
        expect(fragment.length, label).toBeGreaterThan(8);
        expect(JSON.stringify(r.body), label).not.toContain(fragment);
      }
      expect(await count()).toBe(n);
      expect((await events()).length).toBe(ev);
    });

    it('the same check covers everything else the caller wrote, because all of it is recorded for good', async () => {
      const key = pem();
      const token = githubToken();
      for (const [label, body] of [
        ['objective', baseRequest({ objective: `Deploy using ${token} as the credential` })],
        ['executor name', baseRequest({ executor: { type: 'ai_assistant', display_name: token } })],
        ['context and objective together', withContext('com.example', { k: key })]
      ] as Array<[string, unknown]>) {
        const r = await call(requester, 'POST', '/work-sessions', body);
        expect(r.status, label).toBe(400);
        expect(r.body.error, label).toMatch(/secret/);
      }
    });

    it('ordinary identifiers and hashes are not mistaken for secrets', async () => {
      const id = await ok(withContext('com.seedclass.srt1', {
        job_id: crypto.randomUUID(), commit: crypto.randomBytes(20).toString('hex'), digest: sha('anything'), build: 'build-2026-11-09-17', url: 'https://example.com/jobs/12', note: 'Refactor the login route'
      }, { objective: 'Fix the flaky retry test in the checkout service' }));
      expect(id).toBeTruthy();
    });

    it('with no scanner, or one that cannot run, nothing is recorded (it fails closed, like the gateway)', async () => {
      expect(await scanTextForSecrets('anything', null)).toEqual({ status: 'unavailable' });
      expect(await scanTextForSecrets('anything', { path: '/nonexistent/gitleaks', version: 'none' })).toEqual({ status: 'failed' });
      const broken = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'fake-scanner-')), 'gitleaks');
      fs.writeFileSync(broken, '#!/bin/sh\nexit 7\n', { mode: 0o755 });
      expect(await scanTextForSecrets('anything', { path: broken, version: 'fake' })).toEqual({ status: 'failed' });
      const finds = path.join(path.dirname(broken), 'gitleaks-finds');
      fs.writeFileSync(finds, '#!/bin/sh\nexit 42\n', { mode: 0o755 });
      expect(await scanTextForSecrets('anything', { path: finds, version: 'fake' })).toEqual({ status: 'found', rules: [], count: 1 }); // exit 42 with no report still means found
      expect(await scanTextForSecrets('{"note": "plain words"}')).toEqual({ status: 'clean' });
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('what the database refuses, whoever writes', () => {
    const insert = (over: Record<string, unknown>) => {
      const id = crypto.randomUUID();
      const v: Record<string, any> = {
        id, project_id: projectId, repository_id: repoId, session_type: 'automated_work_session', executor_type: 'ai_assistant', sponsor_id: creator.id,
        objective: 'x', base_commit: 'b'.repeat(40), branch_name: `session/${id}/work`, repository_access: 'read', allowed_read_paths: ['a'],
        expires_at: new Date(Date.now() + 3600_000).toISOString(), ...over
      };
      const cols = Object.keys(v);
      return db.query(`INSERT INTO work_session (${cols.join(', ')}) VALUES (${cols.map((_, i) => `$${i + 1}`).join(', ')})`, cols.map((c) => (c === 'external_context_payload' && v[c] !== null ? JSON.stringify(v[c]) : v[c])));
    };
    const good = { external_context_namespace: 'com.example.ok', external_context_payload: { a: 1 }, external_context_sha256: 'a'.repeat(64) };

    it('the three columns go together or not at all', async () => {
      await expect(insert(good)).resolves.toBeTruthy();
      for (const part of ['external_context_namespace', 'external_context_payload', 'external_context_sha256']) {
        await expect(insert({ ...good, [part]: null }), part).rejects.toThrow(/chk_session_external_context/);
      }
      for (const part of Object.keys(good)) await expect(insert({ [part]: (good as any)[part] }), part).rejects.toThrow(/chk_session_external_context/);
    });

    it('the namespace, the hash and the shape of the data are checked', async () => {
      for (const ns of ['Com.Example', 'single', 'custody.core', 'a..b', 'x'.repeat(101) + '.com']) {
        await expect(insert({ ...good, external_context_namespace: ns }), ns).rejects.toThrow(/chk_session_external_context/);
      }
      await expect(insert({ ...good, external_context_sha256: 'xyz' })).rejects.toThrow(/chk_session_external_context/);
      await expect(insert({ ...good, external_context_sha256: 'A'.repeat(64) })).rejects.toThrow(/chk_session_external_context/);
      for (const bad of [[1, 2], 'text', 5, null]) {
        await expect(insert({ ...good, external_context_payload: bad as any }), JSON.stringify(bad)).rejects.toThrow();
      }
      await expect(insert({ ...good, external_context_payload: { big: 'x'.repeat(33000) } })).rejects.toThrow(/chk_session_external_context/);
    });

    it('a human door\'s session has no context', async () => {
      const door = (await db.query(`INSERT INTO door (project_id, job_description, rights_type, expires_at, developer_email) VALUES ($1, 'j', 'contribute', now() + interval '1 day', 'd@example.com') RETURNING id`, [projectId])).rows[0].id;
      await expect(db.query(`UPDATE work_session SET external_context_namespace = 'com.example.x', external_context_payload = '{}'::jsonb, external_context_sha256 = $2 WHERE door_id = $1`, [door, 'a'.repeat(64)])).rejects.toThrow(/chk_session_external_context/);
    });
  });
});
