import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import { getAdminPool, getDbPool, runMigrations, verifyServerProjectEvents } from '../server/db';
import { addPrincipalKey, registerPrincipal, revokeKey, setPrincipalStatus } from '../server/servicePrincipals';
import { evaluateEvidence, evidenceSigningInput, payloadSha256 } from '../server/evidence';
import { assertPoolTargetsTestDb } from './support/safety';
import { withTriggersBypassed } from './support/cleanup';
import { startHarness, Harness } from './support/apiHarness';
import { startApp, RunningApp } from './support/api';
import { installGitleaks } from '../scripts/install-gitleaks';
import { assertion, newKey, sign, TestAlg, TestKey } from './support/principalKeys';

/**
 * Evidence (CL-12): requirements named in the request, signed statements from the named issuer about commits the session produced,
 * and the evaluation of whether a requirement is met. Real database, real HTTP for machine callers (the real app).
 */
describe('Evidence', () => {
  const db = getDbPool()!;
  const admin = getAdminPool()!;
  let h: Harness;
  let app: RunningApp;
  let creator: any, other: any;
  let projectId = '';
  let repoId = '';
  let otherProjectId = '';
  const sha = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
  const commitId = () => crypto.randomBytes(20).toString('hex');

  interface Caller { id: string; keyId: string; key: TestKey }
  async function caller(label: string, scopes: string[], alg: TestAlg = 'Ed25519', who = creator): Promise<Caller> {
    const p = await registerPrincipal(db, who.id, { name: `${label}-${crypto.randomUUID().slice(0, 6)}`, platform_type: 'agent', environment: 'development', allowed_scopes: scopes } as any, 'test');
    const key = newKey(alg);
    return { id: p.id, keyId: (await addPrincipalKey(db, p.id, key.publicJwk, 'test')).key_id, key };
  }
  const v2 = async (c: Caller, method: string, p: string, body?: unknown) => {
    const res = await fetch(`${app.base}/api/v2${p}`, {
      method,
      headers: { Authorization: `Bearer ${assertion(c.key, c.keyId, c.id)}`, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    return { status: res.status, body: (await res.json().catch(() => ({}))) as any };
  };
  let requester: Caller, ciA: Caller, ciB: Caller, noScope: Caller, foreign: Caller, approver: Caller;

  const base = (over: Record<string, unknown> = {}) => ({
    project_id: projectId,
    repository_id: repoId,
    executor: { type: 'ai_assistant', display_name: 'Refactor Engine' },
    sponsor: { type: 'creator', id: creator.id },
    objective: 'Add the export page',
    base_commit: 'a'.repeat(40),
    access: { repository: 'read_and_push', allowed_read_paths: ['src/**'], allowed_write_paths: ['src/lib/**'], prohibited_paths: [] },
    expires_in_seconds: 3600,
    ...over
  });
  const SPEC = sha('spec v1');

  /** A running session with some commits, made the way the product makes them (request, approval) and then moved along by the admin account. */
  async function session(reqs: unknown[] | undefined, commits = 2) {
    const r = await v2(requester, 'POST', '/work-sessions', base(reqs === undefined ? {} : { evidence_requirements: reqs }));
    expect(r.status, JSON.stringify(r.body)).toBe(202);
    const id = r.body.session_id as string;
    expect((await h.api(creator, 'POST', `/projects/${projectId}/work-sessions/${id}/approve`, {})).status).toBe(200);
    await admin.query(`UPDATE work_session SET status = 'active' WHERE id = $1`, [id]);
    const shas: string[] = [];
    for (let i = 0; i < commits; i++) {
      const real = commitId();
      shas.push(real);
      await admin.query(`INSERT INTO session_commit (work_session_id, view_sha, real_sha, parent_view_sha, declared_author) VALUES ($1, $2, $3, $4, 'x')`, [id, commitId(), real, commitId()]);
    }
    return { id, commits: shas };
  }

  /** A signed statement as the issuer's own tooling would make it. */
  function statement(sessionId: string, issuer: Caller, over: Record<string, unknown> = {}, payload: Record<string, unknown> = {}) {
    const fields = {
      work_session_id: sessionId,
      evidence_type: 'tests',
      subject_commit: '',
      status: 'pass',
      specification_hash: SPEC,
      evidence_hash: sha(`report-${crypto.randomUUID()}`),
      payload_sha256: payloadSha256(payload),
      issued_at: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
      ...over
    };
    const { work_session_id: _w, payload_sha256: _p, ...rest } = fields;
    return {
      ...rest,
      payload,
      signature: { key_id: issuer.keyId, algorithm: issuer.key.alg, value: sign(issuer.key, evidenceSigningInput(fields as any)) }
    };
  }
  const submit = (id: string, issuer: Caller, body: unknown) => v2(issuer, 'POST', `/work-sessions/${id}/evidence`, body);
  const REQ = (over: Record<string, unknown> = {}) => ({ type: 'tests', issuer_principal_id: ciA.id, ...over });
  const events = async () => (await db.query('SELECT action, actor_type, actor_id, subject_id, payload FROM event WHERE project_id = $1 ORDER BY seq', [projectId])).rows;
  const submissions = async (id: string) => (await db.query('SELECT * FROM evidence_submission WHERE work_session_id = $1', [id])).rows;

  beforeAll(async () => {
    await assertPoolTargetsTestDb(admin);
    expect((await runMigrations()).success).toBe(true);
    await installGitleaks();
    h = await startHarness();
    app = await startApp();
    creator = await h.newCreator('owner');
    other = await h.newCreator('other');
    projectId = (await db.query(`INSERT INTO project (creator_id, name, purpose) VALUES ($1, 'P', 'x') RETURNING id`, [creator.id])).rows[0].id;
    otherProjectId = (await db.query(`INSERT INTO project (creator_id, name, purpose) VALUES ($1, 'Q', 'x') RETURNING id`, [other.id])).rows[0].id;
    repoId = (await db.query(`INSERT INTO repository (project_id, github_repo_id, full_name) VALUES ($1, '1', 'org/app') RETURNING id`, [projectId])).rows[0].id;
    requester = await caller('requester', ['work-sessions:request', 'work-sessions:read', 'work-sessions:close-own']);
    ciA = await caller('ci-a', ['evidence:submit']);
    ciB = await caller('ci-b', ['evidence:submit'], 'ES256');
    noScope = await caller('noscope', ['work-sessions:read']);
    foreign = await caller('foreign', ['evidence:submit'], 'Ed25519', other);
    approver = await caller('approver', ['work-sessions:approve', 'work-sessions:read']);
  }, 120_000);
  afterAll(async () => {
    await app?.stop();
    await h?.stop();
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('requirements in the request', () => {
    it('are accepted, shown to whoever approves, and written into the record', async () => {
      const r = await v2(requester, 'POST', '/work-sessions', base({ evidence_requirements: [REQ({ specification_hash: SPEC, max_age_seconds: 600 }), { type: 'review.security', issuer_principal_id: ciB.id, required: false, tied_to_commit: false }] }));
      expect(r.status, JSON.stringify(r.body)).toBe(202);
      const id = r.body.session_id;
      const view = (await h.api(creator, 'GET', `/projects/${projectId}/work-sessions`)).body.work_sessions.find((s: any) => s.id === id);
      expect(view.evidence_requirements).toEqual([
        { type: 'review.security', issuer_principal_id: ciB.id, required: false, tied_to_commit: false, specification_hash: null, max_age_seconds: null, issuer_is_requester: false },
        { type: 'tests', issuer_principal_id: ciA.id, required: true, tied_to_commit: true, specification_hash: SPEC, max_age_seconds: 600, issuer_is_requester: false }
      ]);
      const requested = (await events()).find((e) => e.action === 'work_session.requested' && e.subject_id === id)!;
      expect(requested.payload.evidence_requirements).toHaveLength(2);
      // a session with none still works and shows an empty list
      const none = await v2(requester, 'POST', '/work-sessions', base());
      expect(none.status).toBe(202);
      const v = (await v2(requester, 'GET', `/work-sessions/${none.body.session_id}`)).body.work_session;
      expect(v.evidence_requirements).toEqual([]);
    });

    it('are refused when malformed, or when an issuer could not satisfy them; nothing is recorded', async () => {
      const before = (await events()).length;
      const sessions = (await db.query(`SELECT count(*)::int AS n FROM work_session`)).rows[0].n;
      const retired = await caller('retired', ['evidence:submit']);
      await setPrincipalStatus(db, retired.id, 'suspended', 'test');
      const bad: Array<[string, unknown, number, RegExp]> = [
        ['not a list', 'tests', 400, /must be a list/],
        ['not an object', [1], 400, /must be an object/],
        ['unknown field', [REQ({ priority: 1 })], 400, /unknown field/],
        ['bad type', [REQ({ type: 'Tests!' })], 400, /type must be/],
        ['twice', [REQ(), REQ()], 400, /listed twice/],
        ['no issuer', [{ type: 'tests' }], 400, /issuer_principal_id/],
        ['bad hash', [REQ({ specification_hash: 'abc' })], 400, /specification_hash/],
        ['max age too small', [REQ({ max_age_seconds: 5 })], 400, /max_age_seconds/],
        ['required not boolean', [REQ({ required: 'yes' })], 400, /required/],
        ['too many', Array.from({ length: 11 }, (_, i) => REQ({ type: `t${i}` })), 400, /at most 10/],
        ['another owner\'s principal', [REQ({ issuer_principal_id: foreign.id })], 422, /not a principal of this owner/],
        ['unknown principal', [REQ({ issuer_principal_id: crypto.randomUUID() })], 422, /not a principal of this owner/],
        ['principal without the scope', [REQ({ issuer_principal_id: noScope.id })], 422, /evidence:submit/],
        ['suspended principal', [REQ({ issuer_principal_id: retired.id })], 422, /not active/]
      ];
      for (const [why, value, status, message] of bad) {
        const r = await v2(requester, 'POST', '/work-sessions', base({ evidence_requirements: value }));
        expect(r.status, `${why}: ${JSON.stringify(r.body)}`).toBe(status);
        expect(r.body.error, why).toMatch(message);
      }
      expect((await events()).length).toBe(before);
      expect((await db.query(`SELECT count(*)::int AS n FROM work_session`)).rows[0].n).toBe(sessions);
    });

    it('an issuer limited to other projects cannot be named', async () => {
      const narrow = await caller('narrow', ['evidence:submit']);
      await admin.query(`UPDATE service_principal SET allowed_project_ids = $2 WHERE id = $1`, [narrow.id, [crypto.randomUUID()]]);
      const r = await v2(requester, 'POST', '/work-sessions', base({ evidence_requirements: [REQ({ issuer_principal_id: narrow.id })] }));
      expect(r.status).toBe(422);
      expect(r.body.error).toMatch(/cannot act on this project/);
    });

    it('the record is written once: the application cannot change or delete a requirement, and cannot add one later', async () => {
      const s = await session([REQ()]);
      await expect(db.query(`UPDATE evidence_requirement SET is_required = false WHERE work_session_id = $1`, [s.id])).rejects.toThrow();
      await expect(db.query(`DELETE FROM evidence_requirement WHERE work_session_id = $1`, [s.id])).rejects.toThrow();
      // even the owner of the tables is stopped by the trigger, and nothing can be added once the request has been approved
      await expect(admin.query(`UPDATE evidence_requirement SET is_required = false WHERE work_session_id = $1`, [s.id])).rejects.toThrow(/written once/);
      await expect(admin.query(`INSERT INTO evidence_requirement (work_session_id, evidence_type, issuer_principal_id) VALUES ($1, 'late', $2)`, [s.id, ciA.id])).rejects.toThrow(/pending request/);
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('submitting', () => {
    it('records a signed statement (Ed25519 and ES256), writes the event with hashes only, and a repeat is harmless', async () => {
      const s = await session([REQ(), { type: 'review', issuer_principal_id: ciB.id }]);
      const payload = { suite: 'unit', passed: 120, failed: 0 };
      const a = statement(s.id, ciA, { subject_commit: s.commits[0] }, payload);
      const r = await submit(s.id, ciA, a);
      expect(r.status, JSON.stringify(r.body)).toBe(201);
      expect(r.body).toMatchObject({ recorded: true, evidence_type: 'tests', subject_commit: s.commits[0], status: 'pass', issuer_principal_id: ciA.id, signature: { algorithm: 'Ed25519' } });
      const b = statement(s.id, ciB, { evidence_type: 'review', subject_commit: s.commits[0] });
      expect((await submit(s.id, ciB, b)).status).toBe(201); // ES256

      const rows = await submissions(s.id);
      expect(rows).toHaveLength(2);
      expect(rows.find((x) => x.evidence_type === 'tests')).toMatchObject({ raw_payload: payload, signature_key_id: ciA.keyId, payload_sha256: payloadSha256(payload) });
      const ev = (await events()).filter((e) => e.action === 'evidence.submitted' && e.subject_id === s.id);
      expect(ev).toHaveLength(2);
      expect(ev[0]).toMatchObject({ actor_type: 'system', actor_id: `principal:${ciA.id}` });
      expect(ev[0].payload).toMatchObject({ evidence_type: 'tests', subject_commit: s.commits[0], status: 'pass', issuer_is_requester: false });
      expect(JSON.stringify(ev[0].payload)).not.toContain('passed'); // the payload itself is not in the ledger, only its hash
      expect(ev[0].payload.payload_sha256).toBe(payloadSha256(payload));

      const again = await submit(s.id, ciA, a); // the same statement again: nothing new
      expect(again.status).toBe(200);
      expect(again.body).toMatchObject({ recorded: false, id: r.body.id });
      expect(await submissions(s.id)).toHaveLength(2);
      expect((await events()).filter((e) => e.action === 'evidence.submitted' && e.subject_id === s.id)).toHaveLength(2);
    });

    it('is open only to the issuer the request named, and only with the scope', async () => {
      const s = await session([REQ()]);
      const body = (who: Caller) => statement(s.id, who, { subject_commit: s.commits[0] });
      expect((await submit(s.id, noScope, body(noScope))).status).toBe(403);
      expect((await submit(s.id, ciB, body(ciB))).status).toBe(404); // right scope, but not named
      expect((await submit(s.id, requester, body(requester))).status).toBe(403); // the requester has no evidence:submit
      expect((await submit(s.id, foreign, body(foreign))).status).toBe(404);
      expect((await submit(crypto.randomUUID(), ciA, body(ciA))).status).toBe(404);
      expect(await submissions(s.id)).toHaveLength(0);
      // a kind of evidence the request did not ask for is not accepted either
      expect((await submit(s.id, ciA, statement(s.id, ciA, { evidence_type: 'other', subject_commit: s.commits[0] }))).status).toBe(404);
    });

    it('refuses anything whose signature does not verify over exactly this statement', async () => {
      const s = await session([REQ()]);
      const good = statement(s.id, ciA, { subject_commit: s.commits[0] });
      const cases: Array<[string, any]> = [
        ['changed status', { ...good, status: 'fail' }],
        ['changed commit', { ...good, subject_commit: s.commits[1] }],
        ['changed evidence hash', { ...good, evidence_hash: sha('other') }],
        ['changed specification', { ...good, specification_hash: sha('other spec') }],
        ['changed payload', { ...good, payload: { extra: 1 } }],
        ['changed time', { ...good, issued_at: '2020-01-01T00:00:00Z' }],
        ['signed for another session', statement(crypto.randomUUID(), ciA, { subject_commit: s.commits[0] })],
        ['signed by another key', { ...good, signature: { ...good.signature, value: sign(ciB.key, 'x') } }]
      ];
      for (const [why, body] of cases) {
        const r = await submit(s.id, ciA, body);
        expect(r.status, `${why}: ${JSON.stringify(r.body)}`).toBe(422);
      }
      expect(await submissions(s.id)).toHaveLength(0);
    });

    it('refuses a key that is not the caller\'s, is revoked, or whose algorithm is stated wrongly', async () => {
      const s = await session([REQ()]);
      const good = statement(s.id, ciA, { subject_commit: s.commits[0] });
      const theirs = await submit(s.id, ciA, { ...good, signature: { ...good.signature, key_id: ciB.keyId } });
      expect(theirs.status).toBe(422);
      expect(theirs.body.code).toBe('bad_key');
      const wrongAlg = await submit(s.id, ciA, { ...good, signature: { ...good.signature, algorithm: 'ES256' } });
      expect(wrongAlg.body.code).toBe('bad_key');
      const rotating = await caller('rotating', ['evidence:submit']);
      const s2 = await session([REQ({ issuer_principal_id: rotating.id })]);
      const second = newKey('Ed25519');
      const secondId = (await addPrincipalKey(db, rotating.id, second.publicJwk, 'test')).key_id;
      await revokeKey(db, rotating.keyId, 'test');
      // the revoked key can no longer even log in, and a statement signed with it is not taken from the new one either
      expect((await submit(s2.id, rotating, statement(s2.id, rotating, { subject_commit: s2.commits[0] }))).status).toBe(401);
      const viaNew: Caller = { id: rotating.id, keyId: secondId, key: second };
      expect((await submit(s2.id, viaNew, statement(s2.id, viaNew, { subject_commit: s2.commits[0] }))).status).toBe(201);
    });

    it('is bound to the session\'s own commits, and to a time after the commit existed', async () => {
      const s = await session([REQ()]);
      const unknown = await submit(s.id, ciA, statement(s.id, ciA, { subject_commit: commitId() }));
      expect(unknown.body.code).toBe('unknown_commit');
      const other = await session([REQ()]);
      expect((await submit(s.id, ciA, statement(s.id, ciA, { subject_commit: other.commits[0] }))).body.code).toBe('unknown_commit'); // another session's commit
      const early = await submit(s.id, ciA, statement(s.id, ciA, { subject_commit: s.commits[0], issued_at: '2020-01-01T00:00:00Z' }));
      expect(early.body.code).toBe('issued_before_commit');
      const future = await submit(s.id, ciA, statement(s.id, ciA, { subject_commit: s.commits[0], issued_at: new Date(Date.now() + 3600_000).toISOString().replace(/\.\d+Z$/, 'Z') }));
      expect(future.body.code).toBe('issued_in_future');
      expect(await submissions(s.id)).toHaveLength(0);
    });

    it('holds to the specification the request pinned', async () => {
      const s = await session([REQ({ specification_hash: SPEC })]);
      const wrong = await submit(s.id, ciA, statement(s.id, ciA, { subject_commit: s.commits[0], specification_hash: sha('looser spec') }));
      expect(wrong.status).toBe(422);
      expect(wrong.body.code).toBe('wrong_specification');
      expect((await submit(s.id, ciA, statement(s.id, ciA, { subject_commit: s.commits[0] }))).status).toBe(201);
    });

    it('only while the session is running', async () => {
      const waiting = await v2(requester, 'POST', '/work-sessions', base({ evidence_requirements: [REQ()] }));
      const r1 = await submit(waiting.body.session_id, ciA, statement(waiting.body.session_id, ciA, { subject_commit: commitId() }));
      expect(r1.status).toBe(409);
      const s = await session([REQ()]);
      expect((await v2(requester, 'POST', `/work-sessions/${s.id}/close`)).status).toBe(200);
      const r2 = await submit(s.id, ciA, statement(s.id, ciA, { subject_commit: s.commits[0] }));
      expect(r2.status).toBe(409);
      expect(r2.body.code).toBe('not_running');
    });

    it('never replaces what is recorded: a different result with the same evidence hash is a conflict', async () => {
      const s = await session([REQ()]);
      const hash = sha('one report');
      expect((await submit(s.id, ciA, statement(s.id, ciA, { subject_commit: s.commits[0], evidence_hash: hash }))).status).toBe(201);
      const flipped = await submit(s.id, ciA, statement(s.id, ciA, { subject_commit: s.commits[0], evidence_hash: hash, status: 'fail' }));
      expect(flipped.status).toBe(409);
      expect(flipped.body.code).toBe('conflict');
      expect((await submissions(s.id))[0].status).toBe('pass');
    });

    it('is checked for malformed input and for secrets in the payload (the record is permanent)', async () => {
      const s = await session([REQ()]);
      const good = statement(s.id, ciA, { subject_commit: s.commits[0] });
      for (const [why, body] of [
        ['unknown field', { ...good, extra: 1 }],
        ['bad status', { ...good, status: 'maybe' }],
        ['bad commit', { ...good, subject_commit: 'abc' }],
        ['bad time', { ...good, issued_at: '2026-01-01 10:00' }],
        ['time with fractions', { ...good, issued_at: '2026-01-01T10:00:00.5Z' }],
        ['bad signature shape', { ...good, signature: { key_id: ciA.keyId } }],
        ['decimals in the payload', { ...good, payload: { score: 0.5 } }]
      ] as const) {
        expect((await submit(s.id, ciA, body)).status, why).toBe(400);
      }
      const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const pem = privateKey.export({ type: 'pkcs1', format: 'pem' }).toString();
      const leaky = await submit(s.id, ciA, statement(s.id, ciA, { subject_commit: s.commits[0] }, { log: pem }));
      expect(leaky.status).toBe(400);
      expect(leaky.body.code).toBe('secret_found');
      expect(JSON.stringify(leaky.body)).not.toContain(pem.split('\n')[1]);
      expect(await submissions(s.id)).toHaveLength(0);
    });

    it('the database refuses what the application would also refuse (the backstop), and the record is written once', async () => {
      const s = await session([REQ()]);
      const row = (over: Record<string, unknown> = {}) => ({
        session: s.id, type: 'tests', issuer: ciA.id, key: ciA.keyId, alg: 'Ed25519', commit: s.commits[0], spec: SPEC, ...over
      });
      const insert = (o: ReturnType<typeof row>) =>
        db.query(
          `INSERT INTO evidence_submission (work_session_id, evidence_type, issuer_principal_id, signature_key_id, subject_commit, status, specification_hash, evidence_hash, payload_sha256, issued_at, signature_algorithm, signature_value)
           VALUES ($1, $2, $3, $4, $5, 'pass', $6, $7, $8, now(), $9, $10)`,
          [o.session, o.type, o.issuer, o.key, o.commit, o.spec, sha(crypto.randomUUID()), sha('{}'), o.alg, 'A'.repeat(86)]
        );
      await expect(insert(row({ issuer: ciB.id, key: ciB.keyId, alg: 'ES256' }))).rejects.toThrow(/did not ask this principal/);
      await expect(insert(row({ key: ciB.keyId, alg: 'ES256' }))).rejects.toThrow(/not a key of the issuing principal/);
      await expect(insert(row({ commit: commitId() }))).rejects.toThrow(/not one this session produced/);
      await expect(insert(row({ type: 'other' }))).rejects.toThrow(/did not ask/);
      await insert(row()); // all of it right: the database accepts
      await expect(db.query(`UPDATE evidence_submission SET status = 'fail' WHERE work_session_id = $1`, [s.id])).rejects.toThrow();
      await expect(db.query(`DELETE FROM evidence_submission WHERE work_session_id = $1`, [s.id])).rejects.toThrow();
      await expect(admin.query(`UPDATE evidence_submission SET status = 'fail' WHERE work_session_id = $1`, [s.id])).rejects.toThrow(/written once/);
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('evaluation (the question the promotion gate will ask)', () => {
    const state = async (id: string, type = 'tests', commit?: string) => (await evaluateEvidence(db, id, commit ?? null)).requirements.find((r) => r.evidence_type === type)!.state;
    const put = (id: string, issuer: Caller, commit: string, status: string, over: Record<string, unknown> = {}) =>
      submit(id, issuer, statement(id, issuer, { subject_commit: commit, status, ...over }));

    it('missing, then satisfied by a pass, for that commit only (a pass on one commit never satisfies another)', async () => {
      const s = await session([REQ()]);
      expect(await state(s.id)).toBe('missing');
      expect((await evaluateEvidence(db, s.id, null)).ready).toBe(false);
      expect((await put(s.id, ciA, s.commits[0], 'pass')).status).toBe(201);
      expect(await state(s.id, 'tests', s.commits[0])).toBe('satisfied');
      expect(await state(s.id, 'tests', s.commits[1])).toBe('missing');
      // by default the question is about the session's newest commit, which has nothing yet
      expect((await evaluateEvidence(db, s.id, null)).commit).toBe(s.commits[1]);
      expect((await evaluateEvidence(db, s.id, null)).ready).toBe(false);
      expect((await put(s.id, ciA, s.commits[1], 'pass')).status).toBe(201);
      expect((await evaluateEvidence(db, s.id, null)).ready).toBe(true);
    });

    it('the newest statement decides: a later fail overrides a pass, a later pass overrides a fail; inconclusive does not satisfy', async () => {
      const s = await session([REQ()], 1);
      const c = s.commits[0];
      await withTriggersBypassed(admin, async (cl) => {
        await cl.query(`UPDATE session_commit SET created_at = now() - interval '1 hour' WHERE work_session_id = $1`, [s.id]);
      });
      const at = (secondsAgo: number) => new Date(Date.now() - secondsAgo * 1000).toISOString().replace(/\.\d+Z$/, 'Z');
      await put(s.id, ciA, c, 'pass', { issued_at: at(20) });
      expect(await state(s.id)).toBe('satisfied');
      await put(s.id, ciA, c, 'fail', { issued_at: at(10) });
      expect(await state(s.id)).toBe('failed');
      await put(s.id, ciA, c, 'pass', { issued_at: at(5) });
      expect(await state(s.id)).toBe('satisfied');
      await put(s.id, ciA, c, 'inconclusive', { issued_at: at(1) });
      expect(await state(s.id)).toBe('inconclusive');
      expect((await evaluateEvidence(db, s.id, null)).ready).toBe(false);
    });

    it('a statement older than max_age_seconds does not count', async () => {
      const s = await session([REQ({ max_age_seconds: 300 })], 1);
      await put(s.id, ciA, s.commits[0], 'pass');
      expect(await state(s.id)).toBe('satisfied');
      const later = new Date(Date.now() + 10 * 60_000);
      const e = await evaluateEvidence(db, s.id, null, later);
      expect(e.requirements[0].state).toBe('stale');
      expect(e.ready).toBe(false);
    });

    it('optional requirements are reported but never block; evidence not tied to a commit satisfies any commit', async () => {
      const s = await session([REQ({ required: false }), { type: 'licence', issuer_principal_id: ciB.id, tied_to_commit: false }]);
      expect((await evaluateEvidence(db, s.id, null)).ready).toBe(false); // the licence review is required and missing
      await put(s.id, ciB, s.commits[0], 'pass', { evidence_type: 'licence' });
      const e = await evaluateEvidence(db, s.id, s.commits[1]);
      expect(e.requirements.find((r) => r.evidence_type === 'licence')!.state).toBe('satisfied');
      expect(e.requirements.find((r) => r.evidence_type === 'tests')!.state).toBe('missing');
      expect(e.ready).toBe(true);
    });

    it('a revoked key or an issuer that is no longer active invalidates what it signed', async () => {
      const keyed = await caller('keyed', ['evidence:submit']);
      const s = await session([REQ({ issuer_principal_id: keyed.id })], 1);
      await put(s.id, keyed, s.commits[0], 'pass');
      expect(await state(s.id)).toBe('satisfied');
      await setPrincipalStatus(db, keyed.id, 'suspended', 'test');
      expect(await state(s.id)).toBe('issuer_unavailable');
      await setPrincipalStatus(db, keyed.id, 'active', 'test');
      expect(await state(s.id)).toBe('satisfied');
      await revokeKey(db, keyed.keyId, 'test');
      expect(await state(s.id)).toBe('issuer_unavailable');
      expect((await evaluateEvidence(db, s.id, null)).ready).toBe(false);
    });

    it('a session with no requirements is trivially ready', async () => {
      const s = await session(undefined, 1);
      expect(await evaluateEvidence(db, s.id, null)).toMatchObject({ ready: true, requirements: [] });
    });

    it('can be read by the requester, by an approving principal, and by the owner; not by anyone else', async () => {
      const s = await session([REQ()], 1);
      await put(s.id, ciA, s.commits[0], 'pass', {}); // sets up one statement
      const mine = await v2(requester, 'GET', `/work-sessions/${s.id}/evidence`);
      expect(mine.status).toBe(200);
      expect(mine.body.evaluation).toMatchObject({ commit: s.commits[0], ready: true });
      expect(mine.body.submissions).toHaveLength(1);
      expect(mine.body.submissions[0]).toMatchObject({ evidence_type: 'tests', status: 'pass', payload: {} });
      expect((await v2(approver, 'GET', `/work-sessions/${s.id}/evidence`)).status).toBe(200);
      expect((await v2(ciB, 'GET', `/work-sessions/${s.id}/evidence`)).status).toBe(403); // no work-sessions:read
      const stranger = await caller('stranger', ['work-sessions:read']);
      expect((await v2(stranger, 'GET', `/work-sessions/${s.id}/evidence`)).status).toBe(404);
      expect((await v2(requester, 'GET', `/work-sessions/${s.id}/evidence?commit=${commitId()}`)).status).toBe(422);
      expect((await v2(requester, 'GET', `/work-sessions/${s.id}/evidence?commit=zz`)).status).toBe(400);
      const owner = await h.api(creator, 'GET', `/projects/${projectId}/work-sessions/${s.id}/evidence`);
      expect(owner.status).toBe(200);
      expect(owner.body.evaluation.ready).toBe(true);
      expect((await h.api(other, 'GET', `/projects/${otherProjectId}/work-sessions/${s.id}/evidence`)).status).toBe(404);
      expect((await h.api(other, 'GET', `/projects/${projectId}/work-sessions/${s.id}/evidence`)).status).toBe(404);
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  it('everything is in the project\'s tamper-evident record, and the record still verifies', async () => {
    const check = await verifyServerProjectEvents(projectId);
    expect(check.isValid, check.reason).toBe(true);
    expect((await events()).some((e) => e.action === 'evidence.submitted')).toBe(true);
  });
});
