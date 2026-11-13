import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { getAdminPool, getDbPool, runMigrations } from '../server/db';
import { addPrincipalKey, registerPrincipal } from '../server/servicePrincipals';
import { canonicalJsonV2 } from '../shared/crypto';
import { attestationSigningInput as serverAttestationInput } from '../server/attestation';
import { evidenceSigningInput as serverEvidenceInput, payloadSha256 as serverPayloadSha } from '../server/evidence';
import { configureWebhookRuntime, resetWebhookRuntime, signWebhook, verifyWebhookSignature as serverVerify } from '../server/webhooks';
import { forgetInstallationTokens } from '../server/github';
import { openApiDocument } from '../server/openapi';
import { assertPoolTargetsTestDb } from './support/safety';
import { startHarness, Harness } from './support/apiHarness';
import { startApp, RunningApp } from './support/api';
import { startGitHubStandIn, StandIn } from './support/githubStandIn';
import { installGitleaks } from '../scripts/install-gitleaks';
import { newKey, TestKey, TestAlg } from './support/principalKeys';
import { allOperations, checkRequest, checkResponse, findOperation } from './support/openapiCheck';
import {
  CustodyCoreClient, CustodyCoreError, attestationSigningInput, canonicalJson, evidenceSigningInput, payloadSha256, sha256Hex, signText, verifyWebhookSignature
} from '../sdk/typescript/custody-core';

/**
 * The client library and the OpenAPI description, tested against the real application: a whole integration run through the SDK, with every request
 * and every response (errors included) checked against docs/openapi.json, so a description that is wrong in either direction fails here.
 */
const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0' };
function gitc(args: string[], cwd?: string): Promise<{ code: number; out: string }> {
  return new Promise((resolve) => {
    const child = spawn('git', args, { cwd, env: GIT_ENV });
    let out = '';
    child.stdout.on('data', (c) => (out += c));
    child.stderr.on('data', (c) => (out += c));
    child.on('close', (code) => resolve({ code: code ?? 1, out }));
  });
}
function gl(args: string[], cwd?: string) {
  const r = spawnSync('git', args, { cwd, env: GIT_ENV, encoding: 'utf8' });
  expect(r.status, `${args.join(' ')}: ${r.stderr}`).toBe(0);
  return r.stdout.trim();
}
function write(dir: string, file: string, content: string) {
  fs.mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
  fs.writeFileSync(path.join(dir, file), content);
}
const ME = ['-c', 'user.name=Engine', '-c', 'user.email=engine@example.com'];

describe('SDK and OpenAPI description, against the real application', () => {
  const db = getDbPool()!;
  const admin = getAdminPool()!;
  let standIn: StandIn;
  let h: Harness;
  let app: RunningApp;
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-sdk-test-'));
  const savedEnv = { ...process.env };
  const ORG = `org${Date.now()}`;
  const APP = `${ORG}/app`;
  const INSTALLATION = 8000 + Math.floor(Math.random() * 1000);
  let creator: any, other: any;
  let projectId = '', repoId = '', base = '';
  const sha = (s: string) => crypto.createHash('sha256').update(s).digest('hex');

  // everything that crosses the wire is checked against the document
  const problems: string[] = [];
  const exercised = new Set<string>();
  let negative = 0; // inside a deliberately bad request, the request itself is not held to the document (the answer still is)
  const expectError = async (p: () => Promise<unknown> | Promise<unknown>, status: number, code?: string) => {
    negative++;
    const err: any = await (typeof p === 'function' ? p() : p).then(() => null, (e: any) => e).finally(() => negative--);
    expect(err, 'expected a refusal').toBeInstanceOf(CustodyCoreError);
    expect(err.status).toBe(status);
    if (code) expect(err.code).toBe(code);
    expect(err.message).not.toMatch(/ccs_|whsec_|BEGIN/);
    return err as CustodyCoreError;
  };
  const checking: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    const method = init?.method ?? 'GET';
    const op = findOperation(method, url.pathname);
    if (!op) problems.push(`no operation described for ${method} ${url.pathname}`);
    else if (!negative) problems.push(...checkRequest(op, init?.body ? JSON.parse(String(init.body)) : undefined));
    const res = await fetch(input, init);
    if (op) {
      exercised.add(op.operationId);
      problems.push(...checkResponse(op, res.status, await res.clone().json().catch(() => ({}))));
    }
    return res;
  };
  /** The owner's routes, through the test login, checked the same way. */
  async function owner(who: any, method: string, p: string, body?: unknown) {
    const full = `/api/v1${p.split('?')[0]}`;
    const op = findOperation(method, full);
    if (!op) problems.push(`no operation described for ${method} ${full}`);
    else if (!(body && typeof body === 'object' && Object.keys(body as object).length === 0 && !op.op.requestBody)) problems.push(...checkRequest(op, body));
    const r = await h.api(who, method, p, body);
    if (op) {
      exercised.add(op.operationId);
      problems.push(...checkResponse(op, r.status, r.body));
    }
    return r;
  }

  interface Who { id: string; keyId: string; key: TestKey; client: CustodyCoreClient }
  async function principal(label: string, scopes: string[], alg: TestAlg = 'Ed25519'): Promise<Who> {
    const p = await registerPrincipal(db, creator.id, { name: `${label}-${crypto.randomUUID().slice(0, 6)}`, platform_type: 'agent', environment: 'development', allowed_scopes: scopes } as any, 'test');
    const key = newKey(alg);
    const keyId = (await addPrincipalKey(db, p.id, key.publicJwk, 'test')).key_id;
    return { id: p.id, keyId, key, client: new CustodyCoreClient({ baseUrl: app.base, principalId: p.id, keyId, privateKey: key.privateKey, algorithm: alg, fetch: checking }) };
  }
  let requester: Who, ci: Who, promoter: Who, ciEs: Who;
  const SPEC = sha('spec');

  const baseRequest = (over: Record<string, unknown> = {}) => ({
    project_id: projectId, repository_id: repoId,
    executor: { type: 'ai_assistant' as const, provider: 'example-ai', model: 'model-1', external_id: 'agent_99', display_name: 'Refactor Engine' },
    sponsor: { type: 'creator' as const, id: creator.id }, objective: 'Improve the library', base_commit: base,
    access: { repository: 'read_and_push' as const, allowed_read_paths: ['src/**', 'README.md'], allowed_write_paths: ['src/lib/**'], prohibited_paths: ['.env*'] },
    expires_in_seconds: 3600,
    evidence_requirements: [{ type: 'tests', issuer_principal_id: ci.id, specification_hash: SPEC, max_age_seconds: 3600 }],
    ...over
  });

  beforeAll(async () => {
    await assertPoolTargetsTestDb(admin);
    expect((await runMigrations()).success).toBe(true);
    await installGitleaks();
    standIn = await startGitHubStandIn();
    Object.assign(process.env, standIn.env, { GATEWAY_DATA_DIR: path.join(work, 'gateway'), APP_URL: '' });
    forgetInstallationTokens();
    standIn.addInstallation(INSTALLATION, ORG, [APP]);
    standIn.createRepo(APP);
    const seed = path.join(work, 'seed');
    fs.mkdirSync(seed, { recursive: true });
    gl(['init', '--quiet', '--initial-branch=main'], seed);
    write(seed, 'README.md', '# app\n');
    write(seed, 'src/a.ts', 'export const a = 1;\n');
    write(seed, 'src/lib/b.ts', 'export const b = 1;\n');
    gl(['add', '-A'], seed);
    gl([...ME, 'commit', '--quiet', '-m', 'Initial state'], seed);
    base = gl(['rev-parse', 'HEAD'], seed);
    gl(['push', '--quiet', '--force', standIn.upstreamDir(APP), 'main:main'], seed);
    h = await startHarness();
    app = await startApp();
    creator = await h.newCreator('owner');
    other = await h.newCreator('other');
    await db.query(`INSERT INTO github_installation (creator_id, installation_id, account_login, account_type, connected_by_github_login) VALUES ($1, $2, $3, 'Organization', 'octo')`, [creator.id, INSTALLATION, ORG]);
    projectId = (await db.query(`INSERT INTO project (creator_id, name, purpose, status) VALUES ($1, 'SDK', 'x', 'active') RETURNING id`, [creator.id])).rows[0].id;
    repoId = (await db.query(`INSERT INTO repository (project_id, github_repo_id, full_name) VALUES ($1, '1', $2) RETURNING id`, [projectId, APP])).rows[0].id;
    requester = await principal('requester', ['work-sessions:request', 'work-sessions:read', 'work-sessions:close-own', 'repositories:push-session', 'attestations:submit']);
    ci = await principal('ci', ['evidence:submit']);
    ciEs = await principal('ci-es', ['evidence:submit'], 'ES256');
    promoter = await principal('promoter', ['repositories:promote', 'work-sessions:read']);
  }, 180_000);
  afterAll(async () => {
    resetWebhookRuntime();
    await app?.stop();
    await h?.stop();
    await standIn?.stop();
    for (const k of Object.keys(process.env)) if (!(k in savedEnv)) delete process.env[k];
    Object.assign(process.env, savedEnv);
    forgetInstallationTokens();
    fs.rmSync(work, { recursive: true, force: true });
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('the SDK and the server agree on every signed or hashed thing', () => {
    it('canonical JSON is the same as the server\'s, on awkward input too', () => {
      const corpus: unknown[] = [
        null, true, 0, -7, 9007199254740991, 'plain', 'quote " backslash \\ newline \n tab \t', 'é ü 日本 😀', '  \u007f', [], {}, [1, [2, [3]]],
        { b: 1, a: 2, 'é': 3, 'z': { y: [{ d: 1, c: 2 }] }, '😀': 4, '￿': 5, A: 6, a1: 7, '': 8 }, { nested: { deep: { deeper: { deepest: ['x', null, false] } } } }
      ];
      for (const v of corpus) expect(canonicalJson(v), JSON.stringify(v)).toBe(canonicalJsonV2(v));
    });

    it('the evidence and attestation statements, the payload hash and the webhook signature are byte for byte the server\'s', () => {
      const ev = { work_session_id: crypto.randomUUID(), evidence_type: 'tests', subject_commit: 'a'.repeat(40), status: 'pass' as const, specification_hash: sha('s'), evidence_hash: sha('e'), payload_sha256: sha('p'), issued_at: '2026-01-31T12:00:00Z' };
      expect(evidenceSigningInput(ev)).toBe(serverEvidenceInput(ev));
      const at = { authority_id: crypto.randomUUID(), work_session_id: ev.work_session_id, claim: 'owner.reviewed', subject_commit: 'b'.repeat(40), payload_sha256: sha('q'), issued_at: '2026-01-31T12:00:00Z' };
      expect(attestationSigningInput(at)).toBe(serverAttestationInput(at));
      for (const payload of [{}, { a: 1, b: ['x', { c: null }] }]) expect(payloadSha256(payload)).toBe(serverPayloadSha(payload));
      expect(sha256Hex('x')).toBe(sha('x'));
      const body = '{"a":1}';
      const header = signWebhook('whsec_x', body, 1_700_000_000);
      expect(verifyWebhookSignature('whsec_x', header, body, 300, 1_700_000_100)).toBe(true);
      expect(verifyWebhookSignature('whsec_x', header, body, 300, 1_700_000_100)).toBe(serverVerify('whsec_x', header, body, 300, 1_700_000_100));
      expect(verifyWebhookSignature('whsec_x', header, body + ' ', 300, 1_700_000_100)).toBe(false);
      expect(verifyWebhookSignature('whsec_x', header, body, 300, 1_700_001_000)).toBe(false);
    });

    it('has a method for every machine operation in the document (and no stray ones)', () => {
      const methods = Object.getOwnPropertyNames(CustodyCoreClient.prototype).filter((m) => !['constructor', 'assertion', 'call', 'get', 'post'].includes(m));
      const machine = allOperations.filter((o) => o.template.startsWith('/api/v2') && o.operationId !== 'getOpenApiDocument').map((o) => o.operationId);
      expect([...methods].sort()).toEqual([...machine].sort());
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('a whole integration, through the SDK', () => {
    let sessionId = '';
    let clone = '';
    let commit = '';
    let authority: { id: string; key: TestKey } | null = null;

    it('knows who it is, and starts with nothing', async () => {
      const me = await requester.client.whoami();
      expect(me.principal).toMatchObject({ id: requester.id, scopes: expect.arrayContaining(['work-sessions:request']) });
      expect(await requester.client.listWorkSessions()).toEqual([]);
      const doc = await (await fetch(`${app.base}/api/v2/openapi.json`)).json();
      expect(doc.openapi).toBe('3.1.0');
      exercised.add('getOpenApiDocument');
    });

    it('asks for a session, the owner approves it, and the credential works with ordinary git', async () => {
      const requested = await requester.client.requestWorkSession(baseRequest());
      sessionId = requested.session_id;
      expect(requested).toMatchObject({ status: 'requested', requires_approval: true });
      const got = await requester.client.getWorkSession(sessionId);
      expect(got).toMatchObject({ id: sessionId, status: 'requested', evidence_requirements: [expect.objectContaining({ type: 'tests', issuer_principal_id: ci.id })] });
      expect((await requester.client.listWorkSessions({ status: 'requested' })).map((s) => s.id)).toContain(sessionId);
      expect((await requester.client.listWorkSessions({ project_id: projectId })).length).toBe(1);

      expect((await owner(creator, 'GET', `/projects/${projectId}/work-sessions`)).body.work_sessions.map((s: any) => s.id)).toContain(sessionId);
      expect((await owner(creator, 'POST', `/projects/${projectId}/work-sessions/${sessionId}/approve`, {})).status).toBe(200);

      const grant = await requester.client.issueSessionCredential(sessionId);
      expect(grant).toMatchObject({ session_id: sessionId, repository: APP, read_only: false, replaced: false });
      expect(grant.credential.token).toMatch(/^ccs_/);
      const again = await requester.client.issueSessionCredential(sessionId);
      expect(again.replaced).toBe(true);
      clone = path.join(work, 'clone');
      const url = again.git_url.replace('http://', `http://x:${again.credential.token}@`);
      expect((await gitc(['clone', '--quiet', url, clone])).code).toBe(0);
      write(clone, 'src/lib/b.ts', 'export const b = 2;\n');
      gl(['add', '-A'], clone);
      gl([...ME, 'commit', '--quiet', '-m', 'Improve b'], clone);
      const push = await gitc(['push', 'origin', `HEAD:refs/heads/${again.branch_prefix}work`], clone);
      expect(push.code, push.out).toBe(0);
      const commits = await requester.client.listSessionCommits(sessionId);
      expect(commits).toHaveLength(1);
      commit = commits[0].real_sha;
    }, 240_000);

    it('the named issuer signs evidence with the SDK (Ed25519), and the owner sees the evaluation', async () => {
      const first = await ci.client.submitEvidence(sessionId, { evidence_type: 'tests', subject_commit: commit, status: 'pass', specification_hash: SPEC, evidence_hash: sha('report-1'), payload: { passed: 120, failed: 0 }, issued_at: new Date().toISOString().replace(/\.\d+Z$/, 'Z') });
      expect(first).toMatchObject({ recorded: true, status: 'pass', subject_commit: commit });
      const issuedAt = first.issued_at as string;
      const repeat = await ci.client.submitEvidence(sessionId, { evidence_type: 'tests', subject_commit: commit, status: 'pass', specification_hash: SPEC, evidence_hash: sha('report-1'), payload: { passed: 120, failed: 0 }, issued_at: issuedAt });
      expect(repeat).toMatchObject({ recorded: false, id: first.id });
      const report = await requester.client.getEvidence(sessionId);
      expect(report.evaluation).toMatchObject({ commit, ready: true });
      expect((await requester.client.getEvidence(sessionId, commit)).submissions).toHaveLength(1);
      expect((await owner(creator, 'GET', `/projects/${projectId}/work-sessions/${sessionId}/evidence`)).body.evaluation.ready).toBe(true);
      expect((await owner(creator, 'GET', `/projects/${projectId}/work-sessions/${sessionId}/evidence?commit=${commit}`)).status).toBe(200);
    });

    it('shows who authored the commit, and takes an attestation from a signing authority the owner trusts (ES256)', async () => {
      const contributions = await requester.client.getAttribution(sessionId);
      expect(contributions).toHaveLength(1);
      expect(contributions[0]).toMatchObject({ commit, author: { kind: 'executor', principal_id: requester.id }, committer: { kind: 'gateway' } });
      expect((await owner(creator, 'GET', `/projects/${projectId}/work-sessions/${sessionId}/attribution`)).body.contributions).toHaveLength(1);
      expect(await requester.client.listAttestations(sessionId)).toEqual([]);

      const key = newKey('ES256');
      const reg = await owner(creator, 'POST', '/attestation-authorities', { name: 'Notary', public_key: key.publicJwk });
      expect(reg.status).toBe(201);
      authority = { id: reg.body.authority.id, key };
      expect((await owner(creator, 'GET', '/attestation-authorities')).body.authorities).toHaveLength(1);
      const statement = { authority_id: authority.id, work_session_id: sessionId, claim: 'owner.reviewed', subject_commit: commit, payload_sha256: payloadSha256({}), issued_at: new Date().toISOString().replace(/\.\d+Z$/, 'Z') };
      const { work_session_id: _w, payload_sha256: _p, ...rest } = statement;
      const delivered = await owner(creator, 'POST', `/projects/${projectId}/work-sessions/${sessionId}/attestations`, {
        ...rest, signature: { algorithm: 'ES256', value: signText(key.privateKey, 'ES256', attestationSigningInput(statement)) }
      });
      expect(delivered.status, JSON.stringify(delivered.body)).toBe(201);
      expect((await requester.client.listAttestations(sessionId, commit)).map((a) => a.claim)).toEqual(['owner.reviewed']);
      expect((await owner(creator, 'GET', `/projects/${projectId}/work-sessions/${sessionId}/attestations`)).body.attestations).toHaveLength(1);
      // Unattended delivery: the owner grants this principal the authority for the project; the principal submits and gets a receipt.
      const gr = await owner(creator, 'POST', '/attestation-submission-grants', { principal_id: requester.id, authority_id: authority.id, project_id: projectId });
      expect(gr.status, JSON.stringify(gr.body)).toBe(201);
      expect((await owner(creator, 'GET', '/attestation-submission-grants')).body.grants).toHaveLength(1);
      const sent = await requester.client.submitAttestation(sessionId, { authority_id: authority.id, subject_commit: commit, payload: { author_kind: 'ai_assistant' }, signWith: { privateKey: key.privateKey, algorithm: 'ES256' } });
      expect(sent).toMatchObject({ recorded: true, claim: 'commit.attribution', receipt: { contract: 'commit-attribution-submission/1', subject_commit: commit } });
      const again = await requester.client.submitAttestation(sessionId, { authority_id: authority.id, subject_commit: commit, payload: { author_kind: 'ai_assistant' }, issued_at: sent.issued_at as string, signWith: { privateKey: key.privateKey, algorithm: 'ES256' } });
      expect(again).toMatchObject({ recorded: false, receipt: sent.receipt });
      await expectError(() => requester.client.submitAttestation(sessionId, { authority_id: authority!.id, subject_commit: commit, claim: 'owner.reviewed', signWith: { privateKey: key.privateKey, algorithm: 'ES256' } }), 422);
      expect((await requester.client.listAttestations(sessionId, commit)).map((a) => a.claim).sort()).toEqual(['commit.attribution', 'owner.reviewed']);
      expect((await owner(creator, 'POST', `/attestation-submission-grants/${gr.body.grant.id}/revoke`, {})).body.grant.revoked_at).not.toBeNull();
      await expectError(() => requester.client.submitAttestation(sessionId, { authority_id: authority!.id, subject_commit: commit, payload: { n: 2 }, signWith: { privateKey: key.privateKey, algorithm: 'ES256' } }), 403);
      expect((await owner(creator, 'POST', `/attestation-authorities/${authority.id}/revoke`, {})).body.authority.revoked_at).not.toBeNull();
    });

    it('a principal asks to promote, the owner approves, and the default branch moves', async () => {
      const asked = await promoter.client.requestPromotion(sessionId);
      expect(asked).toMatchObject({ status: 'pending', commit });
      expect((await promoter.client.listPromotions(sessionId)).map((p) => p.id)).toEqual([asked.id]);
      expect((await owner(creator, 'GET', `/projects/${projectId}/work-sessions/${sessionId}/promotions`)).body.promotions).toHaveLength(1);
      expect((await owner(creator, 'GET', `/projects/${projectId}/promotions`)).body.promotions).toHaveLength(1);
      const done = await owner(creator, 'POST', `/projects/${projectId}/promotions/${asked.id}/approve`, {});
      expect(done.status, JSON.stringify(done.body)).toBe(200);
      expect(done.body.promotion.status).toBe('completed');
      expect(gl(['rev-parse', 'refs/heads/main'], standIn.upstreamDir(APP))).toBe(commit);
      expect((await requester.client.getWorkSession(sessionId)).status).toBe('completed');
      expect((await requester.client.closeWorkSession(sessionId)).status).toBe('closed');
    });

    it('the owner can also reject a request, ask for a promotion themselves and reject it', async () => {
      const r = await requester.client.requestWorkSession(baseRequest({ evidence_requirements: undefined }));
      expect((await owner(creator, 'POST', `/projects/${projectId}/work-sessions/${r.session_id}/reject`, { reason: 'not now' })).body.status).toBe('rejected');

      // a running session with a commit, made quickly (the same moves the product makes), so a promotion can be asked for and turned down
      const quick = await requester.client.requestWorkSession(baseRequest({ evidence_requirements: [{ type: 'review', issuer_principal_id: ciEs.id }] }));
      await owner(creator, 'POST', `/projects/${projectId}/work-sessions/${quick.session_id}/approve`, {});
      await admin.query(`UPDATE work_session SET status = 'active' WHERE id = $1`, [quick.session_id]);
      await admin.query(`INSERT INTO session_view (work_session_id, base_commit, default_branch, default_branch_tip, view_commit, view_tree, file_count, total_bytes, excluded_count) VALUES ($1, $2, 'main', $2, $3, $3, 1, 1, 0)`, [quick.session_id, base, crypto.randomBytes(20).toString('hex')]);
      const real = crypto.randomBytes(20).toString('hex');
      await admin.query(`INSERT INTO session_commit (work_session_id, view_sha, real_sha, parent_view_sha, declared_author) VALUES ($1, $2, $3, $2, 'x')`, [quick.session_id, crypto.randomBytes(20).toString('hex'), real]);
      await ciEs.client.submitEvidence(quick.session_id, { evidence_type: 'review', subject_commit: real, status: 'pass', specification_hash: SPEC, evidence_hash: sha('review-1') }); // ES256
      const mine = await owner(creator, 'POST', `/projects/${projectId}/work-sessions/${quick.session_id}/promotions`, { commit: real });
      expect(mine.status, JSON.stringify(mine.body)).toBe(201);
      const rej = await owner(creator, 'POST', `/projects/${projectId}/promotions/${mine.body.promotion.id}/reject`, { reason: 'wait' });
      expect(rej.body.promotion.status).toBe('rejected');
    });

    it('webhook endpoints are managed by the owner, and the delivery body and header are in the document', async () => {
      configureWebhookRuntime({ resolve: async () => [{ address: '93.184.216.34', family: 4 }] });
      const created = await owner(creator, 'POST', '/webhook-endpoints', { name: 'Hook', url: 'https://hooks.example.test/in', events: ['promotion.*'] });
      expect(created.status).toBe(201);
      const id = created.body.endpoint.id;
      expect((await owner(creator, 'GET', '/webhook-endpoints')).body.endpoints.map((e: any) => e.id)).toContain(id);
      expect((await owner(creator, 'POST', `/webhook-endpoints/${id}/rotate-secret`, {})).body.secret).not.toBe(created.body.secret);
      expect((await owner(creator, 'POST', `/webhook-endpoints/${id}/disable`, {})).body.endpoint.status).toBe('disabled');
      expect((await owner(creator, 'POST', `/webhook-endpoints/${id}/enable`, {})).body.endpoint.status).toBe('active');
      expect((await owner(creator, 'GET', `/webhook-endpoints/${id}/deliveries`)).status).toBe(200);
      // what a receiver gets validates against the document's own description of it
      const ev = (await db.query(`SELECT * FROM event WHERE project_id = $1 AND action = 'promotion.completed' LIMIT 1`, [projectId])).rows[0];
      const msg = {
        format: 'custody-core.webhook.v1', id: ev.id, type: ev.action, project_id: ev.project_id, occurred_at: new Date(ev.created_at).toISOString(), actor: { type: ev.actor_type, id: ev.actor_id },
        subject: { type: ev.subject_type, id: ev.subject_id }, data: ev.payload,
        record: { seq: Number(ev.seq), prev_hash: ev.prev_hash, hash: ev.hash, hash_version: ev.hash_version, hashed_timestamp: ev.hashed_timestamp, canonical_payload: ev.canonical_payload }
      };
      const hook = (openApiDocument as any).webhooks['custody-event'].post;
      const { validate } = await import('./support/openapiCheck');
      expect(validate(hook.requestBody.content['application/json'].schema, msg)).toEqual([]);
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('refusals are described too, and reach the caller as CustodyCoreError', () => {
    it('wrong key, wrong scope, not yours, not ready, not approved, bad input', async () => {
      const wrongKey = new CustodyCoreClient({ baseUrl: app.base, principalId: requester.id, keyId: requester.keyId, privateKey: newKey('Ed25519').privateKey, algorithm: 'Ed25519', fetch: checking });
      await expectError(() => wrongKey.whoami(), 401);
      await expectError(() => ci.client.requestWorkSession(baseRequest()), 403); // no work-sessions:request
      await expectError(() => requester.client.getWorkSession(crypto.randomUUID()), 404);
      await expectError(() => requester.client.requestWorkSession({ ...baseRequest(), objective: '' }), 400);
      await expectError(() => requester.client.requestWorkSession(baseRequest({ project_id: crypto.randomUUID() })), 404);
      await expectError(() => requester.client.requestWorkSession(baseRequest({ evidence_requirements: [{ type: 'tests', issuer_principal_id: requester.id }] })), 422);
      const waiting = await requester.client.requestWorkSession(baseRequest());
      await expectError(() => requester.client.issueSessionCredential(waiting.session_id), 409, 'not_approved');
      await expectError(() => requester.client.closeWorkSession(crypto.randomUUID()), 404);
      await expectError(() => promoter.client.requestPromotion(waiting.session_id), 409);
      await expectError(() => promoter.client.listPromotions(crypto.randomUUID()), 404);
      await expectError(() => requester.client.getEvidence(waiting.session_id, 'zz'), 400);
      await expectError(() => requester.client.getEvidence(waiting.session_id, 'a'.repeat(40)), 422);
      await expectError(() => ci.client.submitEvidence(waiting.session_id, { evidence_type: 'tests', subject_commit: 'a'.repeat(40), status: 'pass', specification_hash: SPEC, evidence_hash: sha('x') }), 409);
      await expectError(() => ci.client.submitEvidence(waiting.session_id, { evidence_type: 'unasked', subject_commit: 'a'.repeat(40), status: 'pass', specification_hash: SPEC, evidence_hash: sha('x') }), 404);
      await expectError(() => promoter.client.requestPromotion(crypto.randomUUID()), 404);
      await expectError(() => requester.client.listAttestations(waiting.session_id, 'zz'), 400);
      await requester.client.closeWorkSession(waiting.session_id);
    }, 120_000);

    it('a refused promotion explains itself, with the evaluation', async () => {
      const r = await requester.client.requestWorkSession(baseRequest());
      await owner(creator, 'POST', `/projects/${projectId}/work-sessions/${r.session_id}/approve`, {});
      await admin.query(`UPDATE work_session SET status = 'active' WHERE id = $1`, [r.session_id]);
      await admin.query(`INSERT INTO session_view (work_session_id, base_commit, default_branch, default_branch_tip, view_commit, view_tree, file_count, total_bytes, excluded_count) VALUES ($1, $2, 'main', $2, $3, $3, 1, 1, 0)`, [r.session_id, base, crypto.randomBytes(20).toString('hex')]);
      const real = crypto.randomBytes(20).toString('hex');
      await admin.query(`INSERT INTO session_commit (work_session_id, view_sha, real_sha, parent_view_sha, declared_author) VALUES ($1, $2, $3, $2, 'x')`, [r.session_id, crypto.randomBytes(20).toString('hex'), real]);
      const err = await expectError(() => promoter.client.requestPromotion(r.session_id), 422, 'evidence_not_ready');
      expect((err.body as any).evaluation.requirements[0].state).toBe('missing');
      await requester.client.closeWorkSession(r.session_id);
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  it('everything that crossed the wire matched the document, and every operation in it was exercised', () => {
    expect(problems).toEqual([]);
    const missing = allOperations.map((o) => o.operationId).filter((id) => !exercised.has(id));
    expect(missing).toEqual([]);
  });
});
