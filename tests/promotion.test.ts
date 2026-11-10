import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { getAdminPool, getDbPool, runMigrations, verifyServerProjectEvents } from '../server/db';
import { addPrincipalKey, registerPrincipal, revokeKey } from '../server/servicePrincipals';
import { expireOverdueSessions } from '../server/workSessions';
import { evidenceSigningInput, payloadSha256 } from '../server/evidence';
import { sessionViewPath } from '../server/gateway/realMirror';
import { forgetInstallationTokens } from '../server/github';
import { assertPoolTargetsTestDb } from './support/safety';
import { withTriggersBypassed } from './support/cleanup';
import { startHarness, Harness } from './support/apiHarness';
import { startApp, RunningApp } from './support/api';
import { startGitHubStandIn, StandIn } from './support/githubStandIn';
import { installGitleaks } from '../scripts/install-gitleaks';
import { assertion, newKey, sign, TestKey } from './support/principalKeys';

/**
 * Evidence-gated promotion (CL-14), end to end: real git through the session gateway, signed evidence, the owner's approval, and the gateway
 * moving the repository's default branch (on a local stand-in for GitHub) to the session's commit.
 */
const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0' };
function gitc(args: string[], cwd?: string): Promise<{ code: number; out: string }> {
  return new Promise((resolve) => {
    const child = spawn('git', args, { cwd, env: GIT_ENV });
    let out = '';
    child.stdout.on('data', (c) => (out += c));
    child.stderr.on('data', (c) => (out += c));
    const timer = setTimeout(() => child.kill('SIGKILL'), 120_000);
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? 1, out });
    });
  });
}
function gl(args: string[], cwd?: string) {
  const r = spawnSync('git', args, { cwd, env: GIT_ENV, encoding: 'utf8', timeout: 120_000 });
  return { code: r.status ?? 1, out: `${r.stdout}`, err: `${r.stderr}` };
}
const out1 = (args: string[], cwd?: string) => {
  const r = gl(args, cwd);
  expect(r.code, `${args.join(' ')}: ${r.err}`).toBe(0);
  return r.out.trim();
};
const ME = ['-c', 'user.name=Engine', '-c', 'user.email=engine@example.com'];
function write(dir: string, file: string, content: string) {
  fs.mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
  fs.writeFileSync(path.join(dir, file), content);
}
function commitAll(dir: string, message: string) {
  out1(['add', '-A'], dir);
  out1([...ME, 'commit', '--quiet', '-m', message], dir);
  return out1(['rev-parse', 'HEAD'], dir);
}

describe('Promotion', () => {
  const db = getDbPool()!;
  const admin = getAdminPool()!;
  let standIn: StandIn;
  let h: Harness;
  let app: RunningApp;
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-promo-test-'));
  const savedEnv = { ...process.env };
  const ORG = `org${Date.now()}`;
  const APP = `${ORG}/app`;
  const INSTALLATION = 7000 + Math.floor(Math.random() * 1000);
  let creator: any, other: any;
  let projectId = '', repoId = '';
  const upstream = () => standIn.upstreamDir(APP);
  const upstreamMain = () => out1(['rev-parse', 'refs/heads/main'], upstream());
  let base = '';
  let seed = '';

  interface Caller { id: string; keyId: string; key: TestKey }
  async function caller(label: string, scopes: string[], who = creator): Promise<Caller> {
    const p = await registerPrincipal(db, who.id, { name: `${label}-${crypto.randomUUID().slice(0, 6)}`, platform_type: 'agent', environment: 'development', allowed_scopes: scopes } as any, 'test');
    const key = newKey('Ed25519');
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
  let requester: Caller, ci: Caller, promoter: Caller, reader: Caller;
  const SPEC = crypto.createHash('sha256').update('spec').digest('hex');
  const sha = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
  const events = async () => (await db.query('SELECT action, actor_type, actor_id, subject_id, payload FROM event WHERE project_id = $1 ORDER BY seq', [projectId])).rows;
  const sessionRow = async (id: string) => (await db.query('SELECT * FROM work_session WHERE id = $1', [id])).rows[0];
  const promoRow = async (id: string) => (await db.query('SELECT * FROM promotion_request WHERE id = $1', [id])).rows[0];

  interface S { id: string; token: string; commits: string[] }
  /** A running session with `n` pushed commits (through the gateway) and, optionally, passing evidence for the newest one. */
  async function session(opts: { n?: number; evidence?: 'pass' | 'fail' | 'none'; baseCommit?: string } = {}): Promise<S> {
    const n = opts.n ?? 1;
    const r = await v2(requester, 'POST', '/work-sessions', {
      project_id: projectId, repository_id: repoId, executor: { type: 'ai_assistant', display_name: 'Refactor Engine' }, sponsor: { type: 'creator', id: creator.id },
      objective: 'Improve the library', base_commit: opts.baseCommit ?? base,
      access: { repository: 'read_and_push', allowed_read_paths: ['src/**', 'README.md'], allowed_write_paths: ['src/lib/**'], prohibited_paths: [] },
      evidence_requirements: [{ type: 'tests', issuer_principal_id: ci.id, specification_hash: SPEC }]
    });
    expect(r.status, JSON.stringify(r.body)).toBe(202);
    const id = r.body.session_id;
    expect((await h.api(creator, 'POST', `/projects/${projectId}/work-sessions/${id}/approve`, {})).status).toBe(200);
    const c = await v2(requester, 'POST', `/work-sessions/${id}/credential`);
    expect(c.status, JSON.stringify(c.body)).toBe(201);
    const token = c.body.credential.token;
    const dir = path.join(work, `clone-${id}`);
    expect((await gitc(['clone', '--quiet', c.body.git_url.replace('http://', `http://x:${token}@`), dir])).code).toBe(0);
    for (let i = 0; i < n; i++) {
      write(dir, 'src/lib/b.ts', `export const b = ${i + 2};\n`);
      commitAll(dir, `change ${i + 1}`);
    }
    const push = await gitc(['push', 'origin', `HEAD:refs/heads/session/${id}/work`], dir);
    expect(push.code, push.out).toBe(0);
    const commits = (await v2(requester, 'GET', `/work-sessions/${id}/commits`)).body.commits.map((x: any) => x.real_sha) as string[];
    expect(commits).toHaveLength(n);
    const s: S = { id, token, commits };
    if ((opts.evidence ?? 'pass') !== 'none') expect((await evidence(s, s.commits[n - 1], opts.evidence ?? 'pass')).status).toBe(201);
    return s;
  }
  function evidence(s: S, commit: string, status: string, issuer = ci) {
    const f = { work_session_id: s.id, evidence_type: 'tests', subject_commit: commit, status, specification_hash: SPEC, evidence_hash: sha(`r-${crypto.randomUUID()}`), payload_sha256: payloadSha256({}), issued_at: new Date().toISOString().replace(/\.\d+Z$/, 'Z') };
    const { work_session_id: _w, payload_sha256: _p, ...rest } = f;
    return v2(issuer, 'POST', `/work-sessions/${s.id}/evidence`, { ...rest, payload: {}, signature: { key_id: issuer.keyId, algorithm: 'Ed25519', value: sign(issuer.key, evidenceSigningInput(f)) } });
  }
  const promote = (s: S, commit?: string, who = promoter) => v2(who, 'POST', `/work-sessions/${s.id}/promote`, commit ? { commit } : {});
  const approve = (id: string, who = creator, pid = projectId) => h.api(who, 'POST', `/projects/${pid}/promotions/${id}/approve`, {});

  beforeAll(async () => {
    await assertPoolTargetsTestDb(admin);
    expect((await runMigrations()).success).toBe(true);
    await installGitleaks();
    standIn = await startGitHubStandIn();
    Object.assign(process.env, standIn.env, { GATEWAY_DATA_DIR: path.join(work, 'gateway'), APP_URL: '' });
    forgetInstallationTokens();
    standIn.addInstallation(INSTALLATION, ORG, [APP]);
    standIn.createRepo(APP);
    seed = path.join(work, 'seed');
    fs.mkdirSync(seed, { recursive: true });
    out1(['init', '--quiet', '--initial-branch=main'], seed);
    write(seed, 'README.md', '# app\n');
    write(seed, 'src/a.ts', 'export const a = 1;\n');
    write(seed, 'src/lib/b.ts', 'export const b = 1;\n');
    base = commitAll(seed, 'Initial state');
    out1(['push', '--quiet', '--force', upstream(), 'main:main'], seed);
    h = await startHarness();
    app = await startApp();
    creator = await h.newCreator('owner');
    other = await h.newCreator('other');
    await db.query(`INSERT INTO github_installation (creator_id, installation_id, account_login, account_type, connected_by_github_login) VALUES ($1, $2, $3, 'Organization', 'octo')`, [creator.id, INSTALLATION, ORG]);
    projectId = (await db.query(`INSERT INTO project (creator_id, name, purpose, status) VALUES ($1, 'Promotion', 'x', 'active') RETURNING id`, [creator.id])).rows[0].id;
    repoId = (await db.query(`INSERT INTO repository (project_id, github_repo_id, full_name) VALUES ($1, '1', $2) RETURNING id`, [projectId, APP])).rows[0].id;
    requester = await caller('requester', ['work-sessions:request', 'work-sessions:read', 'work-sessions:close-own', 'repositories:push-session']);
    ci = await caller('ci', ['evidence:submit']);
    promoter = await caller('promoter', ['repositories:promote', 'work-sessions:read']);
    reader = await caller('reader', ['work-sessions:read']);
  }, 180_000);
  afterAll(async () => {
    await app?.stop();
    await h?.stop();
    await standIn?.stop();
    for (const k of Object.keys(process.env)) if (!(k in savedEnv)) delete process.env[k];
    Object.assign(process.env, savedEnv);
    forgetInstallationTokens();
    fs.rmSync(work, { recursive: true, force: true });
  });

  /** Put the upstream default branch back to the seed state between tests that move it. */
  async function resetMain() {
    out1(['update-ref', 'refs/heads/main', base], upstream());
  }

  it('moves the default branch to the session\'s commit once the evidence is ready and the owner approves, then ends the session', async () => {
    const s = await session({ n: 2 });
    const r = await promote(s);
    expect(r.status, JSON.stringify(r.body)).toBe(202);
    expect(r.body.requires_approval).toBe(true);
    const p = r.body.promotion;
    expect(p).toMatchObject({ status: 'pending', commit: s.commits[1], target_branch: 'main', requested_by: { kind: 'principal', id: promoter.id } });
    expect(p.evidence_at_request.ready).toBe(true);
    expect(upstreamMain()).toBe(base); // asking changes nothing

    const a = await approve(p.id);
    expect(a.status, JSON.stringify(a.body)).toBe(200);
    expect(a.body.promotion).toMatchObject({ status: 'completed', previous_tip: base, approved_by: `creator:${creator.id}` });
    expect(upstreamMain()).toBe(s.commits[1]);
    // exactly the session's commits landed on top of what was there, every one made by the gateway
    expect(out1(['rev-list', `${base}..main`], upstream()).split('\n')).toEqual([s.commits[1], s.commits[0]]);
    expect(out1(['log', '--format=%cn', `${base}..main`], upstream()).split('\n')).toEqual(['Custody Core', 'Custody Core']);

    const row = await promoRow(p.id);
    expect(row.evaluation_at_completion.ready).toBe(true);
    expect((await sessionRow(s.id)).status).toBe('completed');
    expect((await db.query(`SELECT revoked_at FROM session_credential WHERE work_session_id = $1`, [s.id])).rows.every((c) => c.revoked_at)).toBe(true);
    expect(fs.existsSync(sessionViewPath(s.id))).toBe(false);
    const ev = (await events()).filter((e) => e.subject_id === s.id && e.action.startsWith('promotion.'));
    expect(ev.map((e) => e.action)).toEqual(['promotion.requested', 'promotion.approved', 'promotion.completed']);
    expect(ev[0]).toMatchObject({ actor_type: 'system', actor_id: `principal:${promoter.id}` });
    expect(ev[1]).toMatchObject({ actor_type: 'creator', actor_id: creator.id });
    expect(ev[2]).toMatchObject({ actor_type: 'gateway', actor_id: `promotion:${p.id}` });
    expect(ev[2].payload).toMatchObject({ commit: s.commits[1], previous_tip: base, target_branch: 'main' });
    const listed = await v2(promoter, 'GET', `/work-sessions/${s.id}/promotions`);
    expect(listed.body.promotions.map((x: any) => x.status)).toEqual(['completed']);
    // the finished session can still be closed by its requester
    expect((await v2(requester, 'POST', `/work-sessions/${s.id}/close`)).status).toBe(200);
    await resetMain();
  }, 240_000);

  it('the owner can ask for it too, and may promote an earlier commit of the session (a shorter fast-forward)', async () => {
    const s = await session({ n: 2, evidence: 'none' });
    expect((await evidence(s, s.commits[0], 'pass')).status).toBe(201); // evidence is for the FIRST commit only
    const newest = await h.api(creator, 'POST', `/projects/${projectId}/work-sessions/${s.id}/promotions`, {});
    expect(newest.status).toBe(422); // the default is the newest commit, which has no evidence
    expect(newest.body.code).toBe('evidence_not_ready');
    const mine = await h.api(creator, 'POST', `/projects/${projectId}/work-sessions/${s.id}/promotions`, { commit: s.commits[0] });
    expect(mine.status, JSON.stringify(mine.body)).toBe(201);
    expect(mine.body.promotion.requested_by).toEqual({ kind: 'creator', id: creator.id });
    const a = await approve(mine.body.promotion.id);
    expect(a.body.promotion.status).toBe('completed');
    expect(upstreamMain()).toBe(s.commits[0]);
    await resetMain();
  }, 240_000);

  describe('the evidence gate', () => {
    it('refuses a request when evidence is missing, failed, or about a different commit, and records nothing', async () => {
      const none = await session({ evidence: 'none' });
      const r1 = await promote(none);
      expect(r1.status).toBe(422);
      expect(r1.body).toMatchObject({ code: 'evidence_not_ready', evaluation: { ready: false } });
      expect(r1.body.evaluation.requirements[0].state).toBe('missing');
      const failed = await session({ evidence: 'fail' });
      expect((await promote(failed)).body.evaluation.requirements[0].state).toBe('failed');
      const two = await session({ n: 2, evidence: 'none' });
      expect((await evidence(two, two.commits[0], 'pass')).status).toBe(201);
      expect((await promote(two, two.commits[1])).status).toBe(422); // a pass on one commit never satisfies another
      for (const s of [none, failed, two]) expect((await db.query(`SELECT 1 FROM promotion_request WHERE work_session_id = $1`, [s.id])).rowCount).toBe(0);
      expect((await promote(two, 'a'.repeat(40))).body.code).toBe('unknown_commit');
      expect((await promote(two, 'zz')).status).toBe(400);
    }, 240_000);

    it('checks again at approval: evidence that stopped counting (its key was revoked) blocks the approval, and nothing moves', async () => {
      const ci2 = await caller('ci2', ['evidence:submit']);
      const r = await v2(requester, 'POST', '/work-sessions', {
        project_id: projectId, repository_id: repoId, executor: { type: 'ai_assistant', display_name: 'E' }, sponsor: { type: 'creator', id: creator.id }, objective: 'x', base_commit: base,
        access: { repository: 'read_and_push', allowed_read_paths: ['src/**'], allowed_write_paths: ['src/lib/**'], prohibited_paths: [] },
        evidence_requirements: [{ type: 'tests', issuer_principal_id: ci2.id }]
      });
      const id = r.body.session_id;
      await h.api(creator, 'POST', `/projects/${projectId}/work-sessions/${id}/approve`, {});
      await admin.query(`UPDATE work_session SET status = 'active' WHERE id = $1`, [id]);
      const commit = crypto.randomBytes(20).toString('hex');
      await admin.query(`INSERT INTO session_view (work_session_id, base_commit, default_branch, default_branch_tip, view_commit, view_tree, file_count, total_bytes, excluded_count) VALUES ($1, $2, 'main', $2, $3, $3, 1, 1, 0)`, [id, base, crypto.randomBytes(20).toString('hex')]);
      await admin.query(`INSERT INTO session_commit (work_session_id, view_sha, real_sha, parent_view_sha, declared_author) VALUES ($1, $2, $3, $2, 'x')`, [id, crypto.randomBytes(20).toString('hex'), commit]);
      const s: S = { id, token: '', commits: [commit] };
      const f = { work_session_id: id, evidence_type: 'tests', subject_commit: commit, status: 'pass', specification_hash: SPEC, evidence_hash: sha('x'), payload_sha256: payloadSha256({}), issued_at: new Date().toISOString().replace(/\.\d+Z$/, 'Z') };
      const { work_session_id: _w, payload_sha256: _p, ...rest } = f;
      expect((await v2(ci2, 'POST', `/work-sessions/${id}/evidence`, { ...rest, payload: {}, signature: { key_id: ci2.keyId, algorithm: 'Ed25519', value: sign(ci2.key, evidenceSigningInput(f)) } })).status).toBe(201);
      const p = await promote(s);
      expect(p.status, JSON.stringify(p.body)).toBe(202);
      await revokeKey(db, ci2.keyId, 'test');
      const a = await approve(p.body.promotion.id);
      expect(a.status).toBe(422);
      expect(a.body.code).toBe('evidence_not_ready');
      expect((await promoRow(p.body.promotion.id)).status).toBe('pending');
      expect(upstreamMain()).toBe(base);
    }, 120_000);
  });

  describe('who may do what', () => {
    it('only a principal holding repositories:promote can ask; nobody but the owner can approve or reject', async () => {
      const s = await session();
      expect((await promote(s, undefined, requester)).status).toBe(403); // the requester has work scopes, not promote
      expect((await promote(s, undefined, reader)).status).toBe(403);
      expect((await promote(s, undefined, ci)).status).toBe(403);
      const r = await promote(s);
      expect(r.status).toBe(202);
      const id = r.body.promotion.id;
      // there is no machine route for deciding
      expect((await v2(promoter, 'POST', `/work-sessions/${s.id}/promotions/${id}/approve`, {})).status).toBe(404);
      expect((await v2(promoter, 'POST', `/promotions/${id}/approve`, {})).status).toBe(404);
      expect((await approve(id, other, projectId)).status).toBe(404); // another owner
      expect((await h.api(other, 'POST', `/projects/${projectId}/promotions/${id}/reject`, {})).status).toBe(404);
      expect((await promoRow(id)).status).toBe('pending');
      // principals of another owner cannot see or ask either
      const foreign = await caller('foreign-promoter', ['repositories:promote'], other);
      expect((await promote(s, undefined, foreign)).status).toBe(404);
      expect((await v2(foreign, 'GET', `/work-sessions/${s.id}/promotions`)).status).toBe(404);
      await h.api(creator, 'POST', `/projects/${projectId}/promotions/${id}/reject`, {});
    }, 240_000);

    it('a rejection is final for that request, recorded, and the commit can be asked for again; a live request cannot be duplicated', async () => {
      const s = await session();
      const first = (await promote(s)).body.promotion;
      expect((await promote(s)).status).toBe(409); // already live
      const rej = await h.api(creator, 'POST', `/projects/${projectId}/promotions/${first.id}/reject`, { reason: 'not yet' });
      expect(rej.body.promotion).toMatchObject({ status: 'rejected', rejected_reason: 'not yet' });
      expect((await approve(first.id)).status).toBe(409);
      expect((await h.api(creator, 'POST', `/projects/${projectId}/promotions/${first.id}/reject`, {})).status).toBe(409);
      expect((await events()).some((e) => e.action === 'promotion.rejected' && e.payload.promotion_id === first.id && e.payload.reason === 'not yet')).toBe(true);
      expect(upstreamMain()).toBe(base);
      const again = await promote(s);
      expect(again.status).toBe(202);
      await h.api(creator, 'POST', `/projects/${projectId}/promotions/${again.body.promotion.id}/reject`, {});
    }, 240_000);
  });

  describe('fast-forward only, fail closed', () => {
    it('refuses when the default branch has moved on since the session started, and changes nothing', async () => {
      const s = await session();
      // someone else (the owner, directly) advances the default branch
      const scratch = path.join(work, 'moved');
      out1(['clone', '--quiet', upstream(), scratch]);
      write(scratch, 'src/a.ts', 'export const a = 99;\n');
      const moved = commitAll(scratch, 'owner moved main');
      out1(['push', '--quiet', upstream(), 'HEAD:main'], scratch);
      const p = (await promote(s)).body.promotion;
      const a = await approve(p.id);
      expect(a.status).toBe(409);
      expect(a.body.code).toBe('default_branch_moved');
      expect(upstreamMain()).toBe(moved);
      expect((await promoRow(p.id)).status).toBe('failed');
      expect((await promoRow(p.id)).failure_code).toBe('default_branch_moved');
      expect((await sessionRow(s.id)).status).toBe('active'); // the session lives on
      expect((await events()).filter((e) => e.action === 'promotion.failed' && e.payload.promotion_id === p.id)).toHaveLength(1);
      expect((await approve(p.id)).status).toBe(409); // a failed request is final
      await resetMain();
    }, 240_000);

    it('a failure to reach the repository fails the request and leaves the session running; it can be asked for again', async () => {
      const s = await session();
      const p = (await promote(s)).body.promotion;
      const good = process.env.GITHUB_GIT_URL;
      process.env.GITHUB_GIT_URL = 'http://127.0.0.1:1';
      try {
        const a = await approve(p.id);
        expect(a.status).toBe(502);
        expect(a.body.code).toBe('provider_unavailable');
        expect(JSON.stringify(a.body)).not.toMatch(/ghs_|Authorization/i);
      } finally {
        process.env.GITHUB_GIT_URL = good;
      }
      expect((await promoRow(p.id)).status).toBe('failed');
      expect((await sessionRow(s.id)).status).toBe('active');
      const again = (await promote(s)).body.promotion;
      expect((await approve(again.id)).body.promotion.status).toBe('completed');
      await resetMain();
    }, 240_000);

    it('an approved request that was never carried out (a crash) is resumed by approving again; one already in place completes without pushing', async () => {
      const s = await session();
      const p = (await promote(s)).body.promotion;
      await db.query(`UPDATE promotion_request SET status = 'approved', approved_by = $2, approved_at = now(), decided_at = now() WHERE id = $1`, [p.id, `creator:${creator.id}`]);
      // as if the push had already happened but the record was lost
      out1(['update-ref', 'refs/heads/main', s.commits[0]], upstream());
      const a = await approve(p.id);
      expect(a.body.promotion.status).toBe('completed');
      expect(upstreamMain()).toBe(s.commits[0]);
      const done = (await events()).find((e) => e.action === 'promotion.completed' && e.payload.promotion_id === p.id)!;
      expect(done.payload.already_in_place).toBe(true);
      await resetMain();
    }, 240_000);
  });

  it('the database refuses what the application would refuse, and a request is written once', async () => {
    const s = await session();
    const p = (await promote(s)).body.promotion;
    const ready = JSON.stringify({ ready: true, requirements: [] });
    const insert = (over: Record<string, unknown>) => {
      const o = { commit: s.commits[0], evidence: ready, principal: promoter.id, creator: null as string | null, ...over };
      return db.query(
        `INSERT INTO promotion_request (work_session_id, project_id, repository_id, target_branch, commit_hash, requested_by_principal_id, requested_by_creator_id, evidence_at_request)
         VALUES ($1, $2, $3, 'other-branch', $4, $5, $6, $7::jsonb)`,
        [s.id, projectId, repoId, o.commit, o.principal, o.creator, o.evidence]
      );
    };
    await expect(insert({ evidence: JSON.stringify({ ready: false }) })).rejects.toThrow(/chk_promotion_evidence_ready/);
    await expect(insert({ commit: 'c'.repeat(40) })).rejects.toThrow(/not one this session produced/);
    await expect(insert({ principal: requester.id })).rejects.toThrow(/repositories:promote/);
    await expect(insert({ principal: null, creator: other.id })).rejects.toThrow(/sponsoring owner/);
    await expect(insert({ principal: promoter.id, creator: creator.id })).rejects.toThrow(/chk_promotion_one_requester/);
    await expect(db.query(`UPDATE promotion_request SET commit_hash = $2 WHERE id = $1`, [p.id, 'd'.repeat(40)])).rejects.toThrow(/cannot be changed/);
    await expect(db.query(`UPDATE promotion_request SET status = 'approved', approved_by = $2, approved_at = now() WHERE id = $1`, [p.id, `principal:${promoter.id}`])).rejects.toThrow(/only the sponsoring owner/);
    await expect(db.query(`UPDATE promotion_request SET status = 'completed' WHERE id = $1`, [p.id])).rejects.toThrow(/cannot go from/);
    await expect(db.query(`DELETE FROM promotion_request WHERE id = $1`, [p.id])).rejects.toThrow();
    await expect(admin.query(`DELETE FROM promotion_request WHERE id = $1`, [p.id])).rejects.toThrow(/cannot be deleted/);
    await h.api(creator, 'POST', `/projects/${projectId}/promotions/${p.id}/reject`, {});
  }, 240_000);

  it('a completed session that outlives its end time is closed by the scheduler, not expired (and nothing breaks)', async () => {
    const s = await session();
    const p = (await promote(s)).body.promotion;
    expect((await approve(p.id)).body.promotion.status).toBe('completed');
    await withTriggersBypassed(admin, async (c) => {
      await c.query(`UPDATE work_session SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' WHERE id = $1`, [s.id]);
    });
    expect(await expireOverdueSessions(db)).toContain(s.id);
    expect(await sessionRow(s.id)).toMatchObject({ status: 'closed', closed_reason: 'completed_and_ended' });
    await resetMain();
  }, 240_000);

  it('the project\'s record still verifies', async () => {
    const check = await verifyServerProjectEvents(projectId);
    expect(check.isValid, check.reason).toBe(true);
  });
});
