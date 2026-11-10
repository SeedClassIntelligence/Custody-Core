import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { getAdminPool, getDbPool, runMigrations, verifyServerProjectEvents } from '../server/db';
import { addPrincipalKey, registerPrincipal } from '../server/servicePrincipals';
import { expireOverdueSessions } from '../server/workSessions';
import { recoverStuckProvisioning } from '../server/sessionProvisioning';
import { sessionViewPath } from '../server/gateway/realMirror';
import { forgetInstallationTokens } from '../server/github';
import { assertPoolTargetsTestDb } from './support/safety';
import { withTriggersBypassed } from './support/cleanup';
import { startHarness, Harness } from './support/apiHarness';
import { startApp, RunningApp } from './support/api';
import { startGitHubStandIn, StandIn } from './support/githubStandIn';
import { installGitleaks } from '../scripts/install-gitleaks';
import { assertion, newKey, TestKey } from './support/principalKeys';

/**
 * Controlled materialization (CL-11): an approved automated session gets a credential and a FILTERED copy of the repository, works in it
 * with ordinary git, and what it pushes is replayed onto the real history by the gateway, which alone decides who the author is.
 * Real git, the real app and database, real gitleaks, and a local stand-in for GitHub that serves real git repositories.
 */

const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0' };

// Async on purpose: the gateway under test runs in this same process, so a blocking git call to it would deadlock.
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

/** For git commands that only touch local directories (never the gateway). */
function gl(args: string[], cwd?: string) {
  const r = spawnSync('git', args, { cwd, env: GIT_ENV, encoding: 'utf8', timeout: 120_000 });
  return { code: r.status ?? 1, out: `${r.stdout}`, err: `${r.stderr}` };
}
const out1 = (args: string[], cwd?: string) => {
  const r = gl(args, cwd);
  expect(r.code, `${args.join(' ')}: ${r.err}`).toBe(0);
  return r.out.trim();
};
const ME = ['-c', 'user.name=Alice Creator', '-c', 'user.email=creator@example.com'];
function write(dir: string, file: string, content: string | Buffer, mode?: number) {
  fs.mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
  fs.writeFileSync(path.join(dir, file), content);
  if (mode) fs.chmodSync(path.join(dir, file), mode);
}
function commitAll(dir: string, message: string) {
  out1(['add', '-A'], dir);
  out1([...ME, 'commit', '--quiet', '--allow-empty', '-m', message], dir);
  return out1(['rev-parse', 'HEAD'], dir);
}

describe('Controlled materialization: credentials, filtered view, session gateway, replay onto the real history', () => {
  const db = getDbPool()!;
  const admin = getAdminPool()!;
  let standIn: StandIn;
  let h: Harness;
  let app: RunningApp;
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-mat-test-'));
  const savedEnv = { ...process.env };
  const ORG = `org${Date.now()}`;
  const APP = `${ORG}/app`;
  const OTHER = `${ORG}/other`;
  const INSTALLATION = 6000 + Math.floor(Math.random() * 1000);
  let creator: any;
  let projectId = '';
  let repoId = '';
  let otherRepoId = '';
  let base = ''; // the real repository's default branch tip, and the base of every session
  let sideCommit = ''; // a commit that exists only on a side branch
  let historyOnlyBlob = '';
  const hidden: Record<string, string> = {};
  const upstream = () => standIn.upstreamDir(APP);
  const upstreamRef = (ref: string) => {
    const r = gl(['rev-parse', '--verify', '--quiet', ref], upstream());
    return r.code === 0 ? r.out.trim() : null;
  };

  interface Caller { id: string; keyId: string; key: TestKey }
  async function caller(label: string, scopes: string[]): Promise<Caller> {
    const p = await registerPrincipal(db, creator.id, { name: `${label}-${crypto.randomUUID().slice(0, 6)}`, platform_type: 'agent', environment: 'development', allowed_scopes: scopes } as any, 'test');
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
  let requester: Caller, intruder: Caller, noScope: Caller;

  const RULES = {
    repository: 'read_and_push',
    allowed_read_paths: ['src/**', 'docs/**', 'bin/**', '.github/**', 'README.md'],
    allowed_write_paths: ['src/lib/**', 'docs/**'],
    prohibited_paths: ['**/*.pem', '.env*']
  };
  const EXPECTED_VIEW = ['.github/workflows/ci.yml', 'README.md', 'bin/run.sh', 'docs/readme.md', 'src/a.ts', 'src/lib/b.ts', 'src/lib/old.ts'];

  const sessionRow = async (id: string) => (await db.query('SELECT * FROM work_session WHERE id = $1', [id])).rows[0];
  const credRows = async (id: string) => (await db.query('SELECT * FROM session_credential WHERE work_session_id = $1 ORDER BY created_at', [id])).rows;
  const events = async () => (await db.query('SELECT seq, action, actor_type, actor_id, subject_id, payload FROM event WHERE project_id = $1 ORDER BY seq', [projectId])).rows;
  const lastEvent = async (action: string, sessionId?: string) => (await events()).filter((e) => e.action === action && (!sessionId || e.payload.work_session_id === sessionId || e.subject_id === sessionId)).at(-1);

  interface S { id: string; token: string; url: string; gitUrl: string; viewCommit: string }
  const urlWith = (id: string, token: string, repo = APP) => `${app.base.replace('http://', `http://session:${token}@`)}/git/sessions/${id}/${repo}.git`;

  async function request(over: Record<string, unknown> = {}, who = requester) {
    const r = await v2(who, 'POST', '/work-sessions', {
      project_id: projectId,
      repository_id: repoId,
      executor: { type: 'ai_assistant', provider: 'example-ai', model: 'model-1', external_id: 'agent_99', display_name: 'Refactor Engine' },
      sponsor: { type: 'creator', id: creator.id },
      objective: 'Refactor the library code',
      base_commit: base,
      access: RULES,
      expires_in_seconds: 3600,
      ...over
    });
    expect(r.status, JSON.stringify(r.body)).toBe(202);
    return r.body.session_id as string;
  }
  const approve = async (id: string) => expect((await h.api(creator, 'POST', `/projects/${projectId}/work-sessions/${id}/approve`, {})).status).toBe(200);
  const credential = (id: string, who = requester) => v2(who, 'POST', `/work-sessions/${id}/credential`);
  async function newSession(over: Record<string, unknown> = {}): Promise<S> {
    const id = await request(over);
    await approve(id);
    const r = await credential(id);
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    return { id, token: r.body.credential.token, url: r.body.git_url, gitUrl: urlWith(id, r.body.credential.token), viewCommit: r.body.view.commit };
  }
  async function clone(s: S, name: string) {
    const dir = path.join(work, name);
    const r = await gitc(['clone', '--quiet', s.gitUrl, dir]);
    expect(r.code, r.out).toBe(0);
    return dir;
  }
  const status = async (u: string, token?: string) =>
    (await fetch(u, { headers: token ? { Authorization: `Basic ${Buffer.from(`x:${token}`).toString('base64')}` } : {} })).status;
  const infoRefs = (id: string, repo = APP) => `${app.base}/git/sessions/${id}/${repo}.git/info/refs?service=git-upload-pack`;

  beforeAll(async () => {
    await assertPoolTargetsTestDb(admin);
    expect((await runMigrations()).success).toBe(true);
    await installGitleaks();
    standIn = await startGitHubStandIn();
    Object.assign(process.env, standIn.env, { GATEWAY_DATA_DIR: path.join(work, 'gateway'), APP_URL: '' });
    forgetInstallationTokens();
    standIn.addInstallation(INSTALLATION, ORG, [APP, OTHER]);
    standIn.createRepo(APP);
    standIn.createRepo(OTHER);

    // The real repository: files the session may read, files it may not, a symlink, an executable, and a secret that exists only in old history.
    const seed = path.join(work, 'seed');
    fs.mkdirSync(seed, { recursive: true });
    out1(['init', '--quiet', '--initial-branch=main'], seed);
    write(seed, 'old-secret.txt', 'history only\n');
    const first = commitAll(seed, 'first');
    historyOnlyBlob = out1(['rev-parse', `${first}:old-secret.txt`], seed);
    fs.rmSync(path.join(seed, 'old-secret.txt'));
    write(seed, 'README.md', '# app\n');
    write(seed, 'src/a.ts', 'export const a = 1;\n');
    write(seed, 'src/lib/b.ts', 'export const b = 1;\n');
    write(seed, 'src/lib/old.ts', 'export const old = 1;\n');
    write(seed, 'src/lib/cert.pem', 'not a real certificate\n');
    fs.symlinkSync('../../.env', path.join(seed, 'src/lib/link'));
    write(seed, 'docs/readme.md', 'docs\n');
    write(seed, 'bin/run.sh', '#!/bin/sh\necho hi\n', 0o755);
    write(seed, '.github/workflows/ci.yml', 'name: ci\n');
    write(seed, '.env', 'API_KEY=hunter2\n');
    write(seed, 'secrets/key.txt', 'top secret\n');
    write(seed, 'server/migrations/001.sql', 'select 1;\n');
    base = commitAll(seed, 'Initial state');
    for (const f of ['.env', 'secrets/key.txt', 'src/lib/cert.pem', 'server/migrations/001.sql']) hidden[f] = out1(['rev-parse', `${base}:${f}`], seed);
    out1(['push', '--quiet', '--force', upstream(), 'main:main'], seed);
    // A commit that is on a side branch only (never on the default branch).
    out1(['checkout', '--quiet', '-b', 'side'], seed);
    write(seed, 'src/side.ts', 'side\n');
    sideCommit = commitAll(seed, 'side work');
    out1(['push', '--quiet', upstream(), 'side:side'], seed);

    h = await startHarness();
    app = await startApp();
    creator = await h.newCreator('owner');
    await db.query(`INSERT INTO github_installation (creator_id, installation_id, account_login, account_type, connected_by_github_login) VALUES ($1, $2, $3, 'Organization', 'octo')`, [creator.id, INSTALLATION, ORG]);
    projectId = (await db.query(`INSERT INTO project (creator_id, name, purpose, status) VALUES ($1, 'Materialization', 'x', 'active') RETURNING id`, [creator.id])).rows[0].id;
    repoId = (await db.query(`INSERT INTO repository (project_id, github_repo_id, full_name) VALUES ($1, '1', $2) RETURNING id`, [projectId, APP])).rows[0].id;
    otherRepoId = (await db.query(`INSERT INTO repository (project_id, github_repo_id, full_name) VALUES ($1, '2', $2) RETURNING id`, [projectId, OTHER])).rows[0].id;
    requester = await caller('requester', ['work-sessions:request', 'work-sessions:read', 'work-sessions:close-own', 'repositories:push-session']);
    intruder = await caller('intruder', ['work-sessions:request', 'work-sessions:read', 'repositories:push-session']);
    noScope = await caller('noscope', ['work-sessions:request', 'work-sessions:read']);
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

  // ------------------------------------------------------------------------------------------------------------
  describe('provisioning', () => {
    it('gives nothing to a session that was not approved', async () => {
      const id = await request();
      const r = await credential(id);
      expect(r.status).toBe(409);
      expect(r.body.code).toBe('not_approved');
      expect(await credRows(id)).toHaveLength(0);
      expect((await sessionRow(id)).status).toBe('requested');
    });

    it('a request whose paths could not be enforced is refused when it is made, not when the session is about to start', async () => {
      for (const bad of ['src/\u200b**', 'src/\u202e**', 'src/\u2028**']) {
        const r = await v2(requester, 'POST', '/work-sessions', {
          project_id: projectId, repository_id: repoId, executor: { type: 'ai_assistant' }, sponsor: { type: 'creator', id: creator.id },
          objective: 'x', base_commit: base, access: { ...RULES, allowed_read_paths: [bad] }
        });
        expect(r.status, JSON.stringify(bad)).toBe(400);
        expect(r.body.error).toMatch(/invisible|separator/);
      }
    });

    it('needs the repositories:push-session scope and the principal that requested the session', async () => {
      const id = await request();
      await approve(id);
      expect((await credential(id, noScope)).status).toBe(403);
      expect((await credential(id, intruder)).status).toBe(404); // same creator, same scope, but not its session
      expect(await credRows(id)).toHaveLength(0);
      expect((await sessionRow(id)).status).toBe('approved');
    });

    describe('a normal session', () => {
      let s: S;
      let prov: any;
      it('is prepared: credential shown once and stored only as a hash, view recorded, events written', async () => {
        const id = await request();
        await approve(id);
        const r = await credential(id);
        expect(r.status).toBe(201);
        prov = r.body;
        s = { id, token: prov.credential.token, url: prov.git_url, gitUrl: urlWith(id, prov.credential.token), viewCommit: prov.view.commit };
        expect(prov.credential.token).toMatch(/^ccs_[A-Za-z0-9_-]{40,}$/);
        expect(prov).toMatchObject({ session_id: id, repository: APP, read_only: false, branch_prefix: `session/${id}/`, replaced: false });
        expect(prov.git_url).toBe(`${app.base}/git/sessions/${id}/${APP}.git`);
        expect(prov.view.file_count).toBe(EXPECTED_VIEW.length);

        const row = await sessionRow(id);
        expect(row.status).toBe('active');
        expect(row.provisioning_started_at).toBeNull();
        const creds = await credRows(id);
        expect(creds).toHaveLength(1);
        expect(creds[0].token_hash).toBe(crypto.createHash('sha256').update(prov.credential.token).digest('hex'));
        expect(JSON.stringify(creds)).not.toContain(prov.credential.token);

        const total = out1(['ls-tree', '-r', base], upstream()).split('\n').length;
        const view = (await db.query('SELECT * FROM session_view WHERE work_session_id = $1', [id])).rows[0];
        expect(view).toMatchObject({ base_commit: base, default_branch: 'main', default_branch_tip: base, file_count: EXPECTED_VIEW.length, view_commit: prov.view.commit });
        expect(view.excluded_count).toBe(total - EXPECTED_VIEW.length);

        const ev = await events();
        const provisioned = ev.filter((e) => e.action === 'work_session.provisioned' && e.subject_id === id);
        expect(provisioned).toHaveLength(1);
        // counts only: nothing that names, or reveals the size of, what was left out
        const text = JSON.stringify(provisioned[0].payload);
        for (const name of ['.env', 'secrets', 'key.txt', 'migrations', 'cert.pem', 'link', 'old-secret']) expect(text).not.toContain(name);
        expect(provisioned[0].payload).toMatchObject({ base_commit: base, view_commit: prov.view.commit, file_count: EXPECTED_VIEW.length, excluded_count: total - EXPECTED_VIEW.length, read_only: false });
        const issued = ev.filter((e) => e.action === 'session_credential.issued' && e.subject_id === id);
        expect(issued).toHaveLength(1);
        expect(JSON.stringify(issued)).not.toContain(prov.credential.token);
      }, 90_000);

      it('a clone holds exactly the allowed files, one commit, no history, and none of the hidden objects', async () => {
        const dir = await clone(s, 'view-clone');
        expect(out1(['ls-tree', '-r', '--name-only', 'HEAD'], dir).split('\n').sort()).toEqual([...EXPECTED_VIEW].sort());
        expect(out1(['rev-list', '--all', '--count'], dir)).toBe('1');
        expect(out1(['rev-parse', 'HEAD'], dir)).toBe(s.viewCommit);
        expect(out1(['ls-tree', 'HEAD', 'bin/run.sh'], dir)).toMatch(/^100755 /); // the executable bit is kept
        const all = out1(['cat-file', '--batch-all-objects', '--batch-check=%(objectname)'], dir).split('\n');
        for (const [name, sha] of [...Object.entries(hidden), ['history-only', historyOnlyBlob]]) {
          expect(all, name).not.toContain(sha);
          expect(gl(['cat-file', '-e', sha], dir).code, name).not.toBe(0);
          expect((await gitc(['fetch', 'origin', sha], dir)).code, `fetching ${name} by id`).not.toBe(0);
        }
        // the refs on offer are the view's own: nothing about the real repository's branches
        const refs = (await gitc(['ls-remote', s.gitUrl])).out.trim().split('\n').map((l) => l.split('\t')[1]);
        expect(refs.sort()).toEqual(['HEAD', 'refs/heads/main']);
      }, 60_000);

      it('a replacement credential revokes the old one at once, and every step is recorded', async () => {
        const before = s.token;
        const r = await credential(s.id);
        expect(r.status).toBe(200);
        expect(r.body.replaced).toBe(true);
        expect(r.body.credential.token).not.toBe(before);
        expect(r.body.view.commit).toBe(s.viewCommit);
        expect(await status(infoRefs(s.id), before)).toBe(401);
        expect(await status(infoRefs(s.id), r.body.credential.token)).toBe(200);
        s = { ...s, token: r.body.credential.token, gitUrl: urlWith(s.id, r.body.credential.token) };
        const creds = await credRows(s.id);
        expect(creds.filter((c) => !c.revoked_at)).toHaveLength(1);
        const ev = (await events()).filter((e) => e.subject_id === s.id);
        expect(ev.filter((e) => e.action === 'session_credential.revoked').map((e) => e.payload.reason)).toEqual(['replaced']);
        expect(ev.filter((e) => e.action === 'session_credential.issued')).toHaveLength(2);
      });

      it('credentials are for one session, one repository and one kind of gateway', async () => {
        const other = await newSession();
        expect(await status(infoRefs(s.id), s.token)).toBe(200);
        expect(await status(infoRefs(other.id), s.token)).toBe(403); // another session's address
        expect(await status(infoRefs(s.id, OTHER), s.token)).toBe(404); // another repository
        expect(await status(infoRefs(s.id))).toBe(401); // no credential
        expect(await status(infoRefs(s.id), `ccg_${crypto.randomBytes(32).toString('base64url')}`)).toBe(401); // a door-style token
        expect(await status(infoRefs(s.id), 'ccs_wrong')).toBe(401);
        // a session credential at a door's address (the door route looks only at door credentials)
        expect(await status(`${app.base}/git/${s.id}/${APP}.git/info/refs?service=git-upload-pack`, s.token)).toBe(401);
      }, 90_000);

      it('closing the session ends access on the next request and deletes the gateway\'s copy', async () => {
        const closing = await newSession();
        expect(fs.existsSync(sessionViewPath(closing.id))).toBe(true);
        expect((await v2(requester, 'POST', `/work-sessions/${closing.id}/close`)).status).toBe(200);
        expect(await status(infoRefs(closing.id), closing.token)).toBe(401);
        expect(fs.existsSync(sessionViewPath(closing.id))).toBe(false);
        expect((await credRows(closing.id)).every((c) => c.revoked_at)).toBe(true);
        const revoked = (await events()).filter((e) => e.action === 'session_credential.revoked' && e.subject_id === closing.id);
        expect(revoked.map((e) => e.payload.reason)).toEqual(['session_closed']);
        // a closed session gets no new credential
        expect((await credential(closing.id)).status).toBe(409);
      }, 90_000);

      it('the scheduler revokes the credential and deletes the copy when the session expires', async () => {
        const ending = await newSession();
        await withTriggersBypassed(admin, async (c) => {
          await c.query(`UPDATE work_session SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' WHERE id = $1`, [ending.id]);
        });
        // an expired session is refused even before the scheduler has run
        expect(await status(infoRefs(ending.id), ending.token)).toBe(403);
        expect(await expireOverdueSessions(db)).toContain(ending.id);
        expect(await status(infoRefs(ending.id), ending.token)).toBe(401);
        expect(fs.existsSync(sessionViewPath(ending.id))).toBe(false);
        const revoked = (await events()).filter((e) => e.action === 'session_credential.revoked' && e.subject_id === ending.id);
        expect(revoked.map((e) => [e.actor_id, e.payload.reason])).toEqual([['scheduler', 'session_expired']]);
      }, 90_000);

      it('a session with read access only can clone, and cannot push anything', async () => {
        const ro = await newSession({ access: { repository: 'read', allowed_read_paths: ['src/**'], allowed_write_paths: [], prohibited_paths: [] } });
        const dir = await clone(ro, 'readonly-clone');
        expect(out1(['ls-tree', '-r', '--name-only', 'HEAD'], dir).split('\n').sort()).toEqual(['src/a.ts', 'src/lib/b.ts', 'src/lib/cert.pem', 'src/lib/old.ts']);
        write(dir, 'src/lib/b.ts', 'changed\n');
        commitAll(dir, 'try');
        const r = await gitc(['push', 'origin', `HEAD:session/${ro.id}/work`], dir);
        expect(r.code).not.toBe(0);
        expect(r.out).toMatch(/403|read access/i);
        expect(upstreamRef(`refs/heads/session/${ro.id}/work`)).toBeNull();
      }, 90_000);
    });

    it('refuses a base commit that is not on the default branch, or does not exist, and leaves the session approved with nothing issued', async () => {
      for (const [commit, code] of [[sideCommit, 'base_not_on_default_branch'], ['b'.repeat(40), 'base_missing']] as const) {
        const id = await request({ base_commit: commit });
        await approve(id);
        const r = await credential(id);
        expect(r.status, JSON.stringify(r.body)).toBe(422);
        expect(r.body.code).toBe(code);
        expect((await sessionRow(id)).status).toBe('approved');
        expect(await credRows(id)).toHaveLength(0);
        expect((await db.query('SELECT 1 FROM session_view WHERE work_session_id = $1', [id])).rowCount).toBe(0);
        expect(fs.existsSync(path.dirname(sessionViewPath(id)))).toBe(false);
        const failed = await lastEvent('work_session.provisioning_failed', id);
        expect(failed.payload.reason).toBe(code);
        expect((await events()).some((e) => e.action === 'work_session.provisioned' && e.subject_id === id)).toBe(false);
      }
    }, 90_000);

    it('refuses a session whose rules leave nothing to read', async () => {
      const id = await request({ access: { ...RULES, allowed_read_paths: ['nothing/here/**'] } });
      await approve(id);
      const r = await credential(id);
      expect(r.status).toBe(422);
      expect(r.body.code).toBe('view_no_files');
      expect((await sessionRow(id)).status).toBe('approved');
      expect(await credRows(id)).toHaveLength(0);
    }, 60_000);

    it('a failure while fetching puts the session back to approved, and the next try works', async () => {
      const id = await request();
      await approve(id);
      const good = process.env.GITHUB_GIT_URL;
      process.env.GITHUB_GIT_URL = 'http://127.0.0.1:1';
      try {
        const bad = await credential(id);
        expect(bad.status).toBe(502);
        expect((await sessionRow(id)).status).toBe('approved');
        expect(await credRows(id)).toHaveLength(0);
        expect(JSON.stringify(bad.body)).not.toMatch(/ghs_|Authorization/i);
      } finally {
        process.env.GITHUB_GIT_URL = good;
      }
      const ok = await credential(id);
      expect(ok.status, JSON.stringify(ok.body)).toBe(201);
      expect((await sessionRow(id)).status).toBe('active');
    }, 90_000);

    it('two requests at once give exactly one active credential', async () => {
      const id = await request();
      await approve(id);
      const rs = await Promise.all([credential(id), credential(id)]);
      expect(rs.map((r) => r.status).sort()).toContainEqual(201);
      expect(rs.every((r) => [200, 201, 409].includes(r.status))).toBe(true);
      expect((await credRows(id)).filter((c) => !c.revoked_at)).toHaveLength(1);
      expect((await sessionRow(id)).status).toBe('active');
    }, 90_000);

    it('a session left in provisioning by a crash is put back by the scheduler, a recent one is not touched', async () => {
      const stuck = await request();
      const recent = await request();
      for (const id of [stuck, recent]) {
        await approve(id);
        await db.query(`UPDATE work_session SET status = 'provisioning', provisioning_started_at = now() WHERE id = $1`, [id]);
      }
      await db.query(`UPDATE work_session SET provisioning_started_at = now() - interval '20 minutes' WHERE id = $1`, [stuck]);
      expect(await recoverStuckProvisioning(db)).toEqual([stuck]);
      expect((await sessionRow(stuck)).status).toBe('approved');
      expect((await sessionRow(recent)).status).toBe('provisioning');
      expect((await lastEvent('work_session.provisioning_failed', stuck)).payload.reason).toBe('interrupted');
      await db.query(`UPDATE work_session SET status = 'approved', provisioning_started_at = NULL WHERE id = $1`, [recent]);
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('pushing', () => {
    let s: S;
    let c1: string;
    const branch = () => `session/${s.id}/work`;
    const rejected = async () => (await events()).filter((e) => e.action === 'git.push_rejected' && e.payload.work_session_id === s.id).at(-1);
    const realLog = (ref: string) => out1(['log', '--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%at%x1f%ct%x1f%P%x1f%B%x1e', ref], upstream()).split('\x1e').map((x) => x.trim()).filter(Boolean).map((x) => {
      const [sha, an, ae, cn, ce, at, ct, parents, body] = x.split('\x1f');
      return { sha, an, ae, cn, ce, at, ct, parents: parents ? parents.split(' ') : [], body };
    });

    /** A fresh start from the view's base for each refused push (the clone keeps what was pushed earlier). */
    async function fresh(name: string) {
      const dir = path.join(work, name);
      fs.rmSync(dir, { recursive: true, force: true });
      out1(['clone', '--quiet', '--no-hardlinks', c1, dir]);
      out1(['remote', 'set-url', 'origin', s.gitUrl], dir);
      out1(['checkout', '--quiet', '-B', 'work', s.viewCommit], dir);
      return dir;
    }
    async function expectRefused(dir: string, refspec: string, reason: string, ref = refspecRef(refspec)) {
      const before = ref ? upstreamRef(`refs/heads/${ref}`) : null;
      const r = await gitc(['push', 'origin', refspec], dir);
      expect(r.code, r.out).not.toBe(0);
      expect(r.out).toContain('Custody Core refused');
      if (ref) expect(upstreamRef(`refs/heads/${ref}`)).toBe(before);
      const ev = await rejected();
      expect(ev.payload.reason, r.out).toBe(reason);
      return { out: r.out, event: ev };
    }
    const refspecRef = (spec: string) => (spec.split(':')[1] ?? '').replace(/^refs\/heads\//, '') || null;

    beforeAll(async () => {
      s = await newSession();
      c1 = await clone(s, 'push-clone');
    }, 90_000);

    it('replays a push onto the real history: gateway as committer, the executor as author, the pushed author only as a trailer', async () => {
      write(c1, 'src/lib/b.ts', 'export const b = 2;\n');
      write(c1, 'src/lib/new.ts', '#!/bin/sh\n', 0o755);
      fs.rmSync(path.join(c1, 'src/lib/old.ts'));
      const viewTip = commitAll(c1, 'Update the library\n\nCustody-Work-Session: 00000000-forged');
      const r = await gitc(['push', 'origin', `HEAD:${branch()}`], c1);
      expect(r.code, r.out).toBe(0);

      const log = realLog(`refs/heads/${branch()}`);
      expect(log).toHaveLength(3); // the push, the base, the repository's first commit
      const [tip, parent] = log;
      expect(parent.sha).toBe(base);
      expect(tip.parents).toEqual([base]);
      // who: the declared executor wrote it, the gateway committed it, and the creator's name in the pushed commit is not an author
      expect([tip.an, tip.ae]).toEqual(['Refactor Engine', `session-${s.id}@sessions.custody.invalid`]);
      expect([tip.cn, tip.ce]).toEqual(['Custody Core', 'gateway@custody.invalid']);
      expect(tip.ae).not.toBe('creator@example.com');
      expect(tip.body).toContain(`Custody-Work-Session: ${s.id}`);
      expect(tip.body).toContain('Custody-Declared-Author: Alice Creator <creator@example.com>');
      expect(tip.body).not.toContain('00000000-forged'); // a pushed trailer cannot stand in for the real one
      expect(tip.body.startsWith('Update the library')).toBe(true);
      // what: exactly the three changes, and the new file is executable
      expect(out1(['diff', '--no-renames', '--name-status', base, tip.sha], upstream()).split('\n').sort()).toEqual(['A\tsrc/lib/new.ts', 'D\tsrc/lib/old.ts', 'M\tsrc/lib/b.ts']);
      expect(out1(['ls-tree', tip.sha, 'src/lib/new.ts'], upstream())).toMatch(/^100755 /);
      // everything the session could not see is still there, byte for byte
      for (const f of ['.env', 'secrets/key.txt', 'server/migrations/001.sql', 'src/lib/cert.pem', 'src/lib/link']) {
        expect(out1(['rev-parse', `${tip.sha}:${f}`], upstream()), f).toBe(out1(['rev-parse', `${base}:${f}`], upstream()));
      }
      expect(out1(['ls-tree', tip.sha, 'src/lib/link'], upstream())).toMatch(/^120000 /);
      // the push output tells the executor each pair; the map and the events agree with it
      expect(r.out).toContain(`${viewTip.slice(0, 12)} -> ${tip.sha.slice(0, 12)}`);
      const rows = (await db.query('SELECT * FROM session_commit WHERE work_session_id = $1', [s.id])).rows;
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({ view_sha: viewTip, real_sha: tip.sha, parent_view_sha: s.viewCommit, declared_author: 'Alice Creator <creator@example.com>' });
      const push = (await events()).filter((e) => e.action === 'git.push' && e.payload.work_session_id === s.id).at(-1);
      expect(push).toMatchObject({ actor_type: 'gateway', actor_id: `session:${s.id}` });
      expect(push.payload.commits).toEqual([{ view: viewTip, real: tip.sha }]);
      // who wrote it, as recorded: derived from the session, with the pushed claim (the creator's name) kept only as untrusted evidence
      const attr = await v2(requester, 'GET', `/work-sessions/${s.id}/attribution`);
      expect(attr.body.contributions).toHaveLength(1);
      expect(attr.body.contributions[0]).toMatchObject({
        commit: tip.sha,
        author: { principal_id: requester.id, as_written_in_git: { name: tip.an, email: tip.ae } },
        committer: { kind: 'gateway' },
        sponsor: { id: creator.id },
        declared_author: { value: 'Alice Creator <creator@example.com>', trusted: false }
      });
      const attrEvent = (await events()).filter((e) => e.action === 'attribution.recorded' && e.payload.work_session_id === s.id).at(-1);
      expect(attrEvent).toMatchObject({ actor_type: 'gateway', actor_id: `session:${s.id}` });
      expect(attrEvent.payload).toMatchObject({ author_principal_id: requester.id, sponsor_id: creator.id, committer: 'gateway', commits: [tip.sha] });
      const listed = await v2(requester, 'GET', `/work-sessions/${s.id}/commits`);
      expect(listed.body.commits).toEqual([expect.objectContaining({ view_sha: viewTip, real_sha: tip.sha, parent_view_sha: s.viewCommit })]);
      expect((await v2(intruder, 'GET', `/work-sessions/${s.id}/commits`)).status).toBe(404);
    }, 120_000);

    it('takes several commits in one push, and later pushes on top, as one straight line', async () => {
      write(c1, 'docs/readme.md', 'docs v2\n');
      commitAll(c1, 'docs 1');
      write(c1, 'src/lib/b.ts', 'export const b = 3;\n');
      commitAll(c1, 'lib 2');
      write(c1, 'docs/more.md', 'more\n');
      const tip2 = commitAll(c1, 'docs 3');
      expect((await gitc(['push', 'origin', `HEAD:${branch()}`], c1)).code).toBe(0);
      write(c1, 'docs/more.md', 'more v2\n');
      const tip3 = commitAll(c1, 'docs 4');
      expect((await gitc(['push', 'origin', `HEAD:${branch()}`], c1)).code).toBe(0);

      const log = realLog(`refs/heads/${branch()}`);
      expect(log.map((l) => l.body.split('\n')[0])).toEqual(['docs 4', 'docs 3', 'lib 2', 'docs 1', 'Update the library', 'Initial state', 'first']);
      expect(log[5].sha).toBe(base);
      expect(log.slice(0, 5).every((l) => l.cn === 'Custody Core' && l.an === 'Refactor Engine')).toBe(true);
      expect(log.every((l, i) => i === log.length - 1 || l.parents[0] === log[i + 1].sha)).toBe(true);
      expect(log[0].sha).toBe((await db.query('SELECT real_sha FROM session_commit WHERE work_session_id = $1 AND view_sha = $2', [s.id, tip3])).rows[0].real_sha);
      expect((await db.query('SELECT count(*)::int AS n FROM session_commit WHERE work_session_id = $1', [s.id])).rows[0].n).toBe(5);
      expect(tip2).not.toBe(tip3);
      // the real repository's default branch did not move
      expect(upstreamRef('refs/heads/main')).toBe(base);
    }, 180_000);

    it('replaying is a pure function: the same commits pushed again, even with the map lost, give the same real commits', async () => {
      const tipReal = upstreamRef(`refs/heads/${branch()}`)!;
      const rows = (await db.query('SELECT view_sha, real_sha FROM session_commit WHERE work_session_id = $1 ORDER BY created_at, view_sha', [s.id])).rows;
      await withTriggersBypassed(admin, async (c) => {
        await c.query('DELETE FROM session_commit WHERE work_session_id = $1', [s.id]); // as if the process died before it recorded anything
      });
      const again = await gitc(['push', 'origin', `HEAD:session/${s.id}/again`], c1);
      expect(again.code, again.out).toBe(0);
      expect(upstreamRef(`refs/heads/session/${s.id}/again`)).toBe(tipReal);
      const after = (await db.query('SELECT view_sha, real_sha FROM session_commit WHERE work_session_id = $1 ORDER BY view_sha', [s.id])).rows;
      expect(after).toEqual([...rows].sort((a, b) => (a.view_sha < b.view_sha ? -1 : 1)));
    }, 120_000);

    it('a branch can start from an older pushed commit, and the refs on offer are only the session\'s own', async () => {
      const r = await gitc(['push', 'origin', `HEAD~1:refs/heads/session/${s.id}/mid`], c1);
      expect(r.code, r.out).toBe(0);
      const log = realLog(`refs/heads/session/${s.id}/mid`);
      expect(log[0].body.split('\n')[0]).toBe('docs 3');
      const refs = (await gitc(['ls-remote', s.gitUrl])).out.trim().split('\n').map((l) => l.split('\t')[1]).sort();
      expect(refs).toEqual(['HEAD', 'refs/heads/main', `refs/heads/session/${s.id}/again`, `refs/heads/session/${s.id}/mid`, `refs/heads/session/${s.id}/work`].sort());
    }, 120_000);

    it('refuses writes outside the write paths, naming the path and why', async () => {
      const dir = await fresh('r-outside');
      write(dir, 'src/a.ts', 'export const a = 2;\n');
      commitAll(dir, 'edit outside');
      const { out, event } = await expectRefused(dir, `HEAD:session/${s.id}/r1`, 'path_not_allowed');
      expect(out).toContain('src/a.ts');
      expect(out).toContain('not_writable');
      expect(event.payload.paths).toEqual([expect.objectContaining({ path: 'src/a.ts', reason: 'not_writable' })]);
    }, 90_000);

    it('refuses prohibited paths however they are spelled (case, Unicode compatibility forms)', async () => {
      const dir = await fresh('r-prohibited');
      write(dir, 'src/lib/Deploy.PEM', 'x\n');
      write(dir, 'src/lib/x.ｐｅｍ', 'x\n'); // fullwidth "pem"
      commitAll(dir, 'prohibited');
      const { event } = await expectRefused(dir, `HEAD:session/${s.id}/r2`, 'path_not_allowed');
      expect(event.payload.path_count).toBe(2);
      expect(event.payload.paths.map((p: any) => p.reason)).toEqual(['prohibited', 'prohibited']);
    }, 90_000);

    it('refuses pipeline files and renames that cross the write boundary', async () => {
      const dir = await fresh('r-ci');
      write(dir, '.github/workflows/ci.yml', 'name: owned\n');
      commitAll(dir, 'ci');
      await expectRefused(dir, `HEAD:session/${s.id}/r3`, 'path_not_allowed');
      const dir2 = await fresh('r-rename');
      out1(['mv', 'src/lib/b.ts', 'src/b2.ts'], dir2);
      commitAll(dir2, 'move out');
      const { event } = await expectRefused(dir2, `HEAD:session/${s.id}/r4`, 'path_not_allowed');
      expect(event.payload.paths.map((p: any) => p.path)).toEqual(['src/b2.ts']); // the delete is allowed, the add is not
    }, 120_000);

    it('refuses symlinks, and refuses to overwrite a file of the real tree that the session cannot see', async () => {
      const dir = await fresh('r-link');
      fs.symlinkSync('../../.env', path.join(dir, 'src/lib/s2'));
      commitAll(dir, 'symlink');
      const { event } = await expectRefused(dir, `HEAD:session/${s.id}/r5`, 'path_not_allowed');
      expect(event.payload.paths[0]).toMatchObject({ path: 'src/lib/s2', reason: 'not_a_regular_file' });

      // src/lib/link is a symlink in the real repository: the view omits it, so the session may "add" a file of that name. It must not replace the link.
      const dir2 = await fresh('r-overwrite');
      expect(fs.existsSync(path.join(dir2, 'src/lib/link'))).toBe(false);
      write(dir2, 'src/lib/link', 'now a file\n');
      commitAll(dir2, 'overwrite');
      const r = await expectRefused(dir2, `HEAD:session/${s.id}/r6`, 'path_not_allowed');
      expect(r.event.payload.paths[0]).toMatchObject({ path: 'src/lib/link', reason: 'would_overwrite' });
    }, 120_000);

    it('refuses history rewriting, new roots, merges, tags, deletes and branches that are not the session\'s', async () => {
      // force push over a pushed branch
      const dir = await fresh('r-force');
      write(dir, 'docs/readme.md', 'rewritten\n');
      commitAll(dir, 'a different first commit');
      const before = upstreamRef(`refs/heads/${branch()}`);
      const f = await gitc(['push', '--force', 'origin', `HEAD:${branch()}`], dir);
      expect(f.code).not.toBe(0);
      expect((await rejected()).payload.reason).toBe('not_fast_forward');
      expect(upstreamRef(`refs/heads/${branch()}`)).toBe(before);

      // a new root
      const o = await fresh('r-orphan');
      out1(['checkout', '--quiet', '--orphan', 'orph'], o);
      out1(['rm', '-rf', '--quiet', '.'], o);
      write(o, 'src/lib/orph.txt', 'x\n');
      commitAll(o, 'unrelated root');
      await expectRefused(o, `HEAD:session/${s.id}/r7`, 'new_root');

      // a merge
      const m = await fresh('r-merge');
      write(m, 'docs/m1.md', '1\n');
      const left = commitAll(m, 'left');
      out1(['checkout', '--quiet', '-B', 'right', s.viewCommit], m);
      write(m, 'docs/m2.md', '2\n');
      commitAll(m, 'right');
      out1([...ME, 'merge', '--quiet', '--no-ff', '-m', 'merge', left], m);
      await expectRefused(m, `HEAD:session/${s.id}/r8`, 'merge_commit');

      // tags, other branches (including another session's), deletes
      const t = await fresh('r-refs');
      write(t, 'docs/t.md', 't\n');
      commitAll(t, 'for refs');
      out1(['tag', 'v1'], t);
      await expectRefused(t, 'v1', 'ref_not_allowed', null);
      await expectRefused(t, 'HEAD:main', 'ref_not_allowed', null);
      await expectRefused(t, `HEAD:session/${crypto.randomUUID()}/x`, 'ref_not_allowed', null);
      await expectRefused(t, `:${branch()}`, 'delete_not_allowed', branch());
      expect(upstreamRef(`refs/heads/${branch()}`)).toBe(before);
      expect(upstreamRef('refs/heads/main')).toBe(base);
      expect(upstreamRef('refs/tags/v1')).toBeNull();
    }, 240_000);

    it('refuses a secret, even if a later commit removes it, and never repeats or records it', async () => {
      const dir = await fresh('r-secret');
      const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const pem = privateKey.export({ type: 'pkcs1', format: 'pem' }).toString();
      write(dir, 'src/lib/deploy.txt', pem);
      commitAll(dir, 'add key');
      fs.rmSync(path.join(dir, 'src/lib/deploy.txt'));
      commitAll(dir, 'remove key');
      const { out, event } = await expectRefused(dir, `HEAD:session/${s.id}/r9`, 'secret_found');
      expect(out).toContain('src/lib/deploy.txt');
      expect(out).not.toContain(pem.split('\n')[1]);
      expect(JSON.stringify(event.payload)).not.toContain(pem.split('\n')[1]);
      expect(event.payload.findings[0]).toMatchObject({ rule: 'private-key', file: 'src/lib/deploy.txt' });
    }, 90_000);

    it('enforces the commit, path and file-size limits', async () => {
      const set = (k: string, v: string | undefined) => (v === undefined ? delete process.env[k] : (process.env[k] = v));
      const dir = await fresh('r-limits');
      write(dir, 'docs/l1.md', '1\n');
      commitAll(dir, 'l1');
      write(dir, 'docs/l2.md', '2\n');
      commitAll(dir, 'l2');
      write(dir, 'docs/l3.md', '3\n');
      commitAll(dir, 'l3');
      try {
        set('SESSION_PUSH_MAX_COMMITS', '2');
        await expectRefused(dir, `HEAD:session/${s.id}/r10`, 'too_many_commits');
      } finally {
        set('SESSION_PUSH_MAX_COMMITS', undefined);
      }
      const dir2 = await fresh('r-limits2');
      write(dir2, 'docs/p1.md', '1\n');
      write(dir2, 'docs/p2.md', '2\n');
      commitAll(dir2, 'two paths');
      try {
        set('SESSION_PUSH_MAX_PATHS', '1');
        await expectRefused(dir2, `HEAD:session/${s.id}/r11`, 'too_many_paths');
      } finally {
        set('SESSION_PUSH_MAX_PATHS', undefined);
      }
      const dir3 = await fresh('r-limits3');
      write(dir3, 'docs/big.md', 'x'.repeat(5000));
      commitAll(dir3, 'big');
      try {
        set('SESSION_PUSH_MAX_FILE_BYTES', '1000');
        await expectRefused(dir3, `HEAD:session/${s.id}/r12`, 'file_too_large');
      } finally {
        set('SESSION_PUSH_MAX_FILE_BYTES', undefined);
      }
      // with the limits back to normal the same commits go through
      expect((await gitc(['push', 'origin', `HEAD:session/${s.id}/big-ok`], dir3)).code).toBe(0);
    }, 240_000);

    it('does not overwrite a branch that someone changed in the real repository', async () => {
      const contested = `session/${s.id}/contested`;
      const scratch = path.join(work, 'creator-scratch');
      out1(['clone', '--quiet', upstream(), scratch]);
      out1(['checkout', '--quiet', '-b', 'x'], scratch);
      write(scratch, 'docs/creator.md', 'creator was here\n');
      const theirs = commitAll(scratch, 'creator work');
      out1(['push', '--quiet', upstream(), `x:refs/heads/${contested}`], scratch);
      const dir = await fresh('r-contested');
      write(dir, 'docs/c.md', 'c\n');
      commitAll(dir, 'session work');
      await expectRefused(dir, `HEAD:${contested}`, 'upstream_changed');
      expect(upstreamRef(`refs/heads/${contested}`)).toBe(theirs);
    }, 90_000);

    it('after all of this: the real default branch is untouched, no refused push left a branch behind, and the record verifies', async () => {
      expect(upstreamRef('refs/heads/main')).toBe(base);
      const branches = out1(['for-each-ref', '--format=%(refname)', 'refs/heads/session'], upstream()).split('\n').sort();
      expect(branches).toEqual([`refs/heads/session/${s.id}/again`, `refs/heads/session/${s.id}/big-ok`, `refs/heads/session/${s.id}/contested`, `refs/heads/session/${s.id}/mid`, `refs/heads/session/${s.id}/work`].sort());
      const check = await verifyServerProjectEvents(projectId);
      expect(check.isValid, check.reason).toBe(true);
      // nothing in the project's record contains a credential
      const all = JSON.stringify(await events());
      expect(all).not.toMatch(/ccs_[A-Za-z0-9_-]{20}/);
    }, 60_000);
  });
});
