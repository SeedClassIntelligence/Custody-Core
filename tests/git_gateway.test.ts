import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn, spawnSync } from 'node:child_process';
import express from 'express';
import { getAdminPool, getDbPool, runMigrations, insertEvent, verifyServerProjectEvents } from '../server/db';
import { gatewayRouter } from '../server/gateway/router';
import { mirrorPath } from '../server/gateway/mirror';
import { githubApiRouter, githubCallbackRouter } from '../server/githubRoutes';
import { projectExtrasRouter } from '../server/doors';
import { developerRouter } from '../server/developerRoutes';
import { acceptSignAndGetCredential } from './support/developerFlow';
import { forgetInstallationTokens } from '../server/github';
import { assertPoolTargetsTestDb } from './support/safety';
import { startGitHubStandIn, StandIn } from './support/githubStandIn';
import { installGitleaks } from '../scripts/install-gitleaks';

/**
 * The git gateway end to end: real git commands against the real gateway and database, real gitleaks, and a
 * local stand-in for GitHub that serves real git repositories and checks the App's tokens.
 *
 * Login is not part of this file: the routers are mounted behind a test step that sets the creator, as the real
 * login does after its checks (those are tested in auth_api.test.ts and second_factor.test.ts, and the last test
 * here checks the real app keeps these routes behind login).
 */

const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0' };

// Async on purpose: the gateway under test runs in this same process, so a blocking git call would deadlock.
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
function gitLocal(args: string[], cwd?: string) {
  const r = spawnSync('git', args, { cwd, env: GIT_ENV, encoding: 'utf8', timeout: 120_000 });
  return { code: r.status ?? 1, out: `${r.stdout}\n${r.stderr}` };
}

function commit(dir: string, file: string, content: string, message: string) {
  fs.mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
  fs.writeFileSync(path.join(dir, file), content);
  expect(gitLocal(['add', file], dir).code).toBe(0);
  expect(gitLocal(['-c', 'user.name=Dev', '-c', 'user.email=dev@example.com', 'commit', '--quiet', '-m', message], dir).code).toBe(0);
  return gitLocal(['rev-parse', 'HEAD'], dir).out.trim().split('\n')[0];
}

function upstreamRef(standIn: StandIn, repo: string, ref: string): string | null {
  const r = gitLocal(['rev-parse', '--verify', '--quiet', ref], standIn.upstreamDir(repo));
  return r.code === 0 ? r.out.trim().split('\n')[0] : null;
}

describe('Git gateway (doors, credentials, branch policy, secret scan, GitHub forwarding)', () => {
  const db = getDbPool()!;
  const admin = getAdminPool()!;
  let standIn: StandIn;
  let server: http.Server;
  let base = '';
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-gw-test-'));
  const savedEnv = { ...process.env };

  const creator = { id: '', userId: `user-${crypto.randomUUID()}`, email: `creator_${Date.now()}@example.com` };
  const other = { id: '', userId: `user-${crypto.randomUUID()}`, email: `other_${Date.now()}@example.com` };
  // Developers have their own logins (rows like any signed-in person).
  const dev = { id: '', userId: `user-${crypto.randomUUID()}`, email: 'dev@example.com' };
  const dev2 = { id: '', userId: `user-${crypto.randomUUID()}`, email: 'dev2@example.com' };
  const ORG = `org${Date.now()}`;
  const APP = `${ORG}/app`;
  const DOCS = `${ORG}/docs`;
  const INSTALLATION = 4000 + Math.floor(Math.random() * 1000);
  let projectId = '';

  async function api(who: typeof creator, method: string, p: string, body?: unknown, headers: Record<string, string> = {}) {
    const res = await fetch(`${base}/api/v1${p}`, {
      method,
      redirect: 'manual',
      headers: { 'x-test-creator': who.id, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    return { status: res.status, body: (await res.json().catch(() => ({}))) as any, headers: res.headers };
  }

  function remote(doorId: string, repo: string, token: string) {
    return `${base.replace('http://', `http://door:${token}@`)}/git/${doorId}/${repo}.git`;
  }

  async function actions(): Promise<any[]> {
    return (await db.query('SELECT seq, action, payload FROM event WHERE project_id = $1 ORDER BY seq', [projectId])).rows;
  }

  beforeAll(async () => {
    await assertPoolTargetsTestDb(admin);
    expect((await runMigrations()).success).toBe(true);
    await installGitleaks();

    standIn = await startGitHubStandIn();
    Object.assign(process.env, standIn.env, { GATEWAY_DATA_DIR: path.join(work, 'gateway'), APP_URL: '' });
    forgetInstallationTokens();
    standIn.addInstallation(INSTALLATION, ORG, [APP, DOCS]);
    standIn.createRepo(APP);
    standIn.createRepo(DOCS);

    for (const c of [creator, other, dev, dev2]) {
      c.id = (await db.query('INSERT INTO creator (identity_id, display_name, email) VALUES ($1, $2, $3) RETURNING id', [c.userId, 'Test', c.email])).rows[0].id;
    }
    projectId = (await db.query(`INSERT INTO project (creator_id, name, purpose, status) VALUES ($1, 'Gateway test', 'Testing the gateway', 'active') RETURNING id`, [creator.id])).rows[0].id;
    await insertEvent({ project_id: projectId, actor_type: 'creator', actor_id: creator.id, action: 'project.claimed', subject_type: 'project', subject_id: projectId, payload: {} });

    const app = express();
    app.use('/git', gatewayRouter);
    app.use('/github', githubCallbackRouter);
    app.use(express.json());
    const api = express.Router();
    api.use(async (req, res, next) => {
      const id = req.header('x-test-creator');
      const row = id ? (await db.query('SELECT id, identity_id, email FROM creator WHERE id = $1', [id])).rows[0] : null;
      if (!row) return res.status(401).json({ error: 'test login missing' });
      res.locals.creator = { id: row.id, userId: row.identity_id, email: row.email };
      next();
    });
    api.use('/github', githubApiRouter);
    api.use('/projects/:id', projectExtrasRouter);
    api.use('/developer', developerRouter);
    app.use('/api/v1', api);
    server = http.createServer(app);
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    base = `http://127.0.0.1:${(server.address() as any).port}`;
  });

  afterAll(async () => {
    await new Promise<void>((r) => server?.close(() => r()));
    await standIn?.stop();
    for (const k of Object.keys(process.env)) if (!(k in savedEnv)) delete process.env[k];
    Object.assign(process.env, savedEnv);
    fs.rmSync(work, { recursive: true, force: true });
  });

  describe('connecting GitHub', () => {
    async function startInstall(who = creator) {
      const r = await api(who, 'POST', '/github/install');
      expect(r.status).toBe(200);
      const cookie = r.headers.get('set-cookie')!.split(';')[0];
      const state = new URL(r.body.url).searchParams.get('state')!;
      expect(r.body.url).toContain('/apps/custody-core-test/installations/new');
      return { cookie, state };
    }
    async function callback(query: Record<string, string>, cookie?: string) {
      const res = await fetch(`${base}/github/callback?${new URLSearchParams(query)}`, { redirect: 'manual', headers: cookie ? { cookie } : {} });
      expect(res.status).toBe(303);
      return new URL(res.headers.get('location')!, base).searchParams;
    }

    it('is refused without the cookie from this browser, with a different state, or for someone else\'s installation', async () => {
      const { cookie, state } = await startInstall();
      const code = () => standIn.issueUserCode('octo', [INSTALLATION]);
      expect((await callback({ installation_id: String(INSTALLATION), code: code(), state, setup_action: 'install' })).get('reason')).toBe('start_again');
      expect((await callback({ installation_id: String(INSTALLATION), code: code(), state: 'other', setup_action: 'install' }, cookie)).get('reason')).toBe('start_again');
      // A GitHub user who cannot access the installation cannot attach it to anyone.
      const stranger = standIn.issueUserCode('stranger', [999]);
      expect((await callback({ installation_id: String(INSTALLATION), code: stranger, state, setup_action: 'install' }, cookie)).get('reason')).toBe('not_your_installation');
      expect((await api(creator, 'GET', '/github')).body.connected).toBe(false);
    });

    it('records the installation when the installing GitHub user really has access to it', async () => {
      const { cookie, state } = await startInstall();
      const code = standIn.issueUserCode('octo', [INSTALLATION]);
      const q = await callback({ installation_id: String(INSTALLATION), code, state, setup_action: 'install' }, cookie);
      expect(q.get('github')).toBe('connected');
      const status = await api(creator, 'GET', '/github');
      expect(status.body).toMatchObject({ configured: true, connected: true, account_login: ORG });
      const ev = await db.query(`SELECT payload FROM account_event WHERE account_id = $1 AND action = 'account.github_connected'`, [creator.userId]);
      expect(ev.rows[0].payload).toMatchObject({ installation_id: INSTALLATION, connected_by_github_login: 'octo' });
    });

    it('lists the repositories the installation can see, and adds only those to a project', async () => {
      const list = await api(creator, 'GET', '/github/repositories');
      expect(list.body.repositories.map((r: any) => r.full_name).sort()).toEqual([APP, DOCS].map((s) => s.toLowerCase()).sort());
      expect((await api(creator, 'POST', `/projects/${projectId}/repositories`, { full_names: [`${ORG}/secret-other`] })).status).toBe(422);
      expect((await api(other, 'POST', `/projects/${projectId}/repositories`, { full_names: [APP] })).status).toBe(404);
      const added = await api(creator, 'POST', `/projects/${projectId}/repositories`, { full_names: [APP, DOCS] });
      expect(added.status).toBe(201);
      expect(added.body.repositories).toHaveLength(2);
    });
  });

  describe('a door', () => {
    let doorId = '';
    let token = '';
    let repoIds: Record<string, string> = {};

    it('is created as a draft, and only by the project owner', async () => {
      const repos = (await db.query('SELECT id, full_name FROM repository WHERE project_id = $1', [projectId])).rows;
      repoIds = Object.fromEntries(repos.map((r) => [r.full_name.toLowerCase(), r.id]));
      const body = {
        developer_email: 'dev@example.com',
        job_description: 'Fix the login page',
        rights_type: 'contribute',
        expires_at: new Date(Date.now() + 7 * 86400_000).toISOString(),
        repositories: [{ repository_id: repoIds[APP.toLowerCase()], access: 'write' }, { repository_id: repoIds[DOCS.toLowerCase()], access: 'read' }]
      };
      expect((await api(other, 'POST', `/projects/${projectId}/doors`, body)).status).toBe(404);
      expect((await api(creator, 'POST', `/projects/${projectId}/doors`, { ...body, expires_at: '2000-01-01T00:00:00Z' })).status).toBe(400);
      const created = await api(creator, 'POST', `/projects/${projectId}/doors`, body);
      expect(created.status).toBe(201);
      expect(created.body.door).toMatchObject({ status: 'draft', developer_email: 'dev@example.com', credential: null });
      doorId = created.body.door.id;
      expect(created.body.door.branch_prefix).toBe(`door/${doorId}/`);
    });

    it('opens only after the invited developer signs, and the credential goes to the developer, stored only as a hash', async () => {
      const invited = await api(creator, 'POST', `/projects/${projectId}/doors/${doorId}/invite`);
      expect(invited.status).toBe(200);
      expect(invited.body.door.status).toBe('awaiting_signature');
      token = await acceptSignAndGetCredential(api, dev, invited.body.invite.url);
      expect(token).toMatch(/^ccg_[A-Za-z0-9_-]{43}$/);
      const listed = await api(creator, 'GET', `/projects/${projectId}/doors`);
      const door = listed.body.doors.find((d: any) => d.id === doorId);
      expect(door.status).toBe('open');
      expect(door.remotes.map((r: any) => r.url)).toContain(`${base}/git/${doorId}/${APP.toLowerCase()}.git`);
      const stored = (await db.query('SELECT token_hash FROM gateway_credential WHERE door_id = $1 AND revoked_at IS NULL', [doorId])).rows[0].token_hash;
      expect(stored).toBe(crypto.createHash('sha256').update(token).digest('hex'));
      expect(JSON.stringify(await actions())).not.toContain(token);
      // The creator never sees the credential.
      expect(JSON.stringify(listed.body)).not.toContain(token);
      expect((await api(creator, 'POST', `/projects/${projectId}/doors/${doorId}/invite`)).status).toBe(409);
    });

    it('refuses git requests with no credential, a wrong one, or for another door', async () => {
      const url = `${base}/git/${doorId}/${APP}.git/info/refs?service=git-upload-pack`;
      expect((await fetch(url)).status).toBe(401);
      expect((await fetch(url, { headers: { Authorization: `Basic ${Buffer.from('door:ccg_wrong').toString('base64')}` } })).status).toBe(401);
      const otherDoor = crypto.randomUUID();
      expect((await fetch(`${base}/git/${otherDoor}/${APP}.git/info/refs?service=git-upload-pack`, { headers: { Authorization: `Basic ${Buffer.from(`door:${token}`).toString('base64')}` } })).status).toBe(403);
      expect((await gitc(['ls-remote', remote(doorId, `${ORG}/not-in-door`, token)])).code).not.toBe(0);
    });

    it('clones through the gateway (not GitHub), and never shows another door\'s branches', async () => {
      // Another door's work on GitHub must not reach this developer.
      const elsewhere = path.join(work, 'elsewhere');
      expect((await gitc(['clone', '--quiet', standIn.upstreamDir(APP), elsewhere])).code).toBe(0);
      commit(elsewhere, 'other.txt', 'other door\n', 'Other door work');
      const otherBranch = `door/${crypto.randomUUID()}/work`;
      expect((await gitc(['push', '--quiet', standIn.upstreamDir(APP), `HEAD:${otherBranch}`], elsewhere)).code).toBe(0);

      const clone = path.join(work, 'clone');
      const r = (await gitc(['clone', remote(doorId, APP, token), clone]));
      expect(r.code, r.out).toBe(0);
      expect(fs.readFileSync(path.join(clone, 'README.md'), 'utf8')).toContain(APP);
      const branches = (await gitc(['ls-remote', 'origin'], clone)).out;
      expect(branches).toContain('refs/heads/main');
      expect(branches).not.toContain(otherBranch);
      expect((await gitc(['cat-file', '-e', upstreamRef(standIn, APP, otherBranch)!], mirrorPath(doorId, repoIds[APP.toLowerCase()]))).code).not.toBe(0);
      expect((await actions()).some((e) => e.action === 'git.fetch' && e.payload.repository.toLowerCase() === APP.toLowerCase())).toBe(true);
    });

    it('refuses a push to main or any branch outside door/<door id>/, and GitHub is unchanged', async () => {
      const clone = path.join(work, 'clone');
      const mainBefore = upstreamRef(standIn, APP, 'refs/heads/main');
      commit(clone, 'change.txt', 'hello\n', 'A change');
      const toMain = (await gitc(['push', 'origin', 'HEAD:main'], clone));
      expect(toMain.code).not.toBe(0);
      expect(toMain.out).toContain(`can only push branches under door/${doorId}/`);
      expect((await gitc(['push', 'origin', 'HEAD:feature'], clone)).code).not.toBe(0);
      expect((await gitc(['push', 'origin', 'HEAD:refs/tags/v1'], clone)).code).not.toBe(0);
      expect(upstreamRef(standIn, APP, 'refs/heads/main')).toBe(mainBefore);
      expect(upstreamRef(standIn, APP, 'refs/heads/feature')).toBeNull();
      const rejected = (await actions()).filter((e) => e.action === 'git.push_rejected');
      expect(rejected.at(-1).payload.reason).toBe('ref_not_allowed');
    });

    it('accepts a clean push to door/<door id>/..., scans it, and forwards it to GitHub', async () => {
      const clone = path.join(work, 'clone');
      const head = (await gitc(['rev-parse', 'HEAD'], clone)).out.trim().split('\n')[0];
      const branch = `door/${doorId}/login-fix`;
      const r = (await gitc(['push', 'origin', `HEAD:${branch}`], clone));
      expect(r.code, r.out).toBe(0);
      expect(r.out).toContain('scanned (gitleaks 8.28.0)');
      expect(upstreamRef(standIn, APP, `refs/heads/${branch}`)).toBe(head);
      const pushed = (await actions()).filter((e) => e.action === 'git.push').at(-1);
      expect(pushed.payload).toMatchObject({ scanner: 'gitleaks 8.28.0', developer_email: 'dev@example.com' });
      expect(pushed.payload.updates[0]).toMatchObject({ ref: `refs/heads/${branch}`, new: head });
    });

    it('refuses a push that contains a secret, even if a later commit removes it, and never records the secret', async () => {
      const clone = path.join(work, 'clone');
      const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const pem = privateKey.export({ type: 'pkcs1', format: 'pem' }).toString();
      const branch = `door/${doorId}/login-fix`;
      const before = upstreamRef(standIn, APP, `refs/heads/${branch}`);
      commit(clone, 'config/deploy_key.pem', pem, 'Add deploy key');
      fs.rmSync(path.join(clone, 'config/deploy_key.pem'));
      expect(gitLocal(['-c', 'user.name=Dev', '-c', 'user.email=dev@example.com', 'commit', '--quiet', '-a', '-m', 'Remove key'], clone).code).toBe(0);

      const r = (await gitc(['push', 'origin', `HEAD:${branch}`], clone));
      expect(r.code).not.toBe(0);
      expect(r.out).toContain('possible secret');
      expect(r.out).toContain('config/deploy_key.pem');
      expect(r.out).not.toContain(pem.split('\n')[1]);
      expect(upstreamRef(standIn, APP, `refs/heads/${branch}`)).toBe(before);
      const rejected = (await actions()).filter((e) => e.action === 'git.push_rejected').at(-1);
      expect(rejected.payload.reason).toBe('secret_found');
      expect(rejected.payload.findings[0]).toMatchObject({ rule: 'private-key', file: 'config/deploy_key.pem' });
      expect(JSON.stringify(rejected.payload)).not.toContain(pem.split('\n')[1]);
      // Put the clone back on GitHub's state for the next tests.
      expect((await gitc(['reset', '--quiet', '--hard', before!], clone)).code).toBe(0);
    });

    it('refuses pushes to a repository the door gives only read access to', async () => {
      const docs = path.join(work, 'docs');
      expect((await gitc(['clone', '--quiet', remote(doorId, DOCS, token), docs])).code).toBe(0);
      commit(docs, 'a.md', 'a\n', 'Docs change');
      const r = (await gitc(['push', 'origin', `HEAD:door/${doorId}/docs`], docs));
      expect(r.code).not.toBe(0);
      expect(upstreamRef(standIn, DOCS, `refs/heads/door/${doorId}/docs`)).toBeNull();
    });

    it('stops working on the very next request after the door is closed, and its mirrors are deleted', async () => {
      const clone = path.join(work, 'clone');
      expect((await gitc(['ls-remote', 'origin'], clone)).code).toBe(0);
      expect(fs.existsSync(mirrorPath(doorId, repoIds[APP.toLowerCase()]))).toBe(true);
      expect((await api(other, 'POST', `/projects/${projectId}/doors/${doorId}/close`)).status).toBe(404);
      const closedAt = Date.now();
      const closed = await api(creator, 'POST', `/projects/${projectId}/doors/${doorId}/close`);
      expect(closed.status).toBe(200);
      expect(closed.body.door.status).toBe('closed');
      const after = (await gitc(['ls-remote', 'origin'], clone));
      expect(after.code).not.toBe(0);
      expect(Date.now() - closedAt).toBeLessThan(5000);
      expect(fs.existsSync(mirrorPath(doorId, repoIds[APP.toLowerCase()]))).toBe(false);
      const names = (await actions()).map((e) => e.action);
      expect(names.slice(-2)).toEqual(['credential.revoked', 'door.closed']);
      expect((await api(creator, 'POST', `/projects/${projectId}/doors/${doorId}/close`)).status).toBe(409);
      expect((await api(creator, 'POST', `/projects/${projectId}/doors/${doorId}/invite`)).status).toBe(409);
      // The database itself keeps a closed door closed and a revoked credential revoked.
      await expect(admin.query(`UPDATE door SET status = 'open' WHERE id = $1`, [doorId])).rejects.toThrow(/cannot be reopened/);
      await expect(admin.query('UPDATE gateway_credential SET revoked_at = NULL WHERE door_id = $1', [doorId])).rejects.toThrow(/cannot be undone/);
    });

    it('refuses an expired door even before anyone closes it', async () => {
      const created = await api(creator, 'POST', `/projects/${projectId}/doors`, {
        developer_email: 'dev2@example.com',
        job_description: 'Short job',
        rights_type: 'contribute',
        expires_at: new Date(Date.now() + 86400_000).toISOString(),
        repositories: [{ repository_id: repoIds[APP.toLowerCase()], access: 'write' }]
      });
      const id = created.body.door.id;
      const invited = await api(creator, 'POST', `/projects/${projectId}/doors/${id}/invite`);
      const t = await acceptSignAndGetCredential(api, dev2, invited.body.invite.url);
      expect((await gitc(['ls-remote', remote(id, APP, t)])).code).toBe(0);
      await admin.query(`UPDATE door SET expires_at = now() - interval '1 second' WHERE id = $1`, [id]);
      const r = await fetch(`${base}/git/${id}/${APP}.git/info/refs?service=git-upload-pack`, { headers: { Authorization: `Basic ${Buffer.from(`door:${t}`).toString('base64')}` } });
      expect(r.status).toBe(403);
      expect(await r.text()).toContain('expired');
    });

    it('leaves a project record whose every hash still verifies', async () => {
      const result = await verifyServerProjectEvents(projectId);
      expect(result.isValid).toBe(true);
      const names = (await actions()).map((e) => e.action);
      for (const a of ['repository.added', 'door.created', 'door.invited', 'door.invite_accepted', 'agreement.signed', 'door.opened', 'credential.issued', 'git.fetch', 'git.push', 'git.push_rejected', 'credential.revoked', 'door.closed']) {
        expect(names).toContain(a);
      }
    });
  });

  it('the real app keeps the door and GitHub routes behind login', async () => {
    const { startApp } = await import('./support/api');
    const running = await startApp();
    try {
      for (const p of [`/api/v1/projects/${projectId}/doors`, '/api/v1/github', '/api/v1/github/repositories']) {
        const r = await fetch(`${running.base}${p}`);
        expect([401, 503]).toContain(r.status);
      }
    } finally {
      await running.stop();
    }
  });
});
