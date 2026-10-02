import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createHmac, createPublicKey, createVerify, randomBytes, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import JSZip from 'jszip';
import { getAdminPool, getDbPool, runMigrations } from '../server/db';
import { appJwt, githubConfig, GitHubNotConfigured } from '../server/github/app';
import { signatureFor, signatureIsValid } from '../server/github/webhooks';
import { readZip, repositoryName, BadUpload } from '../server/github/repositories';
import { STATE_COOKIE } from '../server/github/connect';
import { verifyAccountChain } from '../shared/crypto';
import { assertPoolTargetsTestDb } from './support/safety';
import { api, startApp, RunningApp } from './support/api';
import { authStack, createMfaUser, AuthSession } from './support/authStack';
import { startGitHubStandIn, StandIn } from './support/githubStandIn';

/**
 * Code home (Milestone 3) against a local GitHub stand-in (tests/support/githubStandIn.ts). The end-to-end run
 * against real GitHub is scripts/github-e2e.ts.
 */

const WEBHOOK_SECRET = randomBytes(24).toString('hex');

// ------------------------------------------------------------------------------------------------ pure logic

describe('Webhook signatures (real HMAC-SHA256)', () => {
  const body = Buffer.from(JSON.stringify({ action: 'deleted', installation: { id: 1 } }));

  it('accepts exactly the signature GitHub would send, computed independently here', () => {
    const independent = 'sha256=' + createHmac('sha256', 'It\'s a Secret to Everybody').update(body).digest('hex');
    expect(signatureFor('It\'s a Secret to Everybody', body)).toBe(independent);
    expect(signatureIsValid('It\'s a Secret to Everybody', body, independent)).toBe(true);
  });

  it("matches GitHub's published example (docs: validating webhook deliveries)", () => {
    // secret "It's a Secret to Everybody", payload "Hello, World!"
    expect(signatureFor("It's a Secret to Everybody", Buffer.from('Hello, World!'))).toBe(
      'sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17'
    );
  });

  it('refuses a wrong secret, a changed body, a missing or malformed header', () => {
    const good = signatureFor(WEBHOOK_SECRET, body);
    expect(signatureIsValid('another secret', body, good)).toBe(false);
    expect(signatureIsValid(WEBHOOK_SECRET, Buffer.from(body.toString().replace('deleted', 'created')), good)).toBe(false);
    for (const bad of [undefined, '', 'sha1=' + 'a'.repeat(40), good.toUpperCase(), good.slice(0, -1), `${good}0`, `sha256=${'g'.repeat(64)}`]) {
      expect(signatureIsValid(WEBHOOK_SECRET, body, bad as any)).toBe(false);
    }
  });
});

describe('The app login (JWT) and configuration', () => {
  it('signs a JWT GitHub accepts: RS256, issued 60 s back, 9 minutes, issuer = App ID', async () => {
    const gh = await startGitHubStandIn();
    try {
      setGitHubEnv(gh, 'http://127.0.0.1:1');
      const config = githubConfig();
      const now = Date.now();
      const jwt = appJwt(config, now);
      const [h, p, sig] = jwt.split('.');
      expect(JSON.parse(Buffer.from(h, 'base64url').toString())).toEqual({ alg: 'RS256', typ: 'JWT' });
      const claims = JSON.parse(Buffer.from(p, 'base64url').toString());
      expect(claims).toEqual({ iat: Math.floor(now / 1000) - 60, exp: Math.floor(now / 1000) + 540, iss: gh.appId });
      const v = createVerify('RSA-SHA256');
      v.update(`${h}.${p}`);
      expect(v.verify(createPublicKey(gh.privateKeyPem), Buffer.from(sig, 'base64url'))).toBe(true);
    } finally {
      await gh.stop();
    }
  });

  it('refuses to talk to anything but GitHub (or a local test address), and says what is missing', async () => {
    const gh = await startGitHubStandIn();
    try {
      setGitHubEnv(gh, 'http://127.0.0.1:1');
      process.env.GITHUB_API_URL = 'https://evil.example.com';
      expect(() => githubConfig()).toThrow(GitHubNotConfigured);
      setGitHubEnv(gh, 'http://127.0.0.1:1');
      delete process.env.GITHUB_WEBHOOK_SECRET;
      expect(() => githubConfig()).toThrow(/GITHUB_WEBHOOK_SECRET/);
      setGitHubEnv(gh, 'http://127.0.0.1:1');
      process.env.GITHUB_APP_PRIVATE_KEY = 'not a key';
      expect(() => githubConfig()).toThrow(/not a valid private key/);
      setGitHubEnv(gh, 'http://127.0.0.1:1');
      process.env.GITHUB_APP_PRIVATE_KEY = gh.privateKeyPem.replace(/\n/g, '\\n'); // as written on one line in .env
      expect(() => githubConfig()).not.toThrow();
    } finally {
      await gh.stop();
    }
  });
});

describe('Uploaded code (zip)', () => {
  const zipOf = async (files: Record<string, string | { link: string }>) => {
    const z = new JSZip();
    for (const [name, v] of Object.entries(files)) {
      if (typeof v === 'string') z.file(name, v);
      else z.file(name, v.link, { unixPermissions: 0o120777 });
    }
    return z.generateAsync({ type: 'nodebuffer', platform: 'UNIX' });
  };

  it('keeps the files, drops a single wrapping folder and macOS clutter', async () => {
    const files = await readZip(await zipOf({ 'myapp/README.md': '# hi', 'myapp/src/a.js': 'x', '__MACOSX/myapp/._a': 'junk' }));
    expect(files.map((f) => f.path).sort()).toEqual(['README.md', 'src/a.js']);
  });

  /** A zip whose stored names are written byte for byte (JSZip would clean "../" while building one). */
  const zipWithRawName = async (placeholder: string, rawName: string) => {
    const bytes = await zipOf({ [placeholder]: 'x' });
    expect(placeholder.length).toBe(rawName.length);
    let hex = bytes.toString('hex');
    hex = hex.split(Buffer.from(placeholder).toString('hex')).join(Buffer.from(rawName).toString('hex'));
    return Buffer.from(hex, 'hex');
  };

  it.each([
    ['zz/escape.txt', '../escape.txt'],
    ['xabs.txt', '/abs.txt'],
    ['aa/bb/cc/x.txt', 'a/../../../x.t'.padEnd(14, 't')],
    ['qC:/win.txt', 'C:/win.txt'.padStart(11, '/')]
  ])('refuses a zip that stores a path outside its folder (%s written as %s)', async (placeholder, rawName) => {
    await expect(readZip(await zipWithRawName(placeholder, rawName))).rejects.toThrow(/not allowed/);
  });

  it.each([
    [{ 'a/../../escape.txt': 'x' }, /not allowed/],
    [{ 'proj/.git/config': 'x', 'proj/a': 'y' }, /\.git/],
    [{ 'link': { link: '/etc/passwd' } }, /link/]
  ])('refuses a dangerous zip %#', async (files, msg) => {
    await expect(readZip(await zipOf(files as any))).rejects.toThrow(msg);
  });

  it('refuses something that is not a zip, and an empty zip', async () => {
    await expect(readZip(Buffer.from('hello'))).rejects.toThrow(BadUpload);
    await expect(readZip(await new JSZip().generateAsync({ type: 'nodebuffer' }))).rejects.toThrow(/no files/);
  });

  it('turns project names into names GitHub accepts', () => {
    expect(repositoryName('My Great App!')).toBe('my-great-app');
    expect(repositoryName('Café Résumé')).toBe('cafe-resume');
    expect(repositoryName('...')).toBe('project');
    expect(repositoryName('x'.repeat(200)).length).toBe(80);
  });
});

// ------------------------------------------------------------------------------------------------ through the real API

function setGitHubEnv(gh: StandIn, appUrl: string) {
  process.env.GITHUB_APP_ID = gh.appId;
  process.env.GITHUB_APP_SLUG = gh.slug;
  process.env.GITHUB_APP_CLIENT_ID = gh.clientId;
  process.env.GITHUB_APP_CLIENT_SECRET = gh.clientSecret;
  process.env.GITHUB_APP_PRIVATE_KEY = gh.privateKeyPem;
  process.env.GITHUB_WEBHOOK_SECRET = WEBHOOK_SECRET;
  process.env.GITHUB_API_URL = gh.url;
  process.env.GITHUB_WEB_URL = gh.url;
  process.env.APP_URL = appUrl;
}

describe('Code home through the API: connect, lock, claim, webhooks', () => {
  const adminDb = getAdminPool()!;
  let running: RunningApp;
  let gh: StandIn;
  const logs: string[] = [];
  const saved = { log: console.log, warn: console.warn, error: console.error };

  beforeAll(async () => {
    authStack();
    await assertPoolTargetsTestDb(adminDb);
    const res = await runMigrations();
    if (!res.success) throw new Error(res.message);
    running = await startApp();
    gh = await startGitHubStandIn();
    setGitHubEnv(gh, running.base);
    // Keep everything the server logs, to prove no token ever appears in it.
    for (const k of ['log', 'warn', 'error'] as const) {
      console[k] = (...args: unknown[]) => {
        logs.push(args.map(String).join(' '));
        saved[k](...args);
      };
    }
  });

  afterAll(async () => {
    Object.assign(console, saved);
    await running.stop();
    await gh.stop();
  });

  const raw = (path: string, init: RequestInit = {}) => fetch(`${running.base}/api/v1${path}`, { redirect: 'manual', ...init });
  const cookieFrom = (r: Response) => /cc_github_connect=([^;]+)/.exec(r.headers.get('set-cookie') || '')?.[1] ?? null;
  const outcome = (r: Response) => new URL(r.headers.get('location')!).searchParams.get('code_home');

  /** Starts a connection as `session`; returns the state and the browser cookie. */
  async function start(session: AuthSession) {
    const r = await raw('/github/connect', { method: 'POST', headers: { Authorization: `Bearer ${session.accessToken}` } });
    expect(r.status).toBe(200);
    const body: any = await r.json();
    const state = new URL(body.install_url).searchParams.get('state')!;
    expect(body.install_url.startsWith(`${gh.url}/apps/${gh.slug}/installations/new?state=`)).toBe(true);
    expect(body.new_organization_url).toBe(`${gh.url}/account/organizations/new?plan=free`);
    const cookie = cookieFrom(r);
    expect(cookie).toBe(state);
    expect(r.headers.get('set-cookie')).toMatch(/HttpOnly/i);
    expect(r.headers.get('set-cookie')).toMatch(/SameSite=Lax/i);
    return { state, cookie: `${STATE_COOKIE}=${cookie}` };
  }

  /** GitHub's two redirects after "Install" and "Authorize", as a browser would follow them. */
  async function finish(state: string, cookie: string, installationId: number, githubLogin: string) {
    const setup = await raw(`/github/setup?installation_id=${installationId}&setup_action=install&state=${state}`, { headers: { Cookie: cookie } });
    if (setup.status !== 303) return setup;
    const to = new URL(setup.headers.get('location')!);
    if (to.pathname !== '/login/oauth/authorize') return setup;
    expect(to.searchParams.get('client_id')).toBe(gh.clientId);
    expect(to.searchParams.get('state')).toBe(state);
    expect(to.searchParams.get('redirect_uri')).toBe(`${running.base}/api/v1/github/callback`);
    const code = gh.authorizeCode(githubLogin);
    return raw(`/github/callback?code=${code}&state=${state}`, { headers: { Cookie: cookie } });
  }

  async function connectedCreator(label: string, opts: { plan?: 'free' | 'team' } = {}) {
    const { session } = await createMfaUser(label, running.base);
    const org = `${label}-org-${randomBytes(3).toString('hex')}`;
    const owner = `${label}-owner`;
    gh.addOrg(org, { plan: opts.plan, owners: [owner] });
    const installationId = gh.install(org);
    const { state, cookie } = await start(session);
    const done = await finish(state, cookie, installationId, owner);
    expect(outcome(done)).toBe('connected');
    return { session, org, owner, installationId };
  }

  const accountEvents = async (userId: string) =>
    (await adminDb.query('SELECT action, actor_type, actor_id, payload FROM account_event WHERE account_id = $1 ORDER BY seq', [userId])).rows;

  // ---------------------------------------------------------------- connection

  it('connect: GitHub confirms the installer owns the organization, the installation id (only) is stored, and the org is locked as GitHub reports', async () => {
    const { session } = await createMfaUser('conn', running.base);
    const org = `acme-${randomBytes(3).toString('hex')}`;
    gh.addOrg(org, { owners: ['alice'] });
    const installationId = gh.install(org);
    const { state, cookie } = await start(session);
    const tokensBefore = gh.tokens.length;
    const done = await finish(state, cookie, installationId, 'alice');
    expect(done.status).toBe(303);
    expect(done.headers.get('location')).toBe(`${running.base}/?code_home=connected`);

    const row = (await adminDb.query('SELECT * FROM github_installation WHERE installation_id = $1', [installationId])).rows[0];
    expect(row).toMatchObject({ account_login: org, status: 'active' });
    expect(Object.keys(row).sort()).toEqual(['account_id', 'account_login', 'connected_at', 'creator_id', 'id', 'installation_id', 'status', 'status_changed_at']);

    // GitHub now has the locked settings, and the event records what GitHub reported.
    expect(gh.orgs.get(org)!.settings).toMatchObject({
      default_repository_permission: 'none',
      members_can_create_repositories: false,
      members_can_create_private_repositories: false,
      members_can_create_public_repositories: false,
      members_can_fork_private_repositories: false
    });
    const events = await accountEvents(session.userId);
    const connected = events.find((e) => e.action === 'github.connected')!;
    expect(connected.payload).toMatchObject({ organization: org, installation_id: installationId, confirmed_by_github_user: 'alice' });
    const lock = events.find((e) => e.action === 'github.organization_locked')!.payload;
    expect(lock.all_applied).toBe(true);
    expect(lock.plan).toBe('free');
    for (const s of lock.settings) expect(s.reported, s.setting).toEqual(gh.orgs.get(org)!.settings[s.setting]);

    // The lock used one token, for organization administration only, and it was revoked.
    const used = gh.tokens.slice(tokensBefore);
    expect(used).toHaveLength(1);
    expect(used[0]).toMatchObject({ repositories: null, permissions: { organization_administration: 'write' }, revoked: true });
    // The installer's own token answered the two questions and was revoked.
    expect([...gh.userTokens.values()].every((u) => u.revoked)).toBe(true);

    // The connection screen shows it.
    const status = await api(running.base, session, '/github/connection');
    expect(status.status).toBe(200);
    expect(status.body).toMatchObject({ configured: true, installation: { organization: org, status: 'active', installation_id: installationId }, broken: null });
    expect(status.body.organization_lock.settings).toEqual(lock.settings);

    // The account's record verifies.
    const record = await api(running.base, session, '/account/events');
    expect(record.body.valid).toBe(true);
  });

  it('"check again" re-applies the lock after someone loosened a setting on GitHub, and records what GitHub reports now', async () => {
    const c = await connectedCreator('relock');
    gh.orgs.get(c.org)!.settings.default_repository_permission = 'write'; // someone changed it on GitHub
    const r = await api(running.base, c.session, '/github/organization/lock', { method: 'POST', body: {} });
    expect(r.status).toBe(200);
    expect(r.body.all_applied).toBe(true);
    expect(gh.orgs.get(c.org)!.settings.default_repository_permission).toBe('none');
    const locks = (await accountEvents(c.session.userId)).filter((e) => e.action === 'github.organization_locked');
    expect(locks).toHaveLength(2);
    expect(locks[1].actor_type).toBe('creator');
  });

  it('a forged installation id (an installation the GitHub user cannot see) is refused and nothing is linked', async () => {
    const { session } = await createMfaUser('forged', running.base);
    const victimOrg = `victim-${randomBytes(3).toString('hex')}`;
    gh.addOrg(victimOrg, { owners: ['victim'] });
    const victimInstallation = gh.install(victimOrg);
    gh.addOrg(`mine-${randomBytes(3).toString('hex')}`, { owners: ['mallory'] });
    const { state, cookie } = await start(session);
    const done = await finish(state, cookie, victimInstallation, 'mallory');
    expect(outcome(done)).toBe('not_yours');
    expect((await adminDb.query('SELECT 1 FROM github_installation WHERE installation_id = $1', [victimInstallation])).rowCount).toBe(0);
  });

  it('a member who is not an owner cannot connect the organization', async () => {
    const { session } = await createMfaUser('member', running.base);
    const org = `memb-${randomBytes(3).toString('hex')}`;
    gh.addOrg(org, { owners: ['boss'], members: ['worker'] });
    const id = gh.install(org);
    const { state, cookie } = await start(session);
    expect(outcome(await finish(state, cookie, id, 'worker'))).toBe('not_owner');
  });

  it('an installation of some other GitHub App is refused', async () => {
    const { session } = await createMfaUser('otherapp', running.base);
    const org = `oa-${randomBytes(3).toString('hex')}`;
    gh.addOrg(org, { owners: ['carol'] });
    const id = gh.install(org, { appId: '1' });
    const { state, cookie } = await start(session);
    expect(outcome(await finish(state, cookie, id, 'carol'))).toBe('not_yours');
  });

  it("the round trip only works in the browser that started it, and only once (someone else's link cannot attach their org to you)", async () => {
    const { session } = await createMfaUser('csrf', running.base);
    const org = `csrf-${randomBytes(3).toString('hex')}`;
    gh.addOrg(org, { owners: ['dave'] });
    const id = gh.install(org);
    const { state, cookie } = await start(session);
    // no cookie, another cookie, a made-up state
    expect(outcome(await finish(state, '', id, 'dave'))).toBe('expired');
    expect(outcome(await finish(state, `${STATE_COOKIE}=${randomBytes(32).toString('base64url')}`, id, 'dave'))).toBe('expired');
    const fake = randomBytes(32).toString('base64url');
    expect(outcome(await finish(fake, `${STATE_COOKIE}=${fake}`, id, 'dave'))).toBe('expired');
    // the real one works once
    expect(outcome(await finish(state, cookie, id, 'dave'))).toBe('connected');
    expect(outcome(await finish(state, cookie, id, 'dave'))).toBe('expired');
  });

  it('identity never comes from the browser: setup and callback without a signed-in start do nothing, and connect needs a full login', async () => {
    expect((await raw('/github/connect', { method: 'POST' })).status).toBe(401);
    expect((await raw('/github/connection')).status).toBe(401);
    const r = await raw('/github/callback?code=abc&state=' + randomBytes(32).toString('base64url'));
    expect(outcome(r)).toBe('expired');
  });

  it('if GitHub refuses the organization change, the event says so and records what GitHub actually reports', async () => {
    const { session } = await createMfaUser('refuse', running.base);
    const org = `ref-${randomBytes(3).toString('hex')}`;
    gh.addOrg(org, { owners: ['erin'] }).refusePatch = { status: 403, message: 'Resource not accessible by integration' };
    const id = gh.install(org);
    const { state, cookie } = await start(session);
    expect(outcome(await finish(state, cookie, id, 'erin'))).toBe('connected_not_all_locked');
    const lock = (await accountEvents(session.userId)).find((e) => e.action === 'github.organization_locked')!.payload;
    expect(lock.all_applied).toBe(false);
    expect(lock.change_error).toEqual({ status: 403, message: 'Resource not accessible by integration' });
    expect(lock.settings.find((s: any) => s.setting === 'default_repository_permission')).toEqual({
      setting: 'default_repository_permission',
      requested: 'none',
      reported: 'read',
      applied: false
    });
  });

  // ---------------------------------------------------------------- claim it

  async function claim(session: AuthSession, name: string) {
    const r = await api(running.base, session, '/projects', { method: 'POST', body: { name, purpose: 'testing the code home' } });
    expect(r.status).toBe(201);
    return r.body.project.id as string;
  }

  it('claim on a free organization: private repositories, forking off, and branch rules honestly recorded as needing GitHub Team', async () => {
    const c = await connectedCreator('free');
    const projectId = await claim(c.session, `Free Project ${randomBytes(2).toString('hex')}`);
    const before = gh.tokens.length;
    const r = await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: { split_core: true } });
    expect(r.status).toBe(201);
    expect(r.body.repositories.map((x: any) => x.role)).toEqual(['main', 'core']);

    for (const repo of r.body.repositories) {
      const real = gh.repos.get(repo.full_name)!;
      expect(real.private).toBe(true);
      expect(real.allow_forking).toBe(false);
      expect(real.rulesets).toEqual([]); // GitHub refused it
      expect(repo.settings).toEqual([
        { setting: 'private', requested: true, reported: true, applied: true },
        { setting: 'visibility', requested: 'private', reported: 'private', applied: true },
        { setting: 'allow_forking', requested: false, reported: false, applied: true }
      ]);
      expect(repo.ruleset).toEqual({
        applied: false,
        refused: { status: 403, message: 'Upgrade to GitHub Team or make this repository public to enable this feature.', needs_paid_plan: true },
        reported: null
      });
    }

    // Recorded per repository, in the project's chain, and the chain verifies.
    const events = (await adminDb.query(`SELECT action, payload FROM event WHERE project_id = $1 ORDER BY seq`, [projectId])).rows;
    expect(events.map((e) => e.action)).toEqual(['project.claimed', 'repository.created', 'repository.created']);
    expect(events[1].payload.ruleset.applied).toBe(false);
    expect(events[1].payload.fully_locked).toBe(false);
    expect((await api(running.base, c.session, `/projects/${projectId}/events/verify`)).body.valid).toBe(true);
    const rows = (await adminDb.query('SELECT full_name, is_core, locked_at, github_repo_id FROM repository WHERE project_id = $1 ORDER BY is_core', [projectId])).rows;
    expect(rows.map((x) => [x.is_core, x.locked_at])).toEqual([[false, null], [true, null]]); // not fully locked, so not marked locked
    expect(rows[0].github_repo_id).toBe(String(gh.repos.get(rows[0].full_name)!.id));

    // Tokens: one per step, each narrowed, all revoked.
    const used = gh.tokens.slice(before);
    expect(used.every((t) => t.revoked)).toBe(true);
    expect(used.filter((t) => t.repositories === null).map((t) => t.permissions)).toEqual([{ administration: 'write' }, { administration: 'write' }]); // creating (cannot name a repo that does not exist yet)
    for (const t of used.filter((t) => t.repositories !== null)) expect(t.repositories).toHaveLength(1);

    // Doing it again is refused.
    expect((await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: {} })).status).toBe(409);
  });

  it('claim on a GitHub Team organization: the branch rules are applied and read back from GitHub', async () => {
    const c = await connectedCreator('team', { plan: 'team' });
    const projectId = await claim(c.session, `Team Project ${randomBytes(2).toString('hex')}`);
    const r = await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: { split_core: false } });
    expect(r.status).toBe(201);
    const [repo] = r.body.repositories;
    expect(repo.ruleset.applied).toBe(true);
    expect(repo.ruleset.reported).toMatchObject({ enforcement: 'active', rules: ['deletion', 'non_fast_forward', 'update'] });
    expect(repo.ruleset.reported.bypass_actors).toEqual([{ actor_type: 'Integration', actor_id: Number(gh.appId), bypass_mode: 'always' }]);
    expect(gh.repos.get(repo.full_name)!.rulesets).toHaveLength(1);
    const row = (await adminDb.query('SELECT locked_at FROM repository WHERE project_id = $1', [projectId])).rows[0];
    expect(row.locked_at).not.toBeNull();
  });

  it('claim with existing code: the zip becomes the first commit, pushed with a token for that one repository, and GitHub reports the same commit', async () => {
    const c = await connectedCreator('zip');
    const projectId = await claim(c.session, `Zip Project ${randomBytes(2).toString('hex')}`);
    const z = new JSZip();
    z.file('myproj/README.md', '# My project\n');
    z.file('myproj/src/index.js', 'console.log("hi");\n');
    z.file('myproj/run.sh', '#!/bin/sh\necho run\n', { unixPermissions: 0o100755 });
    const zip = await z.generateAsync({ type: 'nodebuffer', platform: 'UNIX' });
    const before = gh.tokens.length;
    const res = await fetch(`${running.base}/api/v1/projects/${projectId}/code-home?split_core=1`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${c.session.accessToken}`, 'Content-Type': 'application/zip' },
      body: new Uint8Array(zip)
    });
    const body: any = await res.json();
    expect(res.status).toBe(201);
    const main = body.repositories.find((x: any) => x.role === 'main');
    const core = body.repositories.find((x: any) => x.role === 'core');
    expect(main.initial_commit).toMatchObject({ pushed: true, files: 3, matches: true });
    expect(main.initial_commit.reported_sha).toMatch(/^[0-9a-f]{40}$/);
    expect(core.initial_commit).toBeNull();

    // Clone what GitHub (the stand-in's real git server) holds and compare.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-'));
    try {
      const bare = gh.repos.get(main.full_name)!.bare;
      expect(spawnSync('git', ['clone', '-q', bare, dir]).status).toBe(0);
      expect(fs.readFileSync(path.join(dir, 'README.md'), 'utf8')).toBe('# My project\n');
      expect(fs.readFileSync(path.join(dir, 'src/index.js'), 'utf8')).toBe('console.log("hi");\n');
      expect(fs.statSync(path.join(dir, 'run.sh')).mode & 0o111).not.toBe(0);
      expect(spawnSync('git', ['-C', dir, 'rev-list', '--count', 'HEAD'], { encoding: 'utf8' }).stdout.trim()).toBe('1');
      expect(spawnSync('git', ['-C', dir, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).stdout.trim()).toBe(main.initial_commit.reported_sha);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
    const pushToken = gh.tokens.slice(before).find((t) => t.permissions.contents === 'write')!;
    expect(pushToken).toMatchObject({ repositories: [main.full_name.split('/')[1]], permissions: { contents: 'write' }, revoked: true });
  });

  it('a zip cannot configure git on the server: a .gitconfig in it runs nothing and does not redirect the push (or its token)', async () => {
    const c = await connectedCreator('gitcfg');
    const projectId = await claim(c.session, `Git Config ${randomBytes(2).toString('hex')}`);
    const marker = path.join(os.tmpdir(), `cc-pwned-${randomBytes(6).toString('hex')}`);
    // A server that would receive the push (and its token) if git followed the zip's url.insteadOf.
    let stolen = '';
    const thief = (await import('node:http')).createServer((req, res) => {
      stolen += String(req.headers.authorization || 'request');
      res.writeHead(500);
      res.end();
    });
    await new Promise<void>((r) => thief.listen(0, '127.0.0.1', () => r()));
    const thiefUrl = `http://127.0.0.1:${(thief.address() as any).port}/`;
    try {
      const z = new JSZip();
      z.file('README.md', '# hi\n');
      z.file('.gitconfig', `[core]\n\tfsmonitor = "touch ${marker}; false"\n[url "${thiefUrl}"]\n\tinsteadOf = ${gh.url}/\n`);
      z.file('.config/git/config', `[core]\n\tfsmonitor = "touch ${marker}; false"\n`);
      const res = await fetch(`${running.base}/api/v1/projects/${projectId}/code-home`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${c.session.accessToken}`, 'Content-Type': 'application/zip' },
        body: new Uint8Array(await z.generateAsync({ type: 'nodebuffer' }))
      });
      const body: any = await res.json();
      expect(res.status).toBe(201);
      expect(fs.existsSync(marker), 'a command from the zip ran on the server').toBe(false);
      expect(stolen, 'the push went somewhere else').toBe('');
      expect(body.repositories[0].initial_commit.matches).toBe(true);
      // The files themselves are kept as ordinary files of the project.
      const bare = gh.repos.get(body.repositories[0].full_name)!.bare;
      const listed = spawnSync('git', ['--git-dir', bare, 'ls-tree', '-r', '--name-only', 'HEAD'], { encoding: 'utf8' }).stdout.trim().split('\n').sort();
      expect(listed).toEqual(['.config/git/config', '.gitconfig', 'README.md']);
    } finally {
      thief.close();
      fs.rmSync(marker, { force: true });
    }
  });

  it('a zip bomb (a small file that unpacks to more than 100 MB) is refused without unpacking it all', async () => {
    const z = new JSZip();
    z.file('zeros.bin', Buffer.alloc(120 * 1024 * 1024), { compression: 'DEFLATE', compressionOptions: { level: 9 } });
    const bomb = await z.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
    expect(bomb.length).toBeLessThan(1024 * 1024);
    await expect(readZip(bomb)).rejects.toThrow(/larger than 100 MB/);
  }, 60_000);

  it('a dangerous zip is refused before anything is created on GitHub', async () => {
    const c = await connectedCreator('badzip');
    const projectId = await claim(c.session, `Bad Zip ${randomBytes(2).toString('hex')}`);
    const z = new JSZip();
    z.file('../../etc/evil', 'x');
    const repos = gh.repos.size;
    const res = await fetch(`${running.base}/api/v1/projects/${projectId}/code-home`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${c.session.accessToken}`, 'Content-Type': 'application/zip' },
      body: new Uint8Array(await z.generateAsync({ type: 'nodebuffer' }))
    });
    expect(res.status).toBe(400);
    expect(gh.repos.size).toBe(repos);
  });

  it("someone else's project, a project without a connection, and a name GitHub refuses", async () => {
    const a = await connectedCreator('owner');
    const b = await connectedCreator('intruder');
    const projectId = await claim(a.session, `Owned ${randomBytes(2).toString('hex')}`);
    expect((await api(running.base, b.session, `/projects/${projectId}/code-home`, { method: 'POST', body: {} })).status).toBe(404);
    expect((await api(running.base, b.session, `/projects/${randomUUID()}/code-home`, { method: 'POST', body: {} })).status).toBe(404);

    const { session: lone } = await createMfaUser('lone', running.base);
    const loneProject = await claim(lone, 'Lonely');
    const r = await api(running.base, lone, `/projects/${loneProject}/code-home`, { method: 'POST', body: {} });
    expect(r.status).toBe(409);
    expect(r.body.error).toMatch(/Connect your code home first/);

    // A repository with that name already exists in the organization: GitHub refuses, and that is recorded.
    const name = `Clash ${randomBytes(2).toString('hex')}`;
    const first = await claim(a.session, name);
    expect((await api(running.base, a.session, `/projects/${first}/code-home`, { method: 'POST', body: {} })).status).toBe(201);
    const second = await claim(a.session, name);
    const clash = await api(running.base, a.session, `/projects/${second}/code-home`, { method: 'POST', body: {} });
    expect(clash.status).toBe(502);
    const failed = (await adminDb.query(`SELECT payload FROM event WHERE project_id = $1 AND action = 'repository.creation_failed'`, [second])).rows[0].payload;
    expect(failed.error).toEqual({ status: 422, message: 'Repository creation failed.' });
    expect((await adminDb.query('SELECT 1 FROM repository WHERE project_id = $1', [second])).rowCount).toBe(0);
  });

  it('a claim that stopped half way can be finished: only the missing repository is created', async () => {
    const c = await connectedCreator('halfway', { plan: 'team' });
    const name = `Half ${randomBytes(2).toString('hex')}`;
    const projectId = await claim(c.session, name);
    // Someone already has a repository with the core repository's name, so GitHub refuses that one.
    const core = `${repositoryName(name)}-core`;
    const blocker = await claim(c.session, `${name} core`);
    expect(repositoryName(`${name} core`)).toBe(core);
    expect((await api(running.base, c.session, `/projects/${blocker}/code-home`, { method: 'POST', body: {} })).status).toBe(201);

    const first = await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: { split_core: true } });
    expect(first.status).toBe(502);
    expect(first.body.repositories.map((r: any) => r.role)).toEqual(['main']);

    // The name is freed on GitHub; asking again creates only the core repository.
    gh.repos.delete(`${c.org}/${core}`);
    await adminDb.query('DELETE FROM repository WHERE full_name = $1', [`${c.org}/${core}`]);
    const before = gh.repos.size;
    const second = await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: { split_core: true } });
    expect(second.status).toBe(201);
    expect(second.body.repositories.map((r: any) => r.role)).toEqual(['core']);
    expect(gh.repos.size).toBe(before + 1);
    const actions = (await adminDb.query('SELECT action FROM event WHERE project_id = $1 ORDER BY seq', [projectId])).rows.map((r) => r.action);
    expect(actions).toEqual(['project.claimed', 'repository.created', 'repository.creation_failed', 'repository.created']);
    expect((await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: { split_core: true } })).status).toBe(409);
  });

  it('the browser cannot name repositories at claim time any more', async () => {
    const { session } = await createMfaUser('names', running.base);
    const r = await api(running.base, session, '/projects', { method: 'POST', body: { name: 'x', purpose: 'y', repositories: [{ full_name: 'someone/else' }] } });
    expect(r.status).toBe(400);
  });

  // ---------------------------------------------------------------- webhooks

  const deliver = (event: string, payload: unknown, opts: { secret?: string; id?: string; signature?: string } = {}) => {
    const body = Buffer.from(JSON.stringify(payload));
    return fetch(`${running.base}/api/v1/github/webhook`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-GitHub-Event': event,
        'X-GitHub-Delivery': opts.id ?? randomUUID(),
        'X-Hub-Signature-256': opts.signature ?? signatureFor(opts.secret ?? WEBHOOK_SECRET, body)
      },
      body
    });
  };

  it('a webhook with a wrong or missing signature is refused and changes nothing', async () => {
    const c = await connectedCreator('sig');
    const payload = { action: 'deleted', installation: { id: c.installationId }, sender: { login: 'x' } };
    const id = randomUUID();
    expect((await deliver('installation', payload, { secret: 'not the secret', id })).status).toBe(401);
    expect((await deliver('installation', payload, { signature: '', id })).status).toBe(401);
    expect((await adminDb.query('SELECT status FROM github_installation WHERE installation_id = $1', [c.installationId])).rows[0].status).toBe('active');
    expect((await adminDb.query('SELECT 1 FROM github_webhook_delivery WHERE delivery_id = $1', [id])).rowCount).toBe(0);
  });

  it('uninstalling the app on GitHub: the connection shows as broken and it is recorded, once even if GitHub delivers twice', async () => {
    const c = await connectedCreator('uninstall');
    const id = randomUUID();
    const payload = { action: 'deleted', installation: { id: c.installationId, account: { login: c.org } }, sender: { login: c.owner } };
    const first = await deliver('installation', payload, { id });
    expect(first.status).toBe(200);
    expect(((await first.json()) as any).outcome).toBe('connection removed');
    const again = await deliver('installation', payload, { id });
    expect(((await again.json()) as any).duplicate).toBe(true);

    const status = await api(running.base, c.session, '/github/connection');
    expect(status.body.installation.status).toBe('removed');
    expect(status.body.broken).toMatchObject({ organization: c.org, reason: 'the app was uninstalled on GitHub', by: c.owner });
    const broken = (await accountEvents(c.session.userId)).filter((e) => e.action === 'github.connection_broken');
    expect(broken).toHaveLength(1);
    expect(broken[0].actor_type).toBe('system');

    // No more claims through a removed installation; the creator can connect again.
    const projectId = await claim(c.session, `After ${randomBytes(2).toString('hex')}`);
    expect((await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: {} })).status).toBe(409);
    expect((await raw('/github/connect', { method: 'POST', headers: { Authorization: `Bearer ${c.session.accessToken}` } })).status).toBe(200);
  });

  it('a repository deleted on GitHub is recorded in its project chain', async () => {
    const c = await connectedCreator('repodel', { plan: 'team' });
    const projectId = await claim(c.session, `Del ${randomBytes(2).toString('hex')}`);
    const made = (await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: {} })).body.repositories[0];
    const r = await deliver('repository', { action: 'deleted', installation: { id: c.installationId }, repository: { id: made.github_repo_id, full_name: made.full_name, private: true }, sender: { login: 'someone' } });
    expect(((await r.json()) as any).outcome).toBe('recorded repository deleted');
    const last = (await adminDb.query(`SELECT action, payload FROM event WHERE project_id = $1 ORDER BY seq DESC LIMIT 1`, [projectId])).rows[0];
    expect(last).toMatchObject({ action: 'repository.deleted_on_github', payload: { full_name_before: made.full_name, by: 'someone' } });
  });

  it('a webhook for an installation nobody connected is kept as received but changes nothing', async () => {
    const r = await deliver('push', { installation: { id: 987654321 }, ref: 'refs/heads/main' });
    expect(r.status).toBe(200);
    expect(((await r.json()) as any).outcome).toBe('installation not linked to a creator');
  });

  // ---------------------------------------------------------------- tokens are never kept

  it('no token GitHub issued appears anywhere in the database or in the server log', async () => {
    const secrets = [...gh.tokens.map((t) => t.token), ...gh.userTokens.keys()];
    expect(secrets.length).toBeGreaterThan(10);
    const tables = (await adminDb.query(`SELECT tablename FROM pg_tables WHERE schemaname = 'public'`)).rows.map((r) => r.tablename);
    let dump = '';
    for (const t of tables) dump += JSON.stringify((await adminDb.query(`SELECT * FROM "${t}"`)).rows);
    expect(dump.length).toBeGreaterThan(1000);
    for (const s of secrets) {
      expect(dump.includes(s), 'token in the database').toBe(false);
      expect(logs.some((l) => l.includes(s)), 'token in the log').toBe(false);
    }
    expect(gh.tokens.every((t) => t.revoked)).toBe(true);
  });

  it('the app database account cannot rewrite received webhooks or delete installations', async () => {
    const app = getDbPool()!;
    await expect(app.query(`UPDATE github_webhook_delivery SET outcome = 'x'`)).rejects.toThrow(/permission denied/);
    await expect(app.query(`DELETE FROM github_installation`)).rejects.toThrow(/permission denied/);
  });

  it('without the GitHub App configured, the code home says so (503) and nothing pretends to work', async () => {
    const { session } = await createMfaUser('nocfg', running.base);
    const saved = process.env.GITHUB_APP_PRIVATE_KEY;
    try {
      delete process.env.GITHUB_APP_PRIVATE_KEY;
      const r = await api(running.base, session, '/github/connect', { method: 'POST', body: {} });
      expect(r.status).toBe(503);
      expect(r.body.configured).toBe(false);
      expect((await api(running.base, session, '/github/connection')).body.configured).toBe(false);
      const signed = await deliver('ping', {});
      expect(signed.status).toBe(503);
    } finally {
      process.env.GITHUB_APP_PRIVATE_KEY = saved;
    }
  });

  it('the account record still verifies after all of this', async () => {
    const c = await connectedCreator('chain');
    const rows = (await adminDb.query('SELECT * FROM account_event WHERE account_id = $1 ORDER BY seq', [c.session.userId])).rows;
    const check = await verifyAccountChain(rows.map((r) => ({ ...r, seq: Number(r.seq), timestamp: r.hashed_timestamp })));
    expect(check.isValid).toBe(true);
  });
});
