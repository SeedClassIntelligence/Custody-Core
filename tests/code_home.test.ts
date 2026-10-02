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
    expect(Object.keys(row).sort()).toEqual(['account_id', 'account_login', 'connected_at', 'creator_id', 'id', 'installation_id', 'owner_id', 'owner_login', 'status', 'status_asked_at', 'status_changed_at']);
    // the GitHub user GitHub confirmed as an owner, by permanent id
    expect({ login: row.owner_login, id: Number(row.owner_id) }).toEqual({ login: 'alice', id: gh.userId('alice') });

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

  it('two owners linking the same installation at the same moment: exactly one is connected, the other is told the truth', async () => {
    const a = await createMfaUser('raceA', running.base);
    const b = await createMfaUser('raceB', running.base);
    const org = `race-${randomBytes(3).toString('hex')}`;
    gh.addOrg(org, { owners: ['ownerA', 'ownerB'] });
    const id = gh.install(org);
    const sa = await start(a.session);
    const sb = await start(b.session);
    const outcomes = (await Promise.all([finish(sa.state, sa.cookie, id, 'ownerA'), finish(sb.state, sb.cookie, id, 'ownerB')])).map(outcome).sort();
    expect(outcomes).toEqual(['connected', 'linked_elsewhere']);
    const connectedEvents = (
      await adminDb.query(`SELECT account_id FROM account_event WHERE action = 'github.connected' AND account_id = ANY($1::text[])`, [[a.session.userId, b.session.userId]])
    ).rows;
    expect(connectedEvents).toHaveLength(1);
    const owner = (await adminDb.query('SELECT c.identity_id FROM github_installation g JOIN creator c ON c.id = g.creator_id WHERE g.installation_id = $1', [id])).rows;
    expect(owner).toEqual([{ identity_id: connectedEvents[0].account_id }]);
  });

  it('a link that overlaps another one in the database (the other not yet committed) still ends "linked elsewhere", never "connected"', async () => {
    const a = await createMfaUser('overlapA', running.base);
    const b = await createMfaUser('overlapB', running.base);
    const org = `overlap-${randomBytes(3).toString('hex')}`;
    const orgRow = gh.addOrg(org, { owners: ['ownerB'] });
    const id = gh.install(org);
    const aCreator = (await adminDb.query('SELECT id FROM creator WHERE identity_id = $1', [a.session.userId])).rows[0].id;
    const sb = await start(b.session);
    // Another link of the same installation is in progress: written, not yet committed.
    const other = await adminDb.connect();
    try {
      await other.query('BEGIN');
      await other.query(`INSERT INTO github_installation (creator_id, installation_id, account_login, account_id, owner_login, owner_id, status) VALUES ($1, $2, $3, $4, 'ownerA', 1, 'active')`, [aCreator, id, org, orgRow.id]);
      const pending = finish(sb.state, sb.cookie, id, 'ownerB');
      await new Promise((r) => setTimeout(r, 1500)); // B reaches the database and has to wait for this one
      await other.query('COMMIT');
      expect(outcome(await pending)).toBe('linked_elsewhere');
    } finally {
      await other.query('ROLLBACK').catch(() => undefined);
      other.release();
    }
    expect((await adminDb.query(`SELECT 1 FROM account_event WHERE account_id = $1 AND action = 'github.connected'`, [b.session.userId])).rowCount).toBe(0);
    expect((await adminDb.query('SELECT creator_id FROM github_installation WHERE installation_id = $1', [id])).rows[0].creator_id).toBe(aCreator);
  });

  it("if the app lacks the Members permission, GitHub cannot confirm ownership: the creator is told exactly that, not 'not an owner'", async () => {
    const { session } = await createMfaUser('noperm', running.base);
    const org = `noperm-${randomBytes(3).toString('hex')}`;
    gh.addOrg(org, { owners: ['frank'] });
    const id = gh.install(org);
    const saved = gh.appPermissions.members;
    delete gh.appPermissions.members;
    try {
      const { state, cookie } = await start(session);
      expect(outcome(await finish(state, cookie, id, 'frank'))).toBe('app_needs_members_permission');
      expect((await adminDb.query('SELECT 1 FROM github_installation WHERE installation_id = $1', [id])).rowCount).toBe(0);
    } finally {
      gh.appPermissions.members = saved;
    }
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
    // creating (cannot name a repo that does not exist yet), plus one read-only check that the owner is still an owner
    expect(used.filter((t) => t.repositories === null).map((t) => t.permissions)).toEqual([{ members: 'read' }, { administration: 'write' }, { administration: 'write' }]);
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
    expect(main.initial_commit).toMatchObject({ pushed: true, files_uploaded: 3, reported_files: 3, matches: true, error: null });
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

  /** A zip whose stored names are exactly these bytes (JSZip would clean some of them when building one). */
  const rawZip = async (files: Record<string, string>) => {
    const z = new JSZip();
    const swaps: Array<[string, string]> = [];
    let i = 0;
    for (const [name, content] of Object.entries(files)) {
      const placeholder = (String.fromCharCode(81 + i++) + 'z'.repeat(400)).slice(0, Buffer.byteLength(name));
      if (Buffer.byteLength(placeholder) !== Buffer.byteLength(name)) throw new Error('placeholder length');
      z.file(placeholder, content);
      swaps.push([placeholder, name]);
    }
    let bytes = (await z.generateAsync({ type: 'nodebuffer', createFolders: false } as any)) as Buffer;
    for (const [from, to] of swaps) {
      let hex = bytes.toString('hex');
      hex = hex.split(Buffer.from(from).toString('hex')).join(Buffer.from(to).toString('hex'));
      bytes = Buffer.from(hex, 'hex');
    }
    return bytes;
  };
  const postZip = (session: AuthSession, projectId: string, zip: Buffer) =>
    fetch(`${running.base}/api/v1/projects/${projectId}/code-home`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${session.accessToken}`, 'Content-Type': 'application/zip' },
      body: new Uint8Array(zip)
    });

  it.each([
    ['a file that is also a folder', { 'docs': 'x', 'docs/b.txt': 'y' }],
    ['.git with a trailing dot', { '.git./config': 'x' }],
    ['.git with a trailing space', { 'sub/.git /hooks/x': 'x' }],
    ['git~1 (Windows short name of .git)', { 'GIT~1/config': 'x' }],
    ['a NUL byte in a name', { 'bad\u0000name.txt': 'x' }],
    ['a name longer than 255 bytes', { ['n'.repeat(300)]: 'x' }],
    ['the same file twice (by case)', { 'README.md': 'x', 'readme.md': 'y' }],
    ['everything inside a .git folder', { '.git/config': 'x', '.git/HEAD': 'y' }]
  ])('an upload with %s is refused before anything is created on GitHub (nothing to clean up, nothing false recorded)', async (_label, files) => {
    const c = await connectedCreator('badnames');
    const projectId = await claim(c.session, `Bad Names ${randomBytes(3).toString('hex')}`);
    const repos = gh.repos.size;
    const tokens = gh.tokens.length;
    const res = await postZip(c.session, projectId, await rawZip(files as Record<string, string>));
    expect(res.status).toBe(400);
    expect(gh.repos.size).toBe(repos);
    expect(gh.tokens.length).toBe(tokens); // not even a token was requested
    const actions = (await adminDb.query('SELECT action FROM event WHERE project_id = $1 ORDER BY seq', [projectId])).rows.map((r) => r.action);
    expect(actions).toEqual(['project.claimed']);
  });

  it('every uploaded file is committed, even ones a .gitignore in the upload lists, and the count is what GitHub reports', async () => {
    const c = await connectedCreator('ignored');
    const projectId = await claim(c.session, `Ignored ${randomBytes(2).toString('hex')}`);
    const z = new JSZip();
    z.file('README.md', '# hi\n');
    z.file('.gitignore', 'secret.txt\nsrc/\n*\n');
    z.file('secret.txt', 'still the creator\'s file\n');
    z.file('src/app.js', 'x\n');
    const res = await postZip(c.session, projectId, await z.generateAsync({ type: 'nodebuffer' }));
    const body: any = await res.json();
    expect(res.status).toBe(201);
    expect(body.repositories[0].initial_commit).toMatchObject({ files_uploaded: 4, reported_files: 4, matches: true });
    const listed = spawnSync('git', ['--git-dir', gh.repos.get(body.repositories[0].full_name)!.bare, 'ls-tree', '-r', '--name-only', 'HEAD'], { encoding: 'utf8' }).stdout.trim().split('\n').sort();
    expect(listed).toEqual(['.gitignore', 'README.md', 'secret.txt', 'src/app.js']);
  });

  it('if something fails after GitHub created the repository, it is still recorded as created, with what failed, never as "not created"', async () => {
    const c = await connectedCreator('afterfail');
    const projectId = await claim(c.session, `After Fail ${randomBytes(2).toString('hex')}`);
    const z = new JSZip();
    z.file('README.md', '# hi\n');
    gh.refusePushes = true;
    try {
      const res = await postZip(c.session, projectId, await z.generateAsync({ type: 'nodebuffer' }));
      const body: any = await res.json();
      expect(res.status).toBe(201);
      const [repo] = body.repositories;
      expect(gh.repos.has(repo.full_name)).toBe(true);
      expect(repo.initial_commit).toMatchObject({ pushed: false, reported_sha: null, matches: false });
      expect(repo.initial_commit.error).toMatch(/push/);
      // The rest of the lock still happened and was read back.
      expect(repo.settings.find((s: any) => s.setting === 'allow_forking')).toMatchObject({ reported: false, applied: true });
      const events = (await adminDb.query('SELECT action, payload FROM event WHERE project_id = $1 ORDER BY seq', [projectId])).rows;
      expect(events.map((e) => e.action)).toEqual(['project.claimed', 'repository.created']);
      expect(events[1].payload.fully_locked).toBe(false);
      expect(events[1].payload.github_repo_id).toBe(gh.repos.get(repo.full_name)!.id);
      const row = (await adminDb.query('SELECT github_repo_id, locked_at FROM repository WHERE project_id = $1', [projectId])).rows[0];
      expect(row).toEqual({ github_repo_id: String(gh.repos.get(repo.full_name)!.id), locked_at: null });
    } finally {
      gh.refusePushes = false;
    }
  });

  it('if GitHub fails while reading the new repository back, it is recorded as created but not finished, never as locked', async () => {
    const c = await connectedCreator('readfail');
    const projectId = await claim(c.session, `Read Fail ${randomBytes(2).toString('hex')}`);
    gh.failRepoRead = true;
    try {
      const r = await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: {} });
      expect(r.status).toBe(201);
      const [repo] = r.body.repositories;
      expect(gh.repos.has(repo.full_name)).toBe(true);
      expect(repo.incomplete).toMatch(/GitHub answered 500/);
      expect(repo.settings).toEqual([]); // nothing GitHub did not report is claimed
      const ev = (await adminDb.query(`SELECT payload FROM event WHERE project_id = $1 AND action = 'repository.created'`, [projectId])).rows[0].payload;
      expect(ev.fully_locked).toBe(false);
      expect((await adminDb.query('SELECT locked_at FROM repository WHERE project_id = $1', [projectId])).rows[0].locked_at).toBeNull();
    } finally {
      gh.failRepoRead = false;
    }
  });

  it('if GitHub cannot report every file in the first commit, the upload is not called a match', async () => {
    const c = await connectedCreator('truncated');
    const projectId = await claim(c.session, `Truncated ${randomBytes(2).toString('hex')}`);
    const z = new JSZip();
    z.file('a.txt', 'a');
    z.file('b.txt', 'b');
    gh.truncateTrees = true;
    try {
      const res = await postZip(c.session, projectId, await z.generateAsync({ type: 'nodebuffer' }));
      const body: any = await res.json();
      expect(body.repositories[0].initial_commit).toMatchObject({ pushed: true, files_uploaded: 2, reported_files: null, matches: false });
    } finally {
      gh.truncateTrees = false;
    }
  });

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

    // Someone made a repository with that name directly on GitHub: GitHub refuses, and that is recorded.
    const name = `Clash ${randomBytes(2).toString('hex')}`;
    gh.addForeignRepo(a.org, repositoryName(name));
    const second = await claim(a.session, name);
    const clash = await api(running.base, a.session, `/projects/${second}/code-home`, { method: 'POST', body: {} });
    expect(clash.status).toBe(502);
    const failed = (await adminDb.query(`SELECT payload FROM event WHERE project_id = $1 AND action = 'repository.creation_failed'`, [second])).rows[0].payload;
    expect(failed.error).toEqual({ status: 422, message: 'Repository creation failed.', details: ['name already exists on this account'] });
    expect(clash.body.error).toMatch(/name already exists on this account/);
    expect((await adminDb.query('SELECT 1 FROM repository WHERE project_id = $1', [second])).rowCount).toBe(0);
  });

  it('a claim that stopped half way can be finished: only the missing repository is created', async () => {
    const c = await connectedCreator('halfway', { plan: 'team' });
    const name = `Half ${randomBytes(2).toString('hex')}`;
    const projectId = await claim(c.session, name);
    // Someone made a repository with the core repository's name directly on GitHub, so GitHub refuses that one.
    const core = `${repositoryName(name)}-core`;
    gh.addForeignRepo(c.org, core);

    const first = await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: { split_core: true } });
    expect(first.status).toBe(502);
    expect(first.body.repositories.map((r: any) => r.role)).toEqual(['main']);

    // The name is freed on GitHub; asking again creates only the core repository.
    gh.repos.delete(`${c.org}/${core}`);
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
    const payload = { action: 'deleted', installation: { id: c.installationId, account: { login: c.org, id: gh.orgs.get(c.org)!.id } }, sender: { login: 'x' } };
    const id = randomUUID();
    expect((await deliver('installation', payload, { secret: 'not the secret', id })).status).toBe(401);
    expect((await deliver('installation', payload, { signature: '', id })).status).toBe(401);
    expect((await adminDb.query('SELECT status FROM github_installation WHERE installation_id = $1', [c.installationId])).rows[0].status).toBe('active');
    expect((await adminDb.query('SELECT 1 FROM github_webhook_delivery WHERE delivery_id = $1', [id])).rowCount).toBe(0);
  });

  it('uninstalling the app on GitHub: the connection shows as broken and it is recorded, once even if GitHub delivers twice', async () => {
    const c = await connectedCreator('uninstall');
    gh.uninstall(c.installationId); // the owner uninstalls it on GitHub; then GitHub sends the webhook
    const id = randomUUID();
    const payload = { action: 'deleted', installation: { id: c.installationId, account: { login: c.org, id: gh.orgs.get(c.org)!.id } }, sender: { login: c.owner } };
    const first = await deliver('installation', payload, { id });
    expect(first.status).toBe(200);
    expect(((await first.json()) as any).outcome).toBe('connection removed');
    // GitHub's own state is what was recorded, not the webhook's word
    const again = await deliver('installation', payload, { id });
    expect(((await again.json()) as any).duplicate).toBe(true);

    const status = await api(running.base, c.session, '/github/connection');
    expect(status.body.installation.status).toBe('removed');
    expect(status.body.broken).toMatchObject({ organization: c.org, reason: 'GitHub reports the app is no longer installed', github_reports: 'removed', webhook_sender_unconfirmed: c.owner });
    const broken = (await accountEvents(c.session.userId)).filter((e) => e.action === 'github.connection_broken');
    expect(broken).toHaveLength(1);
    expect(broken[0].actor_type).toBe('system');

    // No more claims through a removed installation; the creator can connect again.
    const projectId = await claim(c.session, `After ${randomBytes(2).toString('hex')}`);
    expect((await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: {} })).status).toBe(409);
    expect((await raw('/github/connect', { method: 'POST', headers: { Authorization: `Bearer ${c.session.accessToken}` } })).status).toBe(200);
  });

  it('a signed body replayed under another event name, or for another account, changes nothing', async () => {
    const c = await connectedCreator('replay', { plan: 'team' });
    const projectId = await claim(c.session, `Replay ${randomBytes(2).toString('hex')}`);
    const made = (await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: {} })).body.repositories[0];
    const repoBody = { action: 'deleted', installation: { id: c.installationId }, repository: { id: made.github_repo_id, full_name: made.full_name, private: true }, sender: { login: 'x' } };
    const asInstallation = await deliver('installation', repoBody);
    expect(((await asInstallation.json()) as any).outcome).toBe('ignored: body does not match the installation event');
    const otherAccount = await deliver('installation', { action: 'deleted', installation: { id: c.installationId, account: { login: c.org, id: 1 } }, sender: { login: 'x' } });
    expect(((await otherAccount.json()) as any).outcome).toBe('ignored: installation account does not match');
    expect((await adminDb.query('SELECT status FROM github_installation WHERE installation_id = $1', [c.installationId])).rows[0].status).toBe('active');
  });

  it('a repository deleted on GitHub is recorded in its project chain', async () => {
    const c = await connectedCreator('repodel', { plan: 'team' });
    const projectId = await claim(c.session, `Del ${randomBytes(2).toString('hex')}`);
    const made = (await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: {} })).body.repositories[0];
    gh.repos.delete(made.full_name); // deleted on GitHub; then GitHub sends the webhook
    const r = await deliver('repository', { action: 'deleted', installation: { id: c.installationId }, repository: { id: made.github_repo_id, full_name: made.full_name, private: true }, sender: { login: 'someone' } });
    expect(((await r.json()) as any).outcome).toBe('recorded no_longer_visible');
    const last = (await adminDb.query(`SELECT action, payload FROM event WHERE project_id = $1 ORDER BY seq DESC LIMIT 1`, [projectId])).rows[0];
    // GitHub can only tell the app the repository is gone from its view; "deleted" is not claimed.
    expect(last).toMatchObject({ action: 'repository.no_longer_visible_on_github', payload: { before: { exists: true, full_name: made.full_name }, github_reports: { exists: false }, webhook_sender_unconfirmed: 'someone' } });
    // The same delivery again (new id): nothing more is recorded.
    const again = await deliver('repository', { action: 'deleted', installation: { id: c.installationId }, repository: { id: made.github_repo_id, full_name: made.full_name, private: true }, sender: { login: 'someone' } });
    expect(((await again.json()) as any).outcome).toBe('no change (GitHub reports the same as last recorded)');
  });

  it('a webhook for an installation nobody connected is kept as received but changes nothing', async () => {
    const r = await deliver('installation', { action: 'deleted', installation: { id: 987654321, account: { login: 'nobody', id: 1 } } });
    expect(r.status).toBe(200);
    expect(((await r.json()) as any).outcome).toBe('installation not linked to a creator');
    const push = await deliver('push', { installation: { id: 987654321 }, ref: 'refs/heads/main' });
    expect(((await push.json()) as any).outcome).toBe('received, not acted on');
  });

  // ---------------------------------------------------------------- third review: GitHub is asked, not the message believed

  it('replayed webhooks change nothing: a stored "suspend" or "deleted" sent again is checked against GitHub first', async () => {
    const c = await connectedCreator('replay2');
    const account = { login: c.org, id: gh.orgs.get(c.org)!.id };
    const suspendBody = { action: 'suspend', installation: { id: c.installationId, account }, sender: { login: 'x' } };
    gh.suspend(c.installationId, true);
    expect(((await (await deliver('installation', suspendBody)).json()) as any).outcome).toBe('connection suspended');
    gh.suspend(c.installationId, false);
    expect(((await (await deliver('installation', { ...suspendBody, action: 'unsuspend' })).json()) as any).outcome).toBe('connection active');
    // The old "suspend" again, under a new delivery id: GitHub says the app is working, so nothing changes.
    expect(((await (await deliver('installation', suspendBody)).json()) as any).outcome).toBe('no change (GitHub reports active)');
    expect(((await (await deliver('installation', { ...suspendBody, action: 'deleted' })).json()) as any).outcome).toBe('no change (GitHub reports active)');
    expect((await adminDb.query('SELECT status FROM github_installation WHERE installation_id = $1', [c.installationId])).rows[0].status).toBe('active');
    const actions = (await accountEvents(c.session.userId)).map((e) => e.action).filter((a) => a.startsWith('github.connection'));
    expect(actions).toEqual(['github.connection_broken', 'github.connection_restored']);
  });

  it('a "repository deleted" message for a repository GitHub still has is ignored', async () => {
    const c = await connectedCreator('stillthere', { plan: 'team' });
    const projectId = await claim(c.session, `Still ${randomBytes(2).toString('hex')}`);
    const made = (await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: {} })).body.repositories[0];
    const r = await deliver('repository', { action: 'deleted', installation: { id: c.installationId }, repository: { id: made.github_repo_id, full_name: made.full_name, private: true }, sender: { login: 'x' } });
    expect(((await r.json()) as any).outcome).toBe('no change (GitHub reports the same as last recorded)');
    const r2 = await deliver('repository', { action: 'publicized', installation: { id: c.installationId }, repository: { id: made.github_repo_id, full_name: made.full_name, private: false }, sender: { login: 'x' } });
    expect(((await r2.json()) as any).outcome).toBe('no change (GitHub reports the same as last recorded)');
    const actions = (await adminDb.query('SELECT action FROM event WHERE project_id = $1 ORDER BY seq', [projectId])).rows.map((x) => x.action);
    expect(actions).toEqual(['project.claimed', 'repository.created']);
  });

  it("the connection screen shows only the current installation's lock: an earlier organization's success is never shown for a new one", async () => {
    const c = await connectedCreator('stale');
    gh.uninstall(c.installationId);
    await deliver('installation', { action: 'deleted', installation: { id: c.installationId, account: { login: c.org, id: gh.orgs.get(c.org)!.id } }, sender: { login: c.owner } });
    // A newly linked installation with no lock recorded yet must not borrow the earlier organization's lock.
    const creatorId = (await adminDb.query('SELECT id FROM creator WHERE identity_id = $1', [c.session.userId])).rows[0].id;
    const orgX = `stale-x-${randomBytes(3).toString('hex')}`;
    const ox = gh.addOrg(orgX, { owners: [c.owner] });
    const idX = gh.install(orgX);
    await adminDb.query(`INSERT INTO github_installation (creator_id, installation_id, account_login, account_id, owner_login, owner_id, status) VALUES ($1, $2, $3, $4, $5, $6, 'active')`, [creatorId, idX, orgX, ox.id, c.owner, gh.userId(c.owner)]);
    const fresh = await api(running.base, c.session, '/github/connection');
    expect(fresh.body.installation.organization).toBe(orgX);
    expect(fresh.body.organization_lock).toBeNull();
    await adminDb.query(`UPDATE github_installation SET status = 'removed' WHERE installation_id = $1`, [idX]);

    // Connect a second organization whose lock fails (GitHub errors while reading it back).
    const org2 = `stale2-${randomBytes(3).toString('hex')}`;
    gh.addOrg(org2, { owners: [c.owner] });
    const id2 = gh.install(org2);
    const { state, cookie } = await start(c.session);
    gh.failOrgRead = true;
    try {
      expect(outcome(await finish(state, cookie, id2, c.owner))).toBe('connected_lock_failed');
    } finally {
      gh.failOrgRead = false;
    }
    const status = await api(running.base, c.session, '/github/connection');
    expect(status.body.installation.organization).toBe(org2);
    expect(status.body.organization_lock).toBeNull(); // not the first organization's green checks
    expect(status.body.organization_lock_failed).toMatchObject({ organization: org2, error: { status: 500 } });
  });

  it('a repository whose lock could not be finished can be finished later, and empty code can be pushed again', async () => {
    const c = await connectedCreator('relockme', { plan: 'team' });
    const projectId = await claim(c.session, `Relock ${randomBytes(2).toString('hex')}`);
    const z = new JSZip();
    z.file('README.md', '# again\n');
    const zip = await z.generateAsync({ type: 'nodebuffer' });
    gh.refusePushes = true;
    let made: any;
    try {
      made = (await (await postZip(c.session, projectId, zip)).json() as any).repositories[0];
    } finally {
      gh.refusePushes = false;
    }
    expect(made.initial_commit.pushed).toBe(false);
    const repoId = (await adminDb.query('SELECT id FROM repository WHERE project_id = $1', [projectId])).rows[0].id;
    // Retry with the code: pushed now, everything read back, recorded as checked, and now fully locked.
    const res = await fetch(`${running.base}/api/v1/projects/${projectId}/repositories/${repoId}/lock`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${c.session.accessToken}`, 'Content-Type': 'application/zip' },
      body: new Uint8Array(zip)
    });
    const body: any = await res.json();
    expect(res.status).toBe(200);
    expect(body.fully_locked).toBe(true);
    expect(body.repository.initial_commit).toMatchObject({ pushed: true, matches: true, reported_files: 1 });
    expect(gh.repos.get(made.full_name)!.rulesets).toHaveLength(1); // the existing rules were reused, not duplicated
    expect((await adminDb.query('SELECT locked_at FROM repository WHERE id = $1', [repoId])).rows[0].locked_at).not.toBeNull();
    const last = (await adminDb.query(`SELECT action, actor_type FROM event WHERE project_id = $1 ORDER BY seq DESC LIMIT 1`, [projectId])).rows[0];
    expect(last).toEqual({ action: 'repository.lock_checked', actor_type: 'creator' });
    // Code can only go into a repository GitHub reports as empty.
    const again = await fetch(`${running.base}/api/v1/projects/${projectId}/repositories/${repoId}/lock`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${c.session.accessToken}`, 'Content-Type': 'application/zip' },
      body: new Uint8Array(zip)
    });
    expect(again.status).toBe(409);
    // Someone else's repository: 404.
    const other = await connectedCreator('relockother');
    expect((await api(running.base, other.session, `/projects/${projectId}/repositories/${repoId}/lock`, { method: 'POST', body: {} })).status).toBe(404);
  });

  it("if GitHub creates the repository but its answer is lost, Custody Core recognises its own repository and records it", async () => {
    const c = await connectedCreator('lostanswer');
    const projectId = await claim(c.session, `Lost ${randomBytes(2).toString('hex')}`);
    gh.loseCreateAnswer = true;
    let r: any;
    try {
      r = await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: {} });
    } finally {
      gh.loseCreateAnswer = false;
    }
    expect(r.status).toBe(201);
    const [repo] = r.body.repositories;
    expect(repo.adopted).toMatch(/502/);
    expect(gh.repos.get(repo.full_name)!.description).toContain(`Custody Core ${projectId}`);
    expect((await adminDb.query('SELECT github_repo_id FROM repository WHERE project_id = $1', [projectId])).rows[0].github_repo_id).toBe(String(gh.repos.get(repo.full_name)!.id));
    // A repository of the same name that is NOT ours (no marker, made on GitHub) is never adopted.
    const p2 = await claim(c.session, `Foreign ${randomBytes(2).toString('hex')}`);
    const name = (await adminDb.query('SELECT name FROM project WHERE id = $1', [p2])).rows[0].name;
    gh.addForeignRepo(c.org, repositoryName(name));
    expect((await api(running.base, c.session, `/projects/${p2}/code-home`, { method: 'POST', body: {} })).status).toBe(502);
    expect((await adminDb.query('SELECT 1 FROM repository WHERE project_id = $1', [p2])).rowCount).toBe(0);
  });

  it('an upload GitHub would refuse (a .gitmodules pointing outside the repository) is refused before anything is created', async () => {
    const c = await connectedCreator('fsck');
    const projectId = await claim(c.session, `Fsck ${randomBytes(2).toString('hex')}`);
    const z = new JSZip();
    z.file('README.md', 'x');
    z.file('.gitmodules', '[submodule "../../evil"]\n\tpath = evil\n\turl = https://example.com/evil.git\n');
    const repos = gh.repos.size;
    const res = await postZip(c.session, projectId, await z.generateAsync({ type: 'nodebuffer' }));
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toMatch(/cannot be committed/);
    expect(gh.repos.size).toBe(repos);
  });

  it('a renamed organization is followed, and someone no longer an owner on GitHub cannot create repositories', async () => {
    const c = await connectedCreator('renamed');
    const newName = `${c.org}-new`;
    gh.renameOrg(c.org, newName);
    const r = await deliver('organization', { action: 'renamed', installation: { id: c.installationId }, organization: { login: newName }, sender: { login: c.owner } });
    expect(((await r.json()) as any).outcome).toBe(`organization renamed to ${newName}`);
    expect((await api(running.base, c.session, '/github/connection')).body.installation.organization).toBe(newName);
    const projectId = await claim(c.session, `Renamed ${randomBytes(2).toString('hex')}`);
    const ok = await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: {} });
    expect(ok.status).toBe(201);
    expect(ok.body.repositories[0].full_name.startsWith(`${newName}/`)).toBe(true);

    // The person who connected it stops being an owner on GitHub.
    gh.orgs.get(newName)!.owners.delete(c.owner);
    gh.orgs.get(newName)!.members.add(c.owner);
    const p2 = await claim(c.session, `No Owner ${randomBytes(2).toString('hex')}`);
    const refused = await api(running.base, c.session, `/projects/${p2}/code-home`, { method: 'POST', body: {} });
    expect(refused.status).toBe(403);
    expect(refused.body.error).toMatch(/no longer an owner/);
  });

  // ---------------------------------------------------------------- fourth review

  it('25 repository creations at the same moment all get an answer, and the server keeps answering everyone else', async () => {
    const c = await connectedCreator('flood', { plan: 'team' });
    const projects = await Promise.all(Array.from({ length: 25 }, (_, i) => claim(c.session, `Flood ${i} ${randomBytes(2).toString('hex')}`)));
    const timeout = <T,>(p: Promise<T>, ms: number) => Promise.race([p, new Promise<never>((_, rej) => setTimeout(() => rej(new Error('no answer')), ms))]);
    const answers = await timeout(Promise.all(projects.map((id) => api(running.base, c.session, `/projects/${id}/code-home`, { method: 'POST', body: {} }))), 120_000);
    expect(answers.every((a) => a.status === 201)).toBe(true);
    expect((await timeout(api(running.base, c.session, '/me'), 10_000)).status).toBe(200);
    expect((await timeout(fetch(`${running.base}/api/v1/health`), 10_000)).ok).toBe(true);
  }, 180_000);

  it('two operations on the same project at once: one runs, the other is told to wait (no double repositories)', async () => {
    const c = await connectedCreator('twice', { plan: 'team' });
    const projectId = await claim(c.session, `Twice ${randomBytes(2).toString('hex')}`);
    const [a, b] = await Promise.all([
      api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: {} }),
      api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: {} })
    ]);
    expect([a.status, b.status].sort()).toEqual([201, 409]);
    expect((await adminDb.query('SELECT count(*)::int AS n FROM repository WHERE project_id = $1', [projectId])).rows[0].n).toBe(1);
  });

  it('while an operation is running on a project, another one waits; a mark left by a stopped server expires', async () => {
    const c = await connectedCreator('busy', { plan: 'team' });
    const projectId = await claim(c.session, `Busy ${randomBytes(2).toString('hex')}`);
    await adminDb.query(`UPDATE project SET code_home_busy_until = now() + interval '5 minutes' WHERE id = $1`, [projectId]);
    const reposBefore = gh.repos.size;
    const r = await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: {} });
    expect(r.status).toBe(409);
    expect(r.body.error).toMatch(/already being created or checked/);
    expect(gh.repos.size).toBe(reposBefore); // nothing created
    await adminDb.query(`UPDATE project SET code_home_busy_until = now() - interval '1 second' WHERE id = $1`, [projectId]);
    expect((await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: {} })).status).toBe(201);
    expect((await adminDb.query('SELECT code_home_busy_until FROM project WHERE id = $1', [projectId])).rows[0].code_home_busy_until).toBeNull();
  });

  it('re-locking the organization also requires the connector to still be an owner', async () => {
    const c = await connectedCreator('orgrelock');
    gh.orgs.get(c.org)!.owners.delete(c.owner);
    gh.orgs.get(c.org)!.members.add(c.owner);
    const before = { ...gh.orgs.get(c.org)!.settings };
    gh.orgs.get(c.org)!.settings.default_repository_permission = 'write';
    const r = await api(running.base, c.session, '/github/organization/lock', { method: 'POST', body: {} });
    expect(r.status).toBe(403);
    expect(gh.orgs.get(c.org)!.settings.default_repository_permission).toBe('write'); // nothing was changed
    void before;
  });

  it('ownership is checked by GitHub user id: someone else now using the same login does not count', async () => {
    const c = await connectedCreator('sameLogin');
    // The stored owner id now belongs to an account that is not an owner (the login was renamed and re-taken).
    await adminDb.query('UPDATE github_installation SET owner_id = $2 WHERE installation_id = $1', [c.installationId, gh.userId('someone-else-entirely')]);
    const projectId = await claim(c.session, `Same Login ${randomBytes(2).toString('hex')}`);
    expect((await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: {} })).status).toBe(403);
  });

  it('a replayed "made public" message records the change once, and "check again" makes the repository private again', async () => {
    const c = await connectedCreator('public', { plan: 'team' });
    const projectId = await claim(c.session, `Public ${randomBytes(2).toString('hex')}`);
    const made = (await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: {} })).body.repositories[0];
    gh.repos.get(made.full_name)!.private = false; // someone made it public on GitHub
    const body = { action: 'publicized', installation: { id: c.installationId }, repository: { id: made.github_repo_id, full_name: made.full_name, private: false }, sender: { login: 'x' } };
    expect(((await (await deliver('repository', body)).json()) as any).outcome).toBe('recorded publicized');
    expect(((await (await deliver('repository', body)).json()) as any).outcome).toBe('no change (GitHub reports the same as last recorded)');
    expect(((await (await deliver('repository', body)).json()) as any).outcome).toBe('no change (GitHub reports the same as last recorded)');
    const repoId = (await adminDb.query('SELECT id FROM repository WHERE project_id = $1', [projectId])).rows[0].id;
    const fixed = await api(running.base, c.session, `/projects/${projectId}/repositories/${repoId}/lock`, { method: 'POST', body: {} });
    expect(fixed.status).toBe(200);
    expect(gh.repos.get(made.full_name)!.private).toBe(true);
    expect(fixed.body.repository.settings.find((x: any) => x.setting === 'private')).toMatchObject({ reported: true, applied: true });
    const actions = (await adminDb.query('SELECT action FROM event WHERE project_id = $1 ORDER BY seq', [projectId])).rows.map((x) => x.action);
    expect(actions).toEqual(['project.claimed', 'repository.created', 'repository.publicized_on_github', 'repository.lock_checked']);
  });

  it('branch rules narrowed on GitHub are not called active, and "check again" sets them back', async () => {
    const c = await connectedCreator('narrowed', { plan: 'team' });
    const projectId = await claim(c.session, `Narrowed ${randomBytes(2).toString('hex')}`);
    const made = (await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: {} })).body.repositories[0];
    const rs = gh.repos.get(made.full_name)!.rulesets[0];
    rs.conditions = { ref_name: { include: ['refs/heads/nothing-matches'], exclude: [] } }; // loosened on GitHub
    const repoId = (await adminDb.query('SELECT id FROM repository WHERE project_id = $1', [projectId])).rows[0].id;
    const r = await api(running.base, c.session, `/projects/${projectId}/repositories/${repoId}/lock`, { method: 'POST', body: {} });
    expect(r.body.repository.ruleset).toMatchObject({ applied: true, reported: { branches: { include: ['~ALL'], exclude: [] } } });
    expect(gh.repos.get(made.full_name)!.rulesets).toHaveLength(1);
    expect(gh.repos.get(made.full_name)!.rulesets[0].conditions.ref_name.include).toEqual(['~ALL']);
  });

  it('"is it empty?" is asked of GitHub directly: a repository with commits on another branch is not treated as empty', async () => {
    const c = await connectedCreator('notempty', { plan: 'team' });
    const projectId = await claim(c.session, `Not Empty ${randomBytes(2).toString('hex')}`);
    const z = new JSZip();
    z.file('a.txt', 'a');
    gh.refusePushes = true;
    let made: any;
    try {
      made = ((await (await postZip(c.session, projectId, await z.generateAsync({ type: 'nodebuffer' }))).json()) as any).repositories[0];
    } finally {
      gh.refusePushes = false;
    }
    // Someone pushes a commit to another branch (the default branch stays empty).
    const bare = gh.repos.get(made.full_name)!.bare;
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'other-'));
    try {
      spawnSync('git', ['init', '-q', '-b', 'other', tmp]);
      fs.writeFileSync(path.join(tmp, 'x'), 'x');
      spawnSync('git', ['-C', tmp, 'add', '-A']);
      spawnSync('git', ['-C', tmp, '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '-m', 'x']);
      spawnSync('git', ['-C', tmp, 'push', '-q', bare, 'other']);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
    const repoId = (await adminDb.query('SELECT id FROM repository WHERE project_id = $1', [projectId])).rows[0].id;
    const res = await fetch(`${running.base}/api/v1/projects/${projectId}/repositories/${repoId}/lock`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${c.session.accessToken}`, 'Content-Type': 'application/zip' },
      body: new Uint8Array(await z.generateAsync({ type: 'nodebuffer' }))
    });
    expect(res.status).toBe(409);
    expect(((await res.json()) as any).error).toMatch(/already has commits/);
  });

  it("a repository already recorded for another project is never adopted, even renamed on GitHub to this project's name with its marker forged", async () => {
    const c = await connectedCreator('noadopt', { plan: 'team' });
    const first = await claim(c.session, `Adopt ${randomBytes(2).toString('hex')}`);
    const made = (await api(running.base, c.session, `/projects/${first}/code-home`, { method: 'POST', body: {} })).body.repositories[0];
    const second = await claim(c.session, `Other ${randomBytes(2).toString('hex')}`);
    const wantedName = repositoryName((await adminDb.query('SELECT name FROM project WHERE id = $1', [second])).rows[0].name);
    // On GitHub (without Custody Core being told): the first repository is renamed to the name the second
    // project wants, and its description is given the second project's marker.
    gh.renameRepo(made.full_name, wantedName);
    gh.repos.get(`${c.org}/${wantedName}`)!.description = `x · Custody Core ${second}`;
    const r = await api(running.base, c.session, `/projects/${second}/code-home`, { method: 'POST', body: {} });
    expect(r.status).toBe(502); // GitHub: name exists; not adopted, because it is already recorded (by GitHub id)
    expect((await adminDb.query('SELECT 1 FROM repository WHERE project_id = $1', [second])).rowCount).toBe(0);
  });

  it('a second project with the same name gets its own repository name (-2), not a refusal', async () => {
    const c = await connectedCreator('samename', { plan: 'team' });
    const name = `Same ${randomBytes(2).toString('hex')}`;
    const p1 = await claim(c.session, name);
    const p2 = await claim(c.session, name);
    const r1 = await api(running.base, c.session, `/projects/${p1}/code-home`, { method: 'POST', body: { split_core: true } });
    const r2 = await api(running.base, c.session, `/projects/${p2}/code-home`, { method: 'POST', body: { split_core: true } });
    expect(r1.body.repositories.map((x: any) => x.full_name)).toEqual([`${c.org}/${repositoryName(name)}`, `${c.org}/${repositoryName(name)}-core`]);
    expect(r2.body.repositories.map((x: any) => x.full_name)).toEqual([`${c.org}/${repositoryName(name)}-2`, `${c.org}/${repositoryName(name)}-2-core`]);
  });

  it('a repository from an earlier code home connection is not re-locked through the new one', async () => {
    const c = await connectedCreator('oldhome', { plan: 'team' });
    const projectId = await claim(c.session, `Old Home ${randomBytes(2).toString('hex')}`);
    await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: {} });
    const repoId = (await adminDb.query('SELECT id FROM repository WHERE project_id = $1', [projectId])).rows[0].id;
    gh.uninstall(c.installationId);
    await deliver('installation', { action: 'deleted', installation: { id: c.installationId, account: { login: c.org, id: gh.orgs.get(c.org)!.id } }, sender: { login: c.owner } });
    const org2 = `newhome-${randomBytes(3).toString('hex')}`;
    gh.addOrg(org2, { owners: [c.owner] });
    const id2 = gh.install(org2);
    const { state, cookie } = await start(c.session);
    expect(outcome(await finish(state, cookie, id2, c.owner))).toBe('connected');
    const r = await api(running.base, c.session, `/projects/${projectId}/repositories/${repoId}/lock`, { method: 'POST', body: {} });
    expect(r.status).toBe(409);
    expect(r.body.error).toMatch(/earlier code home connection/);
  });

  it('if locking fails after the code was pushed, the record still shows the code was pushed', async () => {
    const c = await connectedCreator('keepcommit');
    const projectId = await claim(c.session, `Keep ${randomBytes(2).toString('hex')}`);
    const z = new JSZip();
    z.file('a.txt', 'a');
    gh.failRepoRead = true;
    try {
      const res = await postZip(c.session, projectId, await z.generateAsync({ type: 'nodebuffer' }));
      const body: any = await res.json();
      expect(body.repositories[0].incomplete).toBeTruthy();
      expect(body.repositories[0].initial_commit).toMatchObject({ pushed: true });
      expect(body.repositories[0].github_repo_id).toBeGreaterThan(0);
    } finally {
      gh.failRepoRead = false;
    }
  });

  // ---------------------------------------------------------------- fifth review

  it('a burst of webhooks while GitHub is slow does not lock anyone else out of the database', async () => {
    const c = await connectedCreator('slowhooks');
    const account = { login: c.org, id: gh.orgs.get(c.org)!.id };
    gh.slowInstallationReadMs = 4000;
    try {
      const burst = Promise.all(Array.from({ length: 14 }, () => deliver('installation', { action: 'new_permissions_accepted', installation: { id: c.installationId, account }, sender: { login: 'x' } })));
      await new Promise((r) => setTimeout(r, 500)); // the webhooks are now waiting on GitHub
      const t0 = Date.now();
      const other = await createMfaUser('bystander', running.base);
      const projects = await api(running.base, other.session, '/projects');
      expect(projects.status).toBe(200);
      expect(Date.now() - t0).toBeLessThan(8000);
      const answers = await burst;
      expect(answers.every((a) => a.status === 200)).toBe(true);
    } finally {
      gh.slowInstallationReadMs = 0;
    }
  }, 60_000);

  it('right after a claim answers, the next request on that project is not told it is still busy', async () => {
    const c = await connectedCreator('rightafter', { plan: 'team' });
    const projectId = await claim(c.session, `Right After ${randomBytes(2).toString('hex')}`);
    for (let i = 0; i < 3; i++) {
      const made = await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: i === 0 ? {} : { split_core: true } });
      expect(made.status).toBe(i === 0 ? 201 : i === 1 ? 201 : 409);
      if (i === 2) expect(made.body.error).toMatch(/already has its repositories/);
    }
    expect((await adminDb.query('SELECT code_home_busy_until, code_home_busy_token FROM project WHERE id = $1', [projectId])).rows[0]).toEqual({ code_home_busy_until: null, code_home_busy_token: null });
  });

  it('"check again" and the webhook check use tokens for that one repository only', async () => {
    const c = await connectedCreator('narrowtok', { plan: 'team' });
    const projectId = await claim(c.session, `Narrow ${randomBytes(2).toString('hex')}`);
    const made = (await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: {} })).body.repositories[0];
    const repoId = (await adminDb.query('SELECT id FROM repository WHERE project_id = $1', [projectId])).rows[0].id;
    const before = gh.tokens.length;
    await api(running.base, c.session, `/projects/${projectId}/repositories/${repoId}/lock`, { method: 'POST', body: {} });
    await deliver('repository', { action: 'edited', installation: { id: c.installationId }, repository: { id: made.github_repo_id, full_name: made.full_name, private: true }, sender: { login: 'x' } });
    const repoName = made.full_name.split('/')[1];
    const used = gh.tokens.slice(before).filter((t) => !('members' in t.permissions)); // (the owner check reads members, never code)
    expect(used.length).toBeGreaterThanOrEqual(3);
    for (const t of used) expect(t.repositories).toEqual([repoName]);
  });

  it('if GitHub refuses the forking change, making the repository private again still happens', async () => {
    const c = await connectedCreator('forkrule', { plan: 'team' });
    const projectId = await claim(c.session, `Fork Rule ${randomBytes(2).toString('hex')}`);
    const made = (await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: {} })).body.repositories[0];
    gh.repos.get(made.full_name)!.private = false;
    const repoId = (await adminDb.query('SELECT id FROM repository WHERE project_id = $1', [projectId])).rows[0].id;
    gh.refuseForkingChange = true;
    try {
      const r = await api(running.base, c.session, `/projects/${projectId}/repositories/${repoId}/lock`, { method: 'POST', body: {} });
      expect(gh.repos.get(made.full_name)!.private).toBe(true);
      expect(r.body.repository.settings.find((x: any) => x.setting === 'allow_forking (change refused)')).toMatchObject({ applied: false });
      expect(r.body.fully_locked).toBe(false);
    } finally {
      gh.refuseForkingChange = false;
    }
  });

  // ---------------------------------------------------------------- sixth review

  it('an older answer from GitHub that arrives late never overwrites a newer one (a public repository is not recorded as private)', async () => {
    const c = await connectedCreator('late', { plan: 'team' });
    const projectId = await claim(c.session, `Late ${randomBytes(2).toString('hex')}`);
    const made = (await api(running.base, c.session, `/projects/${projectId}/code-home`, { method: 'POST', body: {} })).body.repositories[0];
    const repo = gh.repos.get(made.full_name)!;
    const body = (action: string) => ({ action, installation: { id: c.installationId }, repository: { id: made.github_repo_id, full_name: made.full_name }, sender: { login: 'x' } });
    repo.private = false;
    expect(((await (await deliver('repository', body('publicized'))).json()) as any).outcome).toBe('recorded publicized');
    // It is made private again; this webhook's answer from GitHub ("private") arrives late...
    repo.private = true;
    gh.lateRepositoryAnswerMs = 2500;
    const slow = deliver('repository', body('privatized'));
    await new Promise((r) => setTimeout(r, 400));
    gh.lateRepositoryAnswerMs = 0;
    // ...meanwhile it is made public again, and that newer answer is recorded first.
    repo.private = false;
    expect(((await (await deliver('repository', body('publicized'))).json()) as any).outcome).toBe('no change (GitHub reports the same as last recorded)');
    expect(((await (await slow).json()) as any).outcome).toBe('ignored: a newer answer from GitHub is already recorded');
    const stored = (await adminDb.query('SELECT github_state FROM repository WHERE project_id = $1', [projectId])).rows[0].github_state;
    expect(stored.private).toBe(false); // what GitHub reports now
    const actions = (await adminDb.query('SELECT action FROM event WHERE project_id = $1 ORDER BY seq', [projectId])).rows.map((x) => x.action);
    expect(actions).toEqual(['project.claimed', 'repository.created', 'repository.publicized_on_github']);
  });

  it('an older answer about the connection that arrives late never overwrites a newer one (a suspended app is not recorded as working)', async () => {
    const c = await connectedCreator('lateinst');
    const body = (action: string) => ({ action, installation: { id: c.installationId, account: { login: c.org, id: gh.orgs.get(c.org)!.id } }, sender: { login: 'x' } });
    gh.suspend(c.installationId, true);
    expect(((await (await deliver('installation', body('suspend'))).json()) as any).outcome).toBe('connection suspended');
    // The app is unsuspended; this webhook's answer from GitHub ("working") arrives late...
    gh.suspend(c.installationId, false);
    gh.lateInstallationAnswerMs = 2500;
    const slow = deliver('installation', body('unsuspend'));
    await new Promise((r) => setTimeout(r, 400));
    gh.lateInstallationAnswerMs = 0;
    // ...meanwhile it is suspended again, and that newer answer is recorded first.
    gh.suspend(c.installationId, true);
    expect(((await (await deliver('installation', body('suspend'))).json()) as any).outcome).toBe('no change (GitHub reports suspended)');
    expect(((await (await slow).json()) as any).outcome).toBe('ignored: a newer answer from GitHub is already recorded');
    const row = (await adminDb.query('SELECT status FROM github_installation WHERE installation_id = $1', [c.installationId])).rows[0];
    expect(row.status).toBe('suspended'); // what GitHub reports now
    const connection = (await api(running.base, c.session, '/github/connection')).body;
    expect(JSON.stringify(connection)).toContain('suspended');
    gh.suspend(c.installationId, false);
  });

  it('uploads over the limit are refused before their body is read: one per creator, two in total', async () => {
    const http = await import('node:http');
    const [a, b, c2, d] = await Promise.all(['upA', 'upB', 'upC', 'upD'].map((l) => connectedCreator(l)));
    const projects = await Promise.all([a, b, c2, d, a].map((x, i) => claim(x.session, `Upload ${i} ${randomBytes(2).toString('hex')}`)));
    const port = Number(new URL(running.base).port);
    /** Starts an upload that announces 40 MB but sends only the first bytes, and keeps it open. */
    const hold = (session: AuthSession, projectId: string) => {
      const req = http.request({
        host: '127.0.0.1',
        port,
        method: 'POST',
        path: `/api/v1/projects/${projectId}/code-home`,
        headers: { Authorization: `Bearer ${session.accessToken}`, 'Content-Type': 'application/zip', 'Content-Length': String(40 * 1024 * 1024) }
      });
      req.on('error', () => undefined);
      req.write(Buffer.alloc(1024));
      return req;
    };
    /** An upload that announces 40 MB and sends nothing: answered before any body is read? */
    const quickAnswer = (session: AuthSession, projectId: string) =>
      new Promise<number>((resolve, reject) => {
        const req = http.request({
          host: '127.0.0.1',
          port,
          method: 'POST',
          path: `/api/v1/projects/${projectId}/code-home`,
          headers: { Authorization: `Bearer ${session.accessToken}`, 'Content-Type': 'application/zip', 'Content-Length': String(40 * 1024 * 1024) }
        });
        const timer = setTimeout(() => reject(new Error('no answer without the body')), 5000);
        req.on('response', (r) => {
          clearTimeout(timer);
          r.resume();
          resolve(r.statusCode!);
          req.destroy();
        });
        req.on('error', () => undefined);
        req.flushHeaders();
      });
    const heldA = hold(a.session, projects[0]);
    await new Promise((r) => setTimeout(r, 1500)); // its login check is done and it holds a slot
    expect(await quickAnswer(a.session, projects[4])).toBe(429); // same creator, second upload
    const heldB = hold(b.session, projects[1]);
    await new Promise((r) => setTimeout(r, 1500));
    expect(await quickAnswer(d.session, projects[3])).toBe(429); // two in total are already being received
    heldA.destroy();
    heldB.destroy();
    await new Promise((r) => setTimeout(r, 500)); // slots are given back when those connections close
    const z = new JSZip();
    z.file('ok.txt', 'ok');
    const ok = await postZip(c2.session, projects[2], await z.generateAsync({ type: 'nodebuffer' }));
    expect(ok.status).toBe(201);
  }, 60_000);

  it("a creator's upload waiting on a slow GitHub does not block other creators' uploads", async () => {
    const [a, b] = await Promise.all([connectedCreator('slowA'), connectedCreator('slowB')]);
    const [pa, pa2, pb] = await Promise.all([claim(a.session, `Slow A ${randomBytes(2).toString('hex')}`), claim(a.session, `Slow A2 ${randomBytes(2).toString('hex')}`), claim(b.session, `Slow B ${randomBytes(2).toString('hex')}`)]);
    const z = new JSZip();
    z.file('x.txt', 'x');
    const zip = await z.generateAsync({ type: 'nodebuffer' });
    gh.slowInstallationReadMs = 3000;
    try {
      const first = postZip(a.session, pa, zip);
      await new Promise((r) => setTimeout(r, 800)); // A's upload is unpacked, has given back its upload slot, and now waits on GitHub
      const t0 = Date.now();
      const second = postZip(a.session, pa2, zip); // A's next upload is received too: the slot covers receiving, not waiting on GitHub
      const fromB = postZip(b.session, pb, zip);
      const statuses = await Promise.all([first, second, fromB].map(async (p) => (await p).status));
      expect(statuses).toEqual([201, 201, 201]);
      expect(Date.now() - t0).toBeLessThan(15_000);
    } finally {
      gh.slowInstallationReadMs = 0;
    }
  }, 60_000);

  it('the same delivery sent again is answered as a duplicate without asking GitHub anything', async () => {
    const c = await connectedCreator('dupcalls');
    const body = { action: 'new_permissions_accepted', installation: { id: c.installationId, account: { login: c.org, id: gh.orgs.get(c.org)!.id } }, sender: { login: 'x' } };
    const id = randomUUID();
    expect((await deliver('installation', body, { id })).status).toBe(200);
    const before = gh.calls.length;
    for (let i = 0; i < 5; i++) expect(((await (await deliver('installation', body, { id })).json()) as any).duplicate).toBe(true);
    expect(gh.calls.length).toBe(before);
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
