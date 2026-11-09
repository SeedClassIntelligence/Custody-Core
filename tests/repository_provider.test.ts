import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { forgetInstallationTokens } from '../server/github';
import { githubProvider } from '../server/githubProvider';
import { ProviderError, ProviderNotConfigured, githubRef, providerFor, type RepositoryRef } from '../server/repositoryProvider';
import { startGitHubStandIn, StandIn } from './support/githubStandIn';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/**
 * The repository provider seam (Phase 5a, docs/integration/PHASE5_DESIGN.md 4.1). A behavior-preserving wrapper: the
 * gateway, the backups and the lock service ask a provider, and the provider makes exactly the calls they made directly
 * before. The behavior itself is covered by git_gateway, repository_lock, scheduler and developer_signing, which pass
 * unchanged; these tests cover the seam: what it returns, what it throws, and that nothing bypasses it.
 */
describe('Repository provider (GitHub)', () => {
  const INSTALLATION = 4242;
  const ORG = `provorg${Date.now()}`;
  const APP = `${ORG}/app`;
  let standIn: StandIn;
  let ref: RepositoryRef;
  const savedEnv = { ...process.env };

  beforeAll(async () => {
    standIn = await startGitHubStandIn();
    Object.assign(process.env, standIn.env);
    forgetInstallationTokens();
    standIn.addInstallation(INSTALLATION, ORG, [APP]);
    standIn.createRepo(APP);
    ref = githubRef({ id: 'repo-1', full_name: APP, installation_id: String(INSTALLATION) }); // a database row gives the id as text
  });
  afterAll(async () => {
    await standIn?.stop();
    for (const k of Object.keys(process.env)) if (!(k in savedEnv)) delete process.env[k];
    Object.assign(process.env, savedEnv);
    forgetInstallationTokens();
  });

  // Asynchronous on purpose: the GitHub stand-in answers from this same process, so a blocking spawn would freeze it.
  const git = (args: string[]) =>
    new Promise<{ status: number | null; stderr: string }>((resolve) => {
      const child = spawn('git', args, { env: { PATH: process.env.PATH ?? '', HOME: '/nonexistent', GIT_TERMINAL_PROMPT: '0', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' } });
      let stderr = '';
      child.stderr.on('data', (c) => (stderr += c));
      const timer = setTimeout(() => child.kill('SIGKILL'), 60_000);
      child.on('close', (status) => {
        clearTimeout(timer);
        resolve({ status, stderr });
      });
    });

  it('the registry knows GitHub, and refuses a kind it does not know', () => {
    expect(providerFor('github')).toBe(githubProvider);
    expect(githubProvider).toMatchObject({ kind: 'github', label: 'GitHub' });
    expect(() => providerFor('gitlab' as any)).toThrow(/No repository provider is registered/);
  });

  it('a reference is built from a database row (installation ids arrive as text)', () => {
    expect(ref).toEqual({ id: 'repo-1', fullName: APP, provider: 'github', installationId: INSTALLATION });
    expect(typeof ref.installationId).toBe('number');
  });

  it('says whether it is set up on this server', () => {
    expect(githubProvider.isConfigured()).toBe(true);
    const id = process.env.GITHUB_APP_ID;
    delete process.env.GITHUB_APP_ID;
    try {
      expect(githubProvider.isConfigured()).toBe(false);
    } finally {
      process.env.GITHUB_APP_ID = id;
    }
  });

  it('remote(): the repository address and a header that really lets git in (and a wrong header does not)', async () => {
    const remote = await githubProvider.remote(ref);
    expect(remote.url).toBe(`${standIn.env.GITHUB_GIT_URL}/${APP}.git`);
    expect(remote.url).not.toMatch(/@|x-access-token/); // no credential in the address
    expect(remote.authHeader).toMatch(/^Authorization: Basic /);
    expect(Buffer.from(remote.authHeader.replace('Authorization: Basic ', ''), 'base64').toString()).toMatch(/^x-access-token:.+/);

    const ok = await git(['-c', `http.extraHeader=${remote.authHeader}`, '-c', 'credential.helper=', 'ls-remote', remote.url]);
    expect(ok.status, ok.stderr).toBe(0);
    const bad = await git(['-c', `http.extraHeader=Authorization: Basic ${Buffer.from('x-access-token:wrong').toString('base64')}`, '-c', 'credential.helper=', 'ls-remote', remote.url]);
    expect(bad.status).not.toBe(0);
  });

  it('remote(): the credential is the one the gateway always used (can fetch and push); a read-only one asks for less', async () => {
    const before = standIn.tokensIssued();
    await githubProvider.remote(ref);
    await githubProvider.remote(ref, { readOnly: true });
    expect(standIn.tokensIssued()).toBeGreaterThanOrEqual(before); // cached tokens may be reused; what matters is below

    standIn.setInstallationPermissions(INSTALLATION, { contents: 'read', metadata: 'read' });
    forgetInstallationTokens();
    try {
      // a read-only installation can still give a read-only credential...
      await expect(githubProvider.remote(ref, { readOnly: true })).resolves.toMatchObject({ authHeader: expect.stringMatching(/^Authorization: Basic /) });
      // ...but not the default one, which asks for write access
      const err: any = await githubProvider.remote(ref).then(() => null, (e) => e);
      expect(err).toBeInstanceOf(ProviderError);
      expect(err.provider).toBe('github');
      expect(err.status).toBe(422);
      expect(err.message).toMatch(/not granted/);
    } finally {
      standIn.setInstallationPermissions(INSTALLATION, { contents: 'write', metadata: 'read', administration: 'write' });
      forgetInstallationTokens();
    }
  });

  it('remote(): when GitHub is not set up the error says so, with the words the gateway has always shown', async () => {
    const saved = { id: process.env.GITHUB_APP_ID, key: process.env.GITHUB_APP_PRIVATE_KEY };
    delete process.env.GITHUB_APP_ID;
    forgetInstallationTokens();
    try {
      const err: any = await githubProvider.remote(ref).then(() => null, (e) => e);
      expect(err).toBeInstanceOf(ProviderNotConfigured);
      expect(err.provider).toBe('github');
      expect(err.publicMessage).toBe('The GitHub App is not set up on this server.');
      expect(err.message).toMatch(/GITHUB_APP_\* settings/); // the fuller text still goes to logs and snapshot errors
    } finally {
      process.env.GITHUB_APP_ID = saved.id;
      forgetInstallationTokens();
    }
  });

  it('remote(): a GitHub that cannot be reached is reported as before ("refused access: ... could not be reached", status 502)', async () => {
    const api = process.env.GITHUB_API_URL;
    process.env.GITHUB_API_URL = 'http://127.0.0.1:1'; // nothing listens here
    forgetInstallationTokens();
    try {
      const err: any = await githubProvider.remote(ref).then(() => null, (e) => e);
      // GitHub's own call wrapper has always turned a network failure into a GitHubError with status 502, and the gateway has always
      // answered "GitHub refused access: GitHub could not be reached (...)". The provider keeps exactly that.
      expect(err).toBeInstanceOf(ProviderError);
      expect(err).not.toBeInstanceOf(ProviderNotConfigured);
      expect(err.status).toBe(502);
      expect(err.message).toMatch(/could not be reached/);
    } finally {
      process.env.GITHUB_API_URL = api;
      forgetInstallationTokens();
    }
  });

  it('lock(): locks the repository and reports what was found, through the provider', async () => {
    standIn.repoState(APP).rulesets_allowed = true;
    const first = await githubProvider.lock(ref);
    expect(first).toMatchObject({ locked: true, error: null, previous: 'none' });
    expect(typeof first.ruleset_id).toBe('number');
    const again = await githubProvider.lock(ref);
    expect(again).toMatchObject({ locked: true, previous: 'intact', ruleset_id: first.ruleset_id });
  });

  it('lock(): never throws; a refusal is in the result, in words', async () => {
    standIn.repoState(APP).rulesets_allowed = false; // GitHub's free plan on a private repository
    standIn.repoState(APP).rulesets.clear();
    const r = await githubProvider.lock(ref);
    expect(r.locked).toBe(false);
    expect(r.error).toEqual(expect.any(String));
    expect(r.error).toMatch(/GitHub/);
  });

  describe('nothing goes around the seam', () => {
    // These modules used to call GitHub directly. They may import only what is listed here (a name, a constant), never the
    // functions that reach a repository: the provider is the only way in.
    const GITHUB_MODULES = /(^|\/)(github|repositoryLock)$/;
    const ALLOWED: Record<string, Record<string, string[]>> = {
      'server/gateway/router.ts': {},
      'server/snapshots.ts': {},
      'server/scheduler.ts': {},
      // the ruleset's name, recorded in the lock events; it makes no call
      'server/lockService.ts': { './repositoryLock': ['LOCK_NAME'] },
      // the GitHub *connection*: listing what the App can see, when repositories are added
      'server/doors.ts': { './github': ['GitHubError', 'GitHubNotConfigured', 'installationRepositories'] }
    };
    const importsOf = (text: string) =>
      [...text.matchAll(/import\s+(?:type\s+)?(?:\{([^}]*)\}|[\w*\s]+)\s+from\s+['"]([^'"]+)['"]/g)].map((m) => ({
        from: m[2],
        names: (m[1] ?? '').split(',').map((n) => n.replace(/^\s*type\s+/, '').trim()).filter(Boolean)
      }));
    for (const [file, allowed] of Object.entries(ALLOWED)) {
      it(`${file} reaches GitHub only through the provider`, () => {
        const found = importsOf(fs.readFileSync(path.join(root, file), 'utf8')).filter((i) => GITHUB_MODULES.test(i.from));
        const bad = found.flatMap((i) => (i.names.length ? i.names : ['(whole module)']).filter((n) => !(allowed[i.from] ?? []).includes(n)).map((n) => `${n} from ${i.from}`));
        expect(bad, `${file} imports ${bad.join(', ')}`).toEqual([]);
      });
    }

    it('the check can fail: a file that imported a forbidden name would be caught', () => {
      const sample = `import { installationToken, upstreamGitUrl } from './github';\nimport { lockRepository } from './repositoryLock';`;
      const found = importsOf(sample).filter((i) => GITHUB_MODULES.test(i.from));
      expect(found.flatMap((i) => i.names)).toEqual(['installationToken', 'upstreamGitUrl', 'lockRepository']);
    });
  });
});
