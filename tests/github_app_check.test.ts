import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { checkGitHubApp, REQUIRED_PERMISSIONS } from '../server/githubAppCheck';
import { forgetInstallationTokens } from '../server/github';
import { startGitHubStandIn, StandIn } from './support/githubStandIn';

/**
 * "Is the GitHub App still in place?": the check asks GitHub as the App itself. Against the local stand-in (which verifies the App's signed JWT with
 * the App's public key, like GitHub), every way the App can go wrong is produced and must be reported, in words, without ever revealing a secret.
 */
describe('GitHub App check', () => {
  let standIn: StandIn;
  const saved = { ...process.env };
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
  const ORG = `org${Date.now()}`;

  beforeAll(async () => {
    standIn = await startGitHubStandIn();
  });
  afterAll(async () => {
    await standIn.stop();
  });
  const configure = (over: Record<string, string> = {}) => {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved, standIn.env, over);
    forgetInstallationTokens();
  };
  afterEach(() => {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved);
    forgetInstallationTokens();
    standIn.setAppPermissions({ contents: 'write', metadata: 'read', administration: 'write' });
  });
  const text = (f: Array<{ what: string; detail?: string }>) => f.map((x) => `${x.what} ${x.detail ?? ''}`).join('\n');
  const levels = (f: Array<{ level: string }>) => f.map((x) => x.level);

  it('reports a healthy App: it exists, asks for what is needed, and an installation works', async () => {
    const id = 11000 + Math.floor(Math.random() * 900);
    standIn.addInstallation(id, ORG, [`${ORG}/one`, `${ORG}/two`]);
    configure();
    const f = await checkGitHubApp();
    expect(levels(f).filter((l) => l === 'fail')).toEqual([]);
    expect(text(f)).toContain('The App exists and accepts its key: "Custody Core (test)"');
    expect(text(f)).toContain('asks for the permissions Custody Core needs');
    expect(text(f)).toContain(`${ORG} (installation ${id}) works: a token can be made and it can see 2 repositories`);
    expect(text(f)).toContain('Not checkable from here'); // the callback URL and the client secret are listed as things to look at
  });

  it('says plainly when the settings are missing, naming the variables and no values', async () => {
    configure({ GITHUB_APP_ID: '', GITHUB_APP_PRIVATE_KEY: '' });
    const f = await checkGitHubApp();
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ level: 'fail', what: 'The server is not configured with the GitHub App' });
    expect(f[0].detail).toMatch(/GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY/);
    expect(f[0].detail).not.toContain('GITHUB_APP_SLUG'); // only what is missing
  });

  it('a private key that is not a key is reported without echoing it', async () => {
    configure({ GITHUB_APP_PRIVATE_KEY: '-----BEGIN RSA PRIVATE KEY-----\\nnot really a key\\n-----END RSA PRIVATE KEY-----' });
    const f = await checkGitHubApp();
    expect(f.at(-1)).toMatchObject({ level: 'fail', what: 'The private key cannot be used' });
    expect(text(f)).not.toContain('not really a key');
  });

  it('a key GitHub does not know (deleted, or another App\'s) is reported as such', async () => {
    const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    configure({ GITHUB_APP_PRIVATE_KEY: other });
    const f = await checkGitHubApp();
    expect(f.at(-1)).toMatchObject({ level: 'fail', what: 'GitHub does not accept this App ID with this private key' });
    expect(f.at(-1)!.detail).toMatch(/deleted|another App|wrong/);
    expect(text(f)).not.toContain('BEGIN');
    // the wrong App id with the right key is refused the same way
    configure({ GITHUB_APP_ID: '1' });
    expect(levels(await checkGitHubApp())).toContain('fail');
  });

  it('GitHub being unreachable is a failure that says so, not a crash', async () => {
    configure({ GITHUB_API_URL: 'http://127.0.0.1:1' });
    const f = await checkGitHubApp();
    expect(f.at(-1)).toMatchObject({ level: 'fail', what: 'GitHub could not be asked' });
  });

  it('an App that no longer asks for a needed permission fails, saying which and how to fix it', async () => {
    standIn.setAppPermissions({ contents: 'read', metadata: 'read' });
    configure();
    const f = await checkGitHubApp();
    const fails = f.filter((x) => x.level === 'fail').map((x) => x.what);
    expect(fails).toEqual(expect.arrayContaining(['The App does not ask for "contents: write"', 'The App does not ask for "administration: write"']));
    expect(f.find((x) => x.what.includes('administration'))!.detail).toMatch(/Permissions, set administration to Read and write/);
    expect(fails.some((w) => w.includes('metadata'))).toBe(false);
  });

  it('an organization that has not accepted a newer permission, and one that is suspended, are flagged as things to act on', async () => {
    const stale = 12000 + Math.floor(Math.random() * 900);
    const gone = 13000 + Math.floor(Math.random() * 900);
    standIn.addInstallation(stale, `${ORG}-stale`, [`${ORG}-stale/a`]);
    standIn.setInstallationPermissions(stale, { contents: 'write', metadata: 'read' }); // administration was added later and never accepted
    standIn.addInstallation(gone, `${ORG}-gone`, [`${ORG}-gone/a`]);
    standIn.suspendInstallation(gone);
    configure();
    const f = await checkGitHubApp();
    const staleFinding = f.find((x) => x.what.includes(`${ORG}-stale`) && x.level === 'warn')!;
    expect(staleFinding.what).toMatch(/has not accepted: administration write/);
    expect(staleFinding.detail).toMatch(/review request/);
    expect(f.find((x) => x.what.includes(`${ORG}-gone`))).toMatchObject({ level: 'warn' });
    expect(f.find((x) => x.what.includes(`${ORG}-gone`))!.what).toMatch(/suspended/);
    // the stale one still works for what it was given
    expect(f.some((x) => x.level === 'pass' && x.what.includes(`${ORG}-stale`))).toBe(true);
    standIn.suspendInstallation(gone, false);
  });

  it('never returns a secret in anything it says', async () => {
    standIn.addInstallation(14000 + Math.floor(Math.random() * 900), `${ORG}-x`, [`${ORG}-x/a`]);
    configure();
    const all = text(await checkGitHubApp());
    for (const secret of [process.env.GITHUB_APP_PRIVATE_KEY!, process.env.GITHUB_APP_CLIENT_SECRET!, 'ghs_', 'BEGIN']) expect(all).not.toContain(secret);
  });

  it('the command prints PASS/WARN/FAIL lines and exits 1 only on a failure', async () => {
    standIn.addInstallation(15000 + Math.floor(Math.random() * 900), `${ORG}-cli`, [`${ORG}-cli/a`]);
    // asynchronous on purpose: the stand-in GitHub runs in this process, so a blocking call would stop it from answering
    const run = (env: Record<string, string>) =>
      new Promise<{ status: number; stdout: string; stderr: string }>((resolve) => {
        const child = spawn(path.join(root, 'node_modules', '.bin', 'tsx'), ['scripts/check-github-app.ts'], { cwd: root, env: { ...process.env, ...standIn.env, ...env } });
        let stdout = '';
        let stderr = '';
        child.stdout.on('data', (c) => (stdout += c));
        child.stderr.on('data', (c) => (stderr += c));
        child.on('close', (code) => resolve({ status: code ?? 1, stdout, stderr }));
      });
    const good = await run({});
    expect(good.status, good.stdout + good.stderr).toBe(0);
    expect(good.stdout).toMatch(/\[PASS\] The App exists and accepts its key/);
    expect(good.stdout).toMatch(/The App is in place\./);
    const bad = await run({ GITHUB_APP_PRIVATE_KEY: '' });
    expect(bad.status).toBe(1);
    expect(bad.stdout).toMatch(/\[FAIL\] The server is not configured/);
    expect(bad.stdout).toMatch(/1 problem to fix\./);
    expect(REQUIRED_PERMISSIONS.map((p) => p.name)).toEqual(['contents', 'metadata', 'administration']);
  }, 60_000);
});
