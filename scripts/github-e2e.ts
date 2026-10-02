import { spawn, ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import JSZip from 'jszip';
import pg from 'pg';
import { generateSync } from 'otplib';
import { ensureAuthStack } from './auth-stack';
import { startDatabaseProcess, freePort } from '../tests/support/dbProcess';
import { assertSafeTestDatabaseUrl, collectProtectedUrls } from '../tests/support/safety';
import { appJwt, gh, githubConfig, withInstallationToken } from '../server/github/app';
import { RULESET_NAME } from '../server/github/repositories';

/**
 * End-to-end run against REAL GitHub and a dedicated TEST organization (never your real one). Nothing is mocked.
 * See docs/GITHUB_APP_SETUP.md, "End-to-end test".
 *
 *   npm run github-e2e               automatic: lock the test org, claim a project (with a zip and a core
 *                                    repository), then compare every recorded setting with a fresh read from GitHub
 *   npm run github-e2e -- --connect  with you in the loop: connect the test org through GitHub's real install and
 *                                    authorize pages in your browser, then uninstall it, and check what was recorded
 *   npm run github-e2e -- --cleanup  delete the cc-e2e-* repositories this run created in the test organization
 *
 * The app runs on a throwaway local database and the local login stack (Docker); never the live database.
 */
dotenv.config(); // shell environment wins; never override
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = new Set(process.argv.slice(2));
const PREFIX = 'cc-e2e-';

const results: Array<{ what: string; recorded: unknown; github: unknown; ok: boolean }> = [];
const note = (what: string, recorded: unknown, github: unknown) => {
  const ok = JSON.stringify(recorded) === JSON.stringify(github);
  results.push({ what, recorded, github, ok });
  console.log(`${ok ? 'MATCH   ' : 'MISMATCH'}  ${what}: recorded ${JSON.stringify(recorded)}, GitHub reports ${JSON.stringify(github)}`);
};
/** A check that is not a comparison with GitHub (for example, a hash chain verifies). */
const check = (what: string, ok: boolean) => {
  results.push({ what, recorded: ok, github: ok, ok });
  console.log(`${ok ? 'PASS    ' : 'FAIL    '}  ${what}`);
};
const fail = (msg: string): never => {
  console.error(`\nSTOPPED: ${msg}`);
  process.exit(1);
};

async function main() {
  // GITHUB_E2E_SELFTEST=1 checks THIS SCRIPT against the local stand-in. It is not the end-to-end run.
  const selfTest = process.env.GITHUB_E2E_SELFTEST === '1' ? await startSelfTest() : null;
  if (!selfTest) {
    // Real GitHub only: no stand-in addresses.
    delete process.env.GITHUB_API_URL;
    delete process.env.GITHUB_WEB_URL;
  }
  const config = (() => {
    try {
      return githubConfig();
    } catch (err: any) {
      return fail(`${err.message} Put the GitHub App values in .env first (docs/GITHUB_APP_SETUP.md).`);
    }
  })();
  const org = process.env.GITHUB_E2E_ORG || fail('Set GITHUB_E2E_ORG to the name of your dedicated test organization.');
  const ownerLogin = process.env.GITHUB_E2E_OWNER || fail('Set GITHUB_E2E_OWNER to your GitHub username (an owner of the test organization).');
  const installationId = Number(process.env.GITHUB_E2E_INSTALLATION_ID || 0) || fail('Set GITHUB_E2E_INSTALLATION_ID (the number at the end of the installation\'s settings page address).');

  // ---- Safety: this must be the test organization, and it must look like one.
  const installation = await gh(config, { kind: 'app', token: appJwt(config) }, 'GET', `/app/installations/${installationId}`);
  if (installation.account?.login !== org) fail(`Installation ${installationId} is on "${installation.account?.login}", not on GITHUB_E2E_ORG "${org}".`);
  if (installation.account?.type !== 'Organization') fail(`"${org}" is not an organization.`);
  if (process.env.GITHUB_REAL_ORG && process.env.GITHUB_REAL_ORG.toLowerCase() === org.toLowerCase()) fail('GITHUB_E2E_ORG is your real organization. Use a dedicated test organization.');
  const existing: string[] = await withInstallationToken(config, installationId, { permissions: { metadata: 'read' } }, async (token) => {
    const list = await gh(config, { kind: 'token', token }, 'GET', '/installation/repositories?per_page=100');
    return (list.repositories ?? []).map((r: any) => String(r.name));
  });
  const foreign = existing.filter((n) => !n.startsWith(PREFIX));
  if (foreign.length) fail(`"${org}" has repositories that this test did not make (${foreign.slice(0, 5).join(', ')}). Use an empty, dedicated test organization.`);
  console.log(`Test organization: ${org} (installation ${installationId}), ${existing.length} earlier test repositories.`);

  if (args.has('--cleanup')) {
    await withInstallationToken(config, installationId, { repositories: existing, permissions: { administration: 'write' } }, async (token) => {
      for (const name of existing) {
        await gh(config, { kind: 'token', token }, 'DELETE', `/repos/${org}/${name}`);
        console.log(`deleted ${org}/${name}`);
      }
    });
    return;
  }

  // ---- The app, on a throwaway database and the local login stack.
  const authStack = ensureAuthStack();
  process.env.AUTH_API_URL = authStack.apiUrl;
  process.env.AUTH_ANON_KEY = authStack.anonKey;
  process.env.AUTH_JWT_SECRET = authStack.jwtSecret;
  process.env.AUTH_DB_URL = authStack.dbUrl;
  const database = await startDatabaseProcess();
  assertSafeTestDatabaseUrl(database.url, collectProtectedUrls());
  const connectMode = args.has('--connect');
  // In --connect mode GitHub sends your browser back to the URLs registered in the app, so the port is fixed.
  const port = connectMode ? Number(process.env.GITHUB_E2E_PORT || 3000) : await freePort();
  const base = connectMode ? `http://localhost:${port}` : `http://127.0.0.1:${port}`;
  const server: ChildProcess = spawn(process.execPath, ['--import', 'tsx', 'server.ts'], {
    cwd: root,
    env: {
      ...process.env,
      NODE_ENV: 'development',
      DISABLE_HMR: 'true',
      PORT: String(port),
      HOST: '127.0.0.1',
      DATABASE_URL: database.url,
      ADMIN_DATABASE_URL: '',
      APP_DATABASE_URL: '',
      SUPABASE_URL: authStack.apiUrl,
      SUPABASE_ANON_KEY: authStack.anonKey,
      VITE_SUPABASE_URL: authStack.apiUrl,
      VITE_SUPABASE_ANON_KEY: authStack.anonKey,
      MFA_ENCRYPTION_KEY: randomBytes(32).toString('base64'),
      APP_URL: base
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let serverLog = '';
  server.stdout!.on('data', (c) => (serverLog += c));
  server.stderr!.on('data', (c) => (serverLog += c));
  const db = new pg.Pool({ connectionString: database.url });

  try {
    for (let i = 0; i < 240; i++) {
      try {
        if ((await fetch(`${base}/api/v1/health`)).ok) break;
      } catch {
        /* starting */
      }
      await new Promise((r) => setTimeout(r, 250));
    }
    const { createMfaUser, TEST_PASSWORD } = await import('../tests/support/authStack');
    const creator = await createMfaUser('e2e', base);
    const call = async (method: string, p: string, body?: unknown, headers: Record<string, string> = {}) => {
      const isBuf = Buffer.isBuffer(body);
      const r = await fetch(`${base}/api/v1${p}`, {
        method,
        headers: { Authorization: `Bearer ${creator.session.accessToken}`, ...(body !== undefined && !isBuf ? { 'Content-Type': 'application/json' } : {}), ...headers },
        body: body === undefined ? undefined : isBuf ? new Uint8Array(body as Buffer) : JSON.stringify(body)
      });
      return { status: r.status, body: (await r.json().catch(() => ({}))) as any };
    };
    const creatorRow = (await db.query('SELECT id, identity_id FROM creator WHERE identity_id = $1', [creator.session.userId])).rows[0];

    if (connectMode) {
      console.log(`\n=== Connect through GitHub, in your browser ===
1. Open ${base} and sign in with:
     email:    ${creator.email}
     password: ${TEST_PASSWORD}   (a throwaway account in the local test login stack)
   For the 6-digit code, use the code printed below (it changes every 30 seconds).
2. On the dashboard, click "Connect your code home", then "Install Custody Core", choose "${org}", All repositories,
   Install, then Authorize. You will come back to the dashboard.
3. Then claim a project from the dashboard (any name), with "core repository" ticked.
4. Finally, uninstall the app from "${org}" on GitHub (Settings > GitHub Apps > Configure > Uninstall).
   (The uninstall reaches this computer only if the app's webhook URL forwards here; see the guide.)\n`);
      const ticker = setInterval(() => console.log(`   code now: ${generateSync({ secret: creator.secret })}`), 30_000);
      console.log(`   code now: ${generateSync({ secret: creator.secret })}`);
      try {
        await waitFor('the connection', 20 * 60, async () =>
          (await db.query(`SELECT 1 FROM github_installation WHERE creator_id = $1 AND status = 'active'`, [creatorRow.id])).rowCount === 1
        );
        await verifyOrganization(db, config, creatorRow.identity_id, installationId, org);
        await waitFor('a claimed project with repositories', 20 * 60, async () => (await db.query(`SELECT 1 FROM event WHERE action = 'repository.created'`)).rowCount! > 0);
        await verifyRepositories(db, config, installationId, org);
        await waitFor('the uninstall webhook', 10 * 60, async () =>
          (await db.query(`SELECT 1 FROM github_installation WHERE creator_id = $1 AND status = 'removed'`, [creatorRow.id])).rowCount === 1
        ).catch(() => console.log('The uninstall webhook did not arrive (is the webhook URL forwarded to this computer?). Not counted as a match.'));
        const broken = (await db.query(`SELECT payload FROM account_event WHERE account_id = $1 AND action = 'github.connection_broken'`, [creatorRow.identity_id])).rows[0];
        if (broken) check('the uninstall is recorded as a broken connection', true);
      } finally {
        clearInterval(ticker);
      }
    } else {
      // The connection step needs a person in a browser (--connect). Here the installation is linked directly in
      // this throwaway database, so everything after it runs against real GitHub through the real API.
      // The owner as GitHub knows them (permanent id), so the "still an owner?" check runs against real GitHub.
      const owner = await withInstallationToken(config, installationId, { permissions: { members: 'read' } }, (token) =>
        gh(config, { kind: 'token', token }, 'GET', `/orgs/${org}/memberships/${encodeURIComponent(ownerLogin)}`)
      );
      if (owner?.role !== 'admin') fail(`${ownerLogin} is not an owner of ${org} according to GitHub.`);
      await db.query(
        `INSERT INTO github_installation (creator_id, installation_id, account_login, account_id, owner_login, owner_id, status) VALUES ($1, $2, $3, $4, $5, $6, 'active')`,
        [creatorRow.id, installationId, org, installation.account.id, owner.user.login, owner.user.id]
      );
      const lock = await call('POST', '/github/organization/lock', {});
      if (lock.status !== 200) fail(`locking the organization failed: ${JSON.stringify(lock.body)}`);
      await verifyOrganization(db, config, creatorRow.identity_id, installationId, org);

      const projectName = `${PREFIX}${new Date().toISOString().replace(/[-:T.Z]/g, '').slice(0, 14)}`;
      const project = await call('POST', '/projects', { name: projectName, purpose: 'Custody Core end-to-end test' });
      if (project.status !== 201) fail(`claiming failed: ${JSON.stringify(project.body)}`);
      const z = new JSZip();
      z.file('e2e/README.md', `# ${projectName}\n\nUploaded by the Custody Core end-to-end test.\n`);
      z.file('e2e/src/hello.txt', 'hello\n');
      const zip = await z.generateAsync({ type: 'nodebuffer' });
      const made = await call('POST', `/projects/${project.body.project.id}/code-home?split_core=1`, zip, { 'Content-Type': 'application/zip' });
      if (made.status !== 201) fail(`creating repositories failed: ${JSON.stringify(made.body)}`);
      for (const r of made.body.repositories) console.log(`created ${r.html_url}`);
      await verifyRepositories(db, config, installationId, org);
      const chain = await call('GET', `/projects/${project.body.project.id}/events/verify`);
      check('the project event chain verifies', chain.body.valid === true);
      const account = await call('GET', '/account/events');
      check('the account event chain verifies', account.body.valid === true);
    }
  } finally {
    server.kill('SIGTERM');
    await db.end();
    await database.stop();
    await selfTest?.stop();
  }

  const bad = results.filter((r) => !r.ok);
  console.log(`\n${results.length - bad.length} of ${results.length} checks passed (recorded values compared with what GitHub reports now).`);
  if (bad.length || results.length === 0) {
    if (serverLog) console.log(`\nServer log (last part):\n${serverLog.slice(-3000)}`);
    process.exit(1);
  }
  console.log(selfTest ? 'SELF-TEST OF THE SCRIPT PASSED (against the local stand-in; this is NOT the end-to-end run)' : 'END-TO-END PASSED');
}

async function startSelfTest() {
  const { startGitHubStandIn } = await import('../tests/support/githubStandIn');
  const standIn = await startGitHubStandIn();
  standIn.addOrg('cc-selftest-org', { owners: ['selftest'] });
  standIn.userId('selftest');
  const id = standIn.install('cc-selftest-org');
  Object.assign(process.env, {
    GITHUB_APP_ID: standIn.appId,
    GITHUB_APP_SLUG: standIn.slug,
    GITHUB_APP_CLIENT_ID: standIn.clientId,
    GITHUB_APP_CLIENT_SECRET: standIn.clientSecret,
    GITHUB_APP_PRIVATE_KEY: standIn.privateKeyPem,
    GITHUB_WEBHOOK_SECRET: randomBytes(16).toString('hex'),
    GITHUB_API_URL: standIn.url,
    GITHUB_WEB_URL: standIn.url,
    GITHUB_E2E_ORG: 'cc-selftest-org',
    GITHUB_E2E_OWNER: 'selftest',
    GITHUB_E2E_INSTALLATION_ID: String(id)
  });
  console.log('*** SELF-TEST against the local GitHub stand-in: checks this script, NOT GitHub. ***');
  return standIn;
}

async function waitFor(what: string, seconds: number, test: () => Promise<boolean>) {
  console.log(`waiting for ${what}...`);
  for (let i = 0; i < seconds / 2; i++) {
    if (await test()) return;
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error(`timed out waiting for ${what}`);
}

/** The latest recorded organization lock against a fresh read from GitHub. */
async function verifyOrganization(db: pg.Pool, config: ReturnType<typeof githubConfig>, identityId: string, installationId: number, org: string) {
  const recorded = (await db.query(`SELECT payload FROM account_event WHERE account_id = $1 AND action = 'github.organization_locked' ORDER BY seq DESC LIMIT 1`, [identityId])).rows[0]?.payload;
  if (!recorded) fail('no organization lock was recorded');
  const now = await withInstallationToken(config, installationId, { permissions: { organization_administration: 'read' } }, (token) =>
    gh(config, { kind: 'token', token }, 'GET', `/orgs/${org}`)
  );
  for (const s of recorded.settings) note(`organization ${s.setting}`, s.reported, now[s.setting] ?? null);
  note('organization plan', recorded.plan, now.plan?.name ?? null);
}

/** Every recorded repository against a fresh read from GitHub. */
async function verifyRepositories(db: pg.Pool, config: ReturnType<typeof githubConfig>, installationId: number, org: string) {
  const events = (await db.query(`SELECT payload FROM event WHERE action = 'repository.created' ORDER BY created_at`)).rows.map((r) => r.payload);
  if (!events.length) fail('no repository was recorded');
  const names = events.map((e: any) => String(e.full_name).split('/')[1]);
  await withInstallationToken(config, installationId, { repositories: names, permissions: { administration: 'read', contents: 'read' } }, async (token) => {
    const auth = { kind: 'token' as const, token };
    for (const e of events) {
      const repoPath = `/repos/${e.full_name}`;
      const now = await gh(config, auth, 'GET', repoPath);
      for (const s of e.settings) if (!String(s.setting).includes('(')) note(`${e.full_name} ${s.setting}`, s.reported, now[s.setting] ?? null);
      const rulesets: any[] = await gh(config, auth, 'GET', `${repoPath}/rulesets`).catch((err: any) => {
        if (err.status === 403 || err.status === 404) return [];
        throw err;
      });
      const ours = rulesets.find((r) => r.name === RULESET_NAME);
      note(`${e.full_name} branch rules active`, e.ruleset.applied, !!ours && ours.enforcement === 'active');
      if (e.ruleset.refused) console.log(`          (GitHub refused branch rules: "${e.ruleset.refused.message}")`);
      if (e.initial_commit) {
        const head = await gh(config, auth, 'GET', `${repoPath}/commits/${e.default_branch}`);
        note(`${e.full_name} first commit`, e.initial_commit.reported_sha, head.sha);
        const tree = await gh(config, auth, 'GET', `${repoPath}/git/trees/${head.sha}?recursive=1`);
        note(`${e.full_name} files in the first commit`, e.initial_commit.reported_files, (tree.tree ?? []).filter((t: any) => t.type === 'blob').length);
      }
    }
  });
  void org;
}

main().catch((err) => {
  console.error('github-e2e crashed:', err?.message ?? err);
  process.exit(1);
});
