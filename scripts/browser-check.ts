import { spawn, ChildProcess } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium, Page } from 'playwright';
import { generateSync } from 'otplib';
import { ensureAuthStack } from './auth-stack';
import JSZip from 'jszip';
import pg from 'pg';
import { startDatabaseProcess, freePort } from '../tests/support/dbProcess';
import { startGitHubStandIn } from '../tests/support/githubStandIn';
import { signatureFor } from '../server/github/webhooks';
import { assertSafeTestDatabaseUrl, collectProtectedUrls } from '../tests/support/safety';
import { verifyHashChain } from '../shared/crypto';

/**
 * Drives the real app in a headless browser against the local throwaway database: loads every screen,
 * claims a project, views its event record, runs verify (valid, then after tampering), and downloads
 * and independently verifies an export. Screenshots go to browser-check-output/ (see SCREENSHOT_DIR).
 * Run with: npm run browser-check
 */
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
// Screenshots go to an ignored folder by default so runs do not dirty the repo.
// To refresh the committed set: SCREENSHOT_DIR=docs/screenshots/milestone-1 npm run browser-check
const shotsDir = path.resolve(root, process.env.SCREENSHOT_DIR || 'browser-check-output');

const failures: string[] = [];
const consoleErrors: string[] = [];
const expectedErrors: string[] = [];
// Statuses the code-check endpoint is expected to answer at this moment (a deliberate wrong code, or a lock).
let expectedCodeStatuses: number[] = [];
const isCodeCheck = (url: string) => /\/api\/v1\/mfa\/verify$/.test(url);
const wrongCodeFor = (secret: string) => {
  const near = [-1, 0, 1].map((o) => generateSync({ secret, epoch: Math.floor(Date.now() / 1000) + o * 30 }));
  let c = 0;
  while (near.includes(String(c).padStart(6, '0'))) c++;
  return String(c).padStart(6, '0');
};
const pageErrors: string[] = [];
const failedRequests: string[] = [];
const checks: string[] = [];

function check(condition: boolean, description: string) {
  if (condition) checks.push(`PASS  ${description}`);
  else {
    checks.push(`FAIL  ${description}`);
    failures.push(description);
  }
}

async function shot(page: Page, name: string) {
  await page.screenshot({ path: path.join(shotsDir, `${name}.png`), fullPage: true });
}

async function waitForServer(url: string, server: ChildProcess) {
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    if (server.exitCode !== null) throw new Error('The app server exited before it was ready.');
    try {
      const res = await fetch(`${url}/api/v1/health`);
      const body: any = await res.json();
      if (body?.database?.status === 'connected') return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error('Timed out waiting for the app server and its database connection.');
}

async function main() {
  fs.rmSync(shotsDir, { recursive: true, force: true });
  fs.mkdirSync(shotsDir, { recursive: true });

  const authStack = ensureAuthStack(); // local Supabase Auth (Docker); never a hosted project
  const database = await startDatabaseProcess();
  assertSafeTestDatabaseUrl(database.url, collectProtectedUrls());

  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  // GitHub, for this check: the local stand-in (tests/support/githubStandIn.ts). Real GitHub: scripts/github-e2e.ts.
  const gh = await startGitHubStandIn();
  const ghOrg = 'browser-check-org';
  gh.addOrg(ghOrg, { owners: ['browser-owner'] });
  gh.browser = { login: 'browser-owner', org: ghOrg, setupUrl: `${base}/api/v1/github/setup` };
  const webhookSecret = randomBytes(24).toString('hex');
  const server = spawn(process.execPath, ['--import', 'tsx', 'server.ts'], {
    cwd: root,
    env: {
      ...process.env,
      NODE_ENV: 'development',
      DISABLE_HMR: 'true', // Vite's HMR uses a fixed port; the check does not need hot reload
      PORT: String(port),
      // Point the app at the local test database only. Empty strings stop .env from supplying others.
      DATABASE_URL: database.url,
      ADMIN_DATABASE_URL: '',
      APP_DATABASE_URL: '',
      SUPABASE_URL: authStack.apiUrl,
      // A throwaway key for stored authenticator keys (server only; never the real one).
      MFA_ENCRYPTION_KEY: randomBytes(32).toString('base64'),
      SUPABASE_ANON_KEY: authStack.anonKey,
      VITE_SUPABASE_URL: authStack.apiUrl,
      VITE_SUPABASE_ANON_KEY: authStack.anonKey,
      APP_URL: base,
      GITHUB_APP_ID: gh.appId,
      GITHUB_APP_SLUG: gh.slug,
      GITHUB_APP_CLIENT_ID: gh.clientId,
      GITHUB_APP_CLIENT_SECRET: gh.clientSecret,
      GITHUB_APP_PRIVATE_KEY: gh.privateKeyPem,
      GITHUB_WEBHOOK_SECRET: webhookSecret,
      GITHUB_API_URL: gh.url,
      GITHUB_WEB_URL: gh.url
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let serverLog = '';
  server.stdout!.on('data', (c) => (serverLog += c.toString()));
  server.stderr!.on('data', (c) => (serverLog += c.toString()));

  const browser = await chromium.launch({ headless: true });
  try {
    await waitForServer(base, server);

    const context = await browser.newContext({ viewport: { width: 1366, height: 900 }, acceptDownloads: true });
    const page = await context.newPage();
    page.on('console', (m) => {
      if (m.type() !== 'error') return;
      const line = `${m.text()} (${m.location().url})`;
      // A deliberate wrong code (422) or a lock (429) from our code check is the behaviour under test.
      const status = Number(/status of (\d{3})/.exec(m.text())?.[1]);
      if (expectedCodeStatuses.includes(status) && isCodeCheck(m.location().url)) expectedErrors.push(line);
      else consoleErrors.push(line);
    });
    page.on('pageerror', (e) => pageErrors.push(String(e)));
    page.on('requestfailed', (r) => {
      // The browser drops its read of the logout response; that the sign-out really happened is checked
      // separately (the old token must stop working), so this one is not counted as a failure.
      if (/\/auth\/v1\/logout/.test(r.url()) && r.failure()?.errorText === 'net::ERR_ABORTED') return;
      failedRequests.push(`${r.method()} ${r.url()} ${r.failure()?.errorText}`);
    });
    page.on('response', (r) => {
      if (r.status() >= 400 && !(expectedCodeStatuses.includes(r.status()) && isCodeCheck(r.url()))) failedRequests.push(`${r.status()} ${r.request().method()} ${r.url()}`);
    });

    // 1. Empty state: no invented project, and old demo data is not resurrected.
    await page.addInitScript(() => {
      try {
        localStorage.setItem('custody_core_state_v2_real', JSON.stringify({ projects: [{ id: 'x', name: 'STALE DEMO PROJECT' }] }));
      } catch {
        /* ignore */
      }
    });
    await page.goto(base, { waitUntil: 'networkidle' });

    // 0. Signed out: no project screen, and the API refuses anonymous callers.
    await page.getByRole('heading', { name: 'Sign in' }).waitFor();
    check((await page.getByText('Project Home').count()) === 0 && !(await page.content()).includes('STALE DEMO PROJECT'), 'signed out: no project screen is shown');
    check((await page.request.get(`${base}/api/v1/projects`)).status() === 401, 'the API answers an anonymous caller with 401');
    await shot(page, '00-sign-in');

    // Create an account.
    const email = `browser_${Date.now()}@example.com`;
    const password = 'Browser-Check-Passw0rd!';
    await page.getByRole('button', { name: 'New here? Create an account' }).click();
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Password').fill(password);
    await shot(page, '00b-create-account');
    await page.getByRole('button', { name: 'Create account' }).click();

    // Authenticator setup is required before anything else.
    await page.getByRole('heading', { name: 'Set up your authenticator app' }).waitFor();
    check((await page.getByText('Project Home').count()) === 0, 'after sign-up but before a verified code, no project screen is shown');
    const secret = (await page.getByTestId('totp-secret').innerText()).trim();
    check(secret.length >= 16, 'the setup screen shows the authenticator key');
    await shot(page, '00c-authenticator-setup');

    const first = generateSync({ secret });
    expectedCodeStatuses = [422];
    await page.getByLabel('6-digit code').fill(wrongCodeFor(secret));
    await page.getByRole('button', { name: 'Confirm and continue' }).click();
    await page.getByRole('alert').waitFor();
    expectedCodeStatuses = [];
    check(expectedErrors.length === 1, 'our server refused the wrong code with a 422 (expected, not counted as an error)');
    check(/4 tries left/.test(await page.getByRole('alert').innerText()), 'the screen says how many tries are left (4)');
    check((await page.getByText('Project Home').count()) === 0, 'a wrong code does not let you in');
    await shot(page, '00d-wrong-code');

    await page.getByLabel('6-digit code').fill(first);
    await page.getByRole('button', { name: 'Confirm and continue' }).click();

    // 1. Empty state: no invented project, and old demo data is not resurrected.
    await page.getByText('No projects yet').waitFor();
    // The header asks the server on its own request; give it up to 10 seconds, then judge.
    const dbShown = await page.getByText('PostgreSQL Connected').waitFor({ timeout: 10_000 }).then(() => true, () => false);
    check(dbShown, 'header reports the database as connected');
    check(await page.getByText(email).isVisible(), 'the header shows who is signed in');
    await shot(page, '01-project-home-empty');

    // 2. Setup guide: three steps, none connected.
    await page.getByRole('button', { name: 'Setup Guide' }).click();
    check((await page.getByText('Not connected yet').count()) > 0, 'setup guide says Not connected yet');
    await shot(page, '02-setup-guide-step1');
    await page.getByRole('button', { name: '2. Code Home' }).click();
    await shot(page, '03-setup-guide-step2');
    await page.getByRole('button', { name: '3. Backup Mirror' }).click();
    await shot(page, '04-setup-guide-step3');
    await page.getByRole('button', { name: 'Close Guide' }).click();

    // 3. Claim a project.
    await page.getByRole('button', { name: 'Claim Your First Project' }).click();
    await page.getByPlaceholder('The name you call this project').fill('Browser Check Project');
    await page.getByPlaceholder('What this software does and why you are building it.').fill('Proving the claim flow works in a real browser');
    await shot(page, '05-claim-project-filled');
    await page.getByRole('button', { name: 'Record Project' }).click();
    await page.getByRole('heading', { name: 'Browser Check Project' }).waitFor();
    check(true, 'claiming a project shows it on Project Home');
    await page.getByText('1 event in the log').waitFor();
    check(true, 'Project Home reports 1 event from the server');
    await shot(page, '06-project-home-after-claim');

    // 4. Open a door: honest placeholder.
    await page.getByRole('button', { name: 'Open a Door' }).first().click();
    check((await page.getByText('Not connected yet').count()) > 0, 'Open a Door says Not connected yet');
    await shot(page, '07-open-door-not-connected');
    await page.getByRole('button', { name: 'Close', exact: true }).click();

    // 5. Event chain: view the record and verify.
    await page.getByRole('button', { name: /Event Chain/ }).click();
    await page.getByText('Block #1 Inspector').waitFor();
    check(await page.locator('div.cursor-pointer', { hasText: 'project.claimed' }).isVisible(), 'Event Chain lists the project.claimed event as block #1');
    await shot(page, '08-event-chain');
    await page.getByRole('button', { name: 'Check This Record' }).click();
    await page.getByText('Hash chain verified').waitFor();
    check(true, 'Check This Record reports the chain verified');
    check(!(await page.locator('body').innerText()).includes("\\'"), 'no stray backslash-quote in the page text');
    await shot(page, '09-event-chain-verified');

    // 6. Tamper with the stored record (admin, triggers bypassed, local test database only) and verify again.
    const admin = new pg.Client({ connectionString: database.url });
    await admin.connect();
    try {
      await admin.query("SET session_replication_role = 'replica'");
      await admin.query("UPDATE event SET actor_id = 'someone_else' WHERE action = 'project.claimed'");
      await admin.query('RESET session_replication_role');
    } finally {
      await admin.end();
    }
    await page.getByRole('button', { name: 'Check This Record' }).click();
    await page.getByText(/Tamper Detected/).waitFor();
    check(true, 'after the stored record is altered, Check This Record reports tampering');
    await shot(page, '10-event-chain-tamper-detected');

    // Put the record back so the export below is of an intact chain.
    const restore = new pg.Client({ connectionString: database.url });
    await restore.connect();
    try {
      await restore.query("SET session_replication_role = 'replica'");
      await restore.query("UPDATE event SET actor_id = (SELECT creator_id::text FROM project LIMIT 1) WHERE action = 'project.claimed'");
      await restore.query('RESET session_replication_role');
    } finally {
      await restore.end();
    }

    // 7. Developer workspace, demo scenarios.
    await page.getByRole('button', { name: /Developer Workspace/ }).click();
    await page.getByText('Developer Workspace: Not connected yet').waitFor();
    check(true, 'Developer Workspace says Not connected yet');
    await shot(page, '11-developer-workspace');

    await page.getByRole('button', { name: /Demo Scenarios/ }).click();
    await page.getByText('Phase 1 Gate Criteria Reference').waitFor();
    await shot(page, '12-demo-scenarios');

    // 8. Mirror & export: download and independently verify.
    await page.getByRole('button', { name: /Mirror & Export/ }).click();
    await page.getByText('Backup Mirror: Not connected yet').waitFor();
    check(
      !(await page.getByRole('button', { name: /Developer Workspace/ }).getAttribute('class'))!.includes('bg-indigo-600'),
      'only the current tab is highlighted (Developer Workspace is not, on Mirror & Export)'
    );
    await shot(page, '13-mirror-and-export');
    const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Export Records' }).click()]);
    const zipPath = path.join(shotsDir, 'export.zip');
    await download.saveAs(zipPath);
    await page.getByText('Manifest included in the file you just downloaded').waitFor();
    await shot(page, '14-export-downloaded');

    const zip = await JSZip.loadAsync(fs.readFileSync(zipPath));
    fs.rmSync(zipPath);
    check(
      JSON.stringify(Object.keys(zip.files).sort()) === JSON.stringify(['MANIFEST.json', 'events-hashchain.json', 'project-metadata.json']),
      'export contains only the event log, project record and manifest'
    );
    const eventsText = await zip.file('events-hashchain.json')!.async('string');
    const manifest = JSON.parse(await zip.file('MANIFEST.json')!.async('string'));
    for (const f of manifest.files) {
      const content = await zip.file(f.filename)!.async('string');
      check(createHash('sha256').update(content, 'utf8').digest('hex') === f.sha256, `manifest hash matches the bytes of ${f.filename}`);
    }
    const exportedEvents = JSON.parse(eventsText);
    const verification = await verifyHashChain(
      exportedEvents.map((e: any) => ({ ...e, timestamp: e.timestamp }))
    );
    check(verification.isValid && verification.totalEvents === 1, 'the exported event log verifies on its own, outside the database');
    check(manifest.git_bundles_included === false && manifest.events_with_seed_signature === 0, 'export does not claim bundles or signatures');

    // 9. Sign out, sign back in with only the password: the code is required again, and the data is still there.
    const tokenBefore = await page.evaluate(() => {
      const key = Object.keys(localStorage).find((k) => k.startsWith('sb-'));
      return key ? JSON.parse(localStorage.getItem(key)!).access_token : null;
    });
    check((await fetch(`${base}/api/v1/projects`, { headers: { Authorization: `Bearer ${tokenBefore}` } })).status === 200, 'before signing out, the session token works against the API');
    await page.getByRole('button', { name: 'Sign out' }).click();
    await page.getByRole('heading', { name: 'Sign in' }).waitFor();
    await new Promise((r) => setTimeout(r, 1500)); // let the sign-out request reach the server
    const afterSignOut = await fetch(`${base}/api/v1/projects`, { headers: { Authorization: `Bearer ${tokenBefore}` } });
    check(afterSignOut.status === 401, `after signing out, the old session token no longer works (API answered ${afterSignOut.status})`);
    check((await page.getByText('Browser Check Project').count()) === 0, 'after signing out, no project data is shown');
    await shot(page, '15-signed-out-again');
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Password').fill(password);
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await page.getByRole('heading', { name: 'Enter your authenticator code' }).waitFor();
    check((await page.getByText('Browser Check Project').count()) === 0, 'password alone does not open the app: the code is required again');
    await shot(page, '16-code-challenge');
    // A code that was already accepted a moment ago may be refused; wait for the next one.
    let next = generateSync({ secret });
    for (let i = 0; i < 70 && next === first; i++) {
      await new Promise((r) => setTimeout(r, 500));
      next = generateSync({ secret });
    }
    await page.getByLabel('6-digit code').fill(next);
    await page.getByRole('button', { name: 'Verify' }).click();
    await page.getByRole('heading', { name: 'Browser Check Project' }).waitFor();
    check(true, 'with the code, the same creator sees the project they claimed');

    // 9b. Code home: connect GitHub (stand-in), the organization is locked, then create the project's repositories.
    const panel = page.getByTestId('code-home-panel');
    await panel.getByRole('button', { name: 'Connect your code home' }).click();
    await page.getByTestId('install-link').waitFor();
    check(await panel.getByText('Create a free GitHub organization').isVisible(), 'the connection guide explains creating a free organization first');
    await shot(page, '18-code-home-connect');
    await page.getByTestId('install-link').click();
    await panel.getByText('Your code home is connected and locked.').waitFor();
    await panel.getByText('Members can see repositories:').waitFor(); // the settings come from the server a moment later
    check(await panel.getByText(ghOrg).first().isVisible(), `the dashboard shows the connected organization (${ghOrg})`);
    check(!page.url().includes('code_home='), 'the address bar is tidied after coming back from GitHub');
    const orgNow = gh.orgs.get(ghOrg)!.settings;
    check(orgNow.default_repository_permission === 'none' && orgNow.members_can_create_repositories === false, 'the organization on GitHub is really locked');
    check((await panel.locator('li').count()) === 5 && (await panel.locator('li svg.text-rose-400').count()) === 0, 'all 5 organization settings are shown as GitHub reported them, all applied');
    await shot(page, '19-code-home-connected');

    const uploadZipPath = path.join(shotsDir, 'existing-code.zip');
    const z = new JSZip();
    z.file('my-app/README.md', '# Uploaded in the browser check\n');
    z.file('my-app/main.py', 'print("hello")\n');
    fs.writeFileSync(uploadZipPath, await z.generateAsync({ type: 'nodebuffer' }));
    const card = page.getByTestId('repositories-card');
    await card.getByRole('checkbox').check();
    await card.getByTestId('zip-input').setInputFiles(uploadZipPath);
    await card.getByRole('button', { name: 'Create repositories' }).click();
    await card.getByTestId('repository-record').nth(1).waitFor();
    const rulesLines = await card.getByTestId('branch-rules').allInnerTexts();
    check(rulesLines.length === 2 && rulesLines.every((t) => t === 'Branch rules: needs GitHub Team, not active'), `on a free organization the dashboard says "Branch rules: needs GitHub Team, not active" (${rulesLines.join(' | ')})`);
    check(await card.getByText('First commit: 2 files').isVisible(), 'the uploaded code is the first commit, and GitHub reports it');
    const made = [...gh.repos.values()].filter((r) => r.org === ghOrg);
    check(made.length === 2 && made.every((r) => r.private && !r.allow_forking), 'two private, unforkable repositories really exist in the organization');
    await shot(page, '20-repositories-created');

    // Uninstalling the app on GitHub (a signed webhook) shows the connection as broken.
    const installationId = [...gh.installations.entries()].find(([, i]) => i.org === ghOrg)![0];
    const hookBody = Buffer.from(JSON.stringify({ action: 'deleted', installation: { id: installationId }, sender: { login: 'browser-owner' } }));
    const hook = await fetch(`${base}/api/v1/github/webhook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-GitHub-Event': 'installation', 'X-GitHub-Delivery': randomBytes(8).toString('hex'), 'X-Hub-Signature-256': signatureFor(webhookSecret, hookBody) },
      body: hookBody
    });
    check(hook.status === 200, 'the signed uninstall webhook is accepted');
    await page.reload({ waitUntil: 'networkidle' });
    await page.getByRole('heading', { name: 'Enter your authenticator code' }).or(page.getByTestId('code-home-broken')).first().waitFor();
    check(await page.getByTestId('code-home-broken').isVisible(), 'after uninstalling, the dashboard shows the connection as broken');
    await shot(page, '21-code-home-broken');

    // 10. The browser keeps no custody data; only the login session is stored.
    const keys = await page.evaluate(() => Object.keys(localStorage));
    check(keys.every((k) => k.startsWith('sb-')), `only the login session is stored in the browser (keys: ${keys.join(', ') || 'none'})`);

    // 11. Wrong-code limit: sign out, sign in again, enter 5 wrong codes. The screen says code entry is paused,
    //     and even the right code is refused.
    await page.getByRole('button', { name: 'Sign out' }).click();
    await page.getByRole('heading', { name: 'Sign in' }).waitFor();
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Password').fill(password);
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await page.getByRole('heading', { name: 'Enter your authenticator code' }).waitFor();
    expectedCodeStatuses = [422, 429];
    const before = expectedErrors.length;
    for (let i = 1; i <= 5; i++) {
      await page.getByLabel('6-digit code').fill(wrongCodeFor(secret));
      const answered = page.waitForResponse((r) => isCodeCheck(r.url()));
      await page.getByRole('button', { name: 'Verify' }).click();
      await answered;
    }
    check(/paused until/.test(await page.getByRole('alert').innerText()), 'after 5 wrong codes the screen says code entry is paused');
    await shot(page, '17-code-locked');
    const right = generateSync({ secret, epoch: Math.floor(Date.now() / 1000) + 30 });
    await page.getByLabel('6-digit code').fill(right);
    const lockedAnswer = page.waitForResponse((r) => isCodeCheck(r.url()));
    await page.getByRole('button', { name: 'Verify' }).click();
    check((await lockedAnswer).status() === 429, 'while paused, even the right code is refused (429)');
    check((await page.getByText('Browser Check Project').count()) === 0, 'while paused, no project data is shown');
    await page.reload({ waitUntil: 'networkidle' });
    await page.getByRole('heading', { name: 'Enter your authenticator code' }).waitFor();
    check(/paused until/.test(await page.getByRole('alert').innerText()), 'after reloading the page, the pause is still shown (it comes from the server)');
    expectedCodeStatuses = [];
    check(expectedErrors.length - before === 6, `the 4 wrong-code (422) and 2 locked (429) answers were the only errors (got ${expectedErrors.length - before})`);

    await context.close();
  } catch (err) {
    // Show what the page looked like when it went wrong, then fail as before.
    for (const ctx of browser.contexts()) {
      for (const p of ctx.pages()) {
        await p.screenshot({ path: path.join(shotsDir, 'crash.png'), fullPage: true }).catch(() => undefined);
        console.error('Page text at the crash:\n' + (await p.innerText('body').catch(() => '(unavailable)')));
      }
    }
    console.error('Server log:\n' + serverLog.slice(-3000));
    console.error('Console errors so far:', consoleErrors, 'Failed requests so far:', failedRequests);
    throw err;
  } finally {
    await browser.close();
    server.kill('SIGTERM');
    await gh.stop();
    await database.stop();
  }

  check(pageErrors.length === 0, `no uncaught page errors (${pageErrors.length})`);
  check(consoleErrors.length === 0, `no console errors (${consoleErrors.length})`);

  console.log('\n' + checks.join('\n'));
  console.log(`\nConsole errors: ${consoleErrors.length}`);
  for (const e of consoleErrors) console.log(`  - ${e}`);
  console.log(`Page errors: ${pageErrors.length}`);
  for (const e of pageErrors) console.log(`  - ${e}`);
  console.log(`Failed or error responses: ${failedRequests.length}`);
  for (const e of failedRequests) console.log(`  - ${e}`);
  console.log(`Screenshots: ${path.relative(root, shotsDir)}`);
  if (failures.length > 0) {
    console.log(`\n${failures.length} CHECK(S) FAILED`);
    process.exitCode = 1;
  } else {
    console.log('\nALL CHECKS PASSED');
  }
}

main().catch((err) => {
  console.error('browser-check crashed:', err);
  process.exit(1);
});
