import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync, ChildProcess } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { getAdminPool, getDbPool, runMigrations, insertEvent, verifyServerProjectEvents } from '../server/db';
import { forgetInstallationTokens } from '../server/github';
import { closeOverdueDoors, takeDueSnapshots, checkDueLocks } from '../server/scheduler';
import { takeDoorSnapshot, MAX_SNAPSHOT_ATTEMPTS } from '../server/snapshots';
import { assertPoolTargetsTestDb } from './support/safety';
import { startGitHubStandIn, StandIn } from './support/githubStandIn';
import { startHarness, Harness } from './support/apiHarness';
import { acceptSignAndGetCredential } from './support/developerFlow';
import { freePort } from './support/dbProcess';

/**
 * The scheduler: doors close at their end date (also after the server was down), snapshots are taken (and retried)
 * when a door closes, and repository locks are re-checked. Real database, real git bundles, GitHub stand-in.
 */
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' };
const gitLocal = (args: string[], cwd?: string) => {
  const r = spawnSync('git', args, { cwd, env: GIT_ENV, encoding: 'utf8' });
  return { code: r.status ?? 1, out: `${r.stdout}${r.stderr}` };
};

describe('Scheduler: doors close at their end date, snapshots on close, locks re-checked', () => {
  const db = getDbPool()!;
  const admin = getAdminPool()!;
  let standIn: StandIn;
  let h: Harness;
  let creator: any;
  let other: any;
  let projectId = '';
  let repoId = '';
  const ORG = `schedorg${Date.now()}`;
  const REPO = `${ORG}/app`;
  const INSTALLATION = 8000 + Math.floor(Math.random() * 1000);
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-sched-'));
  const saved = { ...process.env };
  const api = (who: any, method: string, p: string, body?: unknown) => h.api(who, method, p, body);
  const events = async (doorId?: string) =>
    (await db.query(`SELECT action, actor_type, actor_id, payload FROM event WHERE project_id = $1 ${doorId ? 'AND subject_id = $2' : ''} ORDER BY seq`, doorId ? [projectId, doorId] : [projectId])).rows;

  /** A door in the given state: 'draft', 'awaiting_signature', or 'open' (invited, signed with a real key). */
  async function door(state: 'draft' | 'awaiting_signature' | 'open', devEmail?: string) {
    const email = devEmail ?? `dev_${crypto.randomBytes(4).toString('hex')}@example.com`;
    const created = await api(creator, 'POST', `/projects/${projectId}/doors`, {
      developer_email: email,
      job_description: 'Scheduled work',
      rights_type: 'contribute',
      expires_at: new Date(Date.now() + 86400_000).toISOString(),
      repositories: [{ repository_id: repoId, access: 'write' }]
    });
    const id = created.body.door.id as string;
    if (state === 'draft') return { id };
    const invited = await api(creator, 'POST', `/projects/${projectId}/doors/${id}/invite`);
    if (state === 'awaiting_signature') return { id, link: invited.body.invite.url };
    const dev = await h.newCreator('dev');
    dev.email = email;
    await db.query('UPDATE creator SET email = $2 WHERE id = $1', [dev.id, email]);
    const token = await acceptSignAndGetCredential(api, dev, invited.body.invite.url);
    return { id, token };
  }
  const expire = (id: string) => admin.query(`UPDATE door SET expires_at = now() - interval '5 minutes' WHERE id = $1`, [id]);

  beforeAll(async () => {
    await assertPoolTargetsTestDb(admin);
    expect((await runMigrations()).success).toBe(true);
    standIn = await startGitHubStandIn();
    Object.assign(process.env, standIn.env, { BACKUP_DIR: path.join(work, 'backups') });
    forgetInstallationTokens();
    standIn.addInstallation(INSTALLATION, ORG, [REPO, `${ORG}/free`]);
    standIn.createRepo(REPO);
    standIn.repoState(`${ORG}/free`).rulesets_allowed = false;
    h = await startHarness();
    creator = await h.newCreator('owner');
    other = await h.newCreator('stranger');
    await db.query(
      `INSERT INTO github_installation (creator_id, installation_id, account_login, account_type, connected_by_github_login) VALUES ($1, $2, $3, 'Organization', 'octo')`,
      [creator.id, INSTALLATION, ORG]
    );
    projectId = (await db.query(`INSERT INTO project (creator_id, name, purpose) VALUES ($1, 'Scheduler test', 'Testing') RETURNING id`, [creator.id])).rows[0].id;
    await insertEvent({ project_id: projectId, actor_type: 'creator', actor_id: creator.id, action: 'project.claimed', subject_type: 'project', subject_id: projectId, payload: {} });
    const added = await api(creator, 'POST', `/projects/${projectId}/repositories`, { full_names: [REPO] });
    repoId = added.body.repositories[0].id;
  });

  afterAll(async () => {
    await h?.stop();
    await standIn?.stop();
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved);
    fs.rmSync(work, { recursive: true, force: true });
  });

  it('closes every door past its end date, whatever its state, as the scheduler, and only those', async () => {
    const draft = await door('draft');
    const waiting = await door('awaiting_signature');
    const open = await door('open');
    const notYet = await door('draft');
    for (const d of [draft, waiting, open]) await expire(d.id);

    const closed = await closeOverdueDoors(db);
    for (const d of [draft, waiting, open]) expect(closed).toContain(d.id);
    expect(closed).not.toContain(notYet.id);

    const rows = (await db.query('SELECT id, status, closed_reason, snapshot_status FROM door WHERE id = ANY($1::uuid[])', [[draft.id, waiting.id, open.id]])).rows;
    for (const r of rows) expect(r).toMatchObject({ status: 'closed', closed_reason: 'expired' });
    // Only a door that was open can hold work: only it gets a snapshot.
    expect(rows.find((r) => r.id === open.id).snapshot_status).toBe('pending');
    expect(rows.find((r) => r.id === draft.id).snapshot_status).toBeNull();

    const openEvents = await events(open.id);
    expect(openEvents.slice(-2).map((e) => e.action)).toEqual(['credential.revoked', 'door.closed']);
    expect(openEvents.at(-1)).toMatchObject({ actor_type: 'system', actor_id: 'scheduler', payload: { reason: 'expired', snapshot_due: true } });
    expect(openEvents.at(-1).payload.closed_seconds_after_end_date).toBeGreaterThanOrEqual(299);
    // The waiting door's link no longer works.
    const invitee = await h.newCreator('late');
    expect((await api(invitee, 'GET', `/developer/invites/${new URL(waiting.link!).searchParams.get('invite')}`)).status).not.toBe(200);
    expect(await closeOverdueDoors(db)).toEqual([]);
  });

  it('two schedulers running at once close each door exactly once', async () => {
    const a = await door('draft');
    const b = await door('draft');
    await expire(a.id);
    await expire(b.id);
    const [x, y] = await Promise.all([closeOverdueDoors(db), closeOverdueDoors(db)]);
    expect([...x, ...y].sort()).toEqual([a.id, b.id].sort());
    for (const id of [a.id, b.id]) expect((await events(id)).filter((e) => e.action === 'door.closed')).toHaveLength(1);
  });

  it('after the server was down past a door\'s end date, the next start closes it before serving, then snapshots it', async () => {
    const d = await door('open');
    // The developer's work, as pushed through the gateway, is on GitHub.
    const clone = path.join(work, 'dev-clone');
    expect(gitLocal(['clone', '--quiet', standIn.upstreamDir(REPO), clone]).code).toBe(0);
    fs.writeFileSync(path.join(clone, 'feature.txt'), 'door work\n');
    gitLocal(['add', '.'], clone);
    gitLocal(['-c', 'user.name=Dev', '-c', 'user.email=dev@example.com', 'commit', '--quiet', '-m', 'Door work'], clone);
    const workSha = gitLocal(['rev-parse', 'HEAD'], clone).out.trim();
    expect(gitLocal(['push', '--quiet', standIn.upstreamDir(REPO), `HEAD:refs/heads/door/${d.id}/feature`], clone).code).toBe(0);

    await expire(d.id); // the end date passed while no server was running

    const port = await freePort();
    const child: ChildProcess = spawn(process.execPath, ['--import', 'tsx', 'server.ts'], {
      cwd: root,
      env: {
        ...process.env,
        NODE_ENV: 'production',
        VITEST: '',
        PORT: String(port),
        HOST: '127.0.0.1',
        DATABASE_URL: process.env.TEST_DATABASE_URL,
        ADMIN_DATABASE_URL: '',
        APP_DATABASE_URL: ''
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let log = '';
    child.stdout!.on('data', (c) => (log += c));
    child.stderr!.on('data', (c) => (log += c));
    try {
      for (let i = 0; i < 120 && !log.includes('Custody Core server running'); i++) await new Promise((r) => setTimeout(r, 250));
      expect(log, log).toContain('Custody Core server running');
      // Closed before the server listened.
      expect(log.indexOf('closed 1 door(s) that passed their end date')).toBeGreaterThan(-1);
      expect(log.indexOf('closed 1 door(s)')).toBeLessThan(log.indexOf('Custody Core server running'));
      expect((await db.query('SELECT status, closed_reason FROM door WHERE id = $1', [d.id])).rows[0]).toEqual({ status: 'closed', closed_reason: 'expired' });

      let snap: any;
      for (let i = 0; i < 80; i++) {
        snap = (await db.query('SELECT snapshot_status, snapshot_error FROM door WHERE id = $1', [d.id])).rows[0];
        if (snap.snapshot_status !== 'pending') break;
        await new Promise((r) => setTimeout(r, 250));
      }
      expect(snap, log).toMatchObject({ snapshot_status: 'done' });
      const health = await (await fetch(`http://127.0.0.1:${port}/api/v1/health`)).json();
      expect(health.scheduler.ok).toBe(true);
    } finally {
      child.kill('SIGTERM');
    }

    // The bundle restores with plain git and holds the door's work, with the SHA-256 recorded.
    const s = (await db.query('SELECT * FROM mirror_snapshot WHERE door_id = $1', [d.id])).rows[0];
    expect(s.refs[`refs/heads/door/${d.id}/feature`]).toBe(workSha);
    expect(Object.keys(s.refs)).toContain('refs/heads/main');
    const file = path.join(work, 'backups', ...s.storage_uri.replace('backup-dir:', '').split('/'));
    expect(crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')).toBe(s.sha256);
    const restored = path.join(work, 'restored');
    expect(gitLocal(['clone', '--quiet', file, restored]).code).toBe(0);
    expect(gitLocal(['checkout', '--quiet', `door/${d.id}/feature`], restored).code).toBe(0);
    expect(fs.readFileSync(path.join(restored, 'feature.txt'), 'utf8')).toBe('door work\n');
    const written = (await events(d.id)).find((e) => e.action === 'mirror.written');
    expect(written.payload.snapshots[0]).toMatchObject({ repository: REPO, sha256: s.sha256 });
  });

  it('the creator downloads a snapshot, and its SHA-256 matches the record; nobody else can', async () => {
    const s = (await db.query(`SELECT id, sha256 FROM mirror_snapshot WHERE door_id IS NOT NULL ORDER BY created_at DESC LIMIT 1`)).rows[0];
    const list = await api(creator, 'GET', `/projects/${projectId}/snapshots`);
    expect(list.body.snapshots.map((x: any) => x.id)).toContain(s.id);
    const res = await fetch(`${h.base}/api/v1/projects/${projectId}/snapshots/${s.id}/bundle`, { headers: { 'x-test-creator': creator.id } });
    expect(res.status).toBe(200);
    const body = Buffer.from(await res.arrayBuffer());
    expect(crypto.createHash('sha256').update(body).digest('hex')).toBe(s.sha256);
    expect(res.headers.get('x-snapshot-sha256')).toBe(s.sha256);
    expect((await fetch(`${h.base}/api/v1/projects/${projectId}/snapshots/${s.id}/bundle`, { headers: { 'x-test-creator': other.id } })).status).toBe(404);
    await expect(admin.query('UPDATE mirror_snapshot SET sha256 = $2 WHERE id = $1', [s.id, 'f'.repeat(64)])).rejects.toThrow(/cannot be changed/);
  });

  it('a snapshot that cannot be taken is retried later, recorded once, and given up after the last attempt', async () => {
    const d = await door('open');
    const close = await api(creator, 'POST', `/projects/${projectId}/doors/${d.id}/close`);
    expect(close.status).toBe(200);
    // GitHub refuses the token (the installation lost access to the repository).
    standIn.addInstallation(INSTALLATION, ORG, [`${ORG}/free`]);
    forgetInstallationTokens();
    try {
      await admin.query(`UPDATE door SET snapshot_next_attempt_at = now() WHERE id = $1`, [d.id]);
      expect(await takeDoorSnapshot(db, d.id)).toBe('retry');
      const row = (await db.query('SELECT snapshot_status, snapshot_attempts, snapshot_error, snapshot_next_attempt_at > now() AS later FROM door WHERE id = $1', [d.id])).rows[0];
      expect(row).toMatchObject({ snapshot_status: 'pending', snapshot_attempts: 1, later: true });
      expect(row.snapshot_error).toBeTruthy();
      expect(await takeDoorSnapshot(db, d.id)).toBe('skipped'); // not due yet

      await admin.query(`UPDATE door SET snapshot_next_attempt_at = now(), snapshot_attempts = $2 WHERE id = $1`, [d.id, MAX_SNAPSHOT_ATTEMPTS - 1]);
      expect(await takeDoorSnapshot(db, d.id)).toBe('failed');
      const names = (await events(d.id)).map((e) => e.action);
      expect(names.filter((n) => n === 'mirror.delayed')).toHaveLength(1);
      expect(names.at(-1)).toBe('mirror.failed');
    } finally {
      standIn.addInstallation(INSTALLATION, ORG, [REPO, `${ORG}/free`]);
      forgetInstallationTokens();
    }

    // With GitHub back, a pending snapshot succeeds.
    const d2 = await door('open');
    await api(creator, 'POST', `/projects/${projectId}/doors/${d2.id}/close`);
    expect(await takeDueSnapshots(db)).toBeGreaterThanOrEqual(1);
    expect((await db.query('SELECT snapshot_status FROM door WHERE id = $1', [d2.id])).rows[0].snapshot_status).toBe('done');
  });

  it('re-checks locks on schedule: puts back a removed lock (recorded), stays quiet when nothing changed', async () => {
    const before = (await events()).length;
    await admin.query(`UPDATE repository SET lock_checked_at = now() - interval '7 hours' WHERE id = $1`, [repoId]);
    expect(await checkDueLocks(db)).toBe(1);
    expect((await events()).length).toBe(before); // intact: only lock_checked_at moved
    expect((await db.query('SELECT lock_checked_at > now() - interval \'1 minute\' AS fresh FROM repository WHERE id = $1', [repoId])).rows[0].fresh).toBe(true);
    expect(await checkDueLocks(db)).toBe(0); // checked recently

    standIn.repoState(REPO).rulesets.clear();
    await admin.query(`UPDATE repository SET lock_checked_at = now() - interval '7 hours' WHERE id = $1`, [repoId]);
    expect(await checkDueLocks(db)).toBe(1);
    const last = (await events()).slice(-2);
    expect(last.map((e) => e.action)).toEqual(['repository.lock_missing', 'repository.locked']);
    expect(last[0]).toMatchObject({ actor_type: 'system', actor_id: 'scheduler' });
    expect(standIn.repoState(REPO).rulesets.size).toBe(1);
  });

  it('a repository GitHub keeps refusing to lock (free plan) is recorded once, not every check', async () => {
    const added = await api(creator, 'POST', `/projects/${projectId}/repositories`, { full_names: [`${ORG}/free`] });
    const freeId = added.body.repositories[0].id;
    const count = async () => (await db.query(`SELECT count(*)::int AS n FROM event WHERE subject_id = $1 AND action = 'repository.lock_failed'`, [freeId])).rows[0].n;
    expect(await count()).toBe(1);
    for (let i = 0; i < 2; i++) {
      await admin.query(`UPDATE repository SET lock_checked_at = now() - interval '7 hours' WHERE id = $1`, [freeId]);
      await checkDueLocks(db);
    }
    expect(await count()).toBe(1);
  });

  it('every scheduled change is in a record whose hashes verify', async () => {
    expect((await verifyServerProjectEvents(projectId)).isValid).toBe(true);
  });
});
