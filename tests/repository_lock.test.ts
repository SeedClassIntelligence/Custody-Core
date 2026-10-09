import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { getAdminPool, getDbPool, runMigrations, insertEvent, verifyServerProjectEvents } from '../server/db';
import { forgetInstallationTokens } from '../server/github';
import { isIntactLock, LOCK_NAME } from '../server/repositoryLock';
import { assertPoolTargetsTestDb } from './support/safety';
import { startGitHubStandIn, StandIn } from './support/githubStandIn';
import { startHarness, Harness } from './support/apiHarness';

/**
 * Locking repositories on GitHub. GitHub is the local stand-in (tests/support/githubStandIn.ts): it keeps rulesets
 * and repository settings, refuses rulesets on private repositories without a paid plan, and refuses requests the
 * installation's permissions do not allow, as GitHub documents. Whether GitHub then really blocks a force push is
 * GitHub's to enforce; docs/GITHUB_APP_SETUP.md has the live check.
 */
describe('Repository lock (GitHub ruleset + forking off, read back before it counts)', () => {
  const db = getDbPool()!;
  let standIn: StandIn;
  let h: Harness;
  let creator: { id: string; userId: string; email: string };
  let other: { id: string; userId: string; email: string };
  let projectId = '';
  const ORG = `lockorg${Date.now()}`;
  const INSTALLATION = 6000 + Math.floor(Math.random() * 1000);
  const saved = { ...process.env };

  const actions = async () => (await db.query('SELECT action, payload FROM event WHERE project_id = $1 ORDER BY seq', [projectId])).rows;
  const repoRow = async (full: string) => (await db.query('SELECT * FROM repository WHERE project_id = $1 AND full_name = $2', [projectId, full])).rows[0];
  const appId = () => Number(standIn.env.GITHUB_APP_ID);

  beforeAll(async () => {
    await assertPoolTargetsTestDb(getAdminPool()!);
    expect((await runMigrations()).success).toBe(true);
    standIn = await startGitHubStandIn();
    Object.assign(process.env, standIn.env);
    forgetInstallationTokens();
    standIn.addInstallation(INSTALLATION, ORG, [`${ORG}/app`, `${ORG}/free`, `${ORG}/noperm`, `${ORG}/nofork`]);
    standIn.repoState(`${ORG}/free`).rulesets_allowed = false;
    h = await startHarness();
    creator = await h.newCreator('locker');
    other = await h.newCreator('stranger');
    await db.query(
      `INSERT INTO github_installation (creator_id, installation_id, account_login, account_type, connected_by_github_login) VALUES ($1, $2, $3, 'Organization', 'octo')`,
      [creator.id, INSTALLATION, ORG]
    );
    projectId = (await db.query(`INSERT INTO project (creator_id, name, purpose) VALUES ($1, 'Lock test', 'Testing locks') RETURNING id`, [creator.id])).rows[0].id;
    await insertEvent({ project_id: projectId, actor_type: 'creator', actor_id: creator.id, action: 'project.claimed', subject_type: 'project', subject_id: projectId, payload: {} });
  });

  afterAll(async () => {
    await h?.stop();
    await standIn?.stop();
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved);
  });

  it('locks a repository when it is added: ruleset on the default branch, only the App may bypass, forking off', async () => {
    const r = await h.api(creator, 'POST', `/projects/${projectId}/repositories`, { full_names: [`${ORG}/app`] });
    expect(r.status).toBe(201);
    const repo = r.body.repositories[0];
    expect(repo.locked_at).toBeTruthy();
    expect(repo.lock_error).toBeNull();

    const st = standIn.repoState(`${ORG}/app`);
    const rulesets = [...st.rulesets.values()];
    expect(rulesets).toHaveLength(1);
    expect(rulesets[0]).toMatchObject({
      name: LOCK_NAME,
      target: 'branch',
      enforcement: 'active',
      conditions: { ref_name: { include: ['~DEFAULT_BRANCH'], exclude: [] } },
      bypass_actors: [{ actor_id: appId(), actor_type: 'Integration', bypass_mode: 'always' }]
    });
    expect(rulesets[0].rules.map((x: any) => x.type).sort()).toEqual(['deletion', 'non_fast_forward']);
    expect(Number(repo.lock_ruleset_id)).toBe(rulesets[0].id);
    expect(st.allow_forking).toBe(false);

    const locked = (await actions()).find((e) => e.action === 'repository.locked');
    expect(locked.payload).toMatchObject({ full_name: `${ORG}/app`, ruleset_id: rulesets[0].id, allow_forking: false });
  });

  it('a check that finds the lock intact keeps its date and records the verification', async () => {
    const before = await repoRow(`${ORG}/app`);
    const r = await h.api(creator, 'POST', `/projects/${projectId}/repositories/${before.id}/lock`);
    expect(r.status).toBe(200);
    expect(new Date(r.body.repository.locked_at).getTime()).toBe(new Date(before.locked_at).getTime());
    expect((await actions()).at(-1).action).toBe('repository.lock_verified');
    expect(standIn.repoState(`${ORG}/app`).rulesets.size).toBe(1);
  });

  it('notices a lock weakened on GitHub, records it, and puts it back', async () => {
    const repo = await repoRow(`${ORG}/app`);
    const st = standIn.repoState(`${ORG}/app`);
    const ruleset = st.rulesets.get(Number(repo.lock_ruleset_id));
    ruleset.enforcement = 'disabled';
    ruleset.bypass_actors.push({ actor_id: 1, actor_type: 'OrganizationAdmin', bypass_mode: 'always' });
    expect(isIntactLock(ruleset, appId())).toBe(false);

    const r = await h.api(creator, 'POST', `/projects/${projectId}/repositories/${repo.id}/lock`);
    expect(r.body.repository.locked_at).toBeTruthy();
    const names = (await actions()).map((e) => e.action);
    expect(names.slice(-2)).toEqual(['repository.lock_missing', 'repository.locked']);
    expect((await actions()).at(-2).payload.found).toBe('ruleset changed on GitHub');
    expect(isIntactLock(st.rulesets.get(Number(repo.lock_ruleset_id)), appId())).toBe(true);
  });

  it('notices a lock deleted on GitHub, records it, and creates it again', async () => {
    const repo = await repoRow(`${ORG}/app`);
    const st = standIn.repoState(`${ORG}/app`);
    st.rulesets.clear();
    st.allow_forking = true;
    const r = await h.api(creator, 'POST', `/projects/${projectId}/repositories/${repo.id}/lock`);
    expect(r.body.repository.locked_at).toBeTruthy();
    expect(Number(r.body.repository.lock_ruleset_id)).not.toBe(Number(repo.lock_ruleset_id));
    expect((await actions()).at(-2)).toMatchObject({ action: 'repository.lock_missing', payload: { found: 'ruleset not found on GitHub' } });
    expect(st.rulesets.size).toBe(1);
    expect(st.allow_forking).toBe(false);
  });

  it('does not count a repository as locked when GitHub refuses (free plan), and says why', async () => {
    const r = await h.api(creator, 'POST', `/projects/${projectId}/repositories`, { full_names: [`${ORG}/free`] });
    expect(r.status).toBe(201);
    const repo = r.body.repositories[0];
    expect(repo.locked_at).toBeNull();
    expect(repo.lock_error).toMatch(/paid plan/);
    // Says plainly what still holds without the lock, and what the lock adds.
    expect(repo.lock_error).toMatch(/Developers you give a door still cannot reach this code on GitHub/);
    expect(repo.lock_error).toMatch(/extra layer against changes made directly on GitHub/);
    expect(standIn.repoState(`${ORG}/free`).rulesets.size).toBe(0);
    expect((await actions()).at(-1)).toMatchObject({ action: 'repository.lock_failed' });
  });

  it('says so when the App was not given the Administration permission', async () => {
    standIn.setInstallationPermissions(INSTALLATION, { contents: 'write', metadata: 'read' });
    forgetInstallationTokens();
    try {
      const r = await h.api(creator, 'POST', `/projects/${projectId}/repositories`, { full_names: [`${ORG}/noperm`] });
      expect(r.body.repositories[0].locked_at).toBeNull();
      expect(r.body.repositories[0].lock_error).toMatch(/Administration: Read and write/);
      // A repository that was locked and can no longer be checked is no longer counted as locked.
      const app = await repoRow(`${ORG}/app`);
      const check = await h.api(creator, 'POST', `/projects/${projectId}/repositories/${app.id}/lock`);
      expect(check.body.repository.locked_at).toBeNull();
      expect((await actions()).at(-1).action).toBe('repository.lock_failed');
    } finally {
      standIn.setInstallationPermissions(INSTALLATION, { contents: 'write', metadata: 'read', administration: 'write' });
      forgetInstallationTokens();
    }
    const app = await repoRow(`${ORG}/app`);
    expect((await h.api(creator, 'POST', `/projects/${projectId}/repositories/${app.id}/lock`)).body.repository.locked_at).toBeTruthy();
  });

  it('only the project owner can check a lock', async () => {
    const app = await repoRow(`${ORG}/app`);
    expect((await h.api(other, 'POST', `/projects/${projectId}/repositories/${app.id}/lock`)).status).toBe(404);
  });

  it('every lock event is in a record whose hashes verify', async () => {
    expect((await verifyServerProjectEvents(projectId)).isValid).toBe(true);
  });
});
