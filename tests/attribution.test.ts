import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import { getAdminPool, getDbPool, runMigrations, verifyServerProjectEvents } from '../server/db';
import { addPrincipalKey, registerPrincipal } from '../server/servicePrincipals';
import { authorFor } from '../server/gateway/sessionRouter';
import { assertPoolTargetsTestDb } from './support/safety';
import { startHarness, Harness } from './support/apiHarness';
import { startApp, RunningApp } from './support/api';
import { installGitleaks } from '../scripts/install-gitleaks';
import { assertion, newKey, TestKey } from './support/principalKeys';

/**
 * Contribution attribution (CL-13): who authored, who committed and who answers for each commit a session pushed, derived by the
 * database from the session, so a pushed commit's own claims (including one that names the creator) can never become the author.
 */
describe('Contribution attribution', () => {
  const db = getDbPool()!;
  const admin = getAdminPool()!;
  let h: Harness;
  let app: RunningApp;
  let creator: any, other: any;
  let projectId = '', repoId = '', otherProjectId = '';
  interface Caller { id: string; keyId: string; key: TestKey }
  async function caller(label: string, scopes: string[], who = creator): Promise<Caller> {
    const p = await registerPrincipal(db, who.id, { name: `${label}-${crypto.randomUUID().slice(0, 6)}`, platform_type: 'agent', environment: 'development', allowed_scopes: scopes } as any, 'test');
    const key = newKey('Ed25519');
    return { id: p.id, keyId: (await addPrincipalKey(db, p.id, key.publicJwk, 'test')).key_id, key };
  }
  const v2 = async (c: Caller, p: string) => {
    const res = await fetch(`${app.base}/api/v2${p}`, { headers: { Authorization: `Bearer ${assertion(c.key, c.keyId, c.id)}` } });
    return { status: res.status, body: (await res.json().catch(() => ({}))) as any };
  };
  let requester: Caller, approver: Caller, stranger: Caller, second: Caller;
  const commitId = () => crypto.randomBytes(20).toString('hex');

  async function session(who: Caller, executor: Record<string, unknown>) {
    const res = await fetch(`${app.base}/api/v2/work-sessions`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${assertion(who.key, who.keyId, who.id)}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: projectId, repository_id: repoId, executor, sponsor: { type: 'creator', id: creator.id }, objective: 'Add the export page', base_commit: 'a'.repeat(40),
        access: { repository: 'read_and_push', allowed_read_paths: ['src/**'], allowed_write_paths: ['src/lib/**'], prohibited_paths: [] }
      })
    });
    const id = ((await res.json()) as any).session_id as string;
    expect((await h.api(creator, 'POST', `/projects/${projectId}/work-sessions/${id}/approve`, {})).status).toBe(200);
    await admin.query(`UPDATE work_session SET status = 'active' WHERE id = $1`, [id]);
    return id;
  }
  /** What the gateway does when a push is accepted: records the commit. The database derives the attribution from it. */
  async function push(id: string, declared: string) {
    const real = commitId();
    await db.query(`INSERT INTO session_commit (work_session_id, view_sha, real_sha, parent_view_sha, declared_author) VALUES ($1, $2, $3, $4, $5)`, [id, commitId(), real, commitId(), declared]);
    return real;
  }

  beforeAll(async () => {
    await assertPoolTargetsTestDb(admin);
    expect((await runMigrations()).success).toBe(true);
    await installGitleaks();
    h = await startHarness();
    app = await startApp();
    creator = await h.newCreator('owner');
    other = await h.newCreator('other');
    projectId = (await db.query(`INSERT INTO project (creator_id, name, purpose) VALUES ($1, 'P', 'x') RETURNING id`, [creator.id])).rows[0].id;
    otherProjectId = (await db.query(`INSERT INTO project (creator_id, name, purpose) VALUES ($1, 'Q', 'x') RETURNING id`, [other.id])).rows[0].id;
    repoId = (await db.query(`INSERT INTO repository (project_id, github_repo_id, full_name) VALUES ($1, '1', 'org/app') RETURNING id`, [projectId])).rows[0].id;
    requester = await caller('requester', ['work-sessions:request', 'work-sessions:read']);
    second = await caller('second', ['work-sessions:request', 'work-sessions:read']);
    approver = await caller('approver', ['work-sessions:approve', 'work-sessions:read']);
    stranger = await caller('stranger', ['work-sessions:read']);
  }, 120_000);
  afterAll(async () => {
    await app?.stop();
    await h?.stop();
  });

  const EXEC = { type: 'ai_assistant', provider: 'example-ai', model: 'model-1', external_id: 'agent_99', display_name: 'Refactor Engine' };

  it('is recorded for every commit, with the executor as author, the gateway as committer and the creator as sponsor', async () => {
    const id = await session(requester, EXEC);
    const a = await push(id, 'Refactor Engine <engine@example.com>');
    const b = await push(id, 'Someone Else <else@example.com>');
    const r = await v2(requester, `/work-sessions/${id}/attribution`);
    expect(r.status).toBe(200);
    expect(r.body.contributions).toHaveLength(2);
    const first = r.body.contributions.find((c: any) => c.commit === a);
    expect(first).toMatchObject({
      commit: a,
      author: { kind: 'executor', principal_id: requester.id, executor: { type: 'ai_assistant', provider: 'example-ai', model: 'model-1', external_id: 'agent_99', display_name: 'Refactor Engine' } },
      committer: { kind: 'gateway' },
      sponsor: { kind: 'creator', id: creator.id }
    });
    expect(first.author.as_written_in_git).toEqual(authorFor({ id, executor_type: 'ai_assistant', executor_provider: 'example-ai', executor_model: 'model-1', executor_external_id: 'agent_99', executor_display_name: 'Refactor Engine' }));
    expect(r.body.contributions.map((c: any) => c.commit).sort()).toEqual([a, b].sort());
  });

  it('a commit that claims to be by the creator (or anyone) is still attributed to the executor; the claim is kept as untrusted evidence', async () => {
    const id = await session(requester, EXEC);
    const claim = `Alice Creator <${creator.email}>`;
    const sha = await push(id, claim);
    const c = (await v2(requester, `/work-sessions/${id}/attribution`)).body.contributions.find((x: any) => x.commit === sha);
    expect(c.declared_author).toEqual({ value: claim, trusted: false });
    expect(c.author.principal_id).toBe(requester.id);
    expect(c.author.kind).toBe('executor');
    expect(JSON.stringify(c.author)).not.toContain(creator.email);
    // the creator appears only as the sponsor, who answers for the session, never as its author
    expect(c.sponsor.id).toBe(creator.id);
  });

  it('two sessions by different principals keep their own authors', async () => {
    const a = await session(requester, EXEC);
    const b = await session(second, { type: 'ci_runtime', display_name: 'Pipeline Bot' });
    await push(a, 'x'); await push(b, 'x');
    const ra = (await v2(requester, `/work-sessions/${a}/attribution`)).body.contributions[0];
    const rb = (await v2(second, `/work-sessions/${b}/attribution`)).body.contributions[0];
    expect([ra.author.principal_id, rb.author.principal_id]).toEqual([requester.id, second.id]);
    expect(rb.author.executor).toMatchObject({ type: 'ci_runtime', display_name: 'Pipeline Bot' });
  });

  it('the database refuses an attribution that names anyone but the session\'s own author and sponsor, and refuses to change or delete one', async () => {
    const id = await session(requester, EXEC);
    await push(id, 'x');
    const row = (await admin.query(`SELECT * FROM contribution_attribution WHERE work_session_id = $1`, [id])).rows[0];
    const insert = (over: Record<string, unknown>) => {
      const r = { ...row, real_sha: commitId(), view_sha: commitId(), id: crypto.randomUUID(), ...over };
      return db.query(
        `INSERT INTO contribution_attribution (id, work_session_id, project_id, repository_id, real_sha, view_sha, author_principal_id, author_executor_type, author_executor_provider, author_executor_model,
                                               author_executor_external_id, author_executor_display_name, sponsor_id, declared_author)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
        [r.id, r.work_session_id, r.project_id, r.repository_id, r.real_sha, r.view_sha, r.author_principal_id, r.author_executor_type, r.author_executor_provider, r.author_executor_model, r.author_executor_external_id, r.author_executor_display_name, r.sponsor_id, r.declared_author]
      );
    };
    await expect(insert({ author_principal_id: second.id })).rejects.toThrow(/must be those of the session/);
    await expect(insert({ sponsor_id: other.id })).rejects.toThrow(/must be those of the session/);
    await expect(insert({ author_executor_display_name: 'The Creator' })).rejects.toThrow(/must be those of the session/);
    await insert({}); // the honest one is accepted
    await expect(db.query(`UPDATE contribution_attribution SET declared_author = 'x' WHERE work_session_id = $1`, [id])).rejects.toThrow();
    await expect(db.query(`DELETE FROM contribution_attribution WHERE work_session_id = $1`, [id])).rejects.toThrow();
    await expect(admin.query(`UPDATE contribution_attribution SET sponsor_id = $2 WHERE work_session_id = $1`, [id, other.id])).rejects.toThrow(/written once/);
  });

  it('human doors have none (only automated sessions have authors in this sense)', async () => {
    expect((await db.query(`SELECT count(*)::int AS n FROM contribution_attribution c JOIN work_session s ON s.id = c.work_session_id WHERE s.session_type <> 'automated_work_session'`)).rows[0].n).toBe(0);
  });

  it('is readable by the requester, an approving principal and the owner; nobody else', async () => {
    const id = await session(requester, EXEC);
    await push(id, 'x');
    expect((await v2(requester, `/work-sessions/${id}/attribution`)).status).toBe(200);
    expect((await v2(approver, `/work-sessions/${id}/attribution`)).status).toBe(200);
    expect((await v2(stranger, `/work-sessions/${id}/attribution`)).status).toBe(404);
    expect((await v2(second, `/work-sessions/${id}/attribution`)).status).toBe(404);
    expect((await v2(requester, `/work-sessions/${crypto.randomUUID()}/attribution`)).status).toBe(404);
    const owner = await h.api(creator, 'GET', `/projects/${projectId}/work-sessions/${id}/attribution`);
    expect(owner.status).toBe(200);
    expect(owner.body.contributions).toHaveLength(1);
    expect((await h.api(other, 'GET', `/projects/${projectId}/work-sessions/${id}/attribution`)).status).toBe(404);
    expect((await h.api(other, 'GET', `/projects/${otherProjectId}/work-sessions/${id}/attribution`)).status).toBe(404);
  });

  it('the project\'s record still verifies', async () => {
    const check = await verifyServerProjectEvents(projectId);
    expect(check.isValid, check.reason).toBe(true);
  });
});
