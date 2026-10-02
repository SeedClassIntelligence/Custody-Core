import type { NextFunction, Request, Response } from 'express';
import type pg from 'pg';
import { appendAccountEvent, getDbPool, insertEvent } from '../db';
import { creatorOf } from '../auth';
import { appJwt, gh, githubConfig, GitHubConfig, GitHubError, GitHubNotConfigured, withInstallationToken } from './app';
import {
  BadUpload,
  createLockedRepository,
  finishRepository,
  prepareInitialCommit,
  PreparedCommit,
  readZip,
  repositoryName,
  RepositoryResult
} from './repositories';

/**
 * POST /api/v1/projects/:id/code-home
 *   application/json  { "split_core": true|false }             empty repositories
 *   application/zip   (body = the zip)  ?split_core=1|0         existing code as the first commit of the main repository
 *
 * POST /api/v1/projects/:id/repositories/:repoId/lock
 *   application/json  {}                                        apply whatever part of the lock is missing, read it back
 *   application/zip   (body = the zip)                          also push code to a main repository that is still empty
 *
 * Creates the project's private repositories in the creator's connected organization, locks them, and records
 * one event per repository with what GitHub reported. A setting GitHub refused is recorded as not applied.
 * Every event is recorded with the creator who asked as its actor; the GitHub App only carries it out.
 */

interface CodeHome {
  installationId: number;
  org: string;
}

/**
 * Before acting on GitHub, ask GitHub (not our own record) whether the installation is still there and not
 * suspended, follow a renamed organization, and check that the GitHub user who connected it is still an owner.
 * Answers with an error and returns null when the creator may not act.
 */
async function codeHomeFor(config: GitHubConfig, db: pg.Pool, res: Response): Promise<CodeHome | null> {
  const creator = creatorOf(res);
  const row = (
    await db.query(`SELECT id, installation_id, account_login, owner_login, status FROM github_installation WHERE creator_id = $1 AND status <> 'removed'`, [
      creator.id
    ])
  ).rows[0];
  if (!row) {
    res.status(409).json({ error: 'Connect your code home first.' });
    return null;
  }
  const installationId = Number(row.installation_id);
  let inst: any;
  try {
    inst = await gh(config, { kind: 'app', token: appJwt(config) }, 'GET', `/app/installations/${installationId}`);
  } catch (err) {
    if (err instanceof GitHubError && err.status === 404) {
      await db.query(`UPDATE github_installation SET status = 'removed', status_changed_at = now() WHERE id = $1 AND status <> 'removed'`, [row.id]);
      await appendAccountEvent(creator.userId, 'system', 'github-app', 'github.connection_broken', {
        installation_id: installationId,
        organization: row.account_login,
        reason: 'GitHub reports the app is no longer installed',
        by: null
      });
      res.status(409).json({ error: 'Your code home connection is broken: the app is no longer installed on GitHub.' });
      return null;
    }
    throw err;
  }
  if (inst.suspended_at) {
    res.status(409).json({ error: 'Your code home connection is not working: the app is suspended on GitHub.' });
    return null;
  }
  let org: string = row.account_login;
  if (typeof inst.account?.login === 'string' && inst.account.login !== org) {
    await db.query('UPDATE github_installation SET account_login = $2 WHERE id = $1', [row.id, inst.account.login]);
    await appendAccountEvent(creator.userId, 'system', 'github-app', 'github.organization_renamed', {
      installation_id: installationId,
      from: org,
      to: inst.account.login
    });
    org = inst.account.login;
  }
  if (row.owner_login) {
    const membership = await withInstallationToken(config, installationId, { permissions: { members: 'read' } }, (token) =>
      gh(config, { kind: 'token', token }, 'GET', `/orgs/${encodeURIComponent(org)}/memberships/${encodeURIComponent(row.owner_login)}`).catch((err) => {
        if (err instanceof GitHubError && err.status === 404) return null;
        throw err;
      })
    );
    if (membership?.state !== 'active' || membership?.role !== 'admin') {
      res.status(403).json({ error: `The GitHub account that connected this code home (${row.owner_login}) is no longer an owner of ${org}.` });
      return null;
    }
  }
  return { installationId, org };
}

function describe(err: any) {
  // GitHub's own words, including its detailed reasons (for example "name already exists on this account").
  const details = err instanceof GitHubError && Array.isArray(err.body?.errors) ? err.body.errors.map((e: any) => e?.message).filter((m: any) => typeof m === 'string') : [];
  return err instanceof GitHubError
    ? { status: err.status, message: String(err.body?.message ?? err.message), ...(details.length ? { details } : {}) }
    : { status: null, message: String(err?.message ?? err).slice(0, 500) };
}

/** Locked only if GitHub confirmed every setting, the branch rules, and (with an upload) the exact commit. */
function isFullyLocked(result: RepositoryResult): boolean {
  return (
    !result.incomplete &&
    result.settings.length > 0 &&
    result.settings.every((s) => s.applied) &&
    result.ruleset.applied &&
    (!result.initial_commit || result.initial_commit.matches)
  );
}

function configOr503(res: Response): GitHubConfig | null {
  try {
    return githubConfig();
  } catch (err) {
    if (err instanceof GitHubNotConfigured) {
      res.status(503).json({ error: err.message });
      return null;
    }
    throw err;
  }
}

export async function createCodeHome(req: Request, res: Response, next: NextFunction) {
  const config = configOr503(res);
  if (!config) return;
  const db = getDbPool();
  if (!db) return res.status(503).json({ error: 'Database not connected.' });
  const creator = creatorOf(res);
  const projectId = req.params.id;

  const isZip = Buffer.isBuffer(req.body);
  const splitCore = isZip ? req.query.split_core === '1' : req.body?.split_core === true;
  if (!isZip && req.body?.split_core !== undefined && typeof req.body.split_core !== 'boolean') {
    return res.status(400).json({ error: 'split_core must be true or false.' });
  }

  let client: pg.PoolClient | null = null;
  let locked = false;
  let prepared: PreparedCommit | null = null;
  try {
    const project = (await db.query('SELECT id, name, purpose FROM project WHERE id = $1 AND creator_id = $2', [projectId, creator.id])).rows[0];
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    let files: Awaited<ReturnType<typeof readZip>> | null = null;
    if (isZip) {
      try {
        files = await readZip(req.body);
      } catch (err) {
        if (err instanceof BadUpload) return res.status(400).json({ error: err.message });
        throw err;
      }
    }

    client = await db.connect();
    // One code-home creation per project at a time.
    await client.query('SELECT pg_advisory_lock(hashtextextended($1, 0))', [`code_home:${projectId}`]);
    locked = true;
    const base = repositoryName(project.name);
    const wanted: Array<{ name: string; role: 'main' | 'core' }> = [{ name: base, role: 'main' }];
    if (splitCore) wanted.push({ name: `${base}-core`, role: 'core' });
    // A claim that stopped half way (for example the core repository failed) can be finished: only what is
    // missing is created.
    const existingRoles = new Set(
      (await client.query('SELECT is_core FROM repository WHERE project_id = $1', [projectId])).rows.map((r) => (r.is_core ? 'core' : 'main'))
    );
    const missing = wanted.filter((w) => !existingRoles.has(w.role));
    if (missing.length === 0) return res.status(409).json({ error: 'This project already has its repositories.' });
    if (files && existingRoles.has('main')) {
      return res.status(400).json({ error: 'Existing code can only be added when the main repository is created; it already exists.' });
    }

    // The first commit is made locally before anything is created on GitHub, so a problem with the files
    // (a name git refuses, an object GitHub would reject) is found while nothing exists yet.
    if (files) {
      try {
        prepared = await prepareInitialCommit(files, 'main');
      } catch (err) {
        if (err instanceof BadUpload) return res.status(400).json({ error: err.message });
        throw err;
      }
    }

    const home = await codeHomeFor(config, db, res);
    if (!home) return;

    const results: RepositoryResult[] = [];
    for (const want of missing) {
      let result: RepositoryResult;
      try {
        result = await createLockedRepository(
          config,
          home.installationId,
          home.org,
          want.name,
          want.role,
          want.role === 'core' ? `${project.name} (core)` : project.name,
          want.role === 'main' ? prepared : null,
          want.role === 'main' && files ? files.length : 0,
          projectId
        );
      } catch (err: any) {
        const failure = describe(err);
        await insertEvent({
          project_id: projectId,
          actor_type: 'creator',
          actor_id: creator.id,
          action: 'repository.creation_failed',
          subject_type: 'project',
          subject_id: projectId,
          payload: { organization: home.org, name: want.name, role: want.role, performed_by: 'github-app', error: failure }
        });
        console.error('[github] creating a repository failed:', failure.status, failure.message);
        const why = 'details' in failure && failure.details ? `${failure.message} (${failure.details.join('; ')})` : failure.message;
        return res.status(502).json({ error: `GitHub did not create ${want.name}: ${why}`, repositories: results });
      }

      const fullyLocked = isFullyLocked(result);
      await client.query('BEGIN');
      const row = (
        await client.query(
          `INSERT INTO repository (project_id, github_repo_id, full_name, default_branch, is_core, installation_id, locked_at)
           VALUES ($1, $2, $3, $4, $5, $6, CASE WHEN $7 THEN now() END) RETURNING id`,
          [projectId, String(result.github_repo_id), result.full_name, result.default_branch, result.role === 'core', home.installationId, fullyLocked]
        )
      ).rows[0];
      await insertEvent(
        {
          project_id: projectId,
          actor_type: 'creator',
          actor_id: creator.id,
          action: 'repository.created',
          subject_type: 'repository',
          subject_id: row.id,
          payload: { ...result, organization: home.org, performed_by: 'github-app', fully_locked: fullyLocked }
        },
        client
      );
      await client.query('COMMIT');
      results.push(result);
    }
    res.status(201).json({ repositories: results });
  } catch (err: any) {
    await client?.query('ROLLBACK').catch(() => undefined);
    next(err);
  } finally {
    prepared?.cleanup();
    if (client) {
      if (locked) await client.query('SELECT pg_advisory_unlock(hashtextextended($1, 0))', [`code_home:${projectId}`]).catch(() => undefined);
      client.release();
    }
  }
}

/**
 * Finishes an existing repository's lock: re-applies forking off and the branch rules where they are missing,
 * reads everything back, and (with a zip) pushes code to a main repository that GitHub reports as still empty.
 */
export async function relockRepository(req: Request, res: Response, next: NextFunction) {
  const config = configOr503(res);
  if (!config) return;
  const db = getDbPool();
  if (!db) return res.status(503).json({ error: 'Database not connected.' });
  const creator = creatorOf(res);
  const { id: projectId, repoId } = req.params;
  const isZip = Buffer.isBuffer(req.body);

  let prepared: PreparedCommit | null = null;
  let client: pg.PoolClient | null = null;
  let locked = false;
  try {
    const repo = (
      await db.query(
        `SELECT r.id, r.full_name, r.is_core, r.default_branch, r.github_repo_id FROM repository r JOIN project p ON p.id = r.project_id
          WHERE r.id = $1 AND r.project_id = $2 AND p.creator_id = $3`,
        [repoId, projectId, creator.id]
      )
    ).rows[0];
    if (!repo) return res.status(404).json({ error: 'Repository not found.' });

    let files: Awaited<ReturnType<typeof readZip>> | null = null;
    if (isZip) {
      if (repo.is_core) return res.status(400).json({ error: 'Existing code goes into the main repository.' });
      try {
        files = await readZip(req.body);
        prepared = await prepareInitialCommit(files, repo.default_branch || 'main');
      } catch (err) {
        if (err instanceof BadUpload) return res.status(400).json({ error: err.message });
        throw err;
      }
    }

    client = await db.connect();
    await client.query('SELECT pg_advisory_lock(hashtextextended($1, 0))', [`code_home:${projectId}`]);
    locked = true;

    const home = await codeHomeFor(config, db, res);
    if (!home) return;

    // Where the repository is now, according to GitHub (it may have been renamed).
    const now = await withInstallationToken(config, home.installationId, { permissions: { metadata: 'read' } }, (token) =>
      gh(config, { kind: 'token', token }, 'GET', `/repositories/${Number(repo.github_repo_id)}`).catch((err) => {
        if (err instanceof GitHubError && err.status === 404) return null;
        throw err;
      })
    );
    if (!now) return res.status(409).json({ error: 'GitHub reports this repository no longer exists.' });
    if (prepared && Number(now.size) !== 0) return res.status(409).json({ error: 'GitHub reports this repository already has code in it.' });

    const [, name] = String(now.full_name).split('/');
    const result: RepositoryResult = await finishRepository(
      config,
      home.installationId,
      name,
      repo.is_core ? 'core' : 'main',
      now.full_name,
      String(now.default_branch || repo.default_branch || 'main'),
      prepared,
      files ? files.length : 0
    ).catch((err) => ({
      role: (repo.is_core ? 'core' : 'main') as 'main' | 'core',
      full_name: String(now.full_name),
      github_repo_id: Number(now.id),
      html_url: String(now.html_url),
      default_branch: String(now.default_branch || 'main'),
      settings: [],
      ruleset: { applied: false, refused: null, reported: null },
      initial_commit: null,
      incomplete: err instanceof GitHubError ? `GitHub answered ${err.status}: ${String(err.body?.message ?? err.message)}` : 'no answer from GitHub'
    }));
    const fullyLocked = isFullyLocked(result);

    await client.query('BEGIN');
    await client.query(
      `UPDATE repository SET full_name = $2, locked_at = CASE WHEN $3 THEN COALESCE(locked_at, now()) END, updated_at = now() WHERE id = $1`,
      [repo.id, result.full_name, fullyLocked]
    );
    await insertEvent(
      {
        project_id: projectId,
        actor_type: 'creator',
        actor_id: creator.id,
        action: 'repository.lock_checked',
        subject_type: 'repository',
        subject_id: repo.id,
        payload: { ...result, organization: home.org, performed_by: 'github-app', fully_locked: fullyLocked }
      },
      client
    );
    await client.query('COMMIT');
    res.json({ repository: result, fully_locked: fullyLocked });
  } catch (err: any) {
    await client?.query('ROLLBACK').catch(() => undefined);
    next(err);
  } finally {
    prepared?.cleanup();
    if (client) {
      if (locked) await client.query('SELECT pg_advisory_unlock(hashtextextended($1, 0))', [`code_home:${projectId}`]).catch(() => undefined);
      client.release();
    }
  }
}
