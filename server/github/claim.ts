import type { NextFunction, Request, Response } from 'express';
import { getDbPool, insertEvent } from '../db';
import { creatorOf } from '../auth';
import { gh, githubConfig, GitHubConfig, GitHubError, GitHubNotConfigured, withInstallationToken } from './app';
import { codeHomeFor } from './home';
import {
  BadUpload,
  createLockedRepository,
  finishRepository,
  isEmpty,
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
 *
 * No database connection is held while GitHub is being asked (that would let a handful of simultaneous requests
 * use up every connection and freeze the server). One operation per project at a time is ensured instead by a
 * short-lived "busy" mark on the project, which expires on its own if the server stops part way.
 */

const BUSY_MINUTES = 10;

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

/** Marks the project busy for a code-home operation. Returns false (and answers) if it is not the creator's or already busy. */
async function markBusy(projectId: string, creatorId: string, res: Response): Promise<boolean> {
  const db = getDbPool()!;
  const marked = await db.query(
    `UPDATE project SET code_home_busy_until = now() + make_interval(mins => $3)
      WHERE id = $1 AND creator_id = $2 AND (code_home_busy_until IS NULL OR code_home_busy_until < now())
      RETURNING id`,
    [projectId, creatorId, BUSY_MINUTES]
  );
  if (marked.rowCount === 1) return true;
  const exists = await db.query('SELECT 1 FROM project WHERE id = $1 AND creator_id = $2', [projectId, creatorId]);
  if (!exists.rowCount) res.status(404).json({ error: 'Project not found.' });
  else res.status(409).json({ error: 'Repositories are already being created or checked for this project. Try again in a moment.' });
  return false;
}

async function clearBusy(projectId: string) {
  await getDbPool()!.query('UPDATE project SET code_home_busy_until = NULL WHERE id = $1', [projectId]).catch(() => undefined);
}

const isRecorded = async (githubRepoId: number) =>
  ((await getDbPool()!.query('SELECT 1 FROM repository WHERE github_repo_id = $1', [String(githubRepoId)])).rowCount ?? 0) > 0;

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

  let busy = false;
  let prepared: PreparedCommit | null = null;
  try {
    const project = (await db.query('SELECT id, name FROM project WHERE id = $1 AND creator_id = $2', [projectId, creator.id])).rows[0];
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

    busy = await markBusy(projectId, creator.id, res);
    if (!busy) return;

    const base = repositoryName(project.name);
    const wanted: Array<{ name: string; role: 'main' | 'core' }> = [{ name: base, role: 'main' }];
    if (splitCore) wanted.push({ name: `${base}-core`, role: 'core' });
    // A claim that stopped half way (for example the core repository failed) can be finished: only what is
    // missing is created.
    const existingRoles = new Set(
      (await db.query('SELECT is_core FROM repository WHERE project_id = $1', [projectId])).rows.map((r) => (r.is_core ? 'core' : 'main'))
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

    const home = await codeHomeFor(config, res);
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
          projectId,
          isRecorded
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
      const client = await db.connect(); // only for this short transaction, never while GitHub is asked
      try {
        await client.query('BEGIN');
        const row = (
          await client.query(
            `INSERT INTO repository (project_id, github_repo_id, full_name, default_branch, is_core, installation_id, github_state, locked_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, CASE WHEN $8 THEN now() END) RETURNING id`,
            [
              projectId,
              String(result.github_repo_id),
              result.full_name,
              result.default_branch,
              result.role === 'core',
              home.installationId,
              JSON.stringify(result.github_state ?? null),
              fullyLocked
            ]
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
      } catch (err: any) {
        await client.query('ROLLBACK').catch(() => undefined);
        if (err?.code === '23505') {
          return res.status(409).json({ error: `GitHub's repository ${result.full_name} is already recorded for a project.`, repositories: results });
        }
        throw err;
      } finally {
        client.release();
      }
      results.push(result);
    }
    res.status(201).json({ repositories: results });
  } catch (err: any) {
    next(err);
  } finally {
    prepared?.cleanup();
    if (busy) await clearBusy(projectId);
  }
}

/**
 * Finishes an existing repository's lock: re-applies privacy, forking off and the branch rules where they are
 * missing or were loosened, reads everything back, and (with a zip) pushes code to a main repository that GitHub
 * reports as having no commits.
 */
export async function relockRepository(req: Request, res: Response, next: NextFunction) {
  const config = configOr503(res);
  if (!config) return;
  const db = getDbPool();
  if (!db) return res.status(503).json({ error: 'Database not connected.' });
  const creator = creatorOf(res);
  const { id: projectId, repoId } = req.params;
  const isZip = Buffer.isBuffer(req.body);

  let busy = false;
  let prepared: PreparedCommit | null = null;
  try {
    const repo = (
      await db.query(
        `SELECT r.id, r.full_name, r.is_core, r.default_branch, r.github_repo_id, r.installation_id FROM repository r JOIN project p ON p.id = r.project_id
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

    busy = await markBusy(projectId, creator.id, res);
    if (!busy) return;

    const home = await codeHomeFor(config, res);
    if (!home) return;
    if (Number(repo.installation_id) !== home.installationId) {
      return res.status(409).json({ error: 'This repository belongs to an earlier code home connection, which Custody Core can no longer act on.' });
    }

    // Where the repository is now, according to GitHub (it may have been renamed), and whether it has commits.
    const now = await withInstallationToken(config, home.installationId, { permissions: { metadata: 'read', contents: 'read' } }, async (token) => {
      const auth = { kind: 'token' as const, token };
      const found = await gh(config, auth, 'GET', `/repositories/${Number(repo.github_repo_id)}`).catch((err) => {
        if (err instanceof GitHubError && err.status === 404) return null;
        throw err;
      });
      if (!found) return null;
      const repoPath = `/repos/${String(found.full_name).split('/').map(encodeURIComponent).join('/')}`;
      return { ...found, empty: prepared ? await isEmpty(config, auth, repoPath) : null };
    });
    if (!now) return res.status(409).json({ error: 'GitHub no longer shows this repository to Custody Core (deleted, moved, or access removed).' });
    if (prepared && !now.empty) return res.status(409).json({ error: 'GitHub reports this repository already has commits.' });

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
    );
    if (!result.github_repo_id) Object.assign(result, { github_repo_id: Number(now.id), html_url: String(now.html_url) });
    const fullyLocked = isFullyLocked(result);

    const client = await db.connect(); // only for this short transaction
    try {
      await client.query('BEGIN');
      await client.query(
        `UPDATE repository SET full_name = $2, github_state = COALESCE($4::jsonb, github_state),
                locked_at = CASE WHEN $3 THEN COALESCE(locked_at, now()) END, updated_at = now() WHERE id = $1`,
        [repo.id, result.full_name, fullyLocked, result.github_state ? JSON.stringify(result.github_state) : null]
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
    } catch (err) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
    res.json({ repository: result, fully_locked: fullyLocked });
  } catch (err: any) {
    next(err);
  } finally {
    prepared?.cleanup();
    if (busy) await clearBusy(projectId);
  }
}
