import { randomUUID } from 'node:crypto';
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

// Uploads are received and unpacked in memory (up to 50 MB in, 100 MB unpacked), so only a few at a time, and
// one per creator. The slot is taken BEFORE the body is read (uploadGate, ahead of the body parser), and given
// back as soon as the files are unpacked and the commit is prepared on disk, not while waiting on GitHub.
const MAX_UPLOADS_AT_ONCE = 2;
let uploadsInProgress = 0;
const uploadsByCreator = new Map<string, number>();

export function uploadGate(req: Request, res: Response, next: NextFunction) {
  if (!req.is('application/zip')) return next();
  const creatorId = creatorOf(res).id;
  if (uploadsByCreator.get(creatorId)) {
    res.set('Connection', 'close');
    return res.status(429).json({ error: 'You already have an upload in progress. Try again when it has finished.' });
  }
  if (uploadsInProgress >= MAX_UPLOADS_AT_ONCE) {
    res.set('Connection', 'close');
    return res.status(429).json({ error: 'Other uploads are being processed. Try again in a moment.' });
  }
  uploadsInProgress++;
  uploadsByCreator.set(creatorId, 1);
  let held = true;
  const release = () => {
    if (!held) return;
    held = false;
    uploadsInProgress--;
    uploadsByCreator.delete(creatorId);
  };
  res.locals.releaseUpload = release;
  res.on('close', release);
  next();
}

const releaseUpload = (res: Response) => (res.locals.releaseUpload as (() => void) | undefined)?.();

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

/**
 * Marks the project busy for one code-home operation, with a token of its own so that only this operation can
 * clear it (an expired mark taken over by a newer operation is not cleared by the old one). Returns the token, or
 * null after answering 404 (not the creator's) or 409 (already busy).
 */
async function markBusy(projectId: string, creatorId: string, res: Response): Promise<string | null> {
  const db = getDbPool()!;
  const token = randomUUID();
  const marked = await db.query(
    `UPDATE project SET code_home_busy_until = now() + make_interval(mins => $3), code_home_busy_token = $4
      WHERE id = $1 AND creator_id = $2 AND (code_home_busy_until IS NULL OR code_home_busy_until < now())
      RETURNING id`,
    [projectId, creatorId, BUSY_MINUTES, token]
  );
  if (marked.rowCount === 1) return token;
  const exists = await db.query('SELECT 1 FROM project WHERE id = $1 AND creator_id = $2', [projectId, creatorId]);
  if (!exists.rowCount) res.status(404).json({ error: 'Project not found.' });
  else res.status(409).json({ error: 'Repositories are already being created or checked for this project. Try again in a moment.' });
  return null;
}

/** Extends this operation's busy mark (only its own), so a slow operation is never overtaken by a second one. */
async function refreshBusy(projectId: string, token: string) {
  await getDbPool()!.query(
    'UPDATE project SET code_home_busy_until = now() + make_interval(mins => $3) WHERE id = $1 AND code_home_busy_token = $2',
    [projectId, token, BUSY_MINUTES]
  );
}

async function clearBusy(projectId: string, token: string) {
  try {
    await getDbPool()!.query('UPDATE project SET code_home_busy_until = NULL, code_home_busy_token = NULL WHERE id = $1 AND code_home_busy_token = $2', [projectId, token]);
  } catch (err: any) {
    // The mark expires by itself; say so loudly rather than hide it.
    console.error(`[github] could not clear the busy mark on project ${projectId} (it expires within ${BUSY_MINUTES} minutes):`, err?.message ?? err);
  }
}

/** Repository names already used by recorded repositories in this organization (any project). */
async function usedNames(org: string): Promise<Set<string>> {
  const rows = (await getDbPool()!.query('SELECT full_name FROM repository WHERE lower(full_name) LIKE lower($1)', [`${org.replace(/[\\%_]/g, '\\$&')}/%`])).rows;
  return new Set(rows.map((r) => String(r.full_name).split('/')[1].toLowerCase()));
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

  let busy: string | null = null;
  let prepared: PreparedCommit | null = null;
  // Every answer given while the project is marked busy clears the mark first, so a follow-up request is not
  // told "already in progress" by an operation that has finished.
  const respond = async (status: number, body: unknown) => {
    if (busy) await clearBusy(projectId, busy);
    busy = null;
    res.status(status).json(body);
  };
  try {
    const project = (await db.query('SELECT id, name FROM project WHERE id = $1 AND creator_id = $2', [projectId, creator.id])).rows[0];
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    // The upload is unpacked and its first commit made locally right away, before anything is created on
    // GitHub, so a problem with the files (a name git refuses, an object GitHub would reject) is found while
    // nothing exists yet. Then the upload's memory and slot are given back.
    let uploadedFiles = 0;
    if (isZip) {
      try {
        const files = await readZip(req.body);
        uploadedFiles = files.length;
        prepared = await prepareInitialCommit(files, 'main');
      } catch (err) {
        if (err instanceof BadUpload) return res.status(400).json({ error: err.message });
        throw err;
      } finally {
        req.body = null;
        releaseUpload(res);
      }
    }

    // Checked with GitHub before anything else (installed, not suspended, renamed followed, owner still owner).
    const home = await codeHomeFor(config, res);
    if (!home) return;

    busy = await markBusy(projectId, creator.id, res);
    if (!busy) return;

    // A claim that stopped half way (for example the core repository failed) can be finished: only what is
    // missing is created.
    const existing = (await db.query('SELECT is_core, full_name FROM repository WHERE project_id = $1', [projectId])).rows;
    const existingRoles = new Set(existing.map((r) => (r.is_core ? 'core' : 'main')));
    // Names: from the project's name, avoiding names already used by recorded repositories in this organization
    // (a second project with the same name gets "-2", and so on). The main repository's name decides the core's.
    const used = await usedNames(home.org);
    const mainRecorded = existing.find((r) => !r.is_core);
    let base = mainRecorded ? String(mainRecorded.full_name).split('/')[1] : repositoryName(project.name);
    if (!mainRecorded) {
      const stem = base;
      for (let i = 2; used.has(base.toLowerCase()) || used.has(`${base}-core`.toLowerCase()); i++) base = `${stem.slice(0, 76)}-${i}`;
    }
    const wanted: Array<{ name: string; role: 'main' | 'core' }> = [{ name: base, role: 'main' }];
    if (splitCore) wanted.push({ name: `${base}-core`, role: 'core' });
    const missing = wanted.filter((w) => !existingRoles.has(w.role));
    if (missing.length === 0) return respond(409, { error: 'This project already has its repositories.' });
    if (prepared && existingRoles.has('main')) {
      return respond(400, { error: 'Existing code can only be added when the main repository is created; it already exists.' });
    }

    const results: RepositoryResult[] = [];
    for (const want of missing) {
      let result: RepositoryResult;
      // Keep the busy mark alive across long steps, and note when GitHub is asked about this repository.
      await refreshBusy(projectId, busy!);
      const askedAt: Date = (await db.query('SELECT clock_timestamp() AS t')).rows[0].t;
      try {
        result = await createLockedRepository(
          config,
          home.installationId,
          home.org,
          want.name,
          want.role,
          want.role === 'core' ? `${project.name} (core)` : project.name,
          want.role === 'main' ? prepared : null,
          want.role === 'main' ? uploadedFiles : 0,
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
        return respond(502, { error: `GitHub did not create ${want.name}: ${why}`, repositories: results });
      }

      const fullyLocked = isFullyLocked(result);
      const client = await db.connect(); // only for this short transaction, never while GitHub is asked
      try {
        await client.query('BEGIN');
        const row = (
          await client.query(
            `INSERT INTO repository (project_id, github_repo_id, full_name, default_branch, is_core, installation_id, github_state, locked_at, github_state_asked_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, CASE WHEN $8 THEN now() END, $9) RETURNING id`,
            [
              projectId,
              String(result.github_repo_id),
              result.full_name,
              result.default_branch,
              result.role === 'core',
              home.installationId,
              JSON.stringify(result.github_state ?? null),
              fullyLocked,
              askedAt
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
          client.release();
          return respond(409, { error: `GitHub's repository ${result.full_name} is already recorded for a project.`, repositories: results });
        }
        client.release();
        throw err;
      }
      client.release();
      results.push(result);
    }
    return respond(201, { repositories: results });
  } catch (err: any) {
    if (busy) await clearBusy(projectId, busy);
    busy = null;
    next(err);
  } finally {
    prepared?.cleanup();
    releaseUpload(res);
    if (busy) await clearBusy(projectId, busy);
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

  let busy: string | null = null;
  let prepared: PreparedCommit | null = null;
  const respond = async (status: number, body: unknown) => {
    if (busy) await clearBusy(projectId, busy);
    busy = null;
    res.status(status).json(body);
  };
  try {
    const repo = (
      await db.query(
        `SELECT r.id, r.full_name, r.is_core, r.default_branch, r.github_repo_id, r.installation_id FROM repository r JOIN project p ON p.id = r.project_id
          WHERE r.id = $1 AND r.project_id = $2 AND p.creator_id = $3`,
        [repoId, projectId, creator.id]
      )
    ).rows[0];
    if (!repo) return res.status(404).json({ error: 'Repository not found.' });

    let uploadedFiles = 0;
    if (isZip) {
      if (repo.is_core) return res.status(400).json({ error: 'Existing code goes into the main repository.' });
      try {
        const files = await readZip(req.body);
        uploadedFiles = files.length;
        prepared = await prepareInitialCommit(files, repo.default_branch || 'main');
      } catch (err) {
        if (err instanceof BadUpload) return res.status(400).json({ error: err.message });
        throw err;
      } finally {
        req.body = null;
        releaseUpload(res);
      }
    }

    const home = await codeHomeFor(config, res);
    if (!home) return;
    if (Number(repo.installation_id) !== home.installationId) {
      return res.status(409).json({ error: 'This repository belongs to an earlier code home connection, which Custody Core can no longer act on.' });
    }

    busy = await markBusy(projectId, creator.id, res);
    if (!busy) return;

    // Where the repository is now, according to GitHub (it may have been renamed), and whether it has commits.
    // The token covers this one repository only.
    const askedAt: Date = (await db.query('SELECT clock_timestamp() AS t')).rows[0].t;
    const now = await withInstallationToken(
      config,
      home.installationId,
      { repositoryIds: [Number(repo.github_repo_id)], permissions: { metadata: 'read', contents: 'read' } },
      async (token) => {
        const auth = { kind: 'token' as const, token };
        const found = await gh(config, auth, 'GET', `/repositories/${Number(repo.github_repo_id)}`);
        const repoPath = `/repos/${String(found.full_name).split('/').map(encodeURIComponent).join('/')}`;
        return { ...found, empty: prepared ? await isEmpty(config, auth, repoPath) : null };
      }
    ).catch((err) => {
      // 404 from the read, or 422 when a token cannot even be narrowed to it: GitHub no longer shows it to the app.
      if (err instanceof GitHubError && (err.status === 404 || err.status === 422)) return null;
      throw err;
    });
    if (!now) return respond(409, { error: 'GitHub no longer shows this repository to Custody Core (deleted, moved, or access removed).' });
    if (prepared && !now.empty) return respond(409, { error: 'GitHub reports this repository already has commits.' });

    const [, name] = String(now.full_name).split('/');
    await refreshBusy(projectId, busy!);
    const result: RepositoryResult = await finishRepository(
      config,
      home.installationId,
      name,
      repo.is_core ? 'core' : 'main',
      now.full_name,
      String(now.default_branch || repo.default_branch || 'main'),
      prepared,
      uploadedFiles
    );
    if (!result.github_repo_id) Object.assign(result, { github_repo_id: Number(now.id), html_url: String(now.html_url) });
    const fullyLocked = isFullyLocked(result);

    const client = await db.connect(); // only for this short transaction
    try {
      await client.query('BEGIN');
      await client.query(
        `UPDATE repository SET full_name = $2,
                -- GitHub's answer replaces the stored one only if no newer answer was recorded meanwhile.
                github_state = CASE WHEN $4::jsonb IS NOT NULL AND (github_state_asked_at IS NULL OR github_state_asked_at <= $5) THEN $4::jsonb ELSE github_state END,
                github_state_asked_at = CASE WHEN $4::jsonb IS NOT NULL AND (github_state_asked_at IS NULL OR github_state_asked_at <= $5) THEN $5 ELSE github_state_asked_at END,
                locked_at = CASE WHEN $3 THEN COALESCE(locked_at, now()) END, updated_at = now() WHERE id = $1`,
        [repo.id, result.full_name, fullyLocked, result.github_state ? JSON.stringify(result.github_state) : null, askedAt]
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
    return respond(200, { repository: result, fully_locked: fullyLocked });
  } catch (err: any) {
    if (busy) await clearBusy(projectId, busy);
    busy = null;
    next(err);
  } finally {
    prepared?.cleanup();
    releaseUpload(res);
    if (busy) await clearBusy(projectId, busy);
  }
}
