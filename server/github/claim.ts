import type { Request, Response } from 'express';
import { getDbPool, insertEvent } from '../db';
import { creatorOf } from '../auth';
import { githubConfig, GitHubConfig, GitHubError, GitHubNotConfigured } from './app';
import { BadUpload, createLockedRepository, readZip, repositoryName, RepositoryResult } from './repositories';

/**
 * POST /api/v1/projects/:id/code-home
 *   application/json  { "split_core": true|false }             empty repositories
 *   application/zip   (body = the zip)  ?split_core=1|0         existing code as the first commit of the main repository
 *
 * Creates the project's private repositories in the creator's connected organization, locks them, and records
 * one event per repository with what GitHub reported. A setting GitHub refused is recorded as not applied.
 */
export async function createCodeHome(req: Request, res: Response) {
  let config: GitHubConfig;
  try {
    config = githubConfig();
  } catch (err) {
    if (err instanceof GitHubNotConfigured) return res.status(503).json({ error: err.message });
    throw err;
  }
  const db = getDbPool();
  if (!db) return res.status(503).json({ error: 'Database not connected.' });
  const creator = creatorOf(res);
  const projectId = req.params.id;

  const isZip = Buffer.isBuffer(req.body);
  const splitCore = isZip ? req.query.split_core === '1' : req.body?.split_core === true;
  if (!isZip && req.body?.split_core !== undefined && typeof req.body.split_core !== 'boolean') {
    return res.status(400).json({ error: 'split_core must be true or false.' });
  }

  const client = await db.connect();
  let locked = false;
  try {
    const project = (await client.query('SELECT id, name, purpose FROM project WHERE id = $1 AND creator_id = $2', [projectId, creator.id])).rows[0];
    if (!project) return res.status(404).json({ error: 'Project not found.' });
    const installation = (
      await client.query(`SELECT installation_id, account_login, status FROM github_installation WHERE creator_id = $1 AND status <> 'removed'`, [creator.id])
    ).rows[0];
    if (!installation) return res.status(409).json({ error: 'Connect your code home first.' });
    if (installation.status !== 'active') return res.status(409).json({ error: 'Your code home connection is not working (the app is suspended on GitHub).' });

    let files: Awaited<ReturnType<typeof readZip>> | null = null;
    if (isZip) {
      try {
        files = await readZip(req.body);
      } catch (err) {
        if (err instanceof BadUpload) return res.status(400).json({ error: err.message });
        throw err;
      }
    }

    // One code-home creation per project at a time, and only once.
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

    const results: RepositoryResult[] = [];
    for (const want of missing) {
      let result: RepositoryResult;
      try {
        result = await createLockedRepository(
          config,
          Number(installation.installation_id),
          installation.account_login,
          want.name,
          want.role,
          want.role === 'core' ? `${project.name} (core)` : project.name,
          want.role === 'main' ? files : null
        );
      } catch (err: any) {
        const failure = err instanceof GitHubError ? { status: err.status, message: String(err.body?.message ?? err.message) } : { status: null, message: String(err?.message ?? err).slice(0, 500) };
        await insertEvent({
          project_id: projectId,
          actor_type: 'system',
          actor_id: 'github-app',
          action: 'repository.creation_failed',
          subject_type: 'project',
          subject_id: projectId,
          payload: { organization: installation.account_login, name: want.name, role: want.role, requested_by: creator.id, error: failure }
        });
        console.error('[github] creating a repository failed:', failure.status, failure.message);
        return res.status(502).json({ error: `GitHub did not create ${want.name}: ${failure.message}`, repositories: results });
      }

      const fullyLocked = result.settings.every((s) => s.applied) && result.ruleset.applied;
      await client.query('BEGIN');
      const row = (
        await client.query(
          `INSERT INTO repository (project_id, github_repo_id, full_name, default_branch, is_core, installation_id, locked_at)
           VALUES ($1, $2, $3, $4, $5, $6, CASE WHEN $7 THEN now() END) RETURNING id`,
          [projectId, String(result.github_repo_id), result.full_name, result.default_branch, result.role === 'core', installation.installation_id, fullyLocked]
        )
      ).rows[0];
      await insertEvent(
        {
          project_id: projectId,
          actor_type: 'system',
          actor_id: 'github-app',
          action: 'repository.created',
          subject_type: 'repository',
          subject_id: row.id,
          payload: { ...result, organization: installation.account_login, requested_by: creator.id, fully_locked: fullyLocked }
        },
        client
      );
      await client.query('COMMIT');
      results.push(result);
    }
    res.status(201).json({ repositories: results });
  } catch (err: any) {
    await client.query('ROLLBACK').catch(() => undefined);
    console.error('[github] code home failed:', err?.message ?? err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  } finally {
    if (locked) await client.query('SELECT pg_advisory_unlock(hashtextextended($1, 0))', [`code_home:${projectId}`]).catch(() => undefined);
    client.release();
  }
}
