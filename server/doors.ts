import express from 'express';
import type pg from 'pg';
import { getDbPool, insertEvent } from './db';
import { creatorOf } from './auth';
import { GitHubError, GitHubNotConfigured, installationRepositories } from './github';
import { installationOf } from './githubRoutes';
import { newGatewayToken } from './gateway/router';
import { removeDoorMirrors } from './gateway/mirror';

/**
 * Doors (mounted at /api/v1/projects/:id/... after login). A door gives one outside developer access to chosen
 * repositories of one project, through the git gateway, until it is closed or expires.
 *
 *   draft  --open-->  open  --close-->  closed   (a closed door is final; the database enforces it)
 *
 * Opening issues the gateway credential and shows it once. Closing revokes it (the next git request is refused)
 * and deletes the door's mirrors from the gateway. Every step is an event in the project's record.
 * Developer accounts, agreement signing and workspaces are not built yet: the creator hands the credential over.
 */

const RIGHTS = ['contribute', 'license', 'transfer', 'maintain'];
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_DAYS = 366;

export const projectExtrasRouter = express.Router({ mergeParams: true });

function db(res: express.Response): pg.Pool | null {
  const pool = getDbPool();
  if (!pool) res.status(503).json({ error: 'Database not connected.' });
  return pool;
}

async function ownProject(pool: pg.Pool, projectId: string, creatorId: string): Promise<boolean> {
  return (await pool.query('SELECT 1 FROM project WHERE id = $1 AND creator_id = $2', [projectId, creatorId])).rowCount === 1;
}

function fail(res: express.Response, err: any, what: string) {
  if (err instanceof GitHubNotConfigured) return res.status(503).json({ error: err.message });
  if (err instanceof GitHubError) return res.status(502).json({ error: err.message });
  console.error(`[doors] ${what}:`, err?.message ?? err);
  return res.status(500).json({ error: 'Something went wrong on the server.' });
}

/** The address the developer's git uses. APP_URL when set (recommended behind a proxy), else this request's host. */
export function gatewayBase(req: express.Request): string {
  const configured = process.env.APP_URL;
  if (configured && /^https?:\/\/[^\s]+$/.test(configured)) return configured.replace(/\/+$/, '');
  return `${req.protocol}://${req.get('host')}`;
}

function remotesFor(req: express.Request, doorId: string, repos: Array<{ full_name: string }>) {
  return repos.map((r) => ({ full_name: r.full_name, url: `${gatewayBase(req)}/git/${doorId}/${r.full_name}.git` }));
}

/** The project id from the parent route (/projects/:id). */
const pid = (req: express.Request): string => (req.params as Record<string, string>).id;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
projectExtrasRouter.use((req, res, next) => {
  if (!UUID.test(pid(req))) return res.status(404).json({ error: 'Project not found.' });
  next();
});
projectExtrasRouter.param('doorId', (_req, res, next, id) => {
  if (!UUID.test(id)) return res.status(404).json({ error: 'Door not found.' });
  next();
});

// --- Repositories ------------------------------------------------------------------------------------------

/** Adds repositories to a project. Each must be one the creator's GitHub App installation can see. */
projectExtrasRouter.post('/repositories', async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  const creator = creatorOf(res);
  const names = req.body?.full_names;
  if (!Array.isArray(names) || names.length === 0 || names.length > 20 || names.some((n) => typeof n !== 'string' || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(n))) {
    return res.status(400).json({ error: 'full_names must be a list of 1 to 20 "owner/repository" names.' });
  }
  try {
    if (!(await ownProject(pool, pid(req), creator.id))) return res.status(404).json({ error: 'Project not found.' });
    const installation = await installationOf(creator.id);
    if (!installation) return res.status(409).json({ error: 'Connect GitHub first.' });
    const visible = new Map((await installationRepositories(installation.installation_id)).map((r) => [r.full_name.toLowerCase(), r]));
    const missing = names.filter((n: string) => !visible.has(n.toLowerCase()));
    if (missing.length) {
      return res.status(422).json({ error: `The GitHub App cannot see: ${missing.join(', ')}. Give it access to these repositories on GitHub.` });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const added = [];
      for (const n of names as string[]) {
        const gh = visible.get(n.toLowerCase())!;
        const exists = await client.query('SELECT 1 FROM repository WHERE project_id = $1 AND lower(full_name) = lower($2)', [pid(req), gh.full_name]);
        if (exists.rowCount) continue;
        const row = (await client.query(
          `INSERT INTO repository (project_id, github_repo_id, full_name, default_branch, is_core)
           VALUES ($1, $2, $3, $4, false) RETURNING *`,
          [pid(req), String(gh.id), gh.full_name, gh.default_branch]
        )).rows[0];
        added.push(row);
      }
      if (added.length) {
        await insertEvent({
          project_id: pid(req),
          actor_type: 'creator',
          actor_id: creator.id,
          action: 'repository.added',
          subject_type: 'project',
          subject_id: pid(req),
          payload: {
            repositories: added.map((r) => ({ id: r.id, full_name: r.full_name, github_repo_id: r.github_repo_id })),
            github_account: installation.account_login
          }
        }, client);
      }
      await client.query('COMMIT');
      res.status(201).json({ repositories: added });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  } catch (err) {
    fail(res, err, 'adding repositories');
  }
});

// --- Doors -------------------------------------------------------------------------------------------------

async function loadDoors(pool: pg.Pool | pg.PoolClient, projectId: string, doorId?: string) {
  const doors = (await pool.query(
    `SELECT d.id, d.project_id, d.developer_email, d.job_description, d.rights_type, d.status, d.opens_at, d.expires_at,
            d.closed_at, d.closed_reason, d.created_at,
            COALESCE((SELECT json_agg(json_build_object('repository_id', r.id, 'full_name', r.full_name, 'access', dr.access) ORDER BY r.full_name)
                        FROM door_repository dr JOIN repository r ON r.id = dr.repository_id WHERE dr.door_id = d.id), '[]') AS repositories,
            (SELECT json_build_object('id', gc.id, 'created_at', gc.created_at, 'last_used_at', gc.last_used_at)
               FROM gateway_credential gc WHERE gc.door_id = d.id AND gc.revoked_at IS NULL ORDER BY gc.created_at DESC LIMIT 1) AS credential
       FROM door d
      WHERE d.project_id = $1 AND ($2::uuid IS NULL OR d.id = $2)
      ORDER BY d.created_at DESC`,
    [projectId, doorId ?? null]
  )).rows;
  return doors.map((d) => ({ ...d, branch_prefix: `door/${d.id}/` }));
}

projectExtrasRouter.get('/doors', async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  try {
    if (!(await ownProject(pool, pid(req), creatorOf(res).id))) return res.status(404).json({ error: 'Project not found.' });
    const doors = await loadDoors(pool, pid(req));
    res.json({ doors: doors.map((d) => ({ ...d, remotes: d.status === 'open' ? remotesFor(req, d.id, d.repositories) : [] })) });
  } catch (err) {
    fail(res, err, 'listing doors');
  }
});

projectExtrasRouter.post('/doors', async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  const creator = creatorOf(res);
  const { developer_email, job_description, rights_type, repositories, expires_at } = req.body ?? {};
  if (typeof developer_email !== 'string' || !EMAIL.test(developer_email) || developer_email.length > 320) {
    return res.status(400).json({ error: 'developer_email must be an email address.' });
  }
  if (typeof job_description !== 'string' || !job_description.trim() || job_description.length > 5000) {
    return res.status(400).json({ error: 'job_description is required (up to 5000 characters).' });
  }
  if (!RIGHTS.includes(rights_type)) return res.status(400).json({ error: `rights_type must be one of: ${RIGHTS.join(', ')}.` });
  const expires = new Date(expires_at);
  if (typeof expires_at !== 'string' || Number.isNaN(expires.getTime()) || expires.getTime() <= Date.now() + 60_000 || expires.getTime() > Date.now() + MAX_DAYS * 86400_000) {
    return res.status(400).json({ error: `expires_at must be a date and time in the future, at most ${MAX_DAYS} days away.` });
  }
  if (
    !Array.isArray(repositories) || repositories.length === 0 || repositories.length > 20 ||
    repositories.some((r: any) => !r || typeof r.repository_id !== 'string' || !UUID.test(r.repository_id) || !['read', 'write'].includes(r.access)) ||
    new Set(repositories.map((r: any) => r.repository_id)).size !== repositories.length
  ) {
    return res.status(400).json({ error: 'repositories must list 1 to 20 different repositories, each with access "read" or "write".' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const owned = await client.query('SELECT 1 FROM project WHERE id = $1 AND creator_id = $2', [pid(req), creator.id]);
    if (owned.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Project not found.' });
    }
    const ids = repositories.map((r: any) => r.repository_id);
    const found = await client.query('SELECT id, full_name FROM repository WHERE project_id = $1 AND id = ANY($2::uuid[])', [pid(req), ids]);
    if (found.rowCount !== ids.length) {
      await client.query('ROLLBACK');
      return res.status(422).json({ error: 'Every repository must belong to this project.' });
    }
    const door = (await client.query(
      `INSERT INTO door (project_id, developer_email, job_description, rights_type, status, expires_at)
       VALUES ($1, $2, $3, $4, 'draft', $5) RETURNING id`,
      [pid(req), developer_email.trim(), job_description.trim(), rights_type, expires.toISOString()]
    )).rows[0];
    for (const r of repositories) {
      await client.query('INSERT INTO door_repository (door_id, repository_id, access) VALUES ($1, $2, $3)', [door.id, r.repository_id, r.access]);
    }
    const names = new Map(found.rows.map((r) => [r.id, r.full_name]));
    await insertEvent({
      project_id: pid(req),
      actor_type: 'creator',
      actor_id: creator.id,
      action: 'door.created',
      subject_type: 'door',
      subject_id: door.id,
      payload: {
        developer_email: developer_email.trim(),
        job_description: job_description.trim(),
        rights_type,
        expires_at: expires.toISOString(),
        branch_prefix: `door/${door.id}/`,
        repositories: repositories.map((r: any) => ({ full_name: names.get(r.repository_id), access: r.access }))
      }
    }, client);
    await client.query('COMMIT');
    const [created] = await loadDoors(pool, pid(req), door.id);
    res.status(201).json({ door: { ...created, remotes: [] } });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    fail(res, err, 'creating a door');
  } finally {
    client.release();
  }
});

projectExtrasRouter.post('/doors/:doorId/open', async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  const creator = creatorOf(res);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const door = (await client.query(
      `SELECT d.* FROM door d JOIN project p ON p.id = d.project_id
        WHERE d.id = $1 AND d.project_id = $2 AND p.creator_id = $3 FOR UPDATE OF d`,
      [req.params.doorId, pid(req), creator.id]
    )).rows[0];
    if (!door) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Door not found.' });
    }
    if (door.status !== 'draft') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: `This door is ${door.status}; only a new (draft) door can be opened.` });
    }
    if (new Date(door.expires_at).getTime() <= Date.now()) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'This door expired before it was opened. Create a new one.' });
    }
    const installation = (await client.query('SELECT installation_id FROM github_installation WHERE creator_id = $1', [creator.id])).rows[0];
    if (!installation) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Connect GitHub first: the gateway reaches your repositories through it.' });
    }
    const { token, hash } = newGatewayToken();
    const credential = (await client.query('INSERT INTO gateway_credential (door_id, token_hash) VALUES ($1, $2) RETURNING id, created_at', [door.id, hash])).rows[0];
    await client.query(`UPDATE door SET status = 'open', opens_at = now(), updated_at = now() WHERE id = $1`, [door.id]);
    await insertEvent({
      project_id: door.project_id,
      actor_type: 'creator',
      actor_id: creator.id,
      action: 'door.opened',
      subject_type: 'door',
      subject_id: door.id,
      // The credential itself is never recorded: only which one was issued.
      payload: { credential_id: credential.id, expires_at: new Date(door.expires_at).toISOString(), branch_prefix: `door/${door.id}/` }
    }, client);
    await client.query('COMMIT');
    const [opened] = await loadDoors(pool, pid(req), door.id);
    res.json({
      door: { ...opened, remotes: remotesFor(req, door.id, opened.repositories) },
      // Shown once. Only its SHA-256 is stored.
      credential: { username: 'door', token }
    });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    fail(res, err, 'opening a door');
  } finally {
    client.release();
  }
});

projectExtrasRouter.post('/doors/:doorId/close', async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  const creator = creatorOf(res);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const door = (await client.query(
      `SELECT d.* FROM door d JOIN project p ON p.id = d.project_id
        WHERE d.id = $1 AND d.project_id = $2 AND p.creator_id = $3 FOR UPDATE OF d`,
      [req.params.doorId, pid(req), creator.id]
    )).rows[0];
    if (!door) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Door not found.' });
    }
    if (door.status === 'closed') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'This door is already closed.' });
    }
    const revoked = (await client.query(
      'UPDATE gateway_credential SET revoked_at = now() WHERE door_id = $1 AND revoked_at IS NULL RETURNING id, revoked_at',
      [door.id]
    )).rows;
    await client.query(`UPDATE door SET status = 'closed', closed_at = now(), closed_reason = 'creator_manual', updated_at = now() WHERE id = $1`, [door.id]);
    for (const c of revoked) {
      await insertEvent({
        project_id: door.project_id,
        actor_type: 'creator',
        actor_id: creator.id,
        action: 'credential.revoked',
        subject_type: 'door',
        subject_id: door.id,
        payload: { credential_id: c.id, revoked_at: new Date(c.revoked_at).toISOString() }
      }, client);
    }
    await insertEvent({
      project_id: door.project_id,
      actor_type: 'creator',
      actor_id: creator.id,
      action: 'door.closed',
      subject_type: 'door',
      subject_id: door.id,
      payload: { reason: 'creator_manual', previous_status: door.status, credentials_revoked: revoked.length, gateway_mirrors_deleted: true }
    }, client);
    await client.query('COMMIT');
    // After the commit: from here on every git request with the old credential is refused.
    try {
      removeDoorMirrors(door.id);
    } catch (err: any) {
      console.error('[doors] could not delete mirrors of a closed door:', err?.message ?? err);
    }
    const [closed] = await loadDoors(pool, pid(req), door.id);
    res.json({ door: { ...closed, remotes: [] } });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    fail(res, err, 'closing a door');
  } finally {
    client.release();
  }
});
