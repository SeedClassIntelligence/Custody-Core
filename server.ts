import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
dotenv.config();

import {
  getDbPool,
  appDatabaseConfigProblem,
  runMigrations,
  getProjectEvents,
  verifyServerProjectEvents,
  insertEvent
} from './server/db';
import { authenticate, creatorOf } from './server/auth';
import { mfaRouter } from './server/mfa';
import { verifyAccountChain } from './shared/crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const isProduction = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT) || 3000;

function serverError(res: express.Response, err: any, what: string) {
  // Internal details (database messages, stack traces) stay in the server log, not in the response.
  console.error(`[server] ${what}:`, err?.message ?? err);
  return res.status(500).json({ error: 'Something went wrong on the server.' });
}

export const app = express();
app.use(express.json());

// --- API Routes (/api/v1/*) ---
const apiRouter = express.Router();

// Health and connection status
  apiRouter.get('/health', async (_req, res) => {
    const hasDb = getDbPool() !== null;
    let dbStatus = 'not_connected';

    if (hasDb) {
      try {
        const pool = getDbPool();
        const client = await pool!.connect();
        await client.query('SELECT 1');
        client.release();
        dbStatus = 'connected';
      } catch (err: any) {
        // The reason stays in the server log: this endpoint is open to anyone.
        dbStatus = 'error';
        console.error('[health] database check failed:', err?.message ?? err);
      }
    }

    res.json({
      status: 'ok',
      service: 'Custody Core Server',
      milestone: 'Milestone 2: login with required multifactor authentication',
      database: {
        status: dbStatus,
        configured: hasDb
      },
      time: new Date().toISOString()
    });
  });

  // The authenticator-code step: needs a real Supabase session, not the code step itself.
  apiRouter.use('/mfa', mfaRouter);

  // Everything below requires a full login: session, confirmed email and the code step passed on this server.
  // Only /health above is open.
  apiRouter.use(authenticate);

  // The signed-in person's own account record (for example lockouts), with a verification of its chain.
  apiRouter.get('/account/events', async (_req, res) => {
    const db = getDbPool();
    if (!db) return res.status(503).json({ error: 'Database not connected.' });
    try {
      const rows = (await db.query('SELECT * FROM account_event WHERE account_id = $1 ORDER BY seq', [creatorOf(res).userId])).rows;
      const events = rows.map((r) => ({ ...r, seq: Number(r.seq) }));
      const check = await verifyAccountChain(events.map((e) => ({ ...e, timestamp: e.hashed_timestamp })));
      res.json({ events, valid: check.isValid, broken_at_seq: check.brokenAtSeq ?? null, count: events.length });
    } catch (err: any) {
      serverError(res, err, 'reading account events');
    }
  });

  apiRouter.get('/me', (_req, res) => {
    const creator = creatorOf(res);
    res.json({ creator: { id: creator.id, email: creator.email } });
  });

  apiRouter.get('/projects', async (req, res) => {
    const db = getDbPool();
    if (!db) {
      return res.json({
        projects: [],
        connected: false,
        message: 'Database not connected. Configure DATABASE_URL in environment secrets.'
      });
    }

    try {
      const result = await db.query(
        `SELECT p.*,
          COALESCE(
            json_agg(
              json_build_object(
                'id', r.id,
                'full_name', r.full_name,
                'default_branch', r.default_branch,
                'is_core', r.is_core,
                'locked_at', r.locked_at
              )
            ) FILTER (WHERE r.id IS NOT NULL), '[]'
          ) as repositories
         FROM project p
         LEFT JOIN repository r ON r.project_id = p.id
         WHERE p.creator_id = $1
         GROUP BY p.id
         ORDER BY p.created_at DESC`,
        [creatorOf(res).id]
      );

      res.json({
        projects: result.rows,
        connected: true
      });
    } catch (err: any) {
      serverError(res, err, 'listing projects');
    }
  });

  apiRouter.post('/projects', async (req, res) => {
    const db = getDbPool();
    if (!db) {
      return res.status(503).json({
        error: 'Database not connected. Cannot persist projects without DATABASE_URL.'
      });
    }

    // Whatever the client sends as creator_id is ignored: the owner is the logged-in creator.
    const { name, purpose, repositories, split_core } = req.body ?? {};
    const creatorId = creatorOf(res).id;
    if (!name || !purpose) {
      return res.status(400).json({ error: 'Project name and purpose are required.' });
    }
    if (typeof name !== 'string' || typeof purpose !== 'string' || name.length > 200 || purpose.length > 5000) {
      return res.status(400).json({ error: 'Project name (up to 200 characters) and purpose (up to 5000) must be text.' });
    }
    if (
      repositories !== undefined &&
      (!Array.isArray(repositories) ||
        repositories.length > 20 ||
        repositories.some((r: any) => !r || typeof r.full_name !== 'string' || !r.full_name.trim() || r.full_name.length > 200))
    ) {
      return res.status(400).json({ error: 'repositories must be a list of up to 20 items, each with a full_name.' });
    }

    const client = await db.connect();
    try {
      await client.query('BEGIN');

      // Insert Project
      const projRes = await client.query(
        `INSERT INTO project (creator_id, name, purpose, status)
         VALUES ($1, $2, $3, 'active')
         RETURNING *`,
        [creatorId, name, purpose]
      );
      const project = projRes.rows[0];

      // Insert Repositories
      const createdRepos = [];
      if (Array.isArray(repositories)) {
        for (const repo of repositories) {
          const repoRes = await client.query(
            // locked_at stays empty: nothing is locked until the GitHub integration reads the lock back.
            `INSERT INTO repository (project_id, full_name, default_branch, is_core)
             VALUES ($1, $2, $3, $4)
             RETURNING *`,
            [project.id, repo.full_name, repo.default_branch || 'main', repo.is_core || false]
          );
          createdRepos.push(repoRes.rows[0]);
        }
      }

      // Record the first event in the same transaction, so a project never exists without its claim event.
      const event = await insertEvent({
        project_id: project.id,
        actor_type: 'creator',
        actor_id: creatorId,
        action: 'project.claimed',
        subject_type: 'project',
        subject_id: project.id,
        payload: {
          name: project.name,
          purpose: project.purpose,
          split_core: !!split_core,
          repositories: createdRepos.map(r => r.full_name)
        }
      }, client);

      await client.query('COMMIT');

      res.status(201).json({
        project: {
          ...project,
          repositories: createdRepos
        },
        event
      });
    } catch (err: any) {
      await client.query('ROLLBACK');
      serverError(res, err, 'recording a project');
    } finally {
      client.release();
    }
  });

  // A project id that is not a UUID cannot name a project, so say "not found" instead of letting the
  // database reject it with a 500.
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  apiRouter.param('id', (req, res, next, id) => {
    if (!UUID.test(id)) {
      return res.status(404).json({ error: 'Project not found.' });
    }
    next();
  });

  // A project that does not exist and a project that belongs to someone else get the same answer,
  // so the response cannot be used to find out whether a project exists.
  async function ownsProject(projectId: string, creatorId: string): Promise<boolean> {
    const db = getDbPool();
    if (!db) return false;
    const r = await db.query('SELECT 1 FROM project WHERE id = $1 AND creator_id = $2', [projectId, creatorId]);
    return r.rowCount === 1;
  }

  apiRouter.get('/projects/:id/events', async (req, res) => {
    const db = getDbPool();
    if (!db) {
      return res.status(503).json({
        events: [],
        connected: false,
        error: 'Database not connected. Configure DATABASE_URL in environment secrets.'
      });
    }

    try {
      if (!(await ownsProject(req.params.id, creatorOf(res).id))) {
        return res.status(404).json({ error: 'Project not found.' });
      }
      const events = await getProjectEvents(req.params.id);
      res.json({
        project_id: req.params.id,
        events,
        count: events.length,
        connected: true
      });
    } catch (err: any) {
      serverError(res, err, 'reading events');
    }
  });

  apiRouter.get('/projects/:id/events/verify', async (req, res) => {
    const db = getDbPool();
    if (!db) {
      return res.status(503).json({
        valid: false,
        broken_at_seq: null,
        count: 0,
        error: 'Database not connected. Configure DATABASE_URL in environment secrets.'
      });
    }

    try {
      if (!(await ownsProject(req.params.id, creatorOf(res).id))) {
        return res.status(404).json({ error: 'Project not found.' });
      }
      const result = await verifyServerProjectEvents(req.params.id);
      res.json({
        valid: result.isValid,
        broken_at_seq: result.brokenAtSeq ?? null,
        count: result.totalEvents
      });
    } catch (err: any) {
      serverError(res, err, 'verifying events');
    }
  });

app.use('/api/v1', apiRouter);

// Bad requests get a short JSON answer; nothing internal (stack traces, database messages) is sent back.
app.use((err: any, _req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (res.headersSent) return next(err);
  if (err?.type === 'entity.parse.failed') return res.status(400).json({ error: 'The request body is not valid JSON.' });
  if (err?.type === 'entity.too.large') return res.status(413).json({ error: 'The request body is too large.' });
  return serverError(res, err, 'unhandled error');
});

export async function startServer() {
  // A database is configured but the app has no password for its own account: refuse to start, rather than
  // quietly run as "not connected".
  const configProblem = appDatabaseConfigProblem();
  if (configProblem) throw new Error(configProblem);

  // Try auto-running migrations if DATABASE_URL is provided
  const db = getDbPool();
  if (db) {
    try {
      const migrationRes = await runMigrations();
      console.log('[DB]', migrationRes.message);
    } catch (err: any) {
      console.warn('[DB Migration Warning]', err.message);
    }
  } else {
    console.log('[DB] No valid DATABASE_URL provided. Operating in honest "Not connected yet" state.');
  }

  // Vite middleware in dev or static files in production
  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  // Development serves the whole source tree through Vite, so it listens on this machine only.
  // A production deployment listens on every interface (set HOST to change either).
  const HOST = process.env.HOST || (isProduction ? '0.0.0.0' : '127.0.0.1');
  return app.listen(PORT, HOST, () => {
    console.log(`Custody Core server running on http://${HOST}:${PORT}`);
  });
}

// Auto-start server when not running in test mode
if (process.env.NODE_ENV !== 'test' && !process.env.VITEST) {
  startServer().catch(err => {
    console.error('Fatal server startup failure:', err);
    process.exit(1);
  });
}
