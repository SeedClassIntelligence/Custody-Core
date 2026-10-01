import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
dotenv.config();

import {
  getDbPool,
  runMigrations,
  getProjectEvents,
  verifyServerProjectEvents,
  insertEvent
} from './server/db';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const isProduction = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT) || 3000;

export const app = express();
app.use(express.json());

// --- API Routes (/api/v1/*) ---
const apiRouter = express.Router();

// Health and connection status
  apiRouter.get('/health', async (_req, res) => {
    const hasDb = getDbPool() !== null;
    let dbStatus = 'not_connected';
    let dbError = null;

    if (hasDb) {
      try {
        const pool = getDbPool();
        const client = await pool!.connect();
        await client.query('SELECT 1');
        client.release();
        dbStatus = 'connected';
      } catch (err: any) {
        dbStatus = 'error';
        dbError = err.message;
      }
    }

    res.json({
      status: 'ok',
      service: 'Custody Core Server',
      milestone: 'Milestone 1: Foundation, Database & Append-Only Event Log',
      database: {
        status: dbStatus,
        configured: hasDb,
        error: dbError
      },
      time: new Date().toISOString()
    });
  });

  // TODO: Milestone 2 creator check - authenticate creator session and filter projects by session creator_id
  apiRouter.get('/projects', async (_req, res) => {
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
         GROUP BY p.id
         ORDER BY p.created_at DESC`
      );

      res.json({
        projects: result.rows,
        connected: true
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // TODO: Milestone 2 creator check - assign project ownership to authenticated creator_id from session
  apiRouter.post('/projects', async (req, res) => {
    const db = getDbPool();
    if (!db) {
      return res.status(503).json({
        error: 'Database not connected. Cannot persist projects without DATABASE_URL.'
      });
    }

    const { name, purpose, creator_id, repositories, split_core } = req.body;
    if (!name || !purpose) {
      return res.status(400).json({ error: 'Project name and purpose are required.' });
    }

    const client = await db.connect();
    try {
      await client.query('BEGIN');

      // Default creator fallback if not provided
      let actualCreatorId = creator_id;
      if (!actualCreatorId) {
        const creatorRes = await client.query('SELECT id FROM creator LIMIT 1');
        if (creatorRes.rows.length > 0) {
          actualCreatorId = creatorRes.rows[0].id;
        } else {
          // Provision default creator
          const newCreator = await client.query(
            `INSERT INTO creator (identity_id, display_name, email)
             VALUES ('default_creator', 'Primary Creator', 'creator@custodycore.internal')
             RETURNING id`
          );
          actualCreatorId = newCreator.rows[0].id;
        }
      }

      // Insert Project
      const projRes = await client.query(
        `INSERT INTO project (creator_id, name, purpose, status)
         VALUES ($1, $2, $3, 'active')
         RETURNING *`,
        [actualCreatorId, name, purpose]
      );
      const project = projRes.rows[0];

      // Insert Repositories
      const createdRepos = [];
      if (Array.isArray(repositories)) {
        for (const repo of repositories) {
          const repoRes = await client.query(
            `INSERT INTO repository (project_id, full_name, default_branch, is_core, locked_at)
             VALUES ($1, $2, $3, $4, now())
             RETURNING *`,
            [project.id, repo.full_name, repo.default_branch || 'main', repo.is_core || false]
          );
          createdRepos.push(repoRes.rows[0]);
        }
      }

      await client.query('COMMIT');

      // Record first event in the append-only log on the server
      const event = await insertEvent({
        project_id: project.id,
        actor_type: 'creator',
        actor_id: actualCreatorId,
        action: 'project.claimed',
        subject_type: 'project',
        subject_id: project.id,
        payload: {
          name: project.name,
          purpose: project.purpose,
          split_core: !!split_core,
          repositories: createdRepos.map(r => r.full_name)
        }
      });

      res.status(201).json({
        project: {
          ...project,
          repositories: createdRepos
        },
        event
      });
    } catch (err: any) {
      await client.query('ROLLBACK');
      res.status(500).json({ error: err.message });
    } finally {
      client.release();
    }
  });

  // TODO: Milestone 2 creator check - verify session creator owns or has granted access to project
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
      const events = await getProjectEvents(req.params.id);
      res.json({
        project_id: req.params.id,
        events,
        count: events.length,
        connected: true
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // TODO: Milestone 2 creator check - verify session creator owns or has granted access to project
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
      const result = await verifyServerProjectEvents(req.params.id);
      res.json({
        valid: result.isValid,
        broken_at_seq: result.brokenAtSeq ?? null,
        count: result.totalEvents
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

app.use('/api/v1', apiRouter);

export async function startServer() {
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

  return app.listen(PORT, '0.0.0.0', () => {
    console.log(`Custody Core server running on http://0.0.0.0:${PORT}`);
  });
}

// Auto-start server when not running in test mode
if (process.env.NODE_ENV !== 'test' && !process.env.VITEST) {
  startServer().catch(err => {
    console.error('Fatal server startup failure:', err);
    process.exit(1);
  });
}
