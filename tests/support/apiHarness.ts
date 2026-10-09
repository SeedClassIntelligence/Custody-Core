import crypto from 'node:crypto';
import http from 'node:http';
import express from 'express';
import { getDbPool } from '../../server/db';
import { gatewayRouter } from '../../server/gateway/router';
import { githubApiRouter, githubCallbackRouter } from '../../server/githubRoutes';
import { projectExtrasRouter } from '../../server/doors';

/**
 * The real API routers behind a test login step that sets the creator, as the real login does after its checks
 * (login itself is tested in auth_api.test.ts and second_factor.test.ts). Creators are real rows.
 */
export interface Harness {
  base: string;
  newCreator(label: string): Promise<{ id: string; userId: string; email: string }>;
  api(who: { id: string }, method: string, path: string, body?: unknown): Promise<{ status: number; body: any; headers: Headers }>;
  stop(): Promise<void>;
}

export async function startHarness(): Promise<Harness> {
  const db = getDbPool()!;
  const app = express();
  app.use('/git', gatewayRouter);
  app.use('/github', githubCallbackRouter);
  app.use(express.json());
  const api = express.Router();
  api.use(async (req, res, next) => {
    const id = req.header('x-test-creator');
    const row = id ? (await db.query('SELECT id, identity_id, email FROM creator WHERE id = $1', [id])).rows[0] : null;
    if (!row) return res.status(401).json({ error: 'test login missing' });
    res.locals.creator = { id: row.id, userId: row.identity_id, email: row.email };
    next();
  });
  api.use('/github', githubApiRouter);
  api.use('/projects/:id', projectExtrasRouter);
  app.use('/api/v1', api);
  const server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const base = `http://127.0.0.1:${(server.address() as any).port}`;

  return {
    base,
    async newCreator(label) {
      const userId = `user-${crypto.randomUUID()}`;
      const email = `${label}_${Date.now()}_${crypto.randomBytes(3).toString('hex')}@example.com`;
      const id = (await db.query('INSERT INTO creator (identity_id, display_name, email) VALUES ($1, $2, $3) RETURNING id', [userId, label, email])).rows[0].id;
      return { id, userId, email };
    },
    async api(who, method, path, body) {
      const res = await fetch(`${base}/api/v1${path}`, {
        method,
        redirect: 'manual',
        headers: { 'x-test-creator': who.id, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
        body: body === undefined ? undefined : JSON.stringify(body)
      });
      return { status: res.status, body: await res.json().catch(() => ({})), headers: res.headers };
    },
    stop: () => new Promise<void>((r) => server.close(() => r()))
  };
}
