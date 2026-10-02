import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Server } from 'node:http';
import { app } from '../server';
import { getAdminPool, runMigrations } from '../server/db';
import { assertPoolTargetsTestDb } from './support/safety';

describe('Project ids in the URL', () => {
  let server: Server;
  let base = '';

  beforeAll(async () => {
    await assertPoolTargetsTestDb(getAdminPool()!);
    const res = await runMigrations();
    if (!res.success) throw new Error(res.message);
    server = app.listen(0);
    await new Promise<void>((resolve) => server.on('listening', resolve));
    const addr = server.address();
    base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
  });

  const malformed = ['not-a-uuid', '123', 'abc-def', '00000000-0000-0000-0000-00000000000g', "1'%20OR%20'1'='1", '..%2F..%2Fetc', '%00', 'x'.repeat(300)];

  it.each(malformed)('GET /projects/%s/events returns 404, not 500', async (id) => {
    const res = await fetch(`${base}/api/v1/projects/${id}/events`);
    expect(res.status).toBe(404);
    expect((await res.json() as any).error).toBe('Project not found.');
  });

  it.each(malformed)('GET /projects/%s/events/verify returns 404, not 500', async (id) => {
    const res = await fetch(`${base}/api/v1/projects/${id}/events/verify`);
    expect(res.status).toBe(404);
    expect((await res.json() as any).error).toBe('Project not found.');
  });

  it('a well-formed id that names no project is still answered normally (empty log), not as a server error', async () => {
    const missing = '00000000-0000-4000-8000-000000000000';
    const events = await fetch(`${base}/api/v1/projects/${missing}/events`);
    expect(events.status).toBe(200);
    expect(((await events.json()) as any).count).toBe(0);
    const verify = await fetch(`${base}/api/v1/projects/${missing}/events/verify`);
    expect(verify.status).toBe(200);
  });
});
