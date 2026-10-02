import { describe, it, expect, beforeAll } from 'vitest';
import { app } from '../server';
import { getAdminPool, runMigrations, verifyServerProjectEvents } from '../server/db';
import { assertPoolTargetsTestDb } from './support/safety';
import { withTriggersBypassed } from './support/cleanup';

describe('Claiming a project through the real API', () => {
  const adminDb = getAdminPool()!;

  beforeAll(async () => {
    await assertPoolTargetsTestDb(adminDb);
    const res = await runMigrations();
    if (!res.success) throw new Error(res.message);
  });

  it('records the project and a first project.claimed event whose hash chain verifies', async () => {
    const server = app.listen(0);
    await new Promise<void>((resolve) => server.on('listening', resolve));
    const addr = server.address();
    const port = typeof addr === 'object' && addr ? addr.port : 0;
    let projectId: string | undefined;

    try {
      // Exactly what the browser sends: name and purpose only.
      const res = await fetch(`http://127.0.0.1:${port}/api/v1/projects`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'Claim Flow Project', purpose: 'Proving the claim flow records real data' })
      });
      const body: any = await res.json();
      expect(res.status).toBe(201);
      projectId = body.project.id;
      expect(body.project.name).toBe('Claim Flow Project');
      expect(body.event.action).toBe('project.claimed');
      expect(body.event.seq).toBe(1);

      const eventsRes = await fetch(`http://127.0.0.1:${port}/api/v1/projects/${projectId}/events`);
      const events: any = await eventsRes.json();
      expect(events.count).toBe(1);
      expect(events.events[0].payload.purpose).toBe('Proving the claim flow records real data');

      const verified = await verifyServerProjectEvents(projectId!);
      expect(verified.isValid).toBe(true);
      expect(verified.totalEvents).toBe(1);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
      if (projectId) {
        await withTriggersBypassed(adminDb, async (admin) => {
          await admin.query('DELETE FROM event WHERE project_id = $1', [projectId]);
          await admin.query('DELETE FROM repository WHERE project_id = $1', [projectId]);
          await admin.query('DELETE FROM project WHERE id = $1', [projectId]);
        });
      }
    }
  });

  it('rejects a claim with no purpose and records nothing', async () => {
    const server = app.listen(0);
    await new Promise<void>((resolve) => server.on('listening', resolve));
    const addr = server.address();
    const port = typeof addr === 'object' && addr ? addr.port : 0;
    try {
      const before = await adminDb.query('SELECT COUNT(*)::int AS n FROM project');
      const res = await fetch(`http://127.0.0.1:${port}/api/v1/projects`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'No Purpose' })
      });
      expect(res.status).toBe(400);
      const after = await adminDb.query('SELECT COUNT(*)::int AS n FROM project');
      expect(after.rows[0].n).toBe(before.rows[0].n);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    }
  });
});
