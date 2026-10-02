import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { getAdminPool, runMigrations, verifyServerProjectEvents } from '../server/db';
import { assertPoolTargetsTestDb } from './support/safety';
import { withTriggersBypassed } from './support/cleanup';
import { api, startApp, RunningApp } from './support/api';
import { authStack, createMfaUser } from './support/authStack';

describe('Claiming a project through the real API (as a logged-in creator)', () => {
  const adminDb = getAdminPool()!;
  let running: RunningApp;
  const userIds: string[] = [];

  beforeAll(async () => {
    authStack();
    await assertPoolTargetsTestDb(adminDb);
    const res = await runMigrations();
    if (!res.success) throw new Error(res.message);
    running = await startApp();
  });

  afterAll(async () => {
    await running.stop();
    await withTriggersBypassed(adminDb, async (admin) => {
      const creators = (await admin.query('SELECT id FROM creator WHERE identity_id = ANY($1::text[])', [userIds])).rows.map((r) => r.id);
      const projects = (await admin.query('SELECT id FROM project WHERE creator_id = ANY($1::uuid[])', [creators])).rows.map((r) => r.id);
      await admin.query('DELETE FROM event WHERE project_id = ANY($1::uuid[])', [projects]);
      await admin.query('DELETE FROM repository WHERE project_id = ANY($1::uuid[])', [projects]);
      await admin.query('DELETE FROM project WHERE id = ANY($1::uuid[])', [projects]);
      await admin.query('DELETE FROM creator WHERE id = ANY($1::uuid[])', [creators]);
    });
  });

  it('records the project and a first project.claimed event, by the logged-in creator, whose hash chain verifies', async () => {
    const { session } = await createMfaUser('claim', running.base);
    userIds.push(session.userId);
    const me = await api(running.base, session, '/me');

    // Exactly what the browser sends: name and purpose only.
    const res = await api(running.base, session, '/projects', {
      method: 'POST',
      body: { name: 'Claim Flow Project', purpose: 'Proving the claim flow records real data' }
    });
    expect(res.status).toBe(201);
    const projectId: string = res.body.project.id;
    expect(res.body.project.name).toBe('Claim Flow Project');
    expect(res.body.project.creator_id).toBe(me.body.creator.id);
    expect(res.body.event.action).toBe('project.claimed');
    expect(res.body.event.seq).toBe(1);
    expect(res.body.event.actor_id).toBe(me.body.creator.id);

    const events = await api(running.base, session, `/projects/${projectId}/events`);
    expect(events.body.count).toBe(1);
    expect(events.body.events[0].actor_id).toBe(me.body.creator.id);
    expect(events.body.events[0].payload.purpose).toBe('Proving the claim flow records real data');

    const verified = await verifyServerProjectEvents(projectId);
    expect(verified.isValid).toBe(true);
    expect(verified.totalEvents).toBe(1);
  });

  it('rejects a claim with no purpose and records nothing', async () => {
    const { session } = await createMfaUser('nopurpose', running.base);
    userIds.push(session.userId);
    const before = (await adminDb.query('SELECT COUNT(*)::int AS n FROM project')).rows[0].n;
    const res = await api(running.base, session, '/projects', { method: 'POST', body: { name: 'No Purpose' } });
    expect(res.status).toBe(400);
    expect((await adminDb.query('SELECT COUNT(*)::int AS n FROM project')).rows[0].n).toBe(before);
  });
});
