import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { getAdminPool, runMigrations } from '../server/db';
import { assertPoolTargetsTestDb } from './support/safety';
import { withTriggersBypassed } from './support/cleanup';
import { api, startApp, RunningApp } from './support/api';
import { authStack, createMfaUser, AuthSession } from './support/authStack';

describe('Project ids in the URL (as a logged-in creator)', () => {
  const adminDb = getAdminPool()!;
  let running: RunningApp;
  let session: AuthSession;

  beforeAll(async () => {
    authStack();
    await assertPoolTargetsTestDb(adminDb);
    const res = await runMigrations();
    if (!res.success) throw new Error(res.message);
    running = await startApp();
    session = (await createMfaUser('ids', running.base)).session;
    await api(running.base, session, '/me'); // creates the creator row
  });

  afterAll(async () => {
    await running.stop();
    await withTriggersBypassed(adminDb, async (admin) => {
      await admin.query('DELETE FROM creator WHERE identity_id = $1', [session.userId]);
    });
  });

  const malformed = ['not-a-uuid', '123', 'abc-def', '00000000-0000-0000-0000-00000000000g', "1'%20OR%20'1'='1", '..%2F..%2Fetc', '%00', 'x'.repeat(300)];

  it.each(malformed)('GET /projects/%s/events returns 404, not 500', async (id) => {
    const res = await api(running.base, session, `/projects/${id}/events`);
    expect(res.status).toBe(404);
    expect(res.body.error).toBe('Project not found.');
  });

  it.each(malformed)('GET /projects/%s/events/verify returns 404, not 500', async (id) => {
    const res = await api(running.base, session, `/projects/${id}/events/verify`);
    expect(res.status).toBe(404);
    expect(res.body.error).toBe('Project not found.');
  });

  it('a well-formed id that names no project is also 404 (it is indistinguishable from someone else\'s project)', async () => {
    const missing = '00000000-0000-4000-8000-000000000000';
    expect((await api(running.base, session, `/projects/${missing}/events`)).status).toBe(404);
    expect((await api(running.base, session, `/projects/${missing}/events/verify`)).status).toBe(404);
  });
});
