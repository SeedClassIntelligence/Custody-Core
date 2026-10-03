import { describe, it, expect, beforeAll } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  getDbPool,
  getAdminPool,
  runMigrations,
  insertEvent,
  verifyServerProjectEvents
} from '../server/db';
import { assertPoolTargetsTestDb } from './support/safety';
import { withTriggersBypassed } from './support/cleanup';
import { api, startApp } from './support/api';
import { authStack, createMfaUser, mfaStatus } from './support/authStack';

const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'server', 'migrations');

describe('PostgreSQL Schema, Append-Only Triggers, Restricted Roles & Multi-Tenant Scoping', () => {
  const db = getDbPool();
  const adminDb = getAdminPool();
  if (!db || !adminDb) {
    throw new Error('Test database is not configured: tests/setupEnv.ts did not provide a database URL.');
  }

  beforeAll(async () => {
    // Refuse to run a single test unless both pools provably point at the local test database.
    await assertPoolTargetsTestDb(adminDb);
    // Migrations create the custody_app role, so they must run before the app pool can connect.
    const res = await runMigrations();
    if (!res.success) throw new Error(`Migrations failed: ${res.message}`);
    await assertPoolTargetsTestDb(db);
  });

  it('records every migration file in schema_migrations and provisions the restricted custody_app role', async () => {
    const recorded = await adminDb.query('SELECT version FROM schema_migrations ORDER BY version');
    const onDisk = fs.readdirSync(migrationsDir).filter((f) => /^\d+_.+\.sql$/.test(f)).sort();
    expect(onDisk.length).toBeGreaterThanOrEqual(3);
    expect(recorded.rows.map((r) => r.version)).toEqual(onDisk);
    const role = await adminDb.query(`SELECT rolname FROM pg_roles WHERE rolname = 'custody_app'`);
    expect(role.rows).toHaveLength(1);
  });

  it('gives the app role no access at all to schema_migrations', async () => {
    const client = await db.connect();
    try {
      for (const sql of ['SELECT * FROM schema_migrations', "INSERT INTO schema_migrations (version) VALUES ('999_forged.sql')", 'DELETE FROM schema_migrations']) {
        await expect(client.query(sql)).rejects.toThrow(/permission denied for table schema_migrations/);
      }
    } finally {
      client.release();
    }
  });

  it('creates all 11 required tables and both append-only triggers in the live database', async () => {
    const tables = await adminDb.query(
      `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`
    );
    const present = tables.rows.map((r) => r.table_name);
    for (const t of [
      'creator', 'developer', 'connection', 'project', 'repository', 'agreement_template',
      'door', 'door_repository', 'workspace', 'mirror_snapshot', 'event'
    ]) {
      expect(present).toContain(t);
    }

    const triggers = await adminDb.query(
      `SELECT tgname FROM pg_trigger WHERE tgrelid = 'event'::regclass AND NOT tgisinternal`
    );
    const names = triggers.rows.map((r) => r.tgname);
    expect(names).toContain('trg_event_append_only');
    expect(names).toContain('trg_event_prevent_truncate');
  });

  // Defect 2 Test: App connects as custody_app role, never as postgres
  it('verifies the application connects as restricted custody_app role with least privilege', async () => {
    const client = await db.connect();
    try {
      const userRes = await client.query('SELECT current_user, session_user;');
      expect(userRes.rows[0].current_user).toBe('custody_app');

      // Can SELECT from event
      const countRes = await client.query('SELECT COUNT(*) FROM event;');
      expect(Number(countRes.rows[0].count)).toBeGreaterThanOrEqual(0);

      // 1. UPDATE on event table must fail with permission denied at grant level
      let updatePermFailed = false;
      try {
        await client.query("UPDATE event SET payload = '{}'::jsonb WHERE id = gen_random_uuid()");
      } catch (err: any) {
        updatePermFailed = true;
        expect(err.message).toContain('permission denied for table event');
      }
      expect(updatePermFailed).toBe(true);

      // 2. DELETE on event table must fail with permission denied at grant level
      let deletePermFailed = false;
      try {
        await client.query("DELETE FROM event WHERE id = gen_random_uuid()");
      } catch (err: any) {
        deletePermFailed = true;
        expect(err.message).toContain('permission denied for table event');
      }
      expect(deletePermFailed).toBe(true);

      // 3. TRUNCATE on event table must fail with permission denied at grant level
      let truncatePermFailed = false;
      try {
        await client.query("TRUNCATE TABLE event");
      } catch (err: any) {
        truncatePermFailed = true;
        expect(err.message).toContain('permission denied for table event');
      }
      expect(truncatePermFailed).toBe(true);
    } finally {
      client.release();
    }
  });

  // Requirement 4 Test: custody_app role cannot disable triggers on event table
  it('shows ALTER TABLE event DISABLE TRIGGER fails as custody_app role', async () => {
    const client = await db.connect();
    try {
      // Disabling all triggers as custody_app must fail
      let disableAllFailed = false;
      try {
        await client.query('ALTER TABLE event DISABLE TRIGGER ALL;');
      } catch (err: any) {
        disableAllFailed = true;
        expect(err.message).toMatch(/must be owner of table event|permission denied/);
      }
      expect(disableAllFailed).toBe(true);

      // Disabling specific append-only trigger as custody_app must fail
      let disableSpecificFailed = false;
      try {
        await client.query('ALTER TABLE event DISABLE TRIGGER trg_event_append_only;');
      } catch (err: any) {
        disableSpecificFailed = true;
        expect(err.message).toMatch(/must be owner of table event|permission denied/);
      }
      expect(disableSpecificFailed).toBe(true);

      // Disabling truncate trigger as custody_app must fail
      let disableTruncateFailed = false;
      try {
        await client.query('ALTER TABLE event DISABLE TRIGGER trg_event_prevent_truncate;');
      } catch (err: any) {
        disableTruncateFailed = true;
        expect(err.message).toMatch(/must be owner of table event|permission denied/);
      }
      expect(disableTruncateFailed).toBe(true);
    } finally {
      client.release();
    }
  });

  // Defect 2 Test: BEFORE TRUNCATE statement trigger on event table
  it('verifies BEFORE TRUNCATE trigger strictly rejects TRUNCATE statements on event table', async () => {
    const adminClient = await adminDb.connect();
    try {
      let truncateFailed = false;
      try {
        await adminClient.query('TRUNCATE TABLE event;');
      } catch (err: any) {
        truncateFailed = true;
        expect(err.message).toContain('Table event is append-only: TRUNCATE operations are strictly forbidden.');
      }
      expect(truncateFailed).toBe(true);
    } finally {
      adminClient.release();
    }
  });

  // Append-only trigger test (UPDATE & DELETE rejection)
  it('verifies the append-only trigger strictly rejects UPDATE and DELETE on event table', async () => {
    const adminClient = await adminDb.connect();
    try {
      await adminClient.query('BEGIN');

      const creator = await adminClient.query(
        `INSERT INTO creator (identity_id, display_name, email)
         VALUES ('auth_trigger_test', 'Trigger Test', 'trigger@custody.io')
         RETURNING id`
      );
      const project = await adminClient.query(
        `INSERT INTO project (creator_id, name, purpose)
         VALUES ($1, 'Trigger Test Project', 'Testing immutability')
         RETURNING id`,
        [creator.rows[0].id]
      );

      // Insert an event directly within this client's transaction
      const eventRes = await adminClient.query(
        `INSERT INTO event (
          seq, project_id, actor_type, actor_id, action, subject_type, subject_id,
          payload, prev_hash, hash, seed_signature_id, hashed_timestamp
        ) VALUES (1, $1, 'creator', $2, 'project.claimed', 'project', $3, '{"intent":"immutable"}'::jsonb, '0000000000000000000000000000000000000000000000000000000000000000', 'genesis_hash', '', '2026-09-30T12:00:00.000Z')
        RETURNING id`,
        [project.rows[0].id, creator.rows[0].id, String(project.rows[0].id)]
      );
      const eventId = eventRes.rows[0].id;

      // 1. Try to UPDATE the event payload directly in SQL -> MUST FAIL
      await adminClient.query('SAVEPOINT sp_update');
      let updateFailed = false;
      try {
        await adminClient.query(
          `UPDATE event SET payload = '{"tampered": true}'::jsonb WHERE id = $1`,
          [eventId]
        );
      } catch (err: any) {
        updateFailed = true;
        expect(err.message).toContain('Table event is append-only');
        await adminClient.query('ROLLBACK TO SAVEPOINT sp_update');
      }
      expect(updateFailed).toBe(true);

      // 2. Try to DELETE the event directly in SQL -> MUST FAIL
      await adminClient.query('SAVEPOINT sp_delete');
      let deleteFailed = false;
      try {
        await adminClient.query(
          `DELETE FROM event WHERE id = $1`,
          [eventId]
        );
      } catch (err: any) {
        deleteFailed = true;
        expect(err.message).toContain('Table event is append-only');
        await adminClient.query('ROLLBACK TO SAVEPOINT sp_delete');
      }
      expect(deleteFailed).toBe(true);

      await adminClient.query('ROLLBACK');
    } finally {
      try {
        await adminClient.query('ROLLBACK');
      } finally {
        adminClient.release();
      }
    }
  });

  it('keeps one unbroken chain with contiguous seq numbers when 20 events are inserted at the same time', async () => {
    const client = await db.connect();
    let creatorId: string | undefined;
    let projectId: string | undefined;
    try {
      creatorId = (await client.query(
        `INSERT INTO creator (identity_id, display_name, email) VALUES ('auth_concurrency_test', 'Concurrency', 'concurrency@custody.io') RETURNING id`
      )).rows[0].id as string;
      projectId = (await client.query(
        `INSERT INTO project (creator_id, name, purpose) VALUES ($1, 'Concurrency Project', 'Concurrent inserts') RETURNING id`,
        [creatorId]
      )).rows[0].id as string;

      const inserted = await Promise.all(
        Array.from({ length: 20 }, (_, i) =>
          insertEvent({
            project_id: projectId!,
            actor_type: 'system',
            actor_id: 'concurrency_test',
            action: 'test.concurrent',
            subject_type: 'project',
            subject_id: projectId!,
            payload: { n: i }
          })
        )
      );

      expect(inserted.map((e) => Number(e.seq)).sort((a, b) => a - b)).toEqual(Array.from({ length: 20 }, (_, i) => i + 1));
      const verified = await verifyServerProjectEvents(projectId);
      expect(verified.isValid).toBe(true);
      expect(verified.totalEvents).toBe(20);
    } finally {
      client.release();
      if (projectId || creatorId) {
        await withTriggersBypassed(adminDb, async (admin) => {
          if (projectId) {
            await admin.query('DELETE FROM event WHERE project_id = $1', [projectId]);
            await admin.query('DELETE FROM project WHERE id = $1', [projectId]);
          }
          if (creatorId) await admin.query('DELETE FROM creator WHERE id = $1', [creatorId]);
        });
      }
    }
  });

  // Defect 1 Test: 3 events through insertEvent -> verifyServerProjectEvents valid -> tamper one row -> verify fails at seq 2
  it('inserts 3 events through insertEvent, verifies intact hash-chain, tampers one row and confirms verification fails at that event', async () => {
    const client = await db.connect();
    let creatorId: string | undefined;
    let projectId: string | undefined;
    try {
      const creatorRes = await client.query(
        `INSERT INTO creator (identity_id, display_name, email)
         VALUES ('auth_hashchain_test', 'HashChain Creator', 'hashchain@custody.io')
         RETURNING id`
      );
      creatorId = creatorRes.rows[0].id as string;

      const projRes = await client.query(
        `INSERT INTO project (creator_id, name, purpose)
         VALUES ($1, 'Tamper Test Project', 'Testing cryptographic verification')
         RETURNING id`,
        [creatorId]
      );
      projectId = projRes.rows[0].id as string;

      const e1 = await insertEvent({
        project_id: projectId,
        actor_type: 'creator',
        actor_id: creatorId,
        action: 'project.claimed',
        subject_type: 'project',
        subject_id: projectId,
        payload: { step: 'initial_claim', audit: 'secure' }
      });

      const e2 = await insertEvent({
        project_id: projectId,
        actor_type: 'system',
        actor_id: 'enforcer_service',
        action: 'repository.locked',
        subject_type: 'project',
        subject_id: projectId,
        payload: { step: 'repo_lock', branch: 'main' }
      });

      const e3 = await insertEvent({
        project_id: projectId,
        actor_type: 'creator',
        actor_id: creatorId,
        action: 'door.created',
        subject_type: 'door',
        subject_id: 'door_test_01',
        payload: { step: 'open_door', duration_days: 7 }
      });

      for (const e of [e1, e2, e3]) {
        expect(typeof e.hashed_timestamp).toBe('string');
        expect(e.hashed_timestamp).not.toBe('');
      }

      const initialVerify = await verifyServerProjectEvents(projectId);
      expect(initialVerify.isValid).toBe(true);
      expect(initialVerify.totalEvents).toBe(3);
      expect(initialVerify.brokenAtSeq).toBeUndefined();

      // Tamper with event 2 behind the trigger's back (local test database only). Changing the stored
      // payload alone is also impossible, see append_event.test.ts; here we change who did it.
      await withTriggersBypassed(adminDb, async (admin) => {
        await admin.query(
          `UPDATE event SET actor_id = 'someone_else' WHERE id = $1`,
          [e2.id]
        );
      });

      const tamperedVerify = await verifyServerProjectEvents(projectId);
      expect(tamperedVerify.isValid).toBe(false);
      expect(tamperedVerify.brokenAtSeq).toBe(2);
    } finally {
      client.release();
      if (projectId || creatorId) {
        await withTriggersBypassed(adminDb, async (admin) => {
          if (projectId) {
            await admin.query('DELETE FROM event WHERE project_id = $1', [projectId]);
            await admin.query('DELETE FROM project WHERE id = $1', [projectId]);
          }
          if (creatorId) await admin.query('DELETE FROM creator WHERE id = $1', [creatorId]);
        });
      }
    }
  });

  // Requirement 2 Test: hashed_timestamp has no DEFAULT and has CHECK (hashed_timestamp <> '')
  it('proves inserting into event without hashed_timestamp fails (NOT NULL and non-empty CHECK constraint)', async () => {
    const client = await adminDb.connect(); // custody_app has no INSERT on event; test the table's own constraints as the owner
    try {
      await client.query('BEGIN');

      const creator = await client.query(
        `INSERT INTO creator (identity_id, display_name, email)
         VALUES ('auth_timestamp_test', 'Timestamp Test', 'timestamp@custody.io')
         RETURNING id`
      );
      const project = await client.query(
        `INSERT INTO project (creator_id, name, purpose)
         VALUES ($1, 'Timestamp Project', 'Testing timestamp constraint')
         RETURNING id`,
        [creator.rows[0].id]
      );
      const projectId = project.rows[0].id;
      const creatorId = creator.rows[0].id;

      // 1. Insert without hashed_timestamp column (omitted -> violates NOT NULL since DEFAULT '' was removed)
      await client.query('SAVEPOINT sp_omitted');
      let insertWithoutTimestampFailed = false;
      try {
        await client.query(
          `INSERT INTO event (
            seq, project_id, actor_type, actor_id, action, subject_type, subject_id,
            payload, prev_hash, hash
          ) VALUES (1, $1, 'creator', $2, 'test.action', 'project', $3, '{}'::jsonb,
            '0000000000000000000000000000000000000000000000000000000000000000',
            '0000000000000000000000000000000000000000000000000000000000000001'
          )`,
          [projectId, creatorId, String(projectId)]
        );
      } catch (err: any) {
        insertWithoutTimestampFailed = true;
        expect(err.message).toMatch(/null value in column "hashed_timestamp" of relation "event" violates not-null constraint/);
        await client.query('ROLLBACK TO SAVEPOINT sp_omitted');
      }
      expect(insertWithoutTimestampFailed).toBe(true);

      // 2. Insert with empty string -> violates CHECK (hashed_timestamp <> '')
      await client.query('SAVEPOINT sp_empty');
      let insertEmptyTimestampFailed = false;
      try {
        await client.query(
          `INSERT INTO event (
            seq, project_id, actor_type, actor_id, action, subject_type, subject_id,
            payload, prev_hash, hash, hashed_timestamp
          ) VALUES (1, $1, 'creator', $2, 'test.action', 'project', $3, '{}'::jsonb,
            '0000000000000000000000000000000000000000000000000000000000000000',
            '0000000000000000000000000000000000000000000000000000000000000001',
            ''
          )`,
          [projectId, creatorId, String(projectId)]
        );
      } catch (err: any) {
        insertEmptyTimestampFailed = true;
        expect(err.message).toMatch(/violates check constraint "chk_event_hashed_timestamp"/);
        await client.query('ROLLBACK TO SAVEPOINT sp_empty');
      }
      expect(insertEmptyTimestampFailed).toBe(true);

      await client.query('ROLLBACK');
    } finally {
      try {
        await client.query('ROLLBACK');
      } finally {
        client.release();
      }
    }
  });

  // Tenant isolation through the real API: two real people, each with a verified authenticator-app code,
  // each signed in with their own session. Identity comes only from the session.
  it('enforces multi-tenant API isolation: creator A cannot list or read creator B\'s project or events', async () => {
    authStack();
    const running = await startApp();
    const alice = await createMfaUser('tenantA', running.base);
    const bob = await createMfaUser('tenantB', running.base);
    try {
      expect((await mfaStatus(running.base, alice.session)).body.verified).toBe(true);
      expect((await mfaStatus(running.base, bob.session)).body.verified).toBe(true);
      expect(alice.session.userId).not.toBe(bob.session.userId);

      const aliceClaim = await api(running.base, alice.session, '/projects', { method: 'POST', body: { name: 'Alice Confidential Core', purpose: 'Confidential' } });
      const bobClaim = await api(running.base, bob.session, '/projects', { method: 'POST', body: { name: 'Bob Proprietary AI', purpose: 'Proprietary' } });
      expect(aliceClaim.status).toBe(201);
      expect(bobClaim.status).toBe(201);
      const aliceProject: string = aliceClaim.body.project.id;
      const bobProject: string = bobClaim.body.project.id;

      // A cannot LIST B's project; each sees exactly their own.
      const aliceList = await api(running.base, alice.session, '/projects');
      expect(aliceList.status).toBe(200);
      expect(aliceList.body.projects.map((p: any) => p.id)).toEqual([aliceProject]);
      const bobList = await api(running.base, bob.session, '/projects');
      expect(bobList.body.projects.map((p: any) => p.id)).toEqual([bobProject]);

      // A cannot READ B's events or verify B's record, and the answer is identical to "no such project",
      // so it cannot be used to discover that B's project exists.
      const unknown = '00000000-0000-4000-8000-0000000000aa';
      const nothing = await api(running.base, alice.session, `/projects/${unknown}/events`);
      for (const suffix of ['/events', '/events/verify']) {
        const theirs = await api(running.base, alice.session, `/projects/${bobProject}${suffix}`);
        const missing = await api(running.base, alice.session, `/projects/${unknown}${suffix}`);
        expect(theirs.status).toBe(404);
        expect(theirs).toEqual(missing);
      }
      expect(nothing.status).toBe(404);

      // The same requests work for the owner, so the 404 above is about ownership and not a broken route.
      const bobEvents = await api(running.base, bob.session, `/projects/${bobProject}/events`);
      expect(bobEvents.status).toBe(200);
      expect(bobEvents.body.count).toBe(1);
      expect((await api(running.base, bob.session, `/projects/${bobProject}/events/verify`)).body.valid).toBe(true);
      expect((await api(running.base, alice.session, `/projects/${aliceProject}/events`)).body.count).toBe(1);

      // No client-chosen identity changes any of this.
      const spoof = await api(running.base, alice.session, `/projects?creator_id=${bobClaim.body.project.creator_id}`, {
        headers: { 'x-creator-id': bobClaim.body.project.creator_id }
      });
      expect(spoof.body.projects.map((p: any) => p.id)).toEqual([aliceProject]);
    } finally {
      await running.stop();
      await withTriggersBypassed(adminDb, async (admin) => {
        const creators = (await admin.query('SELECT id FROM creator WHERE identity_id = ANY($1::text[])', [[alice.session.userId, bob.session.userId]])).rows.map((r) => r.id);
        const projects = (await admin.query('SELECT id FROM project WHERE creator_id = ANY($1::uuid[])', [creators])).rows.map((r) => r.id);
        await admin.query('DELETE FROM event WHERE project_id = ANY($1::uuid[])', [projects]);
        await admin.query('DELETE FROM project WHERE id = ANY($1::uuid[])', [projects]);
        await admin.query('DELETE FROM creator WHERE id = ANY($1::uuid[])', [creators]);
      });
    }
  });
});
