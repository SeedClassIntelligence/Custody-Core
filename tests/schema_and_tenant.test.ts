import { describe, it, expect, beforeAll } from 'vitest';
import { app } from '../server';
import {
  getDbPool,
  getAdminPool,
  runMigrations,
  insertEvent,
  verifyServerProjectEvents
} from '../server/db';
import { assertPoolTargetsTestDb } from './support/safety';
import { withTriggersBypassed } from './support/cleanup';

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
    expect(recorded.rows.map((r) => r.version)).toEqual([
      '001_initial_schema.sql',
      '002_hashed_timestamp_constraint.sql'
    ]);
    const role = await adminDb.query(`SELECT rolname FROM pg_roles WHERE rolname = 'custody_app'`);
    expect(role.rows).toHaveLength(1);
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
      expect(countRes.rows).toBeDefined();

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

      // Tamper with event 2 behind the trigger's back (local test database only).
      await withTriggersBypassed(adminDb, async (admin) => {
        await admin.query(
          `UPDATE event SET payload = '{"step": "repo_lock", "tampered": true}'::jsonb WHERE id = $1`,
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
    const client = await db.connect();
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

  // Tenant isolation against the real HTTP endpoint. The caller sends NO identity at all (no header,
  // no query parameter), because identity must come from a verified login session (Milestone 2).
  // Until then the endpoint returns every creator's projects, so this test is EXPECTED TO FAIL.
  it('enforces multi-tenant API isolation: creator A cannot read creator B projects through GET /api/v1/projects (fails until Milestone 2)', async () => {
    const client = await db.connect();
    const server = app.listen(0);
    await new Promise<void>((resolve) => server.on('listening', resolve));
    const addr = server.address();
    const port = typeof addr === 'object' && addr ? addr.port : 3000;
    const creatorIds: string[] = [];

    try {
      const creatorBRes = await client.query(
        `INSERT INTO creator (identity_id, display_name, email)
         VALUES ('tenant_bob_' || gen_random_uuid(), 'Bob Creator', 'bob_' || gen_random_uuid() || '@custody.io')
         RETURNING id`
      );
      creatorIds.push(creatorBRes.rows[0].id);
      const projBRes = await client.query(
        `INSERT INTO project (creator_id, name, purpose)
         VALUES ($1, 'Bob Proprietary AI', 'Proprietary')
         RETURNING id`,
        [creatorIds[0]]
      );
      const projBId = projBRes.rows[0].id;

      const creatorARes = await client.query(
        `INSERT INTO creator (identity_id, display_name, email)
         VALUES ('tenant_alice_' || gen_random_uuid(), 'Alice Creator', 'alice_' || gen_random_uuid() || '@custody.io')
         RETURNING id`
      );
      creatorIds.push(creatorARes.rows[0].id);
      await client.query(
        `INSERT INTO project (creator_id, name, purpose)
         VALUES ($1, 'Alice Confidential Core', 'Confidential')`,
        [creatorIds[1]]
      );

      // Anonymous request: no x-creator-id header, no creator_id query parameter.
      const res = await fetch(`http://127.0.0.1:${port}/api/v1/projects`);
      const data: any = await res.json();
      const returnedProjects = data.projects || [];

      const bobProjectLeaked = returnedProjects.some((p: any) => p.id === projBId);
      expect(bobProjectLeaked).toBe(false);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      client.release();
      await withTriggersBypassed(adminDb, async (admin) => {
        await admin.query('DELETE FROM project WHERE creator_id = ANY($1::uuid[])', [creatorIds]);
        await admin.query('DELETE FROM creator WHERE id = ANY($1::uuid[])', [creatorIds]);
      });
    }
  });
});
