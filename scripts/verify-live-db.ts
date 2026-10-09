import dotenv from 'dotenv';
dotenv.config(); // same rule as the app: values already in the shell win over .env

import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { getAppDatabaseUrl, getAdminDatabaseUrl, appDatabaseConfigProblem, sslFor } from '../server/db';
import { computeEventHash } from '../shared/crypto';

/**
 * Checks, against whatever database the app is configured for (including the live one), that the
 * event-log protections are in place. It writes NOTHING permanent: the one write test runs inside a
 * transaction that is always rolled back, because the live event log can never be cleaned up.
 *
 *   npm run migrate        (applies the migrations as the admin role)
 *   npm run verify-live    (this script)
 *
 * It never prints connection strings or passwords.
 */
const results: string[] = [];
let failed = 0;
function check(ok: boolean, text: string) {
  results.push(`${ok ? 'PASS' : 'FAIL'}  ${text}`);
  if (!ok) failed++;
}

function poolFor(url: string) {
  return new pg.Pool({
    connectionString: url,
    ssl: sslFor(url),
    connectionTimeoutMillis: 20000
  });
}

async function main() {
  const appUrl = getAppDatabaseUrl();
  const adminUrl = getAdminDatabaseUrl();
  const problem = appDatabaseConfigProblem();
  if (problem) throw new Error(problem);
  if (!appUrl || !adminUrl) throw new Error('No database is configured (DATABASE_URL is missing).');

  const admin = poolFor(adminUrl);
  const app = poolFor(appUrl);
  try {
    // 0. Who are we?
    const who = await app.query('SELECT current_user AS u');
    check(who.rows[0].u === 'custody_app', `the application connects as custody_app (connected as ${who.rows[0].u})`);

    // 1. Migrations recorded
    const migrations = await admin.query('SELECT version FROM schema_migrations ORDER BY version');
    const versions = migrations.rows.map((r) => r.version as string);
    check(versions.some((v) => v.startsWith('003_')), `migration 003 is recorded (recorded: ${versions.join(', ') || 'none'})`);

    // 2. Privileges as the app role sees them
    const priv = await app.query(
      `SELECT has_table_privilege('custody_app','event','INSERT') AS ins,
              has_table_privilege('custody_app','event','UPDATE') AS upd,
              has_table_privilege('custody_app','event','DELETE') AS del,
              has_table_privilege('custody_app','event','TRUNCATE') AS trunc,
              has_table_privilege('custody_app','event','SELECT') AS sel,
              has_function_privilege('custody_app','append_event(uuid,text,text,text,text,text,jsonb)','EXECUTE') AS exec_fn`
    );
    const p = priv.rows[0];
    check(p.ins === false, 'custody_app has no INSERT privilege on event');
    check(p.upd === false && p.del === false && p.trunc === false, 'custody_app has no UPDATE, DELETE or TRUNCATE on event');
    check(p.sel === true, 'custody_app can still read event');
    check(p.exec_fn === true, 'custody_app can execute append_event');

    // 3. A direct INSERT as custody_app is refused (the refused statement changes nothing)
    let refused = '';
    try {
      await app.query(
        `INSERT INTO event (seq, project_id, actor_type, actor_id, action, subject_type, subject_id, payload, prev_hash, hash, hashed_timestamp)
         VALUES (1, gen_random_uuid(), 'creator', 'x', 'x', 'x', 'x', '{}'::jsonb, repeat('0', 64), repeat('1', 64), '2026-01-01T00:00:00.000Z')`
      );
    } catch (err: any) {
      refused = String(err.message);
    }
    check(/permission denied for table event/.test(refused), `a direct INSERT INTO event as custody_app is refused (${refused || 'it was NOT refused'})`);

    // 4. append_event works as custody_app. Everything below is rolled back.
    const client = await app.connect();
    const marker = `verify_live_${randomUUID()}`;
    let projectId = '';
    try {
      await client.query('BEGIN');
      const creator = (await client.query(
        `INSERT INTO creator (identity_id, display_name, email) VALUES ($1, 'Rolled back check', $1 || '@invalid.example') RETURNING id`,
        [marker]
      )).rows[0].id as string;
      projectId = (await client.query(
        `INSERT INTO project (creator_id, name, purpose) VALUES ($1, 'Rolled back check', 'never committed') RETURNING id`, [creator]
      )).rows[0].id as string;

      const call = (action: string, payload: object) => client.query(
        `SELECT * FROM append_event($1::uuid, 'system', 'verify_live', $2, 'project', $3, $4::jsonb)`,
        [projectId, action, projectId, JSON.stringify(payload)]
      );
      const e1 = (await call('verify.first', { n: 1, note: 'café' })).rows[0];
      const e2 = (await call('verify.second', { n: 2 })).rows[0];

      check(Number(e1.seq) === 1 && Number(e2.seq) === 2, `append_event assigned sequence numbers ${e1.seq} and ${e2.seq}`);
      check(e1.prev_hash === '0'.repeat(64) && e2.prev_hash === e1.hash, 'append_event linked the second event to the first');
      check(e1.hash_version === 2 && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(e1.hashed_timestamp), 'the database assigned hash_version 2 and a timestamp');
      const recomputed = await computeEventHash({
        seq: Number(e2.seq), project_id: e2.project_id, actor_type: e2.actor_type, actor_id: e2.actor_id, action: e2.action,
        subject_type: e2.subject_type, subject_id: e2.subject_id, payload: e2.payload, prev_hash: e2.prev_hash,
        timestamp: e2.hashed_timestamp, hash_version: e2.hash_version, canonical_payload: e2.canonical_payload
      });
      check(recomputed === e2.hash, 'JavaScript recomputes the same hash the database stored');
    } finally {
      await client.query('ROLLBACK').catch(() => undefined);
      client.release();
    }

    // 5. Nothing was left behind
    const left = await admin.query(
      `SELECT (SELECT COUNT(*) FROM event WHERE project_id = $1)::int AS events,
              (SELECT COUNT(*) FROM project WHERE id = $1)::int AS projects,
              (SELECT COUNT(*) FROM creator WHERE identity_id = $2)::int AS creators`,
      [projectId || randomUUID(), marker]
    );
    check(left.rows[0].events === 0 && left.rows[0].projects === 0 && left.rows[0].creators === 0,
      `the check left nothing behind (events ${left.rows[0].events}, projects ${left.rows[0].projects}, creators ${left.rows[0].creators})`);
  } finally {
    await app.end();
    await admin.end();
  }
}

main()
  .catch((err) => {
    const msg = String(err.message ?? err).replace(/postgres(ql)?:\/\/\S+/g, '<url>');
    results.push(`FAIL  could not complete the check: ${err.code ? err.code + ' ' : ''}${msg}`);
    failed++;
  })
  .finally(() => {
    console.log(results.join('\n'));
    console.log(failed === 0 ? '\nALL CHECKS PASSED' : `\n${failed} CHECK(S) FAILED`);
    process.exit(failed === 0 ? 0 : 1);
  });
