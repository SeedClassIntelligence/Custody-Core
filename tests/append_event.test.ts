import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createHash } from 'node:crypto';
import { getDbPool, getAdminPool, runMigrations, insertEvent, verifyServerProjectEvents } from '../server/db';
import { canonicalJson, canonicalJsonV2, computeEventHash } from '../shared/crypto';
import { assertPoolTargetsTestDb } from './support/safety';
import { withTriggersBypassed } from './support/cleanup';

/**
 * The database builds the event chain (append_event). The application role can no longer write
 * seq, prev_hash, timestamp or hash, so it can neither forge nor poison a chain.
 */
describe('Database-built event chain (append_event)', () => {
  const db = getDbPool()!; // custody_app: the application's own database account
  const adminDb = getAdminPool()!;
  const creatorIds: string[] = [];
  const projectIds: string[] = [];
  let projectA = '';
  let projectB = '';

  async function makeProject(label: string): Promise<string> {
    const creator = (await adminDb.query(
      `INSERT INTO creator (identity_id, display_name, email) VALUES ($1, $1, $1 || '@custody.io') RETURNING id`,
      [`append_${label}_${Math.random().toString(36).slice(2, 8)}`]
    )).rows[0].id as string;
    creatorIds.push(creator);
    const project = (await adminDb.query(
      `INSERT INTO project (creator_id, name, purpose) VALUES ($1, $2, 'append_event tests') RETURNING id`,
      [creator, `Append ${label}`]
    )).rows[0].id as string;
    projectIds.push(project);
    return project;
  }

  /** Calls append_event as custody_app with the payload given as raw JSON text (no JavaScript number loss). */
  async function appendRaw(projectId: string, payloadJson: string) {
    return (await db.query(
      `SELECT * FROM append_event($1::uuid, 'system', 'matrix', 'test.matrix', 'project', $2, $3::jsonb)`,
      [projectId, projectId, payloadJson]
    )).rows[0];
  }

  async function eventCount(projectId: string): Promise<number> {
    return (await adminDb.query('SELECT COUNT(*)::int AS n FROM event WHERE project_id = $1', [projectId])).rows[0].n;
  }

  /** Rebuilds the hash from the stored row with plain string-building and node:crypto, no shared code. */
  function independentHash(r: any): string {
    const s = (v: string) => JSON.stringify(v);
    const envelope =
      '{"action":' + s(r.action) + ',"actor_id":' + s(r.actor_id) + ',"actor_type":' + s(r.actor_type) +
      ',"payload":' + r.canonical_payload + ',"prev_hash":' + s(r.prev_hash) + ',"project_id":' + s(r.project_id) +
      ',"seq":' + Number(r.seq) + ',"subject_id":' + s(r.subject_id) + ',"subject_type":' + s(r.subject_type) +
      ',"timestamp":' + s(r.hashed_timestamp) + '}';
    return createHash('sha256').update(envelope, 'utf8').digest('hex');
  }

  beforeAll(async () => {
    await assertPoolTargetsTestDb(adminDb);
    const res = await runMigrations();
    if (!res.success) throw new Error(res.message);
    await assertPoolTargetsTestDb(db);
    projectA = await makeProject('A');
    projectB = await makeProject('B');
  });

  afterAll(async () => {
    await withTriggersBypassed(adminDb, async (admin) => {
      await admin.query('DELETE FROM event WHERE project_id = ANY($1::uuid[])', [projectIds]);
      await admin.query('DELETE FROM project WHERE id = ANY($1::uuid[])', [projectIds]);
      await admin.query('DELETE FROM creator WHERE id = ANY($1::uuid[])', [creatorIds]);
    });
  });

  // ---------------------------------------------------------------- the forgery is closed

  it('the app role cannot insert into event at all, including the old forgery (made-up seq and hash into another project)', async () => {
    const before = await eventCount(projectB);
    const client = await db.connect();
    try {
      const forged = [
        // exactly the attack from the review: arbitrary seq, prev_hash and hash, into someone else's project
        `INSERT INTO event (seq, project_id, actor_type, actor_id, action, subject_type, subject_id, payload, prev_hash, hash, hashed_timestamp)
         VALUES (99, '${projectB}', 'creator', 'attacker', 'forged', 'project', 'x', '{}'::jsonb, repeat('a', 64), repeat('b', 64), '2026-01-01T00:00:00.000Z')`,
        // even a perfectly shaped insert
        `INSERT INTO event (seq, project_id, actor_type, actor_id, action, subject_type, subject_id, payload, prev_hash, hash, hashed_timestamp)
         VALUES (1, '${projectB}', 'creator', 'attacker', 'forged', 'project', 'x', '{}'::jsonb, repeat('0', 64), repeat('c', 64), '2026-01-01T00:00:00.000Z')`,
        // and a copy-from-select trick
        `INSERT INTO event SELECT * FROM event WHERE false`
      ];
      for (const sql of forged) {
        await expect(client.query(sql)).rejects.toThrow(/permission denied for table event/);
      }
    } finally {
      client.release();
    }
    expect(await eventCount(projectB)).toBe(before);

    // The chain is not poisoned: the next real event is still seq 1 on a clean genesis.
    const next = await insertEvent({
      project_id: projectB, actor_type: 'system', actor_id: 'real', action: 'real.event',
      subject_type: 'project', subject_id: projectB, payload: { ok: true }
    });
    expect(next.seq).toBe(1);
    expect(next.prev_hash).toBe('0'.repeat(64));
    expect((await verifyServerProjectEvents(projectB)).isValid).toBe(true);
  });

  it('append_event takes no sequence number, hash or timestamp: supplying one is an error', async () => {
    for (const extra of ['p_seq := 99', "p_hash := 'x'", "p_prev_hash := 'x'", "p_timestamp := 'x'"]) {
      await expect(
        db.query(
          `SELECT * FROM append_event(p_project_id := $1::uuid, p_actor_type := 'system', p_actor_id := 'a', p_action := 'a',
            p_subject_type := 'project', p_subject_id := 'a', p_payload := '{}'::jsonb, ${extra})`,
          [projectA]
        )
      ).rejects.toThrow(/does not exist/);
    }
    const sig = await adminDb.query(
      `SELECT pronargs, prosecdef, proconfig, pg_get_function_arguments(oid) AS args
         FROM pg_proc WHERE proname = 'append_event'`
    );
    expect(sig.rows).toHaveLength(1);
    expect(sig.rows[0].pronargs).toBe(7);
    expect(sig.rows[0].prosecdef).toBe(true); // SECURITY DEFINER
    expect(sig.rows[0].proconfig).toContain('search_path=pg_catalog, pg_temp'); // fixed search_path
    expect(sig.rows[0].args).not.toMatch(/seq|hash|timestamp/);
  });

  it('only the app role may call append_event; the public may not, and the app role owns nothing', async () => {
    const priv = await adminDb.query(
      `SELECT has_function_privilege('custody_app', 'append_event(uuid,text,text,text,text,text,jsonb)', 'EXECUTE') AS app,
              has_function_privilege('public', 'append_event(uuid,text,text,text,text,text,jsonb)', 'EXECUTE') AS pub,
              has_function_privilege('custody_app', 'canonical_jsonb(jsonb)', 'EXECUTE') AS canon,
              has_table_privilege('custody_app', 'event', 'INSERT') AS can_insert`
    );
    expect(priv.rows[0]).toEqual({ app: true, pub: false, canon: false, can_insert: false });
  });

  it('the app role cannot replace append_event with its own version', async () => {
    const client = await db.connect();
    try {
      await expect(client.query(
        `CREATE OR REPLACE FUNCTION append_event(uuid,text,text,text,text,text,jsonb) RETURNS public.event
         LANGUAGE sql AS $$ SELECT * FROM public.event LIMIT 1 $$`
      )).rejects.toThrow(/permission denied|must be owner/);
      await expect(client.query(
        `CREATE FUNCTION public.look_alike() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$`
      )).rejects.toThrow(/permission denied/);
    } finally {
      client.release();
    }
  });

  // ---------------------------------------------------------------- what the database assigns

  it('assigns seq, previous hash, timestamp and hash itself, and the hash matches an independent recomputation', async () => {
    const start = Date.now();
    const rows = [];
    for (let i = 1; i <= 3; i++) {
      rows.push(await insertEvent({
        project_id: projectA, actor_type: 'creator', actor_id: `actor_${i}`, action: `test.step_${i}`,
        subject_type: 'project', subject_id: projectA, payload: { step: i, note: 'ünï' }
      }));
    }

    expect(rows.map((r) => r.seq)).toEqual([1, 2, 3]);
    expect(rows[0].prev_hash).toBe('0'.repeat(64));
    expect(rows[1].prev_hash).toBe(rows[0].hash);
    expect(rows[2].prev_hash).toBe(rows[1].hash);

    for (const r of rows) {
      expect(r.hash_version).toBe(2);
      expect(r.seed_signature_id).toBe('');
      expect(r.hashed_timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
      expect(Math.abs(Date.parse(r.hashed_timestamp) - start)).toBeLessThan(60_000);
      expect(r.hash).toMatch(/^[0-9a-f]{64}$/);
      expect(independentHash(r)).toBe(r.hash);
      expect(await computeEventHash({
        seq: r.seq, project_id: r.project_id, actor_type: r.actor_type, actor_id: r.actor_id, action: r.action,
        subject_type: r.subject_type, subject_id: r.subject_id, payload: r.payload, prev_hash: r.prev_hash,
        timestamp: r.hashed_timestamp, hash_version: r.hash_version, canonical_payload: r.canonical_payload
      })).toBe(r.hash);
    }
    expect((await verifyServerProjectEvents(projectA)).isValid).toBe(true);
  });

  it('refuses bad input and records nothing: unknown project, unknown actor type, empty fields, non-object payload, NUL character', async () => {
    const before = await eventCount(projectA);
    const attempts: Array<[string, any[], RegExp]> = [
      [`SELECT * FROM append_event(gen_random_uuid(), 'system', 'a', 'a', 'project', 'a', '{}'::jsonb)`, [], /does not exist/],
      [`SELECT * FROM append_event($1::uuid, 'wizard', 'a', 'a', 'project', 'a', '{}'::jsonb)`, [projectA], /unknown actor_type/],
      [`SELECT * FROM append_event($1::uuid, 'system', '', 'a', 'project', 'a', '{}'::jsonb)`, [projectA], /must not be empty/],
      [`SELECT * FROM append_event($1::uuid, 'system', 'a', '', 'project', 'a', '{}'::jsonb)`, [projectA], /must not be empty/],
      [`SELECT * FROM append_event($1::uuid, 'system', 'a', 'a', 'project', 'a', '[]'::jsonb)`, [projectA], /payload must be a JSON object/],
      [`SELECT * FROM append_event($1::uuid, 'system', 'a', 'a', 'project', 'a', '"text"'::jsonb)`, [projectA], /payload must be a JSON object/],
      [`SELECT * FROM append_event($1::uuid, 'system', 'a', 'a', 'project', 'a', 'null'::jsonb)`, [projectA], /payload must be a JSON object/],
      [`SELECT * FROM append_event($1::uuid, 'system', 'a', 'a', 'project', 'a', NULL)`, [projectA], /every argument is required/],
      [`SELECT * FROM append_event($1::uuid, 'system', 'a', 'a', 'project', 'a', $2::jsonb)`, [projectA, String.raw`{"z":"a\u0000b"}`], /unsupported Unicode escape|\\u0000/i]
    ];
    for (const [sql, params, message] of attempts) {
      await expect(db.query(sql, params)).rejects.toThrow(message);
    }
    expect(await eventCount(projectA)).toBe(before);
  });

  it('the stored payload cannot be changed independently of the hashed text, even by someone who bypasses the triggers', async () => {
    const [row] = (await adminDb.query(`SELECT id FROM event WHERE project_id = $1 AND seq = 1`, [projectA])).rows;
    await withTriggersBypassed(adminDb, async (admin) => {
      await expect(admin.query(`UPDATE event SET payload = '{"tampered":true}'::jsonb WHERE id = $1`, [row.id]))
        .rejects.toThrow(/chk_event_v2_canonical_payload/);
      await expect(admin.query(`UPDATE event SET canonical_payload = '{"tampered":true}' WHERE id = $1`, [row.id]))
        .rejects.toThrow(/chk_event_v2_canonical_payload/);
    });
    expect((await verifyServerProjectEvents(projectA)).isValid).toBe(true);
  });

  // ---------------------------------------------------------------- SQL vs JavaScript: hard payloads

  /**
   * `expected` is the exact canonical text, written by hand. `jsAgrees` says whether the JavaScript
   * serialiser (canonicalJsonV2 over JSON.parse of the same text) produces the same bytes. Where it
   * cannot, the reason is a limit of JavaScript numbers or key ordering, and the verifier uses the
   * stored canonical_payload text instead (see docs/EVENT_HASH_FORMAT.md).
   */
  const matrix: Array<{ name: string; json: string; expected: string; jsAgrees: boolean }> = [
    { name: 'nested objects with unsorted keys', json: '{"b":{"y":[3,2,1],"x":null},"a":true}', expected: '{"a":true,"b":{"x":null,"y":[3,2,1]}}', jsAgrees: true },
    { name: 'empty object and empty containers', json: '{"a":{},"b":[],"c":[[]],"d":[{}]}', expected: '{"a":{},"b":[],"c":[[]],"d":[{}]}', jsAgrees: true },
    { name: 'arrays keep their order, mixed types', json: '{"list":[3,"a",null,false,{"z":1,"a":2},[]]}', expected: '{"list":[3,"a",null,false,{"a":2,"z":1},[]]}', jsAgrees: true },
    { name: 'unicode: accents, CJK, emoji, combining mark', json: String.raw`{"name":"José Ñandú 日本語","emoji":"😀","comb":"á"}`, expected: '{"comb":"á","emoji":"😀","name":"José Ñandú 日本語"}', jsAgrees: true },
    {
      name: 'strings with quotes, backslashes, control characters, DEL and line separators',
      json: String.raw`{"s":"q\" b\\ sl/ t\t n\n r\r bs\b ff\f c1\u0001 c1f\u001f del\u007f ls  ps "}`,
      expected: String.raw`{"s":"q\" b\\ sl/ t\t n\n r\r bs\b ff\f c1\u0001 c1f\u001f del` + '\u007f' + ' ls  ps "}',
      jsAgrees: true
    },
    { name: 'keys needing escapes, empty key, accents', json: String.raw`{"k\"ey":1,"ké":2,"é":3,"Z":4,"a":5,"":6,"k":7}`, expected: String.raw`{"":6,"Z":4,"a":5,"k":7,"k\"ey":1,"ké":2,"é":3}`, jsAgrees: true },
    { name: 'key order is by byte value, not by the database locale (underscore, upper and lower case)', json: '{"b":4,"a":2,"_":1,"B":5,"A":3,"Z":6}', expected: '{"A":3,"B":5,"Z":6,"_":1,"a":2,"b":4}', jsAgrees: true },
    { name: 'key order: an emoji key sorts after a U+FF5E key (code point order)', json: String.raw`{"😀":2,"～":1}`, expected: '{"～":1,"\u{1F600}":2}', jsAgrees: true },
    { name: 'integers including +/- 2^53-1', json: '{"n":[0,1,-1,42,-42,9007199254740991,-9007199254740991]}', expected: '{"n":[0,1,-1,42,-42,9007199254740991,-9007199254740991]}', jsAgrees: true },
    { name: 'decimals, trailing zeros, negative zero', json: '{"d":[0.1,1.5,-2.25,3.14159,100.0,1.50,0.000001,-0.0,-0,2.50e0]}', expected: '{"d":[0.1,1.5,-2.25,3.14159,100,1.5,0.000001,0,0,2.5]}', jsAgrees: true },
    { name: 'exponent notation in the input', json: '{"e":[1e3,1E-2,2.5e2,1e0]}', expected: '{"e":[1000,0.01,250,1]}', jsAgrees: true },
    { name: 'duplicate keys (last wins) and extra whitespace', json: '{ "b" : 1 , "a" : [ 1 , 2 ] , "a" : 3 }', expected: '{"a":3,"b":1}', jsAgrees: true },
    { name: 'a string that looks like JSON', json: String.raw`{"j":"{\"a\":[1,2]}"}`, expected: String.raw`{"j":"{\"a\":[1,2]}"}`, jsAgrees: true },
    { name: 'decimal more precise than a double', json: '{"x":123456789.123456789}', expected: '{"x":123456789.123456789}', jsAgrees: false },
    { name: 'integers beyond 2^53', json: '{"big":9007199254740993,"huge":12345678901234567890123}', expected: '{"big":9007199254740993,"huge":12345678901234567890123}', jsAgrees: false },
    { name: 'very small and very large magnitudes (JavaScript switches to exponent form)', json: '{"t":1e-7,"u":1e21,"v":-1.5e-10}', expected: '{"t":0.0000001,"u":1000000000000000000000,"v":-0.00000000015}', jsAgrees: false },
    {
      name: '60 keys inserted in reverse order',
      json: '{' + Array.from({ length: 60 }, (_, i) => `"k${59 - i}":${59 - i}`).join(',') + '}',
      expected: '{' + Array.from({ length: 60 }, (_, i) => `k${i}`).sort().map((k) => `"${k}":${k.slice(1)}`).join(',') + '}',
      jsAgrees: true
    }
  ];

  it.each(matrix)('canonical payload and hash agree with JavaScript: $name', async ({ json, expected, jsAgrees }) => {
    const row = await appendRaw(projectA, json);

    // 1. The database's canonical text is exactly what was written down by hand.
    expect(row.canonical_payload).toBe(expected);

    // 2. JavaScript, given only the stored row, reproduces the database's hash byte for byte.
    expect(independentHash(row)).toBe(row.hash);
    expect(await computeEventHash({
      seq: Number(row.seq), project_id: row.project_id, actor_type: row.actor_type, actor_id: row.actor_id,
      action: row.action, subject_type: row.subject_type, subject_id: row.subject_id, payload: row.payload,
      prev_hash: row.prev_hash, timestamp: row.hashed_timestamp, hash_version: row.hash_version,
      canonical_payload: row.canonical_payload
    })).toBe(row.hash);

    // 3. Whether JavaScript can also *re-derive* the payload text from the parsed value.
    const rederived = canonicalJsonV2(JSON.parse(json));
    if (jsAgrees) expect(rederived).toBe(expected);
    else expect(rederived).not.toBe(expected);
  });

  it('the v1 (UTF-16 order) serialiser would have ordered astral keys differently, which is why v2 sorts by code point', () => {
    const parsed = JSON.parse(String.raw`{"😀":2,"～":1}`);
    expect(canonicalJson(parsed)).not.toBe(canonicalJsonV2(parsed));
  });

  it('the whole chain, including every hard payload, verifies from the stored rows alone', async () => {
    const result = await verifyServerProjectEvents(projectA);
    expect(result.isValid).toBe(true);
    expect(result.totalEvents).toBe(3 + matrix.length);
  });

  it('twenty concurrent appends keep one chain with contiguous sequence numbers', async () => {
    const results = await Promise.all(
      Array.from({ length: 20 }, (_, i) => insertEvent({
        project_id: projectB, actor_type: 'system', actor_id: 'concurrent', action: 'test.concurrent',
        subject_type: 'project', subject_id: projectB, payload: { i }
      }))
    );
    expect(results).toHaveLength(20);
    const rows = (await adminDb.query('SELECT seq FROM event WHERE project_id = $1 ORDER BY seq', [projectB])).rows;
    expect(rows.map((r) => Number(r.seq))).toEqual(Array.from({ length: rows.length }, (_, i) => i + 1));
    expect((await verifyServerProjectEvents(projectB)).isValid).toBe(true);
  });

  it('runs on a UTF8 database with a non-C collation, like production, so ordering bugs cannot hide', async () => {
    const info = (await adminDb.query(
      `SELECT current_setting('server_encoding') AS enc, datlocprovider AS provider, datcollate FROM pg_database WHERE datname = current_database()`
    )).rows[0];
    expect(info.enc).toBe('UTF8');
    // With the C collation, "C" and the default ordering are identical and the sort test proves nothing.
    expect(info.provider === 'i' || info.datcollate !== 'C').toBe(true);
    const [a, b] = (await adminDb.query(`SELECT 'a' < 'B' AS lt`)).rows[0].lt ? [true, true] : [false, false];
    expect(a && b).toBe(true); // 'a' sorts before 'B' only under a locale-aware collation
  });

  it('accepts a non-ASCII payload written with \\u escapes (needs a UTF8 database)', async () => {
    const row = await appendRaw(projectA, String.raw`{"k":"caf\u00e9 \u65e5\u672c \ud83d\ude00"}`);
    expect(row.canonical_payload).toBe('{"k":"café 日本 😀"}');
    expect(independentHash(row)).toBe(row.hash);
  });

  it('rejects whitespace-only fields and payloads larger than 1 MiB, and records nothing', async () => {
    const before = await eventCount(projectA);
    await expect(db.query(`SELECT * FROM append_event($1::uuid, 'system', '   ', 'a', 'project', 'a', '{}'::jsonb)`, [projectA]))
      .rejects.toThrow(/must not be empty/);
    await expect(db.query(`SELECT * FROM append_event($1::uuid, 'system', 'a', E'\\t', 'project', 'a', '{}'::jsonb)`, [projectA]))
      .rejects.toThrow(/must not be empty/);
    const big = JSON.stringify({ blob: 'x'.repeat(1_100_000) });
    await expect(appendRaw(projectA, big)).rejects.toThrow(/larger than 1 MiB/);
    expect(await eventCount(projectA)).toBe(before);
    const ok = await appendRaw(projectA, JSON.stringify({ blob: 'x'.repeat(200_000) }));
    expect(ok.canonical_payload.length).toBeGreaterThan(200_000);
  });

  it('only hash versions 1 and 2 exist (chk_event_hash_version)', async () => {
    const client = await adminDb.connect();
    try {
      await client.query('BEGIN');
      await expect(client.query(
        `INSERT INTO event (seq, project_id, actor_type, actor_id, action, subject_type, subject_id, payload, prev_hash, hash, hashed_timestamp, hash_version)
         VALUES (900, $1, 'system', 'a', 'a', 'project', 'a', '{}'::jsonb, repeat('0', 64), repeat('1', 64), '2026-01-01T00:00:00.000Z', 3)`,
        [projectB]
      )).rejects.toThrow(/chk_event_hash_version/);
    } finally {
      try { await client.query('ROLLBACK'); } finally { client.release(); }
    }
  });

  it('an event recorded inside a caller transaction disappears with it: a claim cannot leave a project without its event', async () => {
    const creator = (await adminDb.query(`SELECT creator_id FROM project WHERE id = $1`, [projectA])).rows[0].creator_id;
    const eventsBefore = await eventCount(projectA);
    const client = await db.connect();
    let newProject = '';
    try {
      await client.query('BEGIN');
      newProject = (await client.query(
        `INSERT INTO project (creator_id, name, purpose) VALUES ($1, 'Rolled back', 'never committed') RETURNING id`, [creator]
      )).rows[0].id;
      const ev = await insertEvent({
        project_id: newProject, actor_type: 'creator', actor_id: creator, action: 'project.claimed',
        subject_type: 'project', subject_id: newProject, payload: { name: 'Rolled back' }
      }, client);
      expect(ev.seq).toBe(1);
      await client.query('ROLLBACK');
    } finally {
      client.release();
    }
    expect((await adminDb.query('SELECT COUNT(*)::int AS n FROM project WHERE id = $1', [newProject])).rows[0].n).toBe(0);
    expect((await adminDb.query('SELECT COUNT(*)::int AS n FROM event WHERE project_id = $1', [newProject])).rows[0].n).toBe(0);
    expect(await eventCount(projectA)).toBe(eventsBefore);
  });
});
