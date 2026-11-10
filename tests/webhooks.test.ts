import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { getAdminPool, getDbPool, insertEvent, runMigrations } from '../server/db';
import { open } from '../server/secretBox';
import {
  BACKOFF_SECONDS, MAX_ATTEMPTS, SIGNATURE_HEADER, addressProblem, configureWebhookRuntime, deliverDueWebhooks, pinnedHttpsTransport, resetWebhookRuntime,
  signWebhook, urlProblem, verifyWebhookSignature, type TransportRequest
} from '../server/webhooks';
import { assertPoolTargetsTestDb } from './support/safety';
import { withTriggersBypassed } from './support/cleanup';
import { startHarness, Harness } from './support/apiHarness';

/**
 * Signed webhooks and the rules about where they may go (CL-15). Real database. The network is a recorder for most tests (so every status and
 * failure can be produced), and a real local HTTPS server for the one test of the real transport.
 */
describe('Webhooks', () => {
  const db = getDbPool()!;
  const admin = getAdminPool()!;
  let h: Harness;
  let creator: any, other: any;
  let projectId = '', project2 = '', otherProject = '';
  const PUBLIC = [{ address: '93.184.216.34', family: 4 }];

  interface Sent { req: TransportRequest; body: string }
  let sent: Sent[] = [];
  let respond: (req: TransportRequest) => Promise<{ status: number }> | { status: number } = () => ({ status: 200 });
  const recorder = async (req: TransportRequest) => {
    sent.push({ req, body: req.body.toString('utf8') });
    return respond(req);
  };

  const create = (who: any, over: Record<string, unknown> = {}) =>
    h.api(who, 'POST', '/webhook-endpoints', { name: `hook-${crypto.randomUUID().slice(0, 8)}`, url: 'https://hooks.example.test/in', events: ['*'], ...over });
  const record = (project = projectId, action = 'promotion.completed', payload: Record<string, unknown> = { n: 1 }) =>
    insertEvent({ project_id: project, actor_type: 'creator', actor_id: creator.id, action, subject_type: 'work_session', subject_id: crypto.randomUUID(), payload });
  const deliveries = async (endpointId: string) => (await db.query('SELECT * FROM webhook_delivery WHERE endpoint_id = $1 ORDER BY created_at', [endpointId])).rows;
  const attempts = async (deliveryId: string) => (await db.query('SELECT * FROM webhook_attempt WHERE delivery_id = $1 ORDER BY attempt', [deliveryId])).rows;
  const makeDue = (id: string) => db.query(`UPDATE webhook_delivery SET next_attempt_at = now() WHERE id = $1`, [id]);
  /** Only this endpoint's deliveries are due; everything else in the shared test database is pushed out of the way. */
  async function isolate(endpointId: string) {
    await admin.query(`UPDATE webhook_delivery SET next_attempt_at = now() + interval '1 day' WHERE status = 'pending' AND endpoint_id <> $1`, [endpointId]);
    await admin.query(`UPDATE webhook_delivery SET next_attempt_at = now() - interval '1 second' WHERE status = 'pending' AND endpoint_id = $1 AND next_attempt_at > now() + interval '1 hour'`, [endpointId]);
  }

  beforeAll(async () => {
    await assertPoolTargetsTestDb(admin);
    expect((await runMigrations()).success).toBe(true);
    h = await startHarness();
    creator = await h.newCreator('owner');
    other = await h.newCreator('other');
    const project = async (c: any, n: string) => (await db.query(`INSERT INTO project (creator_id, name, purpose) VALUES ($1, $2, 'x') RETURNING id`, [c.id, n])).rows[0].id as string;
    projectId = await project(creator, 'P1');
    project2 = await project(creator, 'P2');
    otherProject = await project(other, 'Q1');
  }, 120_000);
  afterEach(async () => {
    resetWebhookRuntime();
    sent = [];
    respond = () => ({ status: 200 });
    // each test starts with none of the owner's endpoints (there is a limit per owner, and tests must not see each other's deliveries)
    await withTriggersBypassed(admin, async (c) => {
      await c.query(`DELETE FROM webhook_attempt WHERE delivery_id IN (SELECT d.id FROM webhook_delivery d JOIN webhook_endpoint e ON e.id = d.endpoint_id WHERE e.creator_id = $1)`, [creator.id]);
      await c.query(`DELETE FROM webhook_delivery WHERE endpoint_id IN (SELECT id FROM webhook_endpoint WHERE creator_id = $1)`, [creator.id]);
      await c.query(`DELETE FROM webhook_endpoint WHERE creator_id = $1`, [creator.id]);
    });
  });
  afterAll(async () => {
    await h?.stop();
    // leave the shared test database as it was found: other files delete their own creators
    await withTriggersBypassed(admin, async (c) => {
      await c.query(`DELETE FROM webhook_attempt`);
      await c.query(`DELETE FROM webhook_delivery`);
      await c.query(`DELETE FROM webhook_endpoint`);
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('where a webhook may be sent', () => {
    it('refuses every private, loopback, link-local, shared, documentation, multicast and reserved address, however it is written', () => {
      const bad = [
        '127.0.0.1', '127.255.255.254', '10.0.0.1', '10.255.255.255', '172.16.0.1', '172.31.255.255', '192.168.0.1', '192.168.255.255', '169.254.169.254', '169.254.0.1',
        '100.64.0.1', '100.127.255.255', '0.0.0.0', '0.1.2.3', '224.0.0.1', '239.255.255.255', '240.0.0.1', '255.255.255.255', '192.0.2.5', '198.51.100.7', '203.0.113.9', '198.18.0.1', '198.19.255.255',
        '::', '::1', 'fe80::1', 'febf::1', 'fc00::1', 'fd12:3456::1', 'ff02::1', '::ffff:10.0.0.1', '::ffff:127.0.0.1', '::ffff:169.254.169.254', '64:ff9b::808:808', '2002::1', '2001:db8::1', '100::1'
      ];
      for (const a of bad) expect(addressProblem(a), a).not.toBeNull();
      for (const a of ['', 'localhost', '1.2.3', '1.2.3.4.5', 'example.com']) expect(addressProblem(a), a).toBe('not an IP address');
    });

    it('accepts ordinary public addresses (and the edges just outside the blocked ranges)', () => {
      for (const a of ['93.184.216.34', '8.8.8.8', '1.1.1.1', '172.15.255.255', '172.32.0.1', '100.63.255.255', '100.128.0.1', '198.17.255.255', '198.20.0.1', '11.0.0.1', '9.255.255.255', '2606:4700:4700::1111', '2a00:1450:4001::1', '::ffff:8.8.8.8']) {
        expect(addressProblem(a), a).toBeNull();
      }
    });

    it('refuses an address that is not https, has credentials, a fragment, an IP literal, or a name that is not on the public internet', () => {
      for (const u of [
        'http://hooks.example.test/in', 'ftp://hooks.example.test', 'hooks.example.test', '', 'https://', 'https://user:pass@hooks.example.test/', 'https://user@hooks.example.test/',
        'https://hooks.example.test/in#frag', 'https://127.0.0.1/in', 'https://10.0.0.5:8443/in', 'https://[::1]/in', 'https://[2606:4700:4700::1111]/in', 'https://localhost/in',
        'https://app.localhost/in', 'https://intranet/in', 'https://printer.local/in', 'https://db.internal/in', 'https://x.home.arpa/in', 'https://' + 'a'.repeat(2000) + '.example.com'
      ]) {
        expect(urlProblem(u), u).not.toBeNull();
      }
      for (const u of ['https://hooks.example.test/in', 'https://hooks.example.test:8443/in?x=1', 'https://a.b.c.example.org/path/to/hook']) expect(urlProblem(u), u).toBeNull();
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('signatures', () => {
    const secret = 'whsec_test_secret';
    const body = JSON.stringify({ hello: 'world' });
    it('verify, and fail on any change: body, secret, time, shape', () => {
      const now = 1_700_000_000;
      const header = signWebhook(secret, body, now);
      expect(header).toMatch(/^t=1700000000,v1=[0-9a-f]{64}$/);
      expect(verifyWebhookSignature(secret, header, body, 300, now)).toBe(true);
      expect(verifyWebhookSignature(secret, header, body, 300, now + 299)).toBe(true);
      expect(verifyWebhookSignature(secret, header, body + ' ', 300, now)).toBe(false);
      expect(verifyWebhookSignature('whsec_other', header, body, 300, now)).toBe(false);
      expect(verifyWebhookSignature(secret, header, body, 300, now + 301)).toBe(false); // too old: a replay
      expect(verifyWebhookSignature(secret, header, body, 300, now - 301)).toBe(false); // from the future
      expect(verifyWebhookSignature(secret, header.replace('t=1700000000', 't=1700000001'), body, 300, now)).toBe(false);
      for (const bad of ['', 'v1=abc', 't=1', `t=${now},v1=zz`, `t=${now},v1=${'0'.repeat(63)}`, `${header},extra`]) expect(verifyWebhookSignature(secret, bad, body, 300, now), bad).toBe(false);
    });
    it('is HMAC-SHA256 of "<t>.<body>", so a receiver in any language can check it', () => {
      const mac = crypto.createHmac('sha256', secret).update(`1700000000.${body}`).digest('hex');
      expect(signWebhook(secret, body, 1_700_000_000)).toBe(`t=1700000000,v1=${mac}`);
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('endpoints', () => {
    it('are registered with a secret shown once, kept only encrypted, and recorded on the owner\'s account record', async () => {
      configureWebhookRuntime({ resolve: async () => PUBLIC });
      const r = await create(creator, { name: 'Main', events: ['promotion.*', 'evidence.submitted'], project_ids: [projectId] });
      expect(r.status, JSON.stringify(r.body)).toBe(201);
      expect(r.body.secret).toMatch(/^whsec_[A-Za-z0-9_-]{40,}$/);
      expect(r.body.endpoint).toMatchObject({ name: 'Main', url: 'https://hooks.example.test/in', events: ['promotion.*', 'evidence.submitted'], project_ids: [projectId], status: 'active' });
      expect(JSON.stringify(r.body.endpoint)).not.toContain(r.body.secret);
      const row = (await db.query('SELECT * FROM webhook_endpoint WHERE id = $1', [r.body.endpoint.id])).rows[0];
      expect(row.secret_ciphertext).not.toContain(r.body.secret);
      expect(open(row.secret_ciphertext, `webhook_endpoint:${row.id}`)).toBe(r.body.secret);
      // bound to its own row: moved to another endpoint it no longer opens
      expect(() => open(row.secret_ciphertext, `webhook_endpoint:${crypto.randomUUID()}`)).toThrow();
      const list = await h.api(creator, 'GET', '/webhook-endpoints');
      expect(list.body.endpoints.find((e: any) => e.id === row.id)).toMatchObject({ name: 'Main', deliveries: { pending: 0, delivered: 0, dead: 0 } });
      expect(JSON.stringify(list.body)).not.toContain(r.body.secret);
      expect((await h.api(other, 'GET', '/webhook-endpoints')).body.endpoints).toEqual([]);
      const ev = (await admin.query(`SELECT payload FROM account_event WHERE action = 'webhook_endpoint.registered' AND payload->>'endpoint_id' = $1`, [row.id])).rows[0];
      expect(ev.payload).toMatchObject({ endpoint_id: row.id, name: 'Main' });
      expect(JSON.stringify(ev.payload)).not.toContain(r.body.secret);
    });

    it('are refused for a bad address, a name that resolves anywhere private, bad events, other owners\' projects, duplicates and unknown fields', async () => {
      configureWebhookRuntime({ resolve: async () => PUBLIC });
      for (const url of ['http://hooks.example.test/in', 'https://127.0.0.1/in', 'https://localhost/in', 'https://user:p@hooks.example.test/']) {
        expect((await create(creator, { url })).status, url).toBe(400);
      }
      for (const [why, resolved] of [
        ['private', [{ address: '10.0.0.5', family: 4 }]],
        ['metadata service', [{ address: '169.254.169.254', family: 4 }]],
        ['loopback v6', [{ address: '::1', family: 6 }]],
        ['one good, one bad', [{ address: '93.184.216.34', family: 4 }, { address: '192.168.1.1', family: 4 }]]
      ] as const) {
        configureWebhookRuntime({ resolve: async () => resolved as any });
        const r = await create(creator);
        expect(r.status, why).toBe(422);
        expect(r.body.code).toBe('blocked_address');
      }
      configureWebhookRuntime({ resolve: async () => { throw new Error('ENOTFOUND'); } });
      expect((await create(creator)).status).toBe(422);
      configureWebhookRuntime({ resolve: async () => PUBLIC });
      for (const events of [[], 'x', ['Bad Name'], ['a.b.*.c'], ['*', 5], Array.from({ length: 21 }, (_, i) => `e${i}`), ['promotion..x']]) {
        expect((await create(creator, { events })).status, JSON.stringify(events)).toBe(400);
      }
      expect((await create(creator, { project_ids: [otherProject] })).status).toBe(404);
      expect((await create(creator, { project_ids: ['nope'] })).status).toBe(400);
      expect((await create(creator, { extra: 1 })).status).toBe(400);
      expect((await create(creator, { name: '' })).status).toBe(400);
      expect((await create(creator, { name: 'Dup' })).status).toBe(201);
      expect((await create(creator, { name: 'Dup' })).status).toBe(409);
    });

    it('are limited in number per owner', async () => {
      configureWebhookRuntime({ resolve: async () => PUBLIC });
      const lone = await h.newCreator('limited');
      for (let i = 0; i < 20; i++) expect((await create(lone)).status).toBe(201);
      expect((await create(lone)).status).toBe(429);
    }, 120_000);

    it('can rotate their secret (the old one stops signing at once), be disabled and enabled, only by their owner', async () => {
      configureWebhookRuntime({ resolve: async () => PUBLIC, transport: recorder });
      const c = await create(creator, { events: ['rotate.test'] });
      const id = c.body.endpoint.id;
      expect((await h.api(other, 'POST', `/webhook-endpoints/${id}/rotate-secret`, {})).status).toBe(404);
      expect((await h.api(other, 'POST', `/webhook-endpoints/${id}/disable`, {})).status).toBe(404);
      expect((await h.api(other, 'GET', `/webhook-endpoints/${id}/deliveries`)).status).toBe(404);
      const rot = await h.api(creator, 'POST', `/webhook-endpoints/${id}/rotate-secret`, {});
      expect(rot.status).toBe(200);
      expect(rot.body.secret).not.toBe(c.body.secret);
      expect(rot.body.endpoint.secret_rotated_at).not.toBeNull();
      await record(projectId, 'rotate.test');
      await isolate(id);
      await deliverDueWebhooks(db);
      expect(sent).toHaveLength(1);
      const header = sent[0].req.headers[SIGNATURE_HEADER];
      expect(verifyWebhookSignature(rot.body.secret, header, sent[0].body)).toBe(true);
      expect(verifyWebhookSignature(c.body.secret, header, sent[0].body)).toBe(false);

      const off = await h.api(creator, 'POST', `/webhook-endpoints/${id}/disable`, {});
      expect(off.body.endpoint).toMatchObject({ status: 'disabled' });
      await record(projectId, 'rotate.test'); // a disabled endpoint is not owed anything new
      expect(await deliveries(id)).toHaveLength(1);
      const on = await h.api(creator, 'POST', `/webhook-endpoints/${id}/enable`, {});
      expect(on.body.endpoint).toMatchObject({ status: 'active', disabled_at: null });
      const actions = (await admin.query(`SELECT action FROM account_event WHERE payload->>'endpoint_id' = $1 ORDER BY seq`, [id])).rows.map((r) => r.action);
      expect(actions).toEqual(['webhook_endpoint.registered', 'webhook_endpoint.secret_rotated', 'webhook_endpoint.disabled', 'webhook_endpoint.enabled']);
    });

    it('cannot be pointed somewhere private later: turning one back on checks its address again', async () => {
      configureWebhookRuntime({ resolve: async () => PUBLIC });
      const id = (await create(creator)).body.endpoint.id;
      await h.api(creator, 'POST', `/webhook-endpoints/${id}/disable`, {});
      configureWebhookRuntime({ resolve: async () => [{ address: '10.1.1.1', family: 4 }] });
      const on = await h.api(creator, 'POST', `/webhook-endpoints/${id}/enable`, {});
      expect(on.status).toBe(422);
      expect((await db.query('SELECT status FROM webhook_endpoint WHERE id = $1', [id])).rows[0].status).toBe('disabled');
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('what is owed (the database decides, in the same transaction as the event)', () => {
    it('owes exactly the endpoints of the project\'s owner that asked for that event, for that project', async () => {
      configureWebhookRuntime({ resolve: async () => PUBLIC });
      const all = (await create(creator, { events: ['*'] })).body.endpoint.id;
      const family = (await create(creator, { events: ['promotion.*'] })).body.endpoint.id;
      const exact = (await create(creator, { events: ['promotion.completed'] })).body.endpoint.id;
      const onlyP2 = (await create(creator, { events: ['*'], project_ids: [project2] })).body.endpoint.id;
      const evidence = (await create(creator, { events: ['evidence.submitted'] })).body.endpoint.id;
      const off = (await create(creator, { events: ['*'] })).body.endpoint.id;
      await h.api(creator, 'POST', `/webhook-endpoints/${off}/disable`, {});
      const theirs = (await create(other, { events: ['*'] })).body.endpoint.id;
      const ev = await record(projectId, 'promotion.completed');
      const owed = async (e: string) => (await db.query('SELECT 1 FROM webhook_delivery WHERE endpoint_id = $1 AND event_id = $2', [e, ev.id])).rowCount;
      expect([await owed(all), await owed(family), await owed(exact)]).toEqual([1, 1, 1]);
      expect([await owed(onlyP2), await owed(evidence), await owed(off), await owed(theirs)]).toEqual([0, 0, 0, 0]);
      const ev2 = await record(project2, 'promotion.requested');
      const owed2 = async (e: string) => (await db.query('SELECT 1 FROM webhook_delivery WHERE endpoint_id = $1 AND event_id = $2', [e, ev2.id])).rowCount;
      expect([await owed2(all), await owed2(family), await owed2(exact), await owed2(onlyP2)]).toEqual([1, 1, 0, 1]);
      // a family match is on the dot: "promotion_x.foo" is not "promotion.*"
      const ev3 = await record(projectId, 'promotion_x.foo');
      expect((await db.query('SELECT 1 FROM webhook_delivery WHERE endpoint_id = $1 AND event_id = $2', [family, ev3.id])).rowCount).toBe(0);
      expect((await db.query('SELECT 1 FROM webhook_delivery WHERE endpoint_id = $1 AND event_id = $2', [all, ev3.id])).rowCount).toBe(1);
    });

    it('owes nothing for events before the endpoint existed, and nothing is owed if the event itself is rolled back', async () => {
      configureWebhookRuntime({ resolve: async () => PUBLIC });
      const before = await record(projectId, 'early.event');
      const id = (await create(creator, { events: ['early.event', 'rolled.back'] })).body.endpoint.id;
      expect((await db.query('SELECT 1 FROM webhook_delivery WHERE endpoint_id = $1 AND event_id = $2', [id, before.id])).rowCount).toBe(0);
      const c = await db.connect();
      try {
        await c.query('BEGIN');
        await insertEvent({ project_id: projectId, actor_type: 'creator', actor_id: creator.id, action: 'rolled.back', subject_type: 'x', subject_id: 'y', payload: {} }, c);
        expect((await c.query('SELECT count(*)::int AS n FROM webhook_delivery WHERE endpoint_id = $1', [id])).rows[0].n).toBe(1);
        await c.query('ROLLBACK');
      } finally {
        c.release();
      }
      expect(await deliveries(id)).toHaveLength(0);
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('delivery', () => {
    it('sends the signed event with its identity in the headers, and the body lets the receiver check it against the project\'s hash chain', async () => {
      configureWebhookRuntime({ resolve: async () => PUBLIC, transport: recorder });
      const c = await create(creator, { events: ['deliver.ok'], project_ids: [projectId] });
      const id = c.body.endpoint.id;
      const ev = await record(projectId, 'deliver.ok', { commit: 'abc', count: 3 });
      await isolate(id);
      expect(await deliverDueWebhooks(db)).toBeGreaterThanOrEqual(1);
      expect(sent).toHaveLength(1);
      const { req, body } = sent[0];
      expect(req.url.href).toBe('https://hooks.example.test/in');
      expect(req.address).toBe('93.184.216.34');
      expect(req.headers).toMatchObject({ 'content-type': 'application/json', 'custody-event-id': ev.id, 'custody-event-type': 'deliver.ok', 'custody-delivery-attempt': '1' });
      expect(verifyWebhookSignature(c.body.secret, req.headers[SIGNATURE_HEADER], body)).toBe(true);
      const msg = JSON.parse(body);
      expect(msg).toMatchObject({ format: 'custody-core.webhook.v1', id: ev.id, type: 'deliver.ok', project_id: projectId, actor: { type: 'creator', id: creator.id }, data: { commit: 'abc', count: 3 } });
      // recompute the event's hash from what was delivered (docs/EVENT_HASH_FORMAT.md, version 2)
      const r = msg.record;
      expect(r.hash_version).toBe(2);
      const text = `{"action":${JSON.stringify(msg.type)},"actor_id":${JSON.stringify(msg.actor.id)},"actor_type":${JSON.stringify(msg.actor.type)},"payload":${r.canonical_payload},"prev_hash":${JSON.stringify(r.prev_hash)},"project_id":${JSON.stringify(msg.project_id)},"seq":${r.seq},"subject_id":${JSON.stringify(msg.subject.id)},"subject_type":${JSON.stringify(msg.subject.type)},"timestamp":${JSON.stringify(r.hashed_timestamp)}}`;
      expect(crypto.createHash('sha256').update(text).digest('hex')).toBe(r.hash);
      const [d] = await deliveries(id);
      expect(d).toMatchObject({ status: 'delivered', attempts: 1, last_status: 200, last_error: null });
      expect(d.payload_sha256).toBe(crypto.createHash('sha256').update(body).digest('hex'));
      expect(d.delivered_at).not.toBeNull();
      expect(await attempts(d.id)).toEqual([expect.objectContaining({ attempt: 1, outcome: 'delivered', http_status: 200 })]);
      // once delivered, never again
      await deliverDueWebhooks(db);
      expect(sent).toHaveLength(1);
    });

    it('retries a failure with backoff, with the same body and the same event id every time, and stops when it succeeds', async () => {
      configureWebhookRuntime({ resolve: async () => PUBLIC, transport: recorder });
      const c = await create(creator, { events: ['retry.test'] });
      const id = c.body.endpoint.id;
      await record(projectId, 'retry.test', { a: 1 });
      await isolate(id);
      respond = () => ({ status: 500 });
      await deliverDueWebhooks(db);
      let [d] = await deliveries(id);
      expect(d).toMatchObject({ status: 'pending', attempts: 1, last_status: 500 });
      expect(d.last_error).toMatch(/500/);
      const wait = (new Date(d.next_attempt_at).getTime() - Date.now()) / 1000;
      expect(wait).toBeGreaterThan(BACKOFF_SECONDS[0] - 15);
      expect(wait).toBeLessThanOrEqual(BACKOFF_SECONDS[0] + 1);
      await deliverDueWebhooks(db); // not due yet
      expect(sent).toHaveLength(1);
      await makeDue(d.id);
      respond = () => ({ status: 200 });
      await deliverDueWebhooks(db);
      expect(sent).toHaveLength(2);
      expect(sent[1].req.headers['custody-delivery-attempt']).toBe('2');
      expect(sent[1].req.headers['custody-event-id']).toBe(sent[0].req.headers['custody-event-id']);
      expect(sent[1].req.headers['custody-delivery-id']).toBe(sent[0].req.headers['custody-delivery-id']);
      expect(sent[1].body).toBe(sent[0].body); // the same bytes: the receiver can de-duplicate on the event id
      [d] = await deliveries(id);
      expect(d).toMatchObject({ status: 'delivered', attempts: 2 });
      expect((await attempts(d.id)).map((a) => a.outcome)).toEqual(['http_error', 'delivered']);
    });

    it('gives up after the last attempt (dead), following the backoff schedule, and then leaves it alone', async () => {
      configureWebhookRuntime({ resolve: async () => PUBLIC, transport: recorder });
      const c = await create(creator, { events: ['dead.test'] });
      const id = c.body.endpoint.id;
      await record(projectId, 'dead.test');
      await isolate(id);
      respond = () => ({ status: 503 });
      for (let i = 1; i <= MAX_ATTEMPTS; i++) {
        const [d] = await deliveries(id);
        await makeDue(d.id);
        await deliverDueWebhooks(db);
        const after = (await deliveries(id))[0];
        expect(after.attempts).toBe(i);
        if (i < MAX_ATTEMPTS) {
          expect(after.status).toBe('pending');
          const wait = (new Date(after.next_attempt_at).getTime() - Date.now()) / 1000;
          expect(Math.abs(wait - BACKOFF_SECONDS[i - 1])).toBeLessThan(20);
        }
      }
      const [d] = await deliveries(id);
      expect(d.status).toBe('dead');
      expect((await attempts(d.id)).map((a) => a.attempt)).toEqual([1, 2, 3, 4, 5, 6]);
      const n = sent.length;
      await deliverDueWebhooks(db);
      expect(sent.length).toBe(n);
      await expect(db.query(`UPDATE webhook_delivery SET status = 'pending' WHERE id = $1`, [d.id])).rejects.toThrow(/final/);
    }, 60_000);

    it('never follows a redirect; and records a network failure or a timeout by its code only', async () => {
      configureWebhookRuntime({ resolve: async () => PUBLIC, transport: recorder });
      const id = (await create(creator, { events: ['fail.kinds'] })).body.endpoint.id;
      await record(projectId, 'fail.kinds');
      await isolate(id);
      respond = () => ({ status: 302 });
      await deliverDueWebhooks(db);
      let [d] = await deliveries(id);
      expect(d.last_error).toMatch(/redirect/);
      await makeDue(d.id);
      respond = () => { throw Object.assign(new Error('connect ECONNREFUSED 93.184.216.34:443 with whsec_leak'), { code: 'ECONNREFUSED' }); };
      await deliverDueWebhooks(db);
      [d] = await deliveries(id);
      expect(d.last_error).toBe('ECONNREFUSED');
      await makeDue(d.id);
      respond = () => { throw Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }); };
      await deliverDueWebhooks(db);
      expect((await attempts(d.id)).map((a) => a.outcome)).toEqual(['http_error', 'network_error', 'timeout']);
      expect(JSON.stringify(await attempts(d.id))).not.toContain('whsec_leak');
    });

    it('re-checks the address at every attempt: a name that later points inside the network is refused, and nothing is sent', async () => {
      configureWebhookRuntime({ resolve: async () => PUBLIC, transport: recorder });
      const id = (await create(creator, { events: ['rebind.test'] })).body.endpoint.id;
      await record(projectId, 'rebind.test');
      await isolate(id);
      for (const evil of ['10.0.0.5', '169.254.169.254', '127.0.0.1', '::1', '::ffff:192.168.0.1']) {
        const [d] = await deliveries(id);
        await makeDue(d.id);
        configureWebhookRuntime({ resolve: async () => [{ address: evil, family: evil.includes(':') ? 6 : 4 }] });
        await deliverDueWebhooks(db);
        const att = await attempts(d.id);
        expect(att.at(-1).outcome, evil).toBe('blocked_address');
        expect(att.at(-1).error).toMatch(/not a public address|IPv4-mapped/);
      }
      expect(sent).toHaveLength(0);
    });

    it('does not deliver for a disabled endpoint, and picks up where it left off when it is enabled again', async () => {
      configureWebhookRuntime({ resolve: async () => PUBLIC, transport: recorder });
      const id = (await create(creator, { events: ['pause.test'] })).body.endpoint.id;
      await record(projectId, 'pause.test');
      await h.api(creator, 'POST', `/webhook-endpoints/${id}/disable`, {});
      await isolate(id);
      await deliverDueWebhooks(db);
      expect(sent).toHaveLength(0);
      await h.api(creator, 'POST', `/webhook-endpoints/${id}/enable`, {});
      await isolate(id);
      await deliverDueWebhooks(db);
      expect(sent).toHaveLength(1);
    });

    it('sends each delivery once even when two workers run at the same time', async () => {
      configureWebhookRuntime({ resolve: async () => PUBLIC, transport: async (r) => { await new Promise((ok) => setTimeout(ok, 150)); return recorder(r); } });
      const id = (await create(creator, { events: ['race.test'] })).body.endpoint.id;
      for (let i = 0; i < 6; i++) await record(projectId, 'race.test', { i });
      await isolate(id);
      await Promise.all([deliverDueWebhooks(db), deliverDueWebhooks(db), deliverDueWebhooks(db)]);
      expect(sent).toHaveLength(6);
      expect(new Set(sent.map((s) => s.req.headers['custody-event-id'])).size).toBe(6);
      expect((await deliveries(id)).every((d) => d.status === 'delivered' && d.attempts === 1)).toBe(true);
    });

    it('lists deliveries for the owner, with the outcome and what went wrong', async () => {
      configureWebhookRuntime({ resolve: async () => PUBLIC, transport: recorder });
      const id = (await create(creator, { events: ['list.test'] })).body.endpoint.id;
      await record(projectId, 'list.test');
      await isolate(id);
      respond = () => ({ status: 410 });
      await deliverDueWebhooks(db);
      const r = await h.api(creator, 'GET', `/webhook-endpoints/${id}/deliveries`);
      expect(r.status).toBe(200);
      expect(r.body.deliveries).toEqual([expect.objectContaining({ event_type: 'list.test', status: 'pending', attempts: 1, last_status: 410, last_error: 'The receiver answered 410.' })]);
      expect((await h.api(creator, 'GET', '/webhook-endpoints')).body.endpoints.find((e: any) => e.id === id).deliveries.pending).toBe(1);
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  describe('the real transport', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-hook-cert-'));
    const key = path.join(dir, 'key.pem');
    const cert = path.join(dir, 'cert.pem');
    let server: https.Server;
    let port = 0;
    const hits: Array<{ url: string; headers: any; body: string }> = [];
    let mode: 'ok' | 'redirect' | 'slow' = 'ok';

    beforeAll(async () => {
      const r = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', key, '-out', cert, '-days', '2', '-subj', '/CN=hooks.example.test', '-addext', 'subjectAltName=DNS:hooks.example.test'], { encoding: 'utf8' });
      expect(r.status, r.stderr).toBe(0);
      server = https.createServer({ key: fs.readFileSync(key), cert: fs.readFileSync(cert) }, (req, res) => {
        let body = '';
        req.on('data', (c) => (body += c));
        req.on('end', () => {
          hits.push({ url: req.url ?? '', headers: req.headers, body });
          if (mode === 'redirect') {
            res.writeHead(302, { Location: 'https://127.0.0.1:1/elsewhere' });
            return res.end();
          }
          if (mode === 'slow') return; // never answers
          res.writeHead(200);
          res.end('ok');
        });
      });
      await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
      port = (server.address() as any).port;
    });
    afterAll(async () => {
      await new Promise<void>((r) => server.close(() => r()));
      fs.rmSync(dir, { recursive: true, force: true });
    });

    const request = (over: Partial<TransportRequest> = {}): TransportRequest => ({
      url: new URL(`https://hooks.example.test:${port}/in?x=1`), address: '127.0.0.1', family: 4, headers: { 'content-type': 'application/json', 'custody-event-id': 'e1' },
      body: Buffer.from('{"a":1}'), timeoutMs: 3000, ca: fs.readFileSync(cert, 'utf8'), ...over
    });

    it('posts to the one address it was given (the name does not resolve anywhere), verifies the certificate for the host name, and reports the status', async () => {
      hits.length = 0;
      mode = 'ok';
      const r = await pinnedHttpsTransport(request());
      expect(r.status).toBe(200);
      expect(hits).toHaveLength(1);
      expect(hits[0]).toMatchObject({ url: '/in?x=1', body: '{"a":1}' });
      expect(hits[0].headers).toMatchObject({ host: `hooks.example.test:${port}`, 'content-type': 'application/json', 'custody-event-id': 'e1', 'content-length': '7' });
    });

    it('refuses a certificate it does not trust, or one for another name', async () => {
      hits.length = 0;
      mode = 'ok';
      await expect(pinnedHttpsTransport(request({ ca: undefined }))).rejects.toThrow(); // self-signed and not trusted
      await expect(pinnedHttpsTransport(request({ url: new URL(`https://other.example.test:${port}/in`) }))).rejects.toThrow(); // trusted CA, wrong name
      expect(hits).toHaveLength(0);
    });

    it('does not follow a redirect, and gives up on a receiver that never answers', async () => {
      hits.length = 0;
      mode = 'redirect';
      const r = await pinnedHttpsTransport(request());
      expect(r.status).toBe(302);
      expect(hits).toHaveLength(1);
      mode = 'slow';
      await expect(pinnedHttpsTransport(request({ timeoutMs: 400 }))).rejects.toMatchObject({ code: 'ETIMEDOUT' });
      mode = 'ok';
    });

    it('works end to end through the delivery code, signature and all, to a receiver on the loopback only when the test says so', async () => {
      hits.length = 0;
      mode = 'ok';
      const secret = 'whsec_e2e';
      configureWebhookRuntime({ resolve: async () => [{ address: '127.0.0.1', family: 4 }], ca: fs.readFileSync(cert, 'utf8') });
      // by default a loopback receiver is refused, even though it is reachable
      const r = await create(creator, { url: `https://hooks.example.test:${port}/in`, events: ['e2e.test'] });
      expect(r.status).toBe(422);
      configureWebhookRuntime({ allowPrivate: true });
      const c = await create(creator, { url: `https://hooks.example.test:${port}/in`, events: ['e2e.test'] });
      expect(c.status, JSON.stringify(c.body)).toBe(201);
      await record(projectId, 'e2e.test');
      await isolate(c.body.endpoint.id);
      await deliverDueWebhooks(db);
      expect(hits).toHaveLength(1);
      expect(verifyWebhookSignature(c.body.secret, hits[0].headers[SIGNATURE_HEADER], hits[0].body)).toBe(true);
      expect(verifyWebhookSignature(secret, hits[0].headers[SIGNATURE_HEADER], hits[0].body)).toBe(false);
      expect((await deliveries(c.body.endpoint.id))[0].status).toBe('delivered');
    });
  });

  // ------------------------------------------------------------------------------------------------------------
  it('the database keeps its own rules: nothing is deleted, what is owed never changes, attempts go up by one, the record of attempts is written once', async () => {
    configureWebhookRuntime({ resolve: async () => PUBLIC, transport: recorder });
    const id = (await create(creator, { events: ['guard.test'] })).body.endpoint.id;
    await record(projectId, 'guard.test');
    const [d] = await deliveries(id);
    await expect(db.query(`UPDATE webhook_delivery SET attempts = 2 WHERE id = $1`, [d.id])).rejects.toThrow(/one at a time/);
    await expect(db.query(`UPDATE webhook_delivery SET endpoint_id = $2 WHERE id = $1`, [d.id, crypto.randomUUID()])).rejects.toThrow();
    await expect(db.query(`DELETE FROM webhook_delivery WHERE id = $1`, [d.id])).rejects.toThrow();
    await expect(admin.query(`DELETE FROM webhook_delivery WHERE id = $1`, [d.id])).rejects.toThrow(/cannot be deleted/);
    await expect(db.query(`UPDATE webhook_endpoint SET url = 'https://elsewhere.example.test/' WHERE id = $1`, [id])).rejects.toThrow(/only the secret and the enabled state/);
    await expect(db.query(`UPDATE webhook_endpoint SET subscribed_events = ARRAY['*'] WHERE id = $1`, [id])).rejects.toThrow(/only the secret/);
    await expect(db.query(`DELETE FROM webhook_endpoint WHERE id = $1`, [id])).rejects.toThrow();
    await expect(admin.query(`DELETE FROM webhook_endpoint WHERE id = $1`, [id])).rejects.toThrow(/only be disabled|cannot be deleted/);
    await expect(db.query(`INSERT INTO webhook_endpoint (creator_id, name, url, secret_ciphertext, subscribed_events) VALUES ($1, 'x', 'http://insecure.example.test/', 'v1.a.b.c', ARRAY['*'])`, [creator.id])).rejects.toThrow(/webhook_endpoint_url_check/);
    await expect(db.query(`INSERT INTO webhook_endpoint (creator_id, name, url, secret_ciphertext, subscribed_events) VALUES ($1, 'x2', 'https://ok.example.test/', 'not-sealed', ARRAY['*'])`, [creator.id])).rejects.toThrow(/secret_ciphertext_check/);
    await expect(db.query(`INSERT INTO webhook_endpoint (creator_id, name, url, secret_ciphertext, subscribed_events) VALUES ($1, 'x3', 'https://ok.example.test/', 'v1.a.b.c', ARRAY['Not Valid'])`, [creator.id])).rejects.toThrow(/subscribed_events_check/);
    await isolate(id);
    await deliverDueWebhooks(db);
    const [a] = await attempts(d.id);
    await expect(db.query(`UPDATE webhook_attempt SET outcome = 'http_error' WHERE id = $1`, [a.id])).rejects.toThrow();
    await expect(admin.query(`UPDATE webhook_attempt SET outcome = 'http_error' WHERE id = $1`, [a.id])).rejects.toThrow(/written once/);
    await expect(db.query(`UPDATE webhook_delivery SET payload_sha256 = $2 WHERE id = $1`, [d.id, 'a'.repeat(64)])).rejects.toThrow(/final/);
  });
});
