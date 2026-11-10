import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import https from 'node:https';
import net from 'node:net';
import express from 'express';
import type pg from 'pg';
import { getDbPool } from './db';
import { creatorOf } from './auth';
import { SecretBoxNotConfigured, open, seal } from './secretBox';

/**
 * Signed outbound webhooks (docs/integration/PHASE9_DESIGN.md; gate CL-15).
 *
 * The owner registers an https address and says which events of which projects to send (all or a family such as "promotion.*"). Every event the
 * database records that matches is owed a delivery (a trigger, in the same transaction as the event), and this file carries them out: signed with the
 * endpoint's secret, to an address that must resolve to the PUBLIC internet (TM-08), without following redirects, retried with backoff, at least once.
 */

export const WEBHOOK_FORMAT = 'custody-core.webhook.v1';
export const SIGNATURE_HEADER = 'custody-signature';
export const MAX_ENDPOINTS_PER_OWNER = 20;
export const MAX_ATTEMPTS = 6;
/** Seconds to wait after attempt 1, 2, 3, 4, 5. After the sixth failure a delivery is dead. */
export const BACKOFF_SECONDS = [60, 300, 1800, 7200, 21600];
export const ATTEMPT_TIMEOUT_MS = 10_000;
const LEASE_SECONDS = 180;
const BATCH = 40;
const CONCURRENCY = 8;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EVENT_PATTERN = /^(\*|[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*(\.\*)?)$/;

// --- where a webhook may be sent -------------------------------------------------------------------------------------

const blocked = new net.BlockList();
for (const [net4, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
] as const) blocked.addSubnet(net4, prefix, 'ipv4');
for (const [net6, prefix] of [
  ['::', 128], ['::1', 128], ['64:ff9b::', 96], ['64:ff9b:1::', 48], ['100::', 64], ['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8]
] as const) blocked.addSubnet(net6, prefix, 'ipv6');

/** Why an address may not be sent to, or null. Private, loopback, link-local, shared, documentation, multicast and reserved ranges all refuse. */
export function addressProblem(address: string): string | null {
  let ip = address;
  if (net.isIP(ip) === 6) {
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip); // an IPv4 address written as IPv6: judge the IPv4 address
    if (mapped) ip = mapped[1];
    else if (/^::ffff:/i.test(ip)) return 'an IPv4-mapped address';
  }
  const family = net.isIP(ip);
  if (family === 0) return 'not an IP address';
  return blocked.check(ip, family === 4 ? 'ipv4' : 'ipv6') ? 'not a public address' : null;
}

/** Why a webhook address is not acceptable on its face, or null. (Where it resolves is checked separately, and again at every delivery.) */
export function urlProblem(raw: unknown): string | null {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2000) return 'The address must be text of at most 2000 characters.';
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return 'That is not a valid address.';
  }
  if (u.protocol !== 'https:') return 'The address must start with https://.';
  if (u.username || u.password) return 'The address cannot contain a user name or password.';
  if (u.hash) return 'The address cannot contain a #fragment.';
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (!host) return 'The address needs a host name.';
  if (net.isIP(host) !== 0) return 'Use a host name, not an IP address.';
  if (/(^|\.)(localhost|local|internal|localdomain|home\.arpa)$/i.test(host) || !host.includes('.')) return 'That host name is not on the public internet.';
  return null;
}

export type Resolver = (hostname: string) => Promise<Array<{ address: string; family: number }>>;
const defaultResolver: Resolver = (h) => dns.lookup(h, { all: true, verbatim: true });

export interface TransportRequest {
  url: URL;
  address: string;
  family: number;
  headers: Record<string, string>;
  body: Buffer;
  timeoutMs: number;
  ca?: string;
}
export type Transport = (req: TransportRequest) => Promise<{ status: number }>;

/** Connects to the ONE address that was checked (so the name cannot be re-resolved to another), verifies the certificate for the host name, never follows a redirect. */
export const pinnedHttpsTransport: Transport = (r) =>
  new Promise((resolve, reject) => {
    const req = https.request(
      {
        method: 'POST',
        host: r.url.hostname,
        port: r.url.port || 443,
        path: `${r.url.pathname}${r.url.search}`,
        headers: { ...r.headers, 'content-length': String(r.body.length) },
        servername: r.url.hostname,
        agent: false,
        timeout: r.timeoutMs,
        ca: r.ca,
        lookup: ((_h: string, opts: any, cb: any) => (opts?.all ? cb(null, [{ address: r.address, family: r.family }]) : cb(null, r.address, r.family))) as any
      },
      (res) => {
        res.resume();
        res.on('end', () => resolve({ status: res.statusCode ?? 0 }));
        res.on('error', reject);
        setTimeout(() => res.destroy(), 5000).unref();
      }
    );
    req.on('timeout', () => req.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })));
    req.on('error', reject);
    req.end(r.body);
  });

interface Runtime {
  resolve: Resolver;
  transport: Transport;
  /** TESTS ONLY (never read from the environment): allow private addresses and trust this CA, to reach a local receiver. */
  allowPrivate: boolean;
  ca?: string;
}
const defaults: Runtime = { resolve: defaultResolver, transport: pinnedHttpsTransport, allowPrivate: false };
let runtime: Runtime = { ...defaults };
export function configureWebhookRuntime(over: Partial<Runtime>) {
  runtime = { ...runtime, ...over };
}
export function resetWebhookRuntime() {
  runtime = { ...defaults };
}

/** Resolves a host and refuses unless EVERY address it resolves to is public. Returns the address to use. */
async function publicAddressFor(host: string): Promise<{ address: string; family: number } | { problem: string }> {
  let addrs: Array<{ address: string; family: number }>;
  try {
    addrs = await runtime.resolve(host);
  } catch {
    return { problem: 'The host name does not resolve.' };
  }
  if (addrs.length === 0) return { problem: 'The host name does not resolve.' };
  if (!runtime.allowPrivate) {
    for (const a of addrs) {
      const p = addressProblem(a.address);
      if (p) return { problem: `The host name resolves to an address that is ${p}.` };
    }
  }
  return addrs[0];
}

// --- signing ---------------------------------------------------------------------------------------------------------------

/** `t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<body>" with the endpoint's secret>`. Receivers: recompute, compare in constant time, and refuse an old t (five minutes). */
export function signWebhook(secret: string, body: string | Buffer, timestampSeconds = Math.floor(Date.now() / 1000)): string {
  const mac = crypto.createHmac('sha256', secret).update(`${timestampSeconds}.`).update(body).digest('hex');
  return `t=${timestampSeconds},v1=${mac}`;
}

export function verifyWebhookSignature(secret: string, header: string, body: string | Buffer, toleranceSeconds = 300, nowSeconds = Math.floor(Date.now() / 1000)): boolean {
  const m = /^t=(\d{1,12}),v1=([0-9a-f]{64})$/.exec(header ?? '');
  if (!m) return false;
  const t = Number(m[1]);
  if (Math.abs(nowSeconds - t) > toleranceSeconds) return false;
  const expected = Buffer.from(signWebhook(secret, body, t).split('v1=')[1], 'hex');
  return crypto.timingSafeEqual(expected, Buffer.from(m[2], 'hex'));
}

// --- the registry ----------------------------------------------------------------------------------------------------------

export class WebhookError extends Error {
  constructor(
    public status: number,
    message: string,
    public code: string
  ) {
    super(message);
  }
}

async function inTransaction<T>(pool: pg.Pool, work: (c: pg.PoolClient) => Promise<T>): Promise<T> {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const out = await work(c);
    await c.query('COMMIT');
    return out;
  } catch (err) {
    await c.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    c.release();
  }
}

async function accountEvent(c: pg.PoolClient, creatorId: string, action: string, payload: Record<string, unknown>) {
  const who = (await c.query('SELECT identity_id FROM creator WHERE id = $1', [creatorId])).rows[0];
  await c.query('SELECT append_account_event($1, $2, $3, $4, $5::jsonb)', [who.identity_id, 'creator', creatorId, action, JSON.stringify(payload)]);
}

const newSecret = () => `whsec_${crypto.randomBytes(32).toString('base64url')}`;
const ownerOf = (id: string) => `webhook_endpoint:${id}`;

export const endpointView = (r: any) => ({
  id: r.id,
  name: r.name,
  url: r.url,
  events: r.subscribed_events,
  project_ids: r.project_ids,
  status: r.status,
  created_at: new Date(r.created_at).toISOString(),
  secret_rotated_at: r.secret_rotated_at ? new Date(r.secret_rotated_at).toISOString() : null,
  disabled_at: r.disabled_at ? new Date(r.disabled_at).toISOString() : null
});

async function checkDestination(url: string): Promise<void> {
  const problem = urlProblem(url);
  if (problem) throw new WebhookError(400, problem, 'invalid_url');
  const found = await publicAddressFor(new URL(url).hostname);
  if ('problem' in found) throw new WebhookError(422, found.problem, 'blocked_address');
}

export async function createEndpoint(pool: pg.Pool, creatorId: string, input: unknown) {
  const body = input as Record<string, unknown>;
  if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some((k) => !['name', 'url', 'events', 'project_ids'].includes(k))) {
    throw new WebhookError(400, 'Send { "name", "url", "events", "project_ids"? }.', 'invalid');
  }
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  if (!name || name.length > 100) throw new WebhookError(400, 'The name must be 1 to 100 characters.', 'invalid');
  const events = body.events;
  if (!Array.isArray(events) || events.length < 1 || events.length > 20 || events.some((e) => typeof e !== 'string' || !EVENT_PATTERN.test(e) || e.length > 100)) {
    throw new WebhookError(400, 'events must be 1 to 20 event names such as "promotion.completed", families such as "promotion.*", or "*".', 'invalid');
  }
  let projectIds: string[] | null = null;
  if (body.project_ids !== undefined && body.project_ids !== null) {
    if (!Array.isArray(body.project_ids) || body.project_ids.length < 1 || body.project_ids.length > 100 || body.project_ids.some((p) => typeof p !== 'string' || !UUID.test(p))) {
      throw new WebhookError(400, 'project_ids must be a list of project ids.', 'invalid');
    }
    projectIds = [...new Set((body.project_ids as string[]).map((p) => p.toLowerCase()))];
    const mine = (await pool.query(`SELECT count(*)::int AS n FROM project WHERE creator_id = $1 AND id = ANY($2::uuid[])`, [creatorId, projectIds])).rows[0].n;
    if (mine !== projectIds.length) throw new WebhookError(404, 'No such project.', 'not_found');
  }
  await checkDestination(body.url as string);
  const count = (await pool.query(`SELECT count(*)::int AS n FROM webhook_endpoint WHERE creator_id = $1`, [creatorId])).rows[0].n;
  if (count >= MAX_ENDPOINTS_PER_OWNER) throw new WebhookError(429, `You already have ${count} webhook endpoints.`, 'too_many');

  const id = crypto.randomUUID();
  const secret = newSecret();
  let sealed: string;
  try {
    sealed = seal(secret, ownerOf(id));
  } catch (err) {
    if (err instanceof SecretBoxNotConfigured) throw new WebhookError(503, 'The server has no encryption key, so it cannot keep a signing secret.', 'not_configured');
    throw err;
  }
  return inTransaction(pool, async (c) => {
    let row;
    try {
      row = (await c.query(`INSERT INTO webhook_endpoint (id, creator_id, name, url, secret_ciphertext, subscribed_events, project_ids) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`, [id, creatorId, name, body.url, sealed, events, projectIds])).rows[0];
    } catch (err: any) {
      if (err?.code === '23505') throw new WebhookError(409, 'You already have an endpoint with this name.', 'conflict');
      throw err;
    }
    await accountEvent(c, creatorId, 'webhook_endpoint.registered', { endpoint_id: id, name, url: body.url, events, project_ids: projectIds });
    return { endpoint: endpointView(row), secret };
  });
}

export async function rotateSecret(pool: pg.Pool, creatorId: string, id: string) {
  const secret = newSecret();
  let sealed: string;
  try {
    sealed = seal(secret, ownerOf(id));
  } catch (err) {
    if (err instanceof SecretBoxNotConfigured) throw new WebhookError(503, 'The server has no encryption key, so it cannot keep a signing secret.', 'not_configured');
    throw err;
  }
  return inTransaction(pool, async (c) => {
    const row = (await c.query(`UPDATE webhook_endpoint SET secret_ciphertext = $3, secret_rotated_at = now() WHERE id = $1 AND creator_id = $2 RETURNING *`, [id, creatorId, sealed])).rows[0];
    if (!row) throw new WebhookError(404, 'No such webhook endpoint.', 'not_found');
    await accountEvent(c, creatorId, 'webhook_endpoint.secret_rotated', { endpoint_id: id });
    return { endpoint: endpointView(row), secret };
  });
}

export async function setEndpointStatus(pool: pg.Pool, creatorId: string, id: string, status: 'active' | 'disabled') {
  if (status === 'active') {
    const url = (await pool.query(`SELECT url FROM webhook_endpoint WHERE id = $1 AND creator_id = $2`, [id, creatorId])).rows[0]?.url;
    if (url) await checkDestination(url); // turning one back on checks where it points again
  }
  return inTransaction(pool, async (c) => {
    const row = (
      await c.query(`UPDATE webhook_endpoint SET status = $3, disabled_at = CASE WHEN $3 = 'disabled' THEN COALESCE(disabled_at, now()) ELSE NULL END WHERE id = $1 AND creator_id = $2 RETURNING *`, [id, creatorId, status])
    ).rows[0];
    if (!row) throw new WebhookError(404, 'No such webhook endpoint.', 'not_found');
    await accountEvent(c, creatorId, status === 'disabled' ? 'webhook_endpoint.disabled' : 'webhook_endpoint.enabled', { endpoint_id: id });
    return endpointView(row);
  });
}

// --- delivery --------------------------------------------------------------------------------------------------------------

function bodyFor(e: any): string {
  return JSON.stringify({
    format: WEBHOOK_FORMAT,
    id: e.id,
    type: e.action,
    project_id: e.project_id,
    occurred_at: new Date(e.created_at).toISOString(),
    actor: { type: e.actor_type, id: e.actor_id },
    subject: { type: e.subject_type, id: e.subject_id },
    data: e.payload,
    // enough to check the event against the project's hash chain (docs/EVENT_HASH_FORMAT.md)
    record: { seq: Number(e.seq), prev_hash: e.prev_hash, hash: e.hash, hash_version: e.hash_version, hashed_timestamp: e.hashed_timestamp, canonical_payload: e.canonical_payload }
  });
}

type Outcome = 'delivered' | 'http_error' | 'network_error' | 'timeout' | 'blocked_address' | 'endpoint_unavailable';

async function attemptDelivery(d: any, ep: any, ev: any): Promise<{ outcome: Outcome; status: number | null; error: string | null; sha: string | null }> {
  let secret: string;
  try {
    secret = open(ep.secret_ciphertext, ownerOf(ep.id));
  } catch {
    return { outcome: 'endpoint_unavailable', status: null, error: 'The signing secret could not be read.', sha: null };
  }
  const body = bodyFor(ev);
  const sha = crypto.createHash('sha256').update(body).digest('hex');
  if (d.payload_sha256 && d.payload_sha256 !== sha) return { outcome: 'endpoint_unavailable', status: null, error: 'The event no longer matches what was first signed.', sha };
  const url = new URL(ep.url);
  const found = await publicAddressFor(url.hostname); // every attempt, so a name that later points inside is refused
  if ('problem' in found) return { outcome: 'blocked_address', status: null, error: found.problem, sha };
  const attempt = d.attempts + 1;
  try {
    const res = await runtime.transport({
      url,
      address: found.address,
      family: found.family,
      headers: {
        'content-type': 'application/json',
        'user-agent': 'Custody-Core-Webhooks/1',
        [SIGNATURE_HEADER]: signWebhook(secret, body),
        'custody-event-id': ev.id,
        'custody-event-type': ev.action,
        'custody-delivery-id': d.id,
        'custody-delivery-attempt': String(attempt)
      },
      body: Buffer.from(body, 'utf8'),
      timeoutMs: ATTEMPT_TIMEOUT_MS,
      ca: runtime.ca
    });
    if (res.status >= 200 && res.status < 300) return { outcome: 'delivered', status: res.status, error: null, sha };
    // 3xx included: a redirect is never followed
    return { outcome: 'http_error', status: res.status, error: res.status >= 300 && res.status < 400 ? 'The receiver answered with a redirect, which is not followed.' : `The receiver answered ${res.status}.`, sha };
  } catch (err: any) {
    const timedOut = err?.code === 'ETIMEDOUT' || /timeout/i.test(String(err?.message));
    // Never repeat anything that could carry the secret or the body: the error code only.
    return { outcome: timedOut ? 'timeout' : 'network_error', status: null, error: String(err?.code ?? 'connection failed').slice(0, 100), sha };
  }
}

/** Carries out the deliveries that are due (at most a batch). Called by the scheduler. Returns how many attempts it made. */
export async function deliverDueWebhooks(pool: pg.Pool): Promise<number> {
  // Lease them first (push their next time out) so two servers never send the same one; the result is recorded afterwards.
  const claimed = (
    await pool.query(
      `UPDATE webhook_delivery d SET next_attempt_at = now() + make_interval(secs => $2)
        WHERE d.id IN (SELECT d2.id FROM webhook_delivery d2 JOIN webhook_endpoint e ON e.id = d2.endpoint_id
                        WHERE d2.status = 'pending' AND d2.next_attempt_at <= now() AND e.status = 'active'
                        ORDER BY d2.next_attempt_at LIMIT $1 FOR UPDATE OF d2 SKIP LOCKED)
        RETURNING d.*`,
      [BATCH, LEASE_SECONDS]
    )
  ).rows;
  let done = 0;
  const work = async (d: any) => {
    const ep = (await pool.query(`SELECT * FROM webhook_endpoint WHERE id = $1`, [d.endpoint_id])).rows[0];
    const ev = (await pool.query(`SELECT * FROM event WHERE id = $1`, [d.event_id])).rows[0];
    const started = Date.now();
    const startedAt = new Date(started);
    const r = ev ? await attemptDelivery(d, ep, ev) : { outcome: 'endpoint_unavailable' as Outcome, status: null, error: 'The event is no longer in the record.', sha: null };
    const attempt = d.attempts + 1;
    const final = r.outcome === 'delivered';
    const dead = !final && (attempt >= MAX_ATTEMPTS || !ev);
    const wait = BACKOFF_SECONDS[Math.min(attempt - 1, BACKOFF_SECONDS.length - 1)];
    await inTransaction(pool, async (c) => {
      await c.query(`INSERT INTO webhook_attempt (delivery_id, attempt, started_at, duration_ms, outcome, http_status, error) VALUES ($1, $2, $3, $4, $5, $6, $7)`, [d.id, attempt, startedAt, Date.now() - started, r.outcome, r.status, r.error]);
      await c.query(
        `UPDATE webhook_delivery SET attempts = $2, status = $3, last_status = $4, last_error = $5, payload_sha256 = COALESCE(payload_sha256, $6),
                delivered_at = CASE WHEN $3 = 'delivered' THEN now() ELSE NULL END, next_attempt_at = now() + make_interval(secs => $7)
          WHERE id = $1 AND status = 'pending'`,
        [d.id, attempt, final ? 'delivered' : dead ? 'dead' : 'pending', r.status, r.error, r.sha, final || dead ? 0 : wait]
      );
    });
    done++;
  };
  for (let i = 0; i < claimed.length; i += CONCURRENCY) {
    await Promise.all(claimed.slice(i, i + CONCURRENCY).map((d) => work(d).catch((err) => console.error('[webhooks] delivery failed to record:', err?.message ?? err))));
  }
  return done;
}

// --- routes ----------------------------------------------------------------------------------------------------------------

function fail(res: express.Response, err: any, what: string) {
  if (err instanceof WebhookError) return res.status(err.status).json({ error: err.message, code: err.code });
  console.error(`[webhooks] ${what}:`, err?.message ?? err);
  return res.status(500).json({ error: 'Something went wrong on the server.' });
}
const db = (res: express.Response) => {
  const pool = getDbPool();
  if (!pool) res.status(503).json({ error: 'Database not connected.' });
  return pool;
};

/** Mounted at /api/v1/webhook-endpoints, behind the full login. The secret is shown once, when it is made. */
export const webhookEndpointsRouter = express.Router();

webhookEndpointsRouter.get('/', async (_req, res) => {
  const pool = db(res);
  if (!pool) return;
  try {
    const rows = (
      await pool.query(
        `SELECT e.*, (SELECT count(*)::int FROM webhook_delivery d WHERE d.endpoint_id = e.id AND d.status = 'pending') AS pending,
                (SELECT count(*)::int FROM webhook_delivery d WHERE d.endpoint_id = e.id AND d.status = 'delivered') AS delivered,
                (SELECT count(*)::int FROM webhook_delivery d WHERE d.endpoint_id = e.id AND d.status = 'dead') AS dead
           FROM webhook_endpoint e WHERE e.creator_id = $1 ORDER BY e.created_at`,
        [creatorOf(res).id]
      )
    ).rows;
    res.json({ endpoints: rows.map((r) => ({ ...endpointView(r), deliveries: { pending: r.pending, delivered: r.delivered, dead: r.dead } })) });
  } catch (err) {
    fail(res, err, 'listing endpoints');
  }
});

webhookEndpointsRouter.post('/', async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  try {
    res.setHeader('Cache-Control', 'no-store');
    res.status(201).json(await createEndpoint(pool, creatorOf(res).id, req.body));
  } catch (err) {
    fail(res, err, 'registering an endpoint');
  }
});

webhookEndpointsRouter.post('/:id/rotate-secret', async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  if (!UUID.test(req.params.id)) return res.status(404).json({ error: 'No such webhook endpoint.' });
  try {
    res.setHeader('Cache-Control', 'no-store');
    res.json(await rotateSecret(pool, creatorOf(res).id, req.params.id.toLowerCase()));
  } catch (err) {
    fail(res, err, 'rotating a secret');
  }
});

for (const [verb, status] of [['disable', 'disabled'], ['enable', 'active']] as const) {
  webhookEndpointsRouter.post(`/:id/${verb}`, async (req, res) => {
    const pool = db(res);
    if (!pool) return;
    if (!UUID.test(req.params.id)) return res.status(404).json({ error: 'No such webhook endpoint.' });
    try {
      res.json({ endpoint: await setEndpointStatus(pool, creatorOf(res).id, req.params.id.toLowerCase(), status) });
    } catch (err) {
      fail(res, err, `${verb} an endpoint`);
    }
  });
}

webhookEndpointsRouter.get('/:id/deliveries', async (req, res) => {
  const pool = db(res);
  if (!pool) return;
  if (!UUID.test(req.params.id)) return res.status(404).json({ error: 'No such webhook endpoint.' });
  try {
    const own = (await pool.query(`SELECT 1 FROM webhook_endpoint WHERE id = $1 AND creator_id = $2`, [req.params.id, creatorOf(res).id])).rowCount;
    if (!own) return res.status(404).json({ error: 'No such webhook endpoint.' });
    const rows = (
      await pool.query(
        `SELECT d.id, d.status, d.attempts, d.next_attempt_at, d.last_status, d.last_error, d.created_at, d.delivered_at, e.id AS event_id, e.action, e.project_id
           FROM webhook_delivery d JOIN event e ON e.id = d.event_id WHERE d.endpoint_id = $1 ORDER BY d.created_at DESC LIMIT 100`,
        [req.params.id]
      )
    ).rows;
    res.json({
      deliveries: rows.map((r) => ({
        id: r.id, event_id: r.event_id, event_type: r.action, project_id: r.project_id, status: r.status, attempts: r.attempts,
        next_attempt_at: r.status === 'pending' ? new Date(r.next_attempt_at).toISOString() : null, last_status: r.last_status, last_error: r.last_error,
        created_at: new Date(r.created_at).toISOString(), delivered_at: r.delivered_at ? new Date(r.delivered_at).toISOString() : null
      }))
    });
  } catch (err) {
    fail(res, err, 'listing deliveries');
  }
});
