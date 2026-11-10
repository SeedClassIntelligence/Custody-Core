#!/usr/bin/env node
// Verifies a Custody Core project record WITHOUT Custody Core: no server code, no database, no dependencies, only Node's crypto and the format in
// docs/EVENT_HASH_FORMAT.md. Anyone holding the exported events (or the webhook deliveries they received) can run this and check the record for themselves.
//
//   node scripts/verify-chain.mjs <events.json> [--head <hash>] [--project <id>]
//       events.json is the answer of GET /api/v1/projects/:id/events (or just its "events" array).
//       Checks, in order, for every event: same project, seq counting up from 1, prev_hash = the previous event's hash (64 zeros for the first),
//       the hash recomputed from the stored fields, and (version 2) that the stored payload means what the hashed canonical_payload text says.
//       --head <hash>   also require the newest event's hash to be this one. Hash links only point backwards, so cutting off the NEWEST events leaves a
//                       valid chain: record the head hash somewhere else (a webhook delivery's record.hash is one) and pass it here to catch that.
//
//   node scripts/verify-chain.mjs --delivery <body.json> [--chain events.json]
//       body.json is the exact body of one webhook delivery. Recomputes the event's hash from what was delivered; with --chain, also requires the
//       event to be in that record at that position with that hash.
//
// Exit status 0: verified. 1: not verified (the reason is printed). 2: could not read the input.
import crypto from 'node:crypto';
import fs from 'node:fs';

const ZERO = '0'.repeat(64);
const sha256 = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const str = (v) => JSON.stringify(v);

// version 1 (written by application code before migration 003): canonical JSON, keys sorted by UTF-16 code unit
function canonicalV1(o) {
  if (o === null || typeof o !== 'object') return JSON.stringify(o);
  if (Array.isArray(o)) return '[' + o.map(canonicalV1).join(',') + ']';
  return '{' + Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canonicalV1(o[k])}`).join(',') + '}';
}

function sameJson(a, b) {
  if (a === null || typeof a !== 'object' || b === null || typeof b !== 'object') return Object.is(a, b);
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a).sort();
  const kb = Object.keys(b).sort();
  return ka.length === kb.length && ka.every((k, i) => k === kb[i] && sameJson(a[k], b[k]));
}

/** The hash an event should have, from its stored fields (docs/EVENT_HASH_FORMAT.md). */
export function expectedHash(e) {
  const timestamp = e.hashed_timestamp ?? e.timestamp;
  if (e.hash_version === 2) {
    if (typeof e.canonical_payload !== 'string') throw new Error('a version 2 event needs its canonical_payload text');
    return sha256(
      '{"action":' + str(e.action) + ',"actor_id":' + str(e.actor_id) + ',"actor_type":' + str(e.actor_type) + ',"payload":' + e.canonical_payload +
      ',"prev_hash":' + str(e.prev_hash) + ',"project_id":' + str(e.project_id) + ',"seq":' + String(e.seq) + ',"subject_id":' + str(e.subject_id) +
      ',"subject_type":' + str(e.subject_type) + ',"timestamp":' + str(timestamp) + '}'
    );
  }
  const payload = typeof e.payload === 'string' ? JSON.parse(e.payload) : e.payload;
  return sha256(canonicalV1({ action: e.action, actor_id: e.actor_id, actor_type: e.actor_type, payload, prev_hash: e.prev_hash, project_id: e.project_id, seq: e.seq, subject_id: e.subject_id, subject_type: e.subject_type, timestamp }));
}

export function verifyChain(events, { head, project } = {}) {
  if (!Array.isArray(events)) return { ok: false, reason: 'the input has no list of events' };
  let prev = ZERO;
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    const at = `event ${i + 1}${e && e.seq !== undefined ? ` (seq ${e.seq}, ${e.action})` : ''}`;
    if (!e || typeof e !== 'object') return { ok: false, at: i + 1, reason: `${at}: not an event` };
    if (project && e.project_id !== project) return { ok: false, at: e.seq, reason: `${at}: belongs to project ${e.project_id}, not ${project}` };
    if (i > 0 && e.project_id !== events[0].project_id) return { ok: false, at: e.seq, reason: `${at}: a different project from the first event` };
    if (e.seq !== i + 1) return { ok: false, at: e.seq, reason: `${at}: expected seq ${i + 1} (an event is missing, repeated or out of order)` };
    if (e.prev_hash !== prev) return { ok: false, at: e.seq, reason: `${at}: prev_hash is not the previous event's hash` };
    if (!/^[0-9a-f]{64}$/.test(e.hash ?? '')) return { ok: false, at: e.seq, reason: `${at}: the hash is not 64 lowercase hex characters` };
    let computed;
    try {
      computed = expectedHash(e);
    } catch (err) {
      return { ok: false, at: e.seq, reason: `${at}: ${err.message}` };
    }
    if (e.hash_version === 2) {
      let consistent = false;
      try {
        const payload = typeof e.payload === 'string' ? JSON.parse(e.payload) : e.payload;
        consistent = sameJson(JSON.parse(e.canonical_payload), payload);
      } catch {
        consistent = false;
      }
      if (!consistent) return { ok: false, at: e.seq, reason: `${at}: the stored payload is not what was hashed` };
    }
    if (computed !== e.hash) return { ok: false, at: e.seq, reason: `${at}: the hash does not match its contents (something was changed)` };
    prev = e.hash;
  }
  if (head && prev !== head) return { ok: false, reason: `the newest event's hash is ${prev === ZERO ? 'none (empty record)' : prev}, not the expected ${head} (newer events were cut off, or this is a different record)` };
  return { ok: true, count: events.length, head: prev, project: events[0]?.project_id ?? null };
}

export function verifyDelivery(body, chain) {
  if (!body || body.format !== 'custody-core.webhook.v1' || !body.record) return { ok: false, reason: 'not a Custody Core webhook delivery body' };
  const r = body.record;
  const e = { seq: r.seq, project_id: body.project_id, actor_type: body.actor?.type, actor_id: body.actor?.id, action: body.type, subject_type: body.subject?.type, subject_id: body.subject?.id,
    payload: body.data, prev_hash: r.prev_hash, hash: r.hash, hashed_timestamp: r.hashed_timestamp, hash_version: r.hash_version, canonical_payload: r.canonical_payload };
  let computed;
  try {
    computed = expectedHash(e);
  } catch (err) {
    return { ok: false, reason: err.message };
  }
  if (e.hash_version === 2 && !sameJson(JSON.parse(e.canonical_payload), body.data)) return { ok: false, reason: 'the delivered data is not what was hashed' };
  if (computed !== r.hash) return { ok: false, reason: 'the delivered hash does not match the delivered contents' };
  if (chain) {
    const inChain = chain.find((x) => x.seq === r.seq);
    if (!inChain || inChain.hash !== r.hash || inChain.id !== body.id) return { ok: false, reason: `the record has no such event at seq ${r.seq} with this hash` };
  }
  return { ok: true, seq: r.seq, hash: r.hash, type: body.type };
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    console.error(`Cannot read ${file}: ${err.message}`);
    process.exit(2);
  }
}

const isMain = process.argv[1] && import.meta.url === new URL(`file://${fs.realpathSync(process.argv[1])}`).href;
if (isMain) {
  const argv = process.argv.slice(2);
  const opt = (name) => {
    const i = argv.indexOf(name);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  if (argv.includes('--delivery')) {
    const chainFile = opt('--chain');
    const chain = chainFile ? (() => { const c = readJson(chainFile); return Array.isArray(c) ? c : c.events; })() : undefined;
    const r = verifyDelivery(readJson(opt('--delivery')), chain);
    console.log(r.ok ? `OK: delivery of "${r.type}" (seq ${r.seq}) is intact, hash ${r.hash}${chain ? ' and it is in the record' : ''}` : `FAIL: ${r.reason}`);
    process.exit(r.ok ? 0 : 1);
  }
  const file = argv.find((a, i) => !a.startsWith('--') && !['--head', '--project'].includes(argv[i - 1]));
  if (!file) {
    console.error('Usage: verify-chain.mjs <events.json> [--head <hash>] [--project <id>]\n       verify-chain.mjs --delivery <body.json> [--chain <events.json>]');
    process.exit(2);
  }
  const data = readJson(file);
  const r = verifyChain(Array.isArray(data) ? data : data.events, { head: opt('--head'), project: opt('--project') });
  if (r.ok) console.log(`OK: ${r.count} events${r.project ? ` of project ${r.project}` : ''}, newest hash ${r.head}`);
  else console.log(`FAIL${r.at !== undefined ? ` at seq ${r.at}` : ''}: ${r.reason}`);
  process.exit(r.ok ? 0 : 1);
}
