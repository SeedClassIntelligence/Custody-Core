/**
 * Shared cryptographic utilities for Custody Core.
 * Used identically by both the Express server and the React client.
 */

export interface EventHashInput {
  seq: number;
  project_id: string;
  actor_type: string;
  actor_id: string;
  action: string;
  subject_type: string;
  subject_id: string;
  payload: Record<string, any>;
  prev_hash: string;
  timestamp: string;
  /** 1 = hashed by application code (payload re-serialised here); 2 = hashed by the database. */
  hash_version?: number;
  /** Version 2 only: the exact payload text the database hashed. */
  canonical_payload?: string | null;
}

/**
 * Standardize JSON serialization so keys are deterministically sorted at all nested levels.
 */
export function canonicalJson(obj: any): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalJson).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  const pairs = keys.map(k => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`);
  return '{' + pairs.join(',') + '}';
}

function compareCodePoints(a: string, b: string): number {
  const x = Array.from(a);
  const y = Array.from(b);
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) {
    const d = x[i].codePointAt(0)! - y[i].codePointAt(0)!;
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

/**
 * Canonical JSON as the database writes it for hash_version 2 (see docs/EVENT_HASH_FORMAT.md):
 * object keys sorted by Unicode code point (the v1 canonicalJson sorts by UTF-16 unit, which differs
 * for characters above U+FFFF). Numbers use JavaScript's formatting, which matches the database
 * only for integers up to 2^53 and decimals that survive a round trip through a double; for other
 * numbers, trust the stored canonical_payload text, not this function.
 */
export function canonicalJsonV2(obj: any): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalJsonV2).join(',') + ']';
  }
  const keys = Object.keys(obj).sort(compareCodePoints);
  return '{' + keys.map(k => `${JSON.stringify(k)}:${canonicalJsonV2(obj[k])}`).join(',') + '}';
}

/**
 * Computes SHA-256 hash using native Web Crypto API or Node crypto fallback.
 */
export async function sha256(message: string): Promise<string> {
  if (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle) {
    const msgUint8 = new TextEncoder().encode(message);
    const hashBuffer = await globalThis.crypto.subtle.digest('SHA-256', msgUint8);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // Node.js fallback
  try {
    const { createHash } = await import('node:crypto');
    return createHash('sha256').update(message, 'utf8').digest('hex');
  } catch (err) {
    throw new Error('No crypto implementation available for SHA-256');
  }
}

export const GENESIS_PREV_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

/**
 * Compute the cryptographic hash for an event block.
 * Per technical spec: covers every field of the event except `hash` and `seed_signature_id`,
 * specifically including project_id, actor_type, actor_id, subject_type, and subject_id.
 */
export async function computeEventHash(event: EventHashInput): Promise<string> {
  if (event.hash_version === 2) {
    if (typeof event.canonical_payload !== 'string') {
      throw new Error('A hash_version 2 event needs its canonical_payload text.');
    }
    // Same bytes the database hashes: keys in alphabetical order, payload embedded as its stored text.
    const s = (v: string) => JSON.stringify(v);
    return await sha256(
      '{"action":' + s(event.action) +
      ',"actor_id":' + s(event.actor_id) +
      ',"actor_type":' + s(event.actor_type) +
      ',"payload":' + event.canonical_payload +
      ',"prev_hash":' + s(event.prev_hash) +
      ',"project_id":' + s(event.project_id) +
      ',"seq":' + String(event.seq) +
      ',"subject_id":' + s(event.subject_id) +
      ',"subject_type":' + s(event.subject_type) +
      ',"timestamp":' + s(event.timestamp) +
      '}'
    );
  }

  const canonical = canonicalJson({
    action: event.action,
    actor_id: event.actor_id,
    actor_type: event.actor_type,
    payload: event.payload,
    prev_hash: event.prev_hash,
    project_id: event.project_id,
    seq: event.seq,
    subject_id: event.subject_id,
    subject_type: event.subject_type,
    timestamp: event.timestamp
  });

  return await sha256(canonical);
}

export interface VerificationResult {
  isValid: boolean;
  totalEvents: number;
  brokenAtSeq?: number;
  expectedHash?: string;
  actualHash?: string;
  reason?: string;
  verifiedAt: string;
}

/**
 * Verifies the append-only hash chain integrity from genesis to latest block for a project.
 */
export async function verifyHashChain(
  events: Array<EventHashInput & { hash: string; seed_signature_id?: string }>
): Promise<VerificationResult> {
  const now = new Date().toISOString();
  if (events.length === 0) {
    return {
      isValid: true,
      totalEvents: 0,
      verifiedAt: now
    };
  }

  for (let i = 0; i < events.length; i++) {
    const event = events[i];
    const expectedPrevHash = i === 0 ? GENESIS_PREV_HASH : events[i - 1].hash;

    // Check link to previous hash
    if (event.prev_hash !== expectedPrevHash) {
      return {
        isValid: false,
        totalEvents: events.length,
        brokenAtSeq: event.seq,
        expectedHash: expectedPrevHash,
        actualHash: event.prev_hash,
        reason: `Previous hash linkage broken at event #${event.seq} (${event.action}). Expected link: ${expectedPrevHash.substring(0, 16)}..., got: ${event.prev_hash.substring(0, 16)}...`,
        verifiedAt: now
      };
    }

    // Compute expected hash of this event block across all covered fields
    const computedHash = await computeEventHash({
      seq: event.seq,
      project_id: event.project_id,
      actor_type: event.actor_type,
      actor_id: event.actor_id,
      action: event.action,
      subject_type: event.subject_type,
      subject_id: event.subject_id,
      payload: event.payload,
      prev_hash: event.prev_hash,
      timestamp: event.timestamp,
      hash_version: event.hash_version,
      canonical_payload: event.canonical_payload
    });

    // A version 2 hash covers canonical_payload; the separate payload column must say the same thing.
    if (event.hash_version === 2) {
      let consistent = false;
      try {
        consistent = canonicalJsonV2(JSON.parse(event.canonical_payload as string)) === canonicalJsonV2(event.payload);
      } catch {
        consistent = false;
      }
      if (!consistent) {
        return {
          isValid: false,
          totalEvents: events.length,
          brokenAtSeq: event.seq,
          reason: `The stored payload of event #${event.seq} (${event.action}) does not match the payload that was hashed.`,
          verifiedAt: now
        };
      }
    }

    if (computedHash !== event.hash) {
      return {
        isValid: false,
        totalEvents: events.length,
        brokenAtSeq: event.seq,
        expectedHash: computedHash,
        actualHash: event.hash,
        reason: `Hash integrity mismatch at event #${event.seq} (${event.action}). The payload, actor, or metadata has been altered!`,
        verifiedAt: now
      };
    }
  }

  return {
    isValid: true,
    totalEvents: events.length,
    verifiedAt: now
  };
}

export function formatHash(hash: string, lead = 8, trail = 6): string {
  if (!hash) return '';
  if (hash.length <= lead + trail) return hash;
  return `${hash.substring(0, lead)}...${hash.substring(hash.length - trail)}`;
}

/** An account event (account_event table): one hash chain per login, built by the database. */
export interface AccountEventInput {
  seq: number;
  account_id: string;
  actor_type: string;
  actor_id: string;
  action: string;
  payload: Record<string, any>;
  canonical_payload: string;
  prev_hash: string;
  timestamp: string;
}

/**
 * Same rules as a version 2 project event (docs/EVENT_HASH_FORMAT.md), with `account_id` in place of
 * `project_id` and no subject fields: keys in alphabetical order, payload embedded as its stored text.
 */
export async function computeAccountEventHash(event: AccountEventInput): Promise<string> {
  const s = (v: string) => JSON.stringify(v);
  return await sha256(
    '{"account_id":' + s(event.account_id) +
    ',"action":' + s(event.action) +
    ',"actor_id":' + s(event.actor_id) +
    ',"actor_type":' + s(event.actor_type) +
    ',"payload":' + event.canonical_payload +
    ',"prev_hash":' + s(event.prev_hash) +
    ',"seq":' + String(event.seq) +
    ',"timestamp":' + s(event.timestamp) +
    '}'
  );
}

export async function verifyAccountChain(events: Array<AccountEventInput & { hash: string }>): Promise<VerificationResult> {
  const now = new Date().toISOString();
  for (let i = 0; i < events.length; i++) {
    const event = events[i];
    const expectedPrev = i === 0 ? GENESIS_PREV_HASH : events[i - 1].hash;
    const fail = (reason: string) => ({ isValid: false, totalEvents: events.length, brokenAtSeq: event.seq, reason, verifiedAt: now });
    if (event.seq !== i + 1) return fail(`Account event #${event.seq} is out of sequence.`);
    if (event.prev_hash !== expectedPrev) return fail(`Previous hash linkage broken at account event #${event.seq}.`);
    let consistent = false;
    try {
      consistent = canonicalJsonV2(JSON.parse(event.canonical_payload)) === canonicalJsonV2(event.payload);
    } catch {
      consistent = false;
    }
    if (!consistent) return fail(`The stored payload of account event #${event.seq} does not match the payload that was hashed.`);
    if ((await computeAccountEventHash(event)) !== event.hash) return fail(`Hash integrity mismatch at account event #${event.seq}.`);
  }
  return { isValid: true, totalEvents: events.length, verifiedAt: now };
}
