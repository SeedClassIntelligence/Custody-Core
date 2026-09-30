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
      timestamp: event.timestamp
    });

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
