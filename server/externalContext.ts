import crypto from 'node:crypto';
import { canonicalJsonV2 } from '../shared/crypto';

/**
 * External context: a platform-neutral label and a block of data a caller attaches to a work session so that ITS
 * platform can find its way back (for example an orchestrator's own job id). Custody Core never reads it for any
 * purpose: it does not authorize, route, price or decide anything from it, and no code anywhere branches on a
 * namespace. It is stored, shown to the person who approves, and recorded in the project's permanent record.
 *
 * Because that record is permanent and its hashes must be re-derivable by anyone, the data is deliberately plain:
 *   - a JSON object, nested at most 8 levels, at most 1000 values, at most 16 KiB once written canonically;
 *   - keys 1 to 100 characters; text up to 2000 characters; lists up to 200 items;
 *   - numbers only as whole numbers within +/- (2^53 - 1). Anything else (decimals, huge numbers) is sent as text,
 *     because JavaScript cannot represent them exactly and the ledger would otherwise disagree with its own hash
 *     (docs/EVENT_HASH_FORMAT.md, "Where JavaScript can and cannot re-derive the payload text");
 *   - no NUL characters, no unpaired surrogates (the database refuses both), and no "__proto__" key.
 *
 * The namespace is a name the caller chooses, NOT proof of where the data came from. What proves who sent it is the
 * principal the session was requested by, which is recorded alongside.
 */

export const MAX_CONTEXT_DEPTH = 8;
export const MAX_CONTEXT_VALUES = 1000;
export const MAX_CONTEXT_KEY = 100;
export const MAX_CONTEXT_STRING = 2000;
export const MAX_CONTEXT_ARRAY = 200;
export const MAX_CONTEXT_BYTES = 16 * 1024;
export const MAX_NAMESPACE_LENGTH = 100;

/** The platform keeps the first label `custody` for itself. */
export const RESERVED_NAMESPACE_LABEL = 'custody';

/** Lowercase reverse-DNS: at least two labels of letters, digits and inner hyphens, such as com.example.orchestrator. */
const NAMESPACE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;

export function namespaceProblem(ns: unknown): string | null {
  if (typeof ns !== 'string') return 'namespace must be text.';
  if (ns.length > MAX_NAMESPACE_LENGTH) return `namespace can be at most ${MAX_NAMESPACE_LENGTH} characters.`;
  if (!NAMESPACE.test(ns)) {
    return 'namespace must be lowercase reverse-DNS with at least two labels, such as com.example.orchestrator (letters, digits and inner hyphens; no empty labels).';
  }
  if (ns.split('.')[0] === RESERVED_NAMESPACE_LABEL) return `namespaces starting with "${RESERVED_NAMESPACE_LABEL}." are reserved for the platform.`;
  return null;
}

const isPlainObject = (v: unknown): v is Record<string, unknown> => {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
};

/** An unpaired UTF-16 surrogate: not valid text, and the database refuses to store it. */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function textProblem(s: string, max: number, where: string): string | null {
  if (s.length > max) return `${where} is longer than ${max} characters.`;
  if (s.includes('\u0000')) return `${where} contains a NUL character.`;
  if (LONE_SURROGATE.test(s)) return `${where} contains an unpaired surrogate character.`;
  return null;
}

export function contextProblem(context: unknown): string | null {
  if (!isPlainObject(context)) return 'context must be a JSON object.';
  let values = 0;
  const walk = (x: unknown, depth: number, where: string): string | null => {
    if (++values > MAX_CONTEXT_VALUES) return `context has more than ${MAX_CONTEXT_VALUES} values.`;
    if (x === null || typeof x === 'boolean') return null;
    if (typeof x === 'number') {
      return Number.isSafeInteger(x) ? null : `${where}: numbers must be whole numbers no larger than 9007199254740991; send decimals and larger numbers as text.`;
    }
    if (typeof x === 'string') return textProblem(x, MAX_CONTEXT_STRING, where);
    if (depth > MAX_CONTEXT_DEPTH) return `context is nested deeper than ${MAX_CONTEXT_DEPTH} levels.`;
    if (Array.isArray(x)) {
      if (x.length > MAX_CONTEXT_ARRAY) return `${where}: a list can have at most ${MAX_CONTEXT_ARRAY} items.`;
      for (let i = 0; i < x.length; i++) {
        const p = walk(x[i], depth + 1, `${where}[${i}]`);
        if (p) return p;
      }
      return null;
    }
    if (isPlainObject(x)) {
      for (const k of Object.keys(x)) {
        if (!k) return `${where}: a key cannot be empty.`;
        if (k === '__proto__') return `${where}: "__proto__" is not allowed as a key.`;
        const kp = textProblem(k, MAX_CONTEXT_KEY, `${where}: a key`);
        if (kp) return kp;
        const p = walk(x[k], depth + 1, `${where}.${k}`);
        if (p) return p;
      }
      return null;
    }
    return `${where}: this kind of value is not allowed.`;
  };
  const structural = walk(context, 1, 'context');
  if (structural) return structural;
  if (Buffer.byteLength(canonicalJsonV2(context), 'utf8') > MAX_CONTEXT_BYTES) return `context is larger than ${MAX_CONTEXT_BYTES} bytes.`;
  return null;
}

export interface ExternalContext {
  namespace: string;
  context: Record<string, unknown>;
}

/** Why a submitted external_context is not acceptable, or null. */
export function externalContextProblem(v: unknown): string | null {
  if (!isPlainObject(v)) return 'external_context must be { "namespace": ..., "context": {...} }.';
  const extra = Object.keys(v).filter((k) => k !== 'namespace' && k !== 'context');
  if (extra.length) return `Unknown external_context field(s): ${extra.join(', ')}.`;
  if (!('namespace' in v)) return 'external_context.namespace is required.';
  if (!('context' in v)) return 'external_context.context is required.';
  return namespaceProblem(v.namespace) ?? contextProblem(v.context);
}

/**
 * SHA-256 (hex) of the canonical JSON of { context, namespace }, so one hash binds both. Anyone holding the stored
 * context can recompute it, and the database can too (canonical_jsonb); the project's record carries it.
 */
export function externalContextSha256(ec: ExternalContext): string {
  return crypto.createHash('sha256').update(canonicalJsonV2({ namespace: ec.namespace, context: ec.context }), 'utf8').digest('hex');
}
