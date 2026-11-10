/**
 * Custody Core client for machine callers (TypeScript / Node 22+). One file, no dependencies: copy it, or import it.
 *
 *   const client = new CustodyCoreClient({ baseUrl, principalId, keyId, privateKey, algorithm: 'Ed25519' });
 *   const { session_id } = await client.requestWorkSession({ ... });      // then the owner approves it, as a person
 *   const grant = await client.issueSessionCredential(session_id);         // git address and credential, shown once
 *
 * It signs in for you (a fresh client assertion for every request), signs evidence statements, and verifies webhook deliveries.
 * Describes the same API as docs/openapi.json (`GET /api/v2/openapi.json`); tests/sdk.test.ts keeps the two together.
 * Nothing here is a secret store: keep the private key where you keep any signing key.
 */
import crypto from 'node:crypto';

export type KeyAlgorithm = 'Ed25519' | 'ES256';

// --- canonical JSON and the two signed statements -------------------------------------------------------------------------

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

/** Canonical JSON (docs/EVENT_HASH_FORMAT.md): keys sorted by code point, no whitespace. Numbers must be whole numbers. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  const o = value as Record<string, unknown>;
  return '{' + Object.keys(o).sort(compareCodePoints).map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(',') + '}';
}

export const sha256Hex = (text: string | Buffer): string => crypto.createHash('sha256').update(text).digest('hex');

/** The hash a statement carries for its optional payload: SHA-256 of the canonical JSON of `payload` (`{}` if none). */
export const payloadSha256 = (payload: Record<string, unknown> = {}): string => sha256Hex(canonicalJson(payload));

export interface EvidenceStatement {
  work_session_id: string;
  evidence_type: string;
  subject_commit: string;
  status: 'pass' | 'fail' | 'inconclusive';
  specification_hash: string;
  evidence_hash: string;
  payload_sha256: string;
  issued_at: string; // UTC, whole seconds: 2026-01-31T12:00:00Z
}

/** The exact text an evidence issuer signs. */
export function evidenceSigningInput(s: EvidenceStatement): string {
  return canonicalJson({ format: 'custody-core.evidence.v1', ...s });
}

export interface AttestationStatement {
  authority_id: string;
  work_session_id: string;
  claim: string;
  subject_commit: string;
  payload_sha256: string;
  issued_at: string;
}

/** The exact text a signing authority signs (for the tool that makes attestations; the owner delivers them). */
export function attestationSigningInput(s: AttestationStatement): string {
  return canonicalJson({ format: 'custody-core.attestation.v1', ...s });
}

const b64u = (b: Buffer | string) => Buffer.from(b).toString('base64url');

/** Signs bytes the way the API expects: Ed25519 over the bytes, or ES256 as the raw 64-byte r||s. Base64url, no padding. */
export function signText(privateKey: crypto.KeyObject, algorithm: KeyAlgorithm, text: string): string {
  const data = Buffer.from(text, 'utf8');
  const sig = algorithm === 'Ed25519' ? crypto.sign(null, data, privateKey) : crypto.sign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return b64u(sig);
}

/** Whether a webhook delivery is genuine: `Custody-Signature` = `t=<unix>,v1=<hex HMAC-SHA256 of "<t>.<raw body>">`. Pass the RAW body. */
export function verifyWebhookSignature(secret: string, header: string, rawBody: string | Buffer, toleranceSeconds = 300, nowSeconds = Math.floor(Date.now() / 1000)): boolean {
  const m = /^t=(\d{1,12}),v1=([0-9a-f]{64})$/.exec(header ?? '');
  if (!m || Math.abs(nowSeconds - Number(m[1])) > toleranceSeconds) return false;
  const mac = crypto.createHmac('sha256', secret).update(`${m[1]}.`).update(rawBody).digest();
  return crypto.timingSafeEqual(mac, Buffer.from(m[2], 'hex'));
}

// --- types (the shapes of docs/openapi.json, the parts a caller reads or writes) -----------------------------------------------

export type SessionStatus = 'requested' | 'approved' | 'provisioning' | 'active' | 'awaiting_evidence' | 'completed' | 'rejected' | 'closed' | 'expired';

export interface EvidenceRequirementInput {
  type: string;
  issuer_principal_id: string;
  required?: boolean;
  tied_to_commit?: boolean;
  specification_hash?: string | null;
  max_age_seconds?: number | null;
}

export interface WorkSessionRequest {
  project_id: string;
  repository_id: string;
  executor: { type: 'ai_assistant' | 'ide_runtime' | 'ci_runtime' | 'platform_service'; provider?: string | null; model?: string | null; external_id?: string | null; display_name?: string | null };
  sponsor: { type: 'creator'; id: string };
  objective: string;
  base_commit: string;
  access: { repository: 'read' | 'read_and_push'; allowed_read_paths: string[]; allowed_write_paths?: string[]; prohibited_paths?: string[] };
  expires_in_seconds?: number;
  external_context?: { namespace: string; context: Record<string, unknown> };
  evidence_requirements?: EvidenceRequirementInput[];
}

export interface SessionRequested { session_id: string; status: SessionStatus; requires_approval: true; sponsor_id: string; branch_prefix: string; expires_at: string; event_hash: string }

export interface WorkSession {
  id: string; project_id: string; repository_id: string | null; session_type: string; status: SessionStatus; objective: string; base_commit: string | null; branch_name: string | null;
  executor: { type: string; provider: string | null; model: string | null; external_id: string | null; display_name: string | null };
  evidence_requirements: Array<{ type: string; issuer_principal_id: string; required: boolean; tied_to_commit: boolean; specification_hash: string | null; max_age_seconds: number | null; issuer_is_requester: boolean }>;
  created_at: string; approved_at: string | null; expires_at: string | null; closed_at: string | null; closed_reason: string | null;
  [more: string]: unknown;
}

export interface SessionCredential {
  session_id: string; repository: string; read_only: boolean; git_url: string; credential: { token: string; expires_at: string };
  branch_prefix: string; view: { commit: string; tree: string; file_count: number; base_commit: string }; replaced: boolean;
}

export interface EvidenceInput {
  evidence_type: string;
  subject_commit: string;
  status: 'pass' | 'fail' | 'inconclusive';
  specification_hash: string;
  evidence_hash: string;
  /** Default: now. */
  issued_at?: string;
  payload?: Record<string, unknown>;
}

export interface EvidenceEvaluation {
  commit: string | null;
  ready: boolean;
  requirements: Array<{ evidence_type: string; issuer_principal_id: string; required: boolean; tied_to_commit: boolean; state: 'satisfied' | 'failed' | 'inconclusive' | 'missing' | 'stale' | 'issuer_unavailable'; submission_id: string | null; issued_at: string | null; [more: string]: unknown }>;
}

export interface Promotion { id: string; work_session_id: string; commit: string; target_branch: string; status: 'pending' | 'approved' | 'completed' | 'rejected' | 'failed'; [more: string]: unknown }

/** Anything the server refuses: the HTTP status, its words, and its stable `code` where it gives one. Never contains a secret. */
export class CustodyCoreError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly code: string | undefined,
    readonly body: unknown
  ) {
    super(message);
    this.name = 'CustodyCoreError';
  }
}

export interface ClientOptions {
  /** The server's address, for example https://custody.example.com (no trailing path). */
  baseUrl: string;
  principalId: string;
  /** The id of the registered key (`key_id`), not the key itself. */
  keyId: string;
  /** The private key: a Node KeyObject, a PEM string, or a private JWK (the file `npm run principal -- keygen` writes). */
  privateKey: crypto.KeyObject | string | Record<string, unknown>;
  algorithm: KeyAlgorithm;
  /** Seconds each assertion is valid for (default 60, at most 300). */
  assertionLifetimeSeconds?: number;
  /** For tests or proxies. Default: the global fetch. */
  fetch?: typeof fetch;
}

const q = (params: Record<string, string | undefined>) => {
  const e = Object.entries(params).filter(([, v]) => v !== undefined) as Array<[string, string]>;
  return e.length ? `?${new URLSearchParams(e).toString()}` : '';
};

export class CustodyCoreClient {
  private readonly key: crypto.KeyObject;
  constructor(private readonly o: ClientOptions) {
    const k = o.privateKey;
    this.key = typeof k === 'string' ? crypto.createPrivateKey(k) : 'kty' in (k as object) && !(k instanceof crypto.KeyObject) ? crypto.createPrivateKey({ key: k as crypto.JsonWebKey, format: 'jwk' }) : (k as crypto.KeyObject);
    if (!/^https?:\/\/[^/\s]+$/.test(o.baseUrl.replace(/\/+$/, ''))) throw new Error('baseUrl must be like https://custody.example.com');
  }

  /** A fresh client assertion (never reused: the server refuses a repeated `jti`). */
  assertion(): string {
    const now = Math.floor(Date.now() / 1000);
    const life = Math.min(this.o.assertionLifetimeSeconds ?? 60, 300);
    const header = { alg: this.o.algorithm === 'Ed25519' ? 'EdDSA' : 'ES256', typ: 'JWT', kid: this.o.keyId };
    const claims = { iss: this.o.principalId, sub: this.o.principalId, aud: 'custody-core', iat: now, exp: now + life, jti: crypto.randomUUID() };
    const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(claims))}`;
    return `${input}.${signText(this.key, this.o.algorithm, input)}`;
  }

  private async call<T>(method: string, path: string, body?: unknown): Promise<{ status: number; body: T }> {
    const f = this.o.fetch ?? fetch;
    const res = await f(`${this.o.baseUrl.replace(/\/+$/, '')}/api/v2${path}`, {
      method,
      headers: { Authorization: `Bearer ${this.assertion()}`, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    const parsed: any = await res.json().catch(() => ({}));
    if (!res.ok) throw new CustodyCoreError(res.status, String(parsed?.error ?? `HTTP ${res.status}`), typeof parsed?.code === 'string' ? parsed.code : undefined, parsed);
    return { status: res.status, body: parsed as T };
  }
  private async get<T>(path: string) {
    return (await this.call<T>('GET', path)).body;
  }
  private async post<T>(path: string, body?: unknown) {
    return (await this.call<T>('POST', path, body)).body;
  }

  // --- the API (one method per operation in docs/openapi.json) -------------------------------------------------------------

  whoami() {
    return this.get<{ principal: { id: string; name: string; scopes: string[]; allowed_project_ids: string[] | null; [more: string]: unknown } }>('/whoami');
  }
  /** Scope work-sessions:request. The session waits for its owner's approval. */
  requestWorkSession(request: WorkSessionRequest) {
    return this.post<SessionRequested>('/work-sessions', request);
  }
  /** Scope work-sessions:read. */
  async listWorkSessions(filter: { project_id?: string; status?: SessionStatus } = {}) {
    return (await this.get<{ work_sessions: WorkSession[] }>(`/work-sessions${q(filter)}`)).work_sessions;
  }
  async getWorkSession(id: string) {
    return (await this.get<{ work_session: WorkSession }>(`/work-sessions/${id}`)).work_session;
  }
  /** Scope work-sessions:close-own. */
  closeWorkSession(id: string) {
    return this.post<{ session_id: string; status: SessionStatus }>(`/work-sessions/${id}/close`);
  }
  /** Scope repositories:push-session; only the requester. First call prepares the session and issues the credential; later calls replace it. */
  issueSessionCredential(id: string) {
    return this.post<SessionCredential>(`/work-sessions/${id}/credential`);
  }
  async listSessionCommits(id: string) {
    return (await this.get<{ commits: Array<{ view_sha: string; real_sha: string; parent_view_sha: string; declared_author: string; created_at: string }> }>(`/work-sessions/${id}/commits`)).commits;
  }
  /**
   * Scope evidence:submit, as the issuer the request named. Signs the statement with this client's key (the same key as the sign-in) and sends it.
   * Sending the identical statement again changes nothing; pass the same `evidence_hash` and `issued_at`.
   */
  submitEvidence(sessionId: string, e: EvidenceInput) {
    const payload = e.payload ?? {};
    const statement: EvidenceStatement = {
      work_session_id: sessionId, evidence_type: e.evidence_type, subject_commit: e.subject_commit, status: e.status, specification_hash: e.specification_hash, evidence_hash: e.evidence_hash,
      payload_sha256: payloadSha256(payload), issued_at: e.issued_at ?? new Date().toISOString().replace(/\.\d+Z$/, 'Z')
    };
    const { work_session_id: _s, payload_sha256: _p, ...fields } = statement;
    return this.post<Record<string, unknown> & { id: string; recorded: boolean }>(`/work-sessions/${sessionId}/evidence`, {
      ...fields, payload, signature: { key_id: this.o.keyId, algorithm: this.o.algorithm, value: signText(this.key, this.o.algorithm, evidenceSigningInput(statement)) }
    });
  }
  /** The session's evidence, and whether each requirement is met for a commit (default: the newest). */
  getEvidence(id: string, commit?: string) {
    return this.get<{ session_id: string; evaluation: EvidenceEvaluation; submissions: Array<Record<string, unknown>> }>(`/work-sessions/${id}/evidence${q({ commit })}`);
  }
  async getAttribution(id: string) {
    return (await this.get<{ contributions: Array<Record<string, unknown>> }>(`/work-sessions/${id}/attribution`)).contributions;
  }
  async listAttestations(id: string, commit?: string) {
    return (await this.get<{ attestations: Array<Record<string, unknown>> }>(`/work-sessions/${id}/attestations${q({ commit })}`)).attestations;
  }
  /** Scope repositories:promote. The request waits for the owner. */
  async requestPromotion(id: string, commit?: string) {
    return (await this.post<{ promotion: Promotion; requires_approval: true }>(`/work-sessions/${id}/promote`, commit ? { commit } : {})).promotion;
  }
  async listPromotions(id: string) {
    return (await this.get<{ promotions: Promotion[] }>(`/work-sessions/${id}/promotions`)).promotions;
  }
}
