import { authFetch } from '../auth/supabase';
import { canonicalJsonV2, sha256 } from '../../shared/crypto';

/** Owner-side calls for work sessions, evidence, attribution, attestations, promotions, signing authorities, webhooks and backup checks. All on /api/v1 (full login). Shapes follow docs/openapi.json. */

async function jsonOrThrow(res: Response, what: string): Promise<any> {
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `${what} failed (server returned ${res.status}).`);
  return body;
}

const JSON_HEADERS = { 'Content-Type': 'application/json' };
const post = (url: string, what: string, body?: unknown) =>
  authFetch(url, { method: 'POST', ...(body === undefined ? {} : { headers: JSON_HEADERS, body: JSON.stringify(body) }) }).then((r) => jsonOrThrow(r, what));

// --- Types ---------------------------------------------------------------------------------------------------

export type SessionStatus = 'requested' | 'approved' | 'provisioning' | 'active' | 'awaiting_evidence' | 'completed' | 'rejected' | 'closed' | 'expired';

export interface EvidenceRequirement {
  type: string;
  issuer_principal_id: string;
  required: boolean;
  tied_to_commit: boolean;
  specification_hash?: string | null;
  max_age_seconds?: number | null;
  issuer_is_requester?: boolean;
}

export interface WorkSession {
  id: string;
  project_id: string;
  repository_id?: string;
  session_type?: string;
  status: SessionStatus;
  executor?: { type?: string; provider?: string; model?: string; external_id?: string; display_name?: string };
  sponsor_id?: string;
  objective?: string;
  base_commit?: string;
  branch_name?: string;
  access?: { repository?: string; allowed_read_paths?: string[]; allowed_write_paths?: string[]; prohibited_paths?: string[] };
  external_context?: unknown;
  evidence_requirements?: EvidenceRequirement[];
  created_at?: string;
  approved_at?: string | null;
  expires_at?: string | null;
  closed_at?: string | null;
  closed_reason?: string | null;
}

export interface EvidenceEvaluation {
  commit: string | null;
  ready: boolean;
  requirements: Array<{ evidence_type?: string; issuer_principal_id?: string; required?: boolean; tied_to_commit?: boolean; state?: string; submission_id?: string | null; issued_at?: string | null }>;
}
export interface EvidenceReport {
  session_id?: string;
  evaluation?: EvidenceEvaluation;
  submissions?: Array<{ id: string; evidence_type: string; subject_commit: string; status: string; issued_at?: string }>;
}
export interface Contribution {
  commit?: string;
  pushed_as?: string;
  author?: { kind?: string; principal_id?: string; executor?: Record<string, unknown>; as_written_in_git?: Record<string, unknown> };
  sponsor?: { kind?: string; id?: string };
  declared_author?: { value?: string; trusted?: boolean };
  recorded_at?: string;
}
export interface Attestation {
  id: string;
  authority?: { id?: string; name?: string; active?: boolean };
  claim: string;
  subject_commit: string;
  payload_sha256?: string;
  issued_at?: string;
  recorded_at?: string;
}
export interface Promotion {
  id: string;
  work_session_id: string;
  repository_id?: string;
  target_branch?: string;
  commit: string;
  status: 'pending' | 'approved' | 'completed' | 'rejected' | 'failed';
  requested_at?: string;
  approved_at?: string | null;
  rejected_reason?: string | null;
  previous_tip?: string | null;
  completed_at?: string | null;
  failure_code?: string | null;
  evidence_at_request?: EvidenceEvaluation;
  attestations_at_request?: Array<{ id?: string; claim?: string; authority_id?: string }>;
}
export interface Authority {
  id: string;
  name: string;
  algorithm?: string;
  fingerprint?: string;
  created_at?: string;
  revoked_at?: string | null;
}
export interface WebhookEndpoint {
  id: string;
  name: string;
  url: string;
  events: string[];
  project_ids?: string[] | null;
  status: 'active' | 'disabled';
  created_at?: string;
  secret_rotated_at?: string | null;
  disabled_at?: string | null;
  deliveries?: { pending?: number; delivered?: number; dead?: number };
}
export interface WebhookDelivery {
  id?: string;
  event_type?: string;
  status?: 'pending' | 'delivered' | 'dead';
  attempts?: number;
  last_status?: number | null;
  last_error?: string | null;
  created_at?: string;
  delivered_at?: string | null;
}

// --- Work sessions ---------------------------------------------------------------------------------------------

const wsUrl = (p: string, sid?: string, tail = '') => `/api/v1/projects/${p}/work-sessions${sid ? `/${sid}` : ''}${tail}`;

export async function fetchWorkSessions(projectId: string): Promise<WorkSession[]> {
  return (await jsonOrThrow(await authFetch(wsUrl(projectId)), 'Loading work sessions')).work_sessions ?? [];
}
export const approveWorkSession = (projectId: string, sid: string) => post(wsUrl(projectId, sid, '/approve'), 'Approving the session');
export const rejectWorkSession = (projectId: string, sid: string, reason: string) =>
  post(wsUrl(projectId, sid, '/reject'), 'Rejecting the session', reason.trim() ? { reason: reason.trim() } : {});
export async function fetchEvidence(projectId: string, sid: string, commit?: string): Promise<EvidenceReport> {
  return jsonOrThrow(await authFetch(wsUrl(projectId, sid, `/evidence${commit ? `?commit=${commit}` : ''}`)), 'Loading evidence');
}
export async function fetchAttribution(projectId: string, sid: string): Promise<Contribution[]> {
  return (await jsonOrThrow(await authFetch(wsUrl(projectId, sid, '/attribution')), 'Loading attribution')).contributions ?? [];
}
export async function fetchAttestations(projectId: string, sid: string): Promise<Attestation[]> {
  return (await jsonOrThrow(await authFetch(wsUrl(projectId, sid, '/attestations')), 'Loading attestations')).attestations ?? [];
}
export interface AttestationInput {
  authority_id: string;
  claim: string;
  subject_commit: string;
  issued_at: string;
  payload?: Record<string, unknown>;
  signature: { algorithm: 'Ed25519' | 'ES256'; value: string };
}
export const deliverAttestation = (projectId: string, sid: string, input: AttestationInput): Promise<Attestation & { recorded?: boolean }> =>
  post(wsUrl(projectId, sid, '/attestations'), 'Recording the attestation', input);

/** The exact text an authority signs for an attestation (docs/integration/PHASE7_DESIGN.md), built the way the server builds it. */
export async function attestationStatementToSign(input: { authority_id: string; work_session_id: string; claim: string; subject_commit: string; issued_at: string; payload?: Record<string, unknown> }): Promise<string> {
  return canonicalJsonV2({
    format: 'custody-core.attestation.v1',
    authority_id: input.authority_id.toLowerCase(),
    work_session_id: input.work_session_id.toLowerCase(),
    claim: input.claim,
    subject_commit: input.subject_commit,
    payload_sha256: await sha256(canonicalJsonV2(input.payload ?? {})),
    issued_at: input.issued_at
  });
}

// --- Promotions --------------------------------------------------------------------------------------------------

export async function fetchSessionPromotions(projectId: string, sid: string): Promise<Promotion[]> {
  return (await jsonOrThrow(await authFetch(wsUrl(projectId, sid, '/promotions')), 'Loading promotions')).promotions ?? [];
}
export async function fetchProjectPromotions(projectId: string): Promise<Promotion[]> {
  return (await jsonOrThrow(await authFetch(`/api/v1/projects/${projectId}/promotions`), 'Loading promotions')).promotions ?? [];
}
export async function requestPromotion(projectId: string, sid: string, commit?: string): Promise<Promotion> {
  return (await post(wsUrl(projectId, sid, '/promotions'), 'Requesting the promotion', commit ? { commit } : {})).promotion;
}
export async function approvePromotion(projectId: string, pid: string): Promise<Promotion> {
  return (await post(`/api/v1/projects/${projectId}/promotions/${pid}/approve`, 'Approving the promotion')).promotion;
}
export async function rejectPromotion(projectId: string, pid: string, reason: string): Promise<Promotion> {
  return (await post(`/api/v1/projects/${projectId}/promotions/${pid}/reject`, 'Rejecting the promotion', reason.trim() ? { reason: reason.trim() } : {})).promotion;
}

// --- Signing authorities -------------------------------------------------------------------------------------------

export async function fetchAuthorities(): Promise<Authority[]> {
  return (await jsonOrThrow(await authFetch('/api/v1/attestation-authorities'), 'Loading signing authorities')).authorities ?? [];
}
export async function registerAuthority(name: string, publicKey: unknown): Promise<Authority> {
  return (await post('/api/v1/attestation-authorities', 'Registering the authority', { name, public_key: publicKey })).authority;
}
export async function revokeAuthority(id: string): Promise<Authority> {
  return (await post(`/api/v1/attestation-authorities/${id}/revoke`, 'Revoking the authority')).authority;
}

// --- Webhooks ------------------------------------------------------------------------------------------------------

export async function fetchWebhookEndpoints(): Promise<WebhookEndpoint[]> {
  return (await jsonOrThrow(await authFetch('/api/v1/webhook-endpoints'), 'Loading webhook endpoints')).endpoints ?? [];
}
export const createWebhookEndpoint = (input: { name: string; url: string; events: string[]; project_ids?: string[] }): Promise<{ endpoint: WebhookEndpoint; secret: string }> =>
  post('/api/v1/webhook-endpoints', 'Creating the webhook endpoint', input);
export const rotateWebhookSecret = (id: string): Promise<{ endpoint: WebhookEndpoint; secret: string }> => post(`/api/v1/webhook-endpoints/${id}/rotate-secret`, 'Rotating the secret');
export async function setWebhookEnabled(id: string, enabled: boolean): Promise<WebhookEndpoint> {
  return (await post(`/api/v1/webhook-endpoints/${id}/${enabled ? 'enable' : 'disable'}`, enabled ? 'Enabling the endpoint' : 'Disabling the endpoint')).endpoint;
}
export async function fetchWebhookDeliveries(id: string): Promise<WebhookDelivery[]> {
  return (await jsonOrThrow(await authFetch(`/api/v1/webhook-endpoints/${id}/deliveries`), 'Loading deliveries')).deliveries ?? [];
}

// --- Backups ---------------------------------------------------------------------------------------------------------

export interface SnapshotCheck {
  ok: boolean;
  encrypted?: boolean;
  bytes?: number;
  problem?: string;
  error?: string;
}
/** Opens the stored backup completely on the server and compares it with its record. A damaged backup answers 409 with the problem, which is a result, not a failure. */
export async function verifySnapshot(projectId: string, snapshotId: string): Promise<SnapshotCheck> {
  const res = await authFetch(`/api/v1/projects/${projectId}/snapshots/${snapshotId}/verify`, { method: 'POST' });
  const body = await res.json().catch(() => ({}));
  if (res.ok || res.status === 409) return body;
  throw new Error(body.error || `Checking the backup failed (server returned ${res.status}).`);
}
