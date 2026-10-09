import { CustodyEvent, Project } from '../types/custody';
import { authFetch } from '../auth/supabase';

/** Thin wrappers over the server API. Nothing here invents data: failures throw. */

export interface ProjectsResponse {
  projects: Project[];
  connected: boolean;
  message?: string;
}

export async function fetchProjects(): Promise<ProjectsResponse> {
  const res = await authFetch('/api/v1/projects');
  if (!res.ok) throw new Error(`Could not load projects (server returned ${res.status}).`);
  const data = await res.json();
  return {
    projects: Array.isArray(data.projects) ? data.projects : [],
    connected: data.connected !== false,
    message: data.message
  };
}

export function mapServerEvent(e: any): CustodyEvent {
  return {
    seq: Number(e.seq),
    project_id: e.project_id,
    actor_type: e.actor_type,
    actor_id: e.actor_id,
    actor_name: e.actor_name || e.actor_id,
    action: e.action,
    subject_type: e.subject_type,
    subject_id: e.subject_id,
    payload: typeof e.payload === 'string' ? JSON.parse(e.payload) : e.payload,
    prev_hash: e.prev_hash,
    hash: e.hash,
    seed_signature_id: e.seed_signature_id || '',
    timestamp: e.timestamp || e.hashed_timestamp || e.created_at,
    hash_version: e.hash_version,
    canonical_payload: e.canonical_payload
  };
}

export async function fetchProjectEvents(projectId: string): Promise<CustodyEvent[]> {
  const res = await authFetch(`/api/v1/projects/${projectId}/events`);
  if (!res.ok) throw new Error(`Could not load the event log (server returned ${res.status}).`);
  const data = await res.json();
  return (data.events || []).map(mapServerEvent);
}

export async function claimProject(input: { name: string; purpose: string }): Promise<Project> {
  const res = await authFetch('/api/v1/projects', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: input.name, purpose: input.purpose })
  });
  const payload = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(payload.error || `The server could not record the project (status ${res.status}).`);
  }
  return payload.project as Project;
}

// --- GitHub connection ---------------------------------------------------------------------------------------

export interface GitHubStatus {
  configured: boolean;
  connected: boolean;
  account_login: string | null;
  account_type: string | null;
}

async function jsonOrThrow(res: Response, what: string): Promise<any> {
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `${what} failed (server returned ${res.status}).`);
  return body;
}

export async function fetchGitHubStatus(): Promise<GitHubStatus> {
  return jsonOrThrow(await authFetch('/api/v1/github'), 'Reading the GitHub connection');
}

/** Starts installing the GitHub App: the server sets a short-lived cookie for this browser and returns GitHub's page. */
export async function startGitHubInstall(): Promise<string> {
  const body = await jsonOrThrow(await authFetch('/api/v1/github/install', { method: 'POST' }), 'Starting the GitHub connection');
  return body.url as string;
}

export interface GitHubRepository {
  id: number;
  full_name: string;
  default_branch: string;
  private: boolean;
}

export async function fetchGitHubRepositories(): Promise<GitHubRepository[]> {
  return (await jsonOrThrow(await authFetch('/api/v1/github/repositories'), 'Listing GitHub repositories')).repositories;
}

export async function addRepositories(projectId: string, fullNames: string[]) {
  return (await jsonOrThrow(
    await authFetch(`/api/v1/projects/${projectId}/repositories`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ full_names: fullNames })
    }),
    'Adding repositories'
  )).repositories;
}

// --- Doors ---------------------------------------------------------------------------------------------------

export interface ServerDoor {
  id: string;
  project_id: string;
  developer_email: string;
  job_description: string;
  rights_type: string;
  status: 'draft' | 'open' | 'closed' | string;
  opens_at: string | null;
  expires_at: string;
  closed_at: string | null;
  closed_reason: string | null;
  created_at: string;
  branch_prefix: string;
  repositories: Array<{ repository_id: string; full_name: string; access: 'read' | 'write' }>;
  credential: { id: string; created_at: string; last_used_at: string | null } | null;
  remotes: Array<{ full_name: string; url: string }>;
  agreement_version?: string | null;
  agreement_sha256?: string | null;
  agreement_signed_at?: string | null;
  agreement_signer_name?: string | null;
  agreement_key_fingerprint?: string | null;
  invite?: { created_at: string; expires_at: string; accepted_at: string | null } | null;
  snapshot_status?: 'pending' | 'done' | 'failed' | null;
  snapshot_error?: string | null;
  snapshot_attempts?: number;
}

export async function fetchDoors(projectId: string): Promise<ServerDoor[]> {
  return (await jsonOrThrow(await authFetch(`/api/v1/projects/${projectId}/doors`), 'Loading doors')).doors;
}

export async function createDoor(
  projectId: string,
  input: {
    developer_email: string;
    job_description: string;
    rights_type: string;
    expires_at: string;
    repositories: Array<{ repository_id: string; access: 'read' | 'write' }>;
  }
): Promise<ServerDoor> {
  return (await jsonOrThrow(
    await authFetch(`/api/v1/projects/${projectId}/doors`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input)
    }),
    'Creating the door'
  )).door;
}

export async function openDoor(projectId: string, doorId: string): Promise<{ door: ServerDoor; credential: { username: string; token: string } }> {
  return jsonOrThrow(await authFetch(`/api/v1/projects/${projectId}/doors/${doorId}/open`, { method: 'POST' }), 'Opening the door');
}

export async function closeDoor(projectId: string, doorId: string): Promise<ServerDoor> {
  return (await jsonOrThrow(await authFetch(`/api/v1/projects/${projectId}/doors/${doorId}/close`, { method: 'POST' }), 'Closing the door')).door;
}

/** Locks a repository on GitHub, or re-checks the lock (and puts it back if it was removed or changed). */
export async function checkRepositoryLock(projectId: string, repositoryId: string) {
  return (await jsonOrThrow(
    await authFetch(`/api/v1/projects/${projectId}/repositories/${repositoryId}/lock`, { method: 'POST' }),
    'Checking the lock'
  )).repository;
}

// --- Invitations and signing ---------------------------------------------------------------------------------

export async function inviteDeveloper(projectId: string, doorId: string): Promise<{ door: ServerDoor; invite: { url: string; expires_at: string } }> {
  return jsonOrThrow(await authFetch(`/api/v1/projects/${projectId}/doors/${doorId}/invite`, { method: 'POST' }), 'Sending the invitation');
}

export async function fetchDoorAgreement(projectId: string, doorId: string) {
  return (await jsonOrThrow(await authFetch(`/api/v1/projects/${projectId}/doors/${doorId}/agreement`), 'Reading the agreement')).agreement as {
    agreement_version: string | null;
    agreement_text: string | null;
    agreement_sha256: string | null;
    agreement_signed_at: string | null;
    agreement_signed_message: string | null;
    agreement_signature: string | null;
    public_key_spki: string | null;
    fingerprint: string | null;
  };
}

export interface DeveloperDoor {
  id: string;
  project_id: string;
  project_name: string;
  creator_name: string;
  job_description: string;
  rights_type: string;
  status: string;
  expires_at: string;
  opens_at: string | null;
  closed_at: string | null;
  developer_email: string;
  agreement_version: string | null;
  agreement_text: string | null;
  agreement_sha256: string | null;
  agreement_signed_at: string | null;
  branch_prefix: string;
  repositories: Array<{ full_name: string; access: string }>;
  credential: { id: string; created_at: string; last_used_at: string | null } | null;
  remotes: Array<{ full_name: string; url: string }>;
}

export async function fetchInvite(token: string) {
  return (await jsonOrThrow(await authFetch(`/api/v1/developer/invites/${encodeURIComponent(token)}`), 'Opening the invitation')).invite;
}

export async function acceptInvite(token: string): Promise<string> {
  return (await jsonOrThrow(await authFetch(`/api/v1/developer/invites/${encodeURIComponent(token)}/accept`, { method: 'POST' }), 'Accepting the invitation')).door_id;
}

export async function fetchDeveloperDoors(): Promise<{ developer_identity?: string; key: { fingerprint: string } | null; doors: DeveloperDoor[] }> {
  return jsonOrThrow(await authFetch('/api/v1/developer/doors'), 'Loading your doors');
}

export async function registerDeveloperKey(publicKeySpki: string) {
  return (await jsonOrThrow(
    await authFetch('/api/v1/developer/keys', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ public_key_spki: publicKeySpki }) }),
    'Registering your signing key'
  )).key;
}

export async function signDoorAgreement(doorId: string, statement: string, signature: string) {
  return jsonOrThrow(
    await authFetch(`/api/v1/developer/doors/${doorId}/sign`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ statement, signature }) }),
    'Signing'
  );
}

export async function getDoorCredential(doorId: string): Promise<{ credential: { username: string; token: string }; remotes: Array<{ full_name: string; url: string }>; branch_prefix: string }> {
  return jsonOrThrow(await authFetch(`/api/v1/developer/doors/${doorId}/credential`, { method: 'POST' }), 'Getting your git credential');
}

// --- Backup snapshots -----------------------------------------------------------------------------------------

export interface Snapshot {
  id: string;
  door_id: string | null;
  trigger: string;
  refs: Record<string, string>;
  sha256: string;
  size_bytes: number;
  created_at: string;
  full_name: string;
}

export async function fetchSnapshots(projectId: string): Promise<Snapshot[]> {
  return (await jsonOrThrow(await authFetch(`/api/v1/projects/${projectId}/snapshots`), 'Loading snapshots')).snapshots;
}

/** Downloads a snapshot bundle (with the login token) and hands it to the browser as a file. */
export async function downloadSnapshot(projectId: string, s: Snapshot): Promise<void> {
  const res = await authFetch(`/api/v1/projects/${projectId}/snapshots/${s.id}/bundle`);
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `Download failed (${res.status}).`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${s.full_name.replace('/', '__')}-${s.created_at.slice(0, 10)}.bundle`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
