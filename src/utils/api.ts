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
