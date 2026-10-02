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

// ---------------------------------------------------------------- code home (GitHub)

export interface SettingResult {
  setting: string;
  requested: unknown;
  reported: unknown;
  applied: boolean;
}

export interface CodeHomeStatus {
  configured: boolean;
  installation: { installation_id: number; organization: string; status: 'active' | 'suspended' | 'removed'; connected_at: string; status_changed_at: string } | null;
  organization_lock: { organization: string; plan: string | null; settings: SettingResult[]; all_applied: boolean; change_error: { status: number; message: string } | null; recorded_at: string } | null;
  broken: { organization: string; reason: string; by: string | null; recorded_at: string } | null;
}

export async function fetchCodeHome(): Promise<CodeHomeStatus> {
  const res = await authFetch('/api/v1/github/connection');
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `Could not load your code home (server returned ${res.status}).`);
  return body as CodeHomeStatus;
}

/** Starts connecting. The server sets a one-time code in this browser and returns GitHub's install page. */
export async function startCodeHomeConnection(): Promise<{ install_url: string; new_organization_url: string }> {
  const res = await authFetch('/api/v1/github/connect', { method: 'POST' });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `Could not start connecting (server returned ${res.status}).`);
  return body;
}

export interface RepositoryResult {
  role: 'main' | 'core';
  full_name: string;
  html_url: string;
  settings: SettingResult[];
  ruleset: { applied: boolean; refused: { status: number; message: string; needs_paid_plan: boolean } | null };
  initial_commit: { pushed: boolean; files_uploaded: number; reported_files: number | null; reported_sha: string | null; matches: boolean; error: string | null } | null;
  incomplete?: string;
}

/** Creates the project's repositories on GitHub (empty, or with an uploaded zip as the first commit). */
export async function createCodeHomeRepositories(projectId: string, opts: { splitCore: boolean; zip: File | null }): Promise<RepositoryResult[]> {
  const res = opts.zip
    ? await authFetch(`/api/v1/projects/${projectId}/code-home?split_core=${opts.splitCore ? 1 : 0}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/zip' },
        body: opts.zip
      })
    : await authFetch(`/api/v1/projects/${projectId}/code-home`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ split_core: opts.splitCore })
      });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `GitHub repositories could not be created (server returned ${res.status}).`);
  return body.repositories as RepositoryResult[];
}

/** Re-applies the organization lock and returns what GitHub reports now. */
export async function relockOrganization(): Promise<void> {
  const res = await authFetch('/api/v1/github/organization/lock', { method: 'POST' });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `Could not check with GitHub (server returned ${res.status}).`);
}
