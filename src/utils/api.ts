import { CustodyEvent, Project } from '../types/custody';

/** Thin wrappers over the server API. Nothing here invents data: failures throw. */

export interface ProjectsResponse {
  projects: Project[];
  connected: boolean;
  message?: string;
}

export async function fetchProjects(): Promise<ProjectsResponse> {
  const res = await fetch('/api/v1/projects');
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
  const res = await fetch(`/api/v1/projects/${projectId}/events`);
  if (!res.ok) throw new Error(`Could not load the event log (server returned ${res.status}).`);
  const data = await res.json();
  return (data.events || []).map(mapServerEvent);
}

export async function claimProject(input: { name: string; purpose: string }): Promise<Project> {
  const res = await fetch('/api/v1/projects', {
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
