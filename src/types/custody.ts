export type RoleMode = 'creator' | 'developer' | 'auditor';

export interface Creator {
  id: string;
  identity_id: string;
  display_name: string;
  email: string;
  seed_signature_creator_id: string;
  mfa_enabled: boolean;
  passkey_registered: boolean;
  created_at: string;
}

export interface Developer {
  id: string;
  identity_id: string;
  display_name: string;
  email: string;
  signing_public_key: string;
  mfa_enabled: boolean;
  created_at: string;
}

export type ConnectionKind = 'github' | 'storage_s3' | 'storage_drive';
export type ConnectionStatus = 'connected' | 'pending' | 'locked' | 'unconnected';

export interface Connection {
  id: string;
  creator_id: string;
  kind: ConnectionKind;
  external_account: string;
  status: ConnectionStatus;
  secret_ref: string; // Stored in Infisical reference
  settings?: {
    organization?: string;
    bucket_name?: string;
    versioning_enabled?: boolean;
    folder_name?: string;
  };
  connected_at: string;
}

export interface Repository {
  id: string;
  project_id: string;
  github_repo_id: string;
  full_name: string;
  default_branch: string;
  is_core: boolean;
  locked_at: string;
  allow_forking: boolean;
  ruleset_active: boolean;
}

export interface Project {
  id: string;
  creator_id: string;
  name: string;
  purpose: string;
  status: 'active' | 'archived';
  created_at: string;
  repositories: Repository[];
}

export type RightsType = 'contribute' | 'license' | 'transfer' | 'maintain';

export interface AgreementTemplate {
  id: string;
  creator_id: string;
  rights_type: RightsType;
  title: string;
  document_ref: string;
  version: string;
  terms: string;
}

export type DoorStatus =
  | 'draft'
  | 'awaiting_signature'
  | 'opening'
  | 'open'
  | 'closing'
  | 'closed'
  | 'failed';

export interface DoorRepository {
  door_id: string;
  repository_id: string;
  access: 'read' | 'write';
}

export interface Door {
  id: string;
  project_id: string;
  developer_id?: string;
  developer_email: string;
  job_description: string;
  rights_type: RightsType;
  agreement_id?: string;
  agreement_signed_at?: string;
  agreement_signature_hash?: string;
  status: DoorStatus;
  opens_at?: string;
  expires_at: string;
  closed_at?: string;
  closed_reason?: 'creator_manual' | 'expired' | 'admin' | 'security_revocation';
  repositories: DoorRepository[];
  branch_prefix: string; // e.g., "door/{door-id}"
}

export interface Workspace {
  id: string;
  door_id: string;
  coder_workspace_id: string;
  status: 'provisioning' | 'active' | 'stopped' | 'destroyed';
  namespace: string;
  git_remote_url: string; // points to gateway!
  network_egress_policy: 'restricted';
  destroyed_at?: string;
}

export interface MirrorSnapshot {
  id: string;
  repository_id: string;
  repository_name: string;
  commit_sha: string;
  storage_uri: string;
  sha256: string;
  size_bytes: number;
  trigger: 'initial' | 'push' | 'closing' | 'nightly' | 'export';
  timestamp: string;
}

export type EventAction =
  | 'connection.changed'
  | 'project.claimed'
  | 'repository.locked'
  | 'door.created'
  | 'agreement.signed'
  | 'door.opened'
  | 'git.fetch'
  | 'git.push'
  | 'git.push_rejected'
  | 'door.work_accepted'
  | 'door.expired'
  | 'door.closed'
  | 'credential.revoked'
  | 'workspace.destroyed'
  | 'mirror.written'
  | 'export.requested'
  | 'system.tamper_detected';

export interface CustodyEvent {
  seq: number;
  project_id: string;
  actor_type: 'creator' | 'developer' | 'system' | 'gateway';
  actor_id: string;
  actor_name: string;
  action: EventAction;
  subject_type: 'project' | 'repository' | 'door' | 'workspace' | 'mirror' | 'connection' | 'agreement';
  subject_id: string;
  payload: Record<string, any>;
  prev_hash: string;
  hash: string;
  seed_signature_id: string; // Empty in Phase 1, ready for Phase 2
  timestamp: string;
}

export interface ClosingReport {
  door_id: string;
  developer_email: string;
  job_description: string;
  closed_at: string;
  closed_reason: string;
  duration_active_minutes: number;
  work_preserved: {
    branches_mirrored: string[];
    mirror_snapshot_id: string;
    sha256: string;
    storage_uri: string;
    commits_count: number;
  };
  credentials_revoked: {
    gateway_token_revoked_at: string;
    coder_workspace_identity_deleted_at: string;
    infisical_secrets_machine_identity_deleted_at: string;
  };
  workspace_destroyed: {
    coder_workspace_id: string;
    k8s_namespace_deleted: string;
    storage_volume_erased: boolean;
    destroyed_at: string;
  };
  checklist_items: Array<{
    item: string;
    status: 'automated_complete' | 'creator_verify';
    description: string;
  }>;
}

export interface AcceptanceTestResult {
  id: number;
  name: string;
  description: string;
  status: 'idle' | 'running' | 'passed' | 'failed';
  log: string[];
  duration_ms?: number;
}
