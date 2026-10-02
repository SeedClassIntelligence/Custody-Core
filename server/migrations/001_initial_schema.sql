-- 001_initial_schema.sql
-- Custody Core Phase 1 PostgreSQL Schema
-- Eleven tables with UUID primary keys, timestamps, and an append-only event log.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. creator
CREATE TABLE IF NOT EXISTS creator (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  seed_signature_creator_id TEXT DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. developer
CREATE TABLE IF NOT EXISTS developer (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  signing_public_key TEXT DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 3. connection
CREATE TABLE IF NOT EXISTS connection (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  creator_id UUID NOT NULL REFERENCES creator(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, -- 'github', 'storage_s3', 'storage_drive'
  external_account TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending', -- 'pending', 'locked', 'connected'
  secret_ref TEXT NOT NULL, -- Infisical reference, no raw secrets in DB
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 4. project
CREATE TABLE IF NOT EXISTS project (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  creator_id UUID NOT NULL REFERENCES creator(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  purpose TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active', -- 'active', 'archived'
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 5. repository
CREATE TABLE IF NOT EXISTS repository (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES project(id) ON DELETE CASCADE,
  github_repo_id TEXT NOT NULL DEFAULT '',
  full_name TEXT NOT NULL,
  default_branch TEXT NOT NULL DEFAULT 'main',
  is_core BOOLEAN NOT NULL DEFAULT false,
  locked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 6. agreement_template
CREATE TABLE IF NOT EXISTS agreement_template (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  creator_id UUID NOT NULL REFERENCES creator(id) ON DELETE CASCADE,
  rights_type TEXT NOT NULL, -- 'contribute', 'license', 'transfer', 'maintain'
  document_ref TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '1.0',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 7. door
CREATE TABLE IF NOT EXISTS door (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES project(id) ON DELETE CASCADE,
  developer_id UUID REFERENCES developer(id) ON DELETE SET NULL,
  job_description TEXT NOT NULL,
  rights_type TEXT NOT NULL,
  agreement_id TEXT,
  status TEXT NOT NULL DEFAULT 'draft', -- 'draft', 'awaiting_signature', 'opening', 'open', 'closing', 'closed', 'failed'
  opens_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  closed_at TIMESTAMPTZ,
  closed_reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 8. door_repository
CREATE TABLE IF NOT EXISTS door_repository (
  door_id UUID NOT NULL REFERENCES door(id) ON DELETE CASCADE,
  repository_id UUID NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
  access TEXT NOT NULL DEFAULT 'read', -- 'read', 'write'
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (door_id, repository_id)
);

-- 9. workspace
CREATE TABLE IF NOT EXISTS workspace (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  door_id UUID NOT NULL REFERENCES door(id) ON DELETE CASCADE,
  coder_workspace_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'provisioning', -- 'provisioning', 'active', 'stopped', 'destroyed'
  destroyed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 10. mirror_snapshot
CREATE TABLE IF NOT EXISTS mirror_snapshot (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  repository_id UUID NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
  commit_sha TEXT NOT NULL,
  storage_uri TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size_bytes BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 11. event (Append-Only Hash-Chained Log)
CREATE TABLE IF NOT EXISTS event (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  seq BIGINT NOT NULL,
  project_id UUID NOT NULL REFERENCES project(id) ON DELETE CASCADE,
  actor_type TEXT NOT NULL, -- 'creator', 'developer', 'system', 'gateway'
  actor_id TEXT NOT NULL,
  action TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  prev_hash CHAR(64) NOT NULL,
  hash CHAR(64) NOT NULL,
  seed_signature_id TEXT DEFAULT '',
  hashed_timestamp TEXT NOT NULL CHECK (hashed_timestamp <> ''),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_event_project_seq UNIQUE (project_id, seq)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_project_creator ON project(creator_id);
CREATE INDEX IF NOT EXISTS idx_event_project_seq ON event(project_id, seq ASC);
CREATE INDEX IF NOT EXISTS idx_door_project ON door(project_id);

-- Append-only trigger: strictly reject any UPDATE or DELETE on event table
CREATE OR REPLACE FUNCTION reject_event_update_or_delete()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Table event is append-only: UPDATE and DELETE operations are strictly forbidden.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_event_append_only ON event;
CREATE TRIGGER trg_event_append_only
BEFORE UPDATE OR DELETE ON event
FOR EACH ROW
EXECUTE FUNCTION reject_event_update_or_delete();

-- Truncate prevention trigger: strictly reject any TRUNCATE statement on event table
CREATE OR REPLACE FUNCTION reject_event_truncate()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Table event is append-only: TRUNCATE operations are strictly forbidden.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_event_prevent_truncate ON event;
CREATE TRIGGER trg_event_prevent_truncate
BEFORE TRUNCATE ON event
FOR EACH STATEMENT
EXECUTE FUNCTION reject_event_truncate();
