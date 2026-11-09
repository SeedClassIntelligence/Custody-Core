-- ---------------------------------------------------------------------------------------------------------
-- Phase 5c: what an approved automated session needs to actually work (docs/integration/PHASE5_DESIGN.md, 4.3).
--
--   session_credential  the secret the session's git client sends (prefix ccs_). Its own table: door credentials (gateway_credential)
--                       are not touched at all, and a token of one kind can never be looked up as the other.
--   session_view        what was provisioned for a session: written once, never changed.
--   session_commit      which real commit each pushed (view) commit became. Immutable. It is a cache of a pure function (translation
--                       is deterministic), kept for queries and as the base for the attribution records of a later phase.
--   repository.provider which provider hosts the repository (only 'github' exists today).
--
-- A failed provisioning must be retryable, so the guard from migration 013 gains one step: provisioning may go back to approved.
-- ---------------------------------------------------------------------------------------------------------

ALTER TABLE repository ADD COLUMN provider TEXT NOT NULL DEFAULT 'github' CHECK (provider IN ('github'));

-- When provisioning began, so a session left in 'provisioning' by a crash can be put back (never touched while it is recent).
ALTER TABLE work_session ADD COLUMN provisioning_started_at TIMESTAMPTZ;

CREATE TABLE session_credential (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  work_session_id UUID NOT NULL REFERENCES work_session (id) ON DELETE CASCADE,
  token_hash CHAR(64) NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ
);
CREATE INDEX idx_session_credential_session ON session_credential (work_session_id);

-- A credential's secret and session never change, and a revocation can never be undone (as for doors).
CREATE FUNCTION session_credential_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.token_hash <> OLD.token_hash OR NEW.work_session_id <> OLD.work_session_id OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'session_credential %: only last_used_at and revoked_at can change', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    RAISE EXCEPTION 'session_credential %: a revocation cannot be undone', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_session_credential_guard BEFORE UPDATE ON session_credential
  FOR EACH ROW EXECUTE FUNCTION session_credential_guard();

CREATE TABLE session_view (
  work_session_id UUID PRIMARY KEY REFERENCES work_session (id) ON DELETE CASCADE,
  base_commit CHAR(40) NOT NULL CHECK (base_commit ~ '^[0-9a-f]{40}$'),
  default_branch TEXT NOT NULL,
  default_branch_tip CHAR(40) NOT NULL CHECK (default_branch_tip ~ '^[0-9a-f]{40}$'),
  view_commit CHAR(40) NOT NULL CHECK (view_commit ~ '^[0-9a-f]{40}$'),
  view_tree CHAR(40) NOT NULL CHECK (view_tree ~ '^[0-9a-f]{40}$'),
  file_count INTEGER NOT NULL CHECK (file_count >= 1),
  total_bytes BIGINT NOT NULL CHECK (total_bytes >= 0),
  excluded_count INTEGER NOT NULL CHECK (excluded_count >= 0),
  built_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE session_commit (
  work_session_id UUID NOT NULL REFERENCES work_session (id) ON DELETE CASCADE,
  view_sha CHAR(40) NOT NULL CHECK (view_sha ~ '^[0-9a-f]{40}$'),
  real_sha CHAR(40) NOT NULL CHECK (real_sha ~ '^[0-9a-f]{40}$'),
  parent_view_sha CHAR(40) NOT NULL CHECK (parent_view_sha ~ '^[0-9a-f]{40}$'),
  declared_author TEXT NOT NULL,   -- the author the pushed commit claimed; kept as a record, never trusted
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (work_session_id, view_sha),
  UNIQUE (work_session_id, real_sha)
);

-- Records: written once. The application's account also has UPDATE and DELETE revoked on these two (roles.sql).
CREATE FUNCTION session_record_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '%: records are written once and cannot be changed or deleted', TG_TABLE_NAME USING ERRCODE = 'check_violation';
END
$$;
CREATE TRIGGER trg_session_view_immutable BEFORE UPDATE OR DELETE ON session_view FOR EACH ROW EXECUTE FUNCTION session_record_immutable();
CREATE TRIGGER trg_session_commit_immutable BEFORE UPDATE OR DELETE ON session_commit FOR EACH ROW EXECUTE FUNCTION session_record_immutable();

-- The guard from migration 013, with one step added: provisioning -> approved (a failed build is retried).
CREATE OR REPLACE FUNCTION work_session_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  ok boolean;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.session_type = 'automated_work_session'
       AND (NEW.status <> 'requested' OR NEW.approved_at IS NOT NULL OR NEW.approved_by IS NOT NULL OR NEW.closed_at IS NOT NULL) THEN
      RAISE EXCEPTION 'work_session %: an automated session must be created as requested, not approved or closed', NEW.id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.id <> OLD.id OR NEW.project_id <> OLD.project_id OR NEW.session_type <> OLD.session_type
     OR NEW.door_id IS DISTINCT FROM OLD.door_id THEN
    RAISE EXCEPTION 'work_session %: what the session is and which project and door it belongs to cannot change', OLD.id USING ERRCODE = 'check_violation';
  END IF;

  IF OLD.session_type = 'human_door' THEN
    RETURN NEW;
  END IF;

  IF NEW.repository_id IS DISTINCT FROM OLD.repository_id OR NEW.executor_type <> OLD.executor_type
     OR NEW.executor_provider IS DISTINCT FROM OLD.executor_provider OR NEW.executor_model IS DISTINCT FROM OLD.executor_model
     OR NEW.executor_external_id IS DISTINCT FROM OLD.executor_external_id OR NEW.executor_display_name IS DISTINCT FROM OLD.executor_display_name
     OR NEW.sponsor_id <> OLD.sponsor_id OR NEW.objective <> OLD.objective OR NEW.base_commit IS DISTINCT FROM OLD.base_commit
     OR NEW.branch_name IS DISTINCT FROM OLD.branch_name OR NEW.repository_access IS DISTINCT FROM OLD.repository_access
     OR NEW.allowed_read_paths <> OLD.allowed_read_paths OR NEW.allowed_write_paths <> OLD.allowed_write_paths
     OR NEW.prohibited_paths <> OLD.prohibited_paths OR NEW.created_at <> OLD.created_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.external_context_namespace IS DISTINCT FROM OLD.external_context_namespace
     OR NEW.external_context_payload IS DISTINCT FROM OLD.external_context_payload
     OR NEW.external_context_sha256 IS DISTINCT FROM OLD.external_context_sha256 THEN
    RAISE EXCEPTION 'work_session %: the request (who, what, where, how long, context) cannot be changed once made', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.requested_by_principal_id IS NOT NULL AND NEW.requested_by_principal_id IS DISTINCT FROM OLD.requested_by_principal_id THEN
    RAISE EXCEPTION 'work_session %: the requester cannot change', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.approved_at IS NOT NULL AND (NEW.approved_at IS DISTINCT FROM OLD.approved_at OR NEW.approved_by IS DISTINCT FROM OLD.approved_by) THEN
    RAISE EXCEPTION 'work_session %: the approval cannot be changed', OLD.id USING ERRCODE = 'check_violation';
  END IF;

  IF NEW.status = OLD.status THEN
    RETURN NEW;
  END IF;
  ok := CASE OLD.status
    WHEN 'requested'         THEN NEW.status IN ('approved', 'rejected', 'expired', 'closed')
    WHEN 'approved'          THEN NEW.status IN ('provisioning', 'active', 'closed', 'expired')
    WHEN 'provisioning'      THEN NEW.status IN ('approved', 'active', 'closed', 'expired')
    WHEN 'active'            THEN NEW.status IN ('awaiting_evidence', 'completed', 'closed', 'expired')
    WHEN 'awaiting_evidence' THEN NEW.status IN ('active', 'completed', 'closed', 'expired')
    WHEN 'completed'         THEN NEW.status IN ('closed')
    ELSE false
  END;
  IF NOT ok THEN
    RAISE EXCEPTION 'work_session %: cannot go from % to %', OLD.id, OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
