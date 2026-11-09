-- ---------------------------------------------------------------------------------------------------------
-- Phase 4: external context on automated work sessions (docs/integration/PHASE0_SPEC.md, Phase 4).
--
-- A caller can attach a namespace (reverse-DNS, chosen by the caller) and a block of plain JSON so that its own platform
-- can find its way back to the session. Custody Core never acts on it. It is stored once, cannot be changed, and its
-- hash is kept so the copy in the project's permanent record can be checked against the copy here.
--
-- The three columns go together or not at all, and only automated sessions have them. The size limit here is a loose
-- backstop (jsonb prints with spaces, so it is larger than the 16 KiB canonical limit the server enforces).
-- ---------------------------------------------------------------------------------------------------------

ALTER TABLE work_session ADD COLUMN external_context_namespace TEXT;
ALTER TABLE work_session ADD COLUMN external_context_payload JSONB;
ALTER TABLE work_session ADD COLUMN external_context_sha256 CHAR(64);

ALTER TABLE work_session ADD CONSTRAINT chk_session_external_context CHECK (
  (external_context_namespace IS NULL AND external_context_payload IS NULL AND external_context_sha256 IS NULL)
  OR (
    session_type = 'automated_work_session'
    AND external_context_namespace IS NOT NULL AND external_context_payload IS NOT NULL AND external_context_sha256 IS NOT NULL
    AND length(external_context_namespace) <= 100
    AND external_context_namespace ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
    AND split_part(external_context_namespace, '.', 1) <> 'custody'
    AND jsonb_typeof(external_context_payload) = 'object'
    AND octet_length(external_context_payload::text) <= 32768
    AND external_context_sha256 ~ '^[0-9a-f]{64}$'
  )
);

-- The guard from migration 012, with the context added to what cannot change after the request is made.
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
    WHEN 'provisioning'      THEN NEW.status IN ('active', 'closed', 'expired')
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
