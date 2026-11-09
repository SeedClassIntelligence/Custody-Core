-- ---------------------------------------------------------------------------------------------------------
-- Phase 3: universal work sessions (docs/integration/PHASE0_SPEC.md, sections 3.2 and 6).
--
-- A work session is one bounded piece of work on one project: either a human developer's door (a mirror of the
-- door table, so every existing door is also a session) or an automated session requested by a service principal and
-- approved by a person. Nothing existing is changed or removed: the door table, its triggers and its API stay as they are.
--
-- Human doors: the session is a mirror, kept in step by a trigger on door. It is derived, never edited by hand, and the
-- trigger must never block a door operation, so the guard below lets a mirror follow whatever the door does.
-- Automated sessions: created 'requested' (the database refuses to create one already approved), approved only with the
-- sponsoring creator named as the approver, and then move along a fixed set of transitions to a final state.
--
-- Evidence tables (spec 3.2) are not here: they arrive with the evidence phase, in their own migration.
-- ---------------------------------------------------------------------------------------------------------

CREATE TABLE work_session (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES project(id) ON DELETE CASCADE,
  -- A human door can cover several repositories (door_repository), so it has none here. An automated session has exactly one.
  repository_id UUID REFERENCES repository(id) ON DELETE CASCADE,
  session_type TEXT NOT NULL CHECK (session_type IN ('human_door', 'automated_work_session')),
  door_id UUID UNIQUE REFERENCES door(id) ON DELETE CASCADE,
  requested_by_principal_id UUID REFERENCES service_principal(id) ON DELETE SET NULL,

  executor_type TEXT NOT NULL CHECK (executor_type IN ('human_developer', 'ai_assistant', 'ide_runtime', 'ci_runtime', 'platform_service')),
  executor_provider TEXT,
  executor_model TEXT,
  executor_external_id TEXT,
  executor_display_name TEXT,

  sponsor_id UUID NOT NULL REFERENCES creator(id),
  objective TEXT NOT NULL,

  base_commit CHAR(40) CHECK (base_commit ~ '^[0-9a-f]{40}$'),
  branch_name TEXT,
  repository_access TEXT CHECK (repository_access IN ('read', 'read_and_push')),
  -- Default deny: nothing is allowed unless listed. How paths are matched is enforced when sessions get a way to push.
  allowed_read_paths TEXT[] NOT NULL DEFAULT '{}' CHECK (cardinality(allowed_read_paths) <= 100),
  allowed_write_paths TEXT[] NOT NULL DEFAULT '{}' CHECK (cardinality(allowed_write_paths) <= 100),
  prohibited_paths TEXT[] NOT NULL DEFAULT '{}' CHECK (cardinality(prohibited_paths) <= 100),

  status TEXT NOT NULL DEFAULT 'requested' CHECK (status IN
    ('requested', 'approved', 'provisioning', 'active', 'awaiting_evidence', 'completed', 'rejected', 'closed', 'expired')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  approved_at TIMESTAMPTZ,
  approved_by TEXT,
  expires_at TIMESTAMPTZ,
  closed_at TIMESTAMPTZ,
  closed_reason TEXT,

  -- A session is a human door exactly when it is linked to one, and then its executor is a human developer.
  CONSTRAINT chk_session_door CHECK ((session_type = 'human_door') = (door_id IS NOT NULL)),
  CONSTRAINT chk_session_executor CHECK ((session_type = 'human_door') = (executor_type = 'human_developer')),
  -- What an automated session must have.
  CONSTRAINT chk_session_automated_fields CHECK (
    session_type = 'human_door' OR (
      repository_id IS NOT NULL AND base_commit IS NOT NULL AND branch_name IS NOT NULL AND repository_access IS NOT NULL
      AND expires_at IS NOT NULL AND expires_at > created_at
      AND length(objective) BETWEEN 1 AND 2000
      AND cardinality(allowed_read_paths) >= 1
      AND ((repository_access = 'read_and_push' AND cardinality(allowed_write_paths) >= 1)
        OR (repository_access = 'read' AND cardinality(allowed_write_paths) = 0))
    )
  ),
  -- Its branch is under its own prefix, nothing else.
  CONSTRAINT chk_session_branch CHECK (branch_name IS NULL OR branch_name LIKE 'session/' || id::text || '/%'),
  -- Approval: the sponsoring creator, or (later) a named policy. Never the requesting principal, never nobody.
  CONSTRAINT chk_session_approver CHECK (
    session_type = 'human_door' OR approved_by IS NULL
    OR approved_by = 'creator:' || sponsor_id::text OR approved_by LIKE 'policy:%'
  ),
  CONSTRAINT chk_session_approved_has_approval CHECK (
    session_type = 'human_door' OR status IN ('requested', 'rejected', 'closed', 'expired') OR (approved_at IS NOT NULL AND approved_by IS NOT NULL)
  ),
  CONSTRAINT chk_session_final_has_close_time CHECK (
    session_type = 'human_door' OR ((status IN ('rejected', 'closed', 'expired')) = (closed_at IS NOT NULL))
  )
);

CREATE INDEX idx_work_session_project ON work_session (project_id, status);
CREATE INDEX idx_work_session_principal ON work_session (requested_by_principal_id, status) WHERE requested_by_principal_id IS NOT NULL;
CREATE INDEX idx_work_session_expiry ON work_session (expires_at) WHERE session_type = 'automated_work_session' AND status NOT IN ('rejected', 'closed', 'expired');

-- ---- the guard ----------------------------------------------------------------------------------------------------
CREATE FUNCTION work_session_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  ok boolean;
BEGIN
  IF TG_OP = 'INSERT' THEN
    -- No session can be created already approved or finished: approval is a step that has to happen.
    IF NEW.session_type = 'automated_work_session'
       AND (NEW.status <> 'requested' OR NEW.approved_at IS NOT NULL OR NEW.approved_by IS NOT NULL OR NEW.closed_at IS NOT NULL) THEN
      RAISE EXCEPTION 'work_session %: an automated session must be created as requested, not approved or closed', NEW.id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;

  -- What identifies a session never changes (a human mirror included).
  IF NEW.id <> OLD.id OR NEW.project_id <> OLD.project_id OR NEW.session_type <> OLD.session_type
     OR NEW.door_id IS DISTINCT FROM OLD.door_id THEN
    RAISE EXCEPTION 'work_session %: what the session is and which project and door it belongs to cannot change', OLD.id USING ERRCODE = 'check_violation';
  END IF;

  -- A human mirror follows its door, whatever the door does. It must never be the reason a door operation fails.
  IF OLD.session_type = 'human_door' THEN
    RETURN NEW;
  END IF;

  -- An automated session's request is fixed the moment it is made. Only its progress changes.
  IF NEW.repository_id IS DISTINCT FROM OLD.repository_id OR NEW.executor_type <> OLD.executor_type
     OR NEW.executor_provider IS DISTINCT FROM OLD.executor_provider OR NEW.executor_model IS DISTINCT FROM OLD.executor_model
     OR NEW.executor_external_id IS DISTINCT FROM OLD.executor_external_id OR NEW.executor_display_name IS DISTINCT FROM OLD.executor_display_name
     OR NEW.sponsor_id <> OLD.sponsor_id OR NEW.objective <> OLD.objective OR NEW.base_commit IS DISTINCT FROM OLD.base_commit
     OR NEW.branch_name IS DISTINCT FROM OLD.branch_name OR NEW.repository_access IS DISTINCT FROM OLD.repository_access
     OR NEW.allowed_read_paths <> OLD.allowed_read_paths OR NEW.allowed_write_paths <> OLD.allowed_write_paths
     OR NEW.prohibited_paths <> OLD.prohibited_paths OR NEW.created_at <> OLD.created_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    RAISE EXCEPTION 'work_session %: the request (who, what, where, how long) cannot be changed once made', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  -- Only the one that requested it can be replaced by NULL (when that principal is removed); never pointed elsewhere.
  IF NEW.requested_by_principal_id IS NOT NULL AND NEW.requested_by_principal_id IS DISTINCT FROM OLD.requested_by_principal_id THEN
    RAISE EXCEPTION 'work_session %: the requester cannot change', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  -- Approval, once given, cannot be rewritten.
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
    ELSE false   -- rejected, closed and expired are final
  END;
  IF NOT ok THEN
    RAISE EXCEPTION 'work_session %: cannot go from % to %', OLD.id, OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_work_session_guard BEFORE INSERT OR UPDATE ON work_session
  FOR EACH ROW EXECUTE FUNCTION work_session_guard();

-- ---- human doors are sessions too ---------------------------------------------------------------------------------
-- door status -> session status. A door that is closing is still active until it is closed; a door that expired is expired.
CREATE FUNCTION work_session_status_for_door(p_status text, p_reason text) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE p_status
    WHEN 'draft' THEN 'requested'
    WHEN 'awaiting_signature' THEN 'approved'
    WHEN 'opening' THEN 'provisioning'
    WHEN 'open' THEN 'active'
    WHEN 'closing' THEN 'active'
    WHEN 'closed' THEN CASE WHEN p_reason = 'expired' THEN 'expired' ELSE 'closed' END
    WHEN 'failed' THEN 'closed'
    ELSE 'requested'
  END
$$;

CREATE FUNCTION door_mirror_to_work_session() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    INSERT INTO work_session (project_id, session_type, door_id, executor_type, executor_display_name, sponsor_id, objective,
                              status, created_at, expires_at, closed_at, closed_reason)
    SELECT NEW.project_id, 'human_door', NEW.id, 'human_developer', NEW.developer_email, p.creator_id, NEW.job_description,
           work_session_status_for_door(NEW.status, NEW.closed_reason), NEW.created_at, NEW.expires_at, NEW.closed_at, NEW.closed_reason
      FROM project p WHERE p.id = NEW.project_id;
  ELSE
    UPDATE work_session
       SET status = work_session_status_for_door(NEW.status, NEW.closed_reason),
           objective = NEW.job_description,
           executor_display_name = NEW.developer_email,
           expires_at = NEW.expires_at,
           closed_at = NEW.closed_at,
           closed_reason = NEW.closed_reason
     WHERE door_id = NEW.id;
  END IF;
  RETURN NULL;
END
$$;
CREATE TRIGGER trg_door_mirror_insert AFTER INSERT ON door FOR EACH ROW EXECUTE FUNCTION door_mirror_to_work_session();
CREATE TRIGGER trg_door_mirror_update AFTER UPDATE ON door FOR EACH ROW
  WHEN (OLD.status IS DISTINCT FROM NEW.status OR OLD.job_description IS DISTINCT FROM NEW.job_description
        OR OLD.developer_email IS DISTINCT FROM NEW.developer_email OR OLD.expires_at IS DISTINCT FROM NEW.expires_at
        OR OLD.closed_at IS DISTINCT FROM NEW.closed_at OR OLD.closed_reason IS DISTINCT FROM NEW.closed_reason)
  EXECUTE FUNCTION door_mirror_to_work_session();

-- Every door that already exists becomes a session now. No events are written: the doors' own records are unchanged.
INSERT INTO work_session (project_id, session_type, door_id, executor_type, executor_display_name, sponsor_id, objective,
                          status, created_at, expires_at, closed_at, closed_reason)
SELECT d.project_id, 'human_door', d.id, 'human_developer', d.developer_email, p.creator_id, d.job_description,
       work_session_status_for_door(d.status, d.closed_reason), d.created_at, d.expires_at, d.closed_at, d.closed_reason
  FROM door d JOIN project p ON p.id = d.project_id;
