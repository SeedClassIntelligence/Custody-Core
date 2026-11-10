-- ---------------------------------------------------------------------------------------------------------
-- Phase 8: evidence-gated promotion (docs/integration/PHASE8_DESIGN.md).
--
-- Promotion is moving a repository's default branch forward to a commit a session produced. It is asked for (by a principal holding
-- repositories:promote, or by the owner), checked against the evidence, APPROVED BY THE OWNER ONLY, and then carried out by the gateway.
--
--   pending -> approved -> completed          (approved -> failed if carrying it out fails; a failed one is final, ask again)
--   pending -> rejected
--
-- The database refuses a request that is not backed by evidence that was ready, a commit the session did not produce, an approval by anyone but
-- the session's sponsor, and any change to a request after it is made.
-- ---------------------------------------------------------------------------------------------------------

CREATE TABLE promotion_request (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  work_session_id UUID NOT NULL REFERENCES work_session (id) ON DELETE CASCADE,
  project_id UUID NOT NULL REFERENCES project (id),
  repository_id UUID NOT NULL REFERENCES repository (id),
  target_branch TEXT NOT NULL CHECK (char_length(target_branch) BETWEEN 1 AND 250),
  commit_hash CHAR(40) NOT NULL CHECK (commit_hash ~ '^[0-9a-f]{40}$'),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'completed', 'rejected', 'failed')),
  requested_by_principal_id UUID REFERENCES service_principal (id),
  requested_by_creator_id UUID REFERENCES creator (id),
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  evidence_at_request JSONB NOT NULL,
  attestations_at_request JSONB NOT NULL DEFAULT '[]'::jsonb,
  approved_by TEXT,
  approved_at TIMESTAMPTZ,
  rejected_reason TEXT,
  decided_at TIMESTAMPTZ,
  previous_tip CHAR(40) CHECK (previous_tip IS NULL OR previous_tip ~ '^[0-9a-f]{40}$'),
  evaluation_at_completion JSONB,
  completed_at TIMESTAMPTZ,
  failure_code TEXT,
  CONSTRAINT chk_promotion_one_requester CHECK ((requested_by_principal_id IS NOT NULL) <> (requested_by_creator_id IS NOT NULL)),
  CONSTRAINT chk_promotion_evidence_ready CHECK ((evidence_at_request ->> 'ready') = 'true')
);
-- One live request per commit and branch; a rejected or failed one can be asked for again.
CREATE UNIQUE INDEX uq_promotion_live ON promotion_request (work_session_id, target_branch, commit_hash) WHERE status IN ('pending', 'approved', 'completed');
CREATE INDEX idx_promotion_project ON promotion_request (project_id, status);

CREATE FUNCTION promotion_request_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  s work_session%ROWTYPE;
  ok boolean;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO s FROM work_session WHERE id = NEW.work_session_id;
    IF NOT FOUND OR s.session_type <> 'automated_work_session' OR s.status NOT IN ('active', 'awaiting_evidence')
       OR s.project_id <> NEW.project_id OR s.repository_id <> NEW.repository_id THEN
      RAISE EXCEPTION 'promotion_request: only for a running automated session, its own project and repository' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status <> 'pending' OR NEW.approved_by IS NOT NULL OR NEW.approved_at IS NOT NULL OR NEW.completed_at IS NOT NULL THEN
      RAISE EXCEPTION 'promotion_request: must be created pending' USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM session_commit c WHERE c.work_session_id = NEW.work_session_id AND c.real_sha = NEW.commit_hash) THEN
      RAISE EXCEPTION 'promotion_request: the commit is not one this session produced' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.requested_by_principal_id IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM service_principal sp JOIN project p ON p.id = NEW.project_id
       WHERE sp.id = NEW.requested_by_principal_id AND sp.creator_id = p.creator_id AND 'repositories:promote' = ANY (sp.allowed_scopes)
    ) THEN
      RAISE EXCEPTION 'promotion_request: the requesting principal must hold repositories:promote for this owner' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.requested_by_creator_id IS NOT NULL AND NEW.requested_by_creator_id <> s.sponsor_id THEN
      RAISE EXCEPTION 'promotion_request: only the sponsoring owner can ask for it as a person' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;

  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'promotion_request %: cannot be deleted', OLD.id USING ERRCODE = 'check_violation';
  END IF;

  IF NEW.id <> OLD.id OR NEW.work_session_id <> OLD.work_session_id OR NEW.project_id <> OLD.project_id OR NEW.repository_id <> OLD.repository_id
     OR NEW.target_branch <> OLD.target_branch OR NEW.commit_hash <> OLD.commit_hash
     OR NEW.requested_by_principal_id IS DISTINCT FROM OLD.requested_by_principal_id OR NEW.requested_by_creator_id IS DISTINCT FROM OLD.requested_by_creator_id
     OR NEW.requested_at <> OLD.requested_at OR NEW.evidence_at_request IS DISTINCT FROM OLD.evidence_at_request
     OR NEW.attestations_at_request IS DISTINCT FROM OLD.attestations_at_request THEN
    RAISE EXCEPTION 'promotion_request %: what was asked for cannot be changed', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.approved_at IS NOT NULL AND (NEW.approved_at IS DISTINCT FROM OLD.approved_at OR NEW.approved_by IS DISTINCT FROM OLD.approved_by) THEN
    RAISE EXCEPTION 'promotion_request %: the approval cannot be changed', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.status = OLD.status THEN
    RETURN NEW;
  END IF;
  ok := CASE OLD.status
    WHEN 'pending'  THEN NEW.status IN ('approved', 'rejected')
    WHEN 'approved' THEN NEW.status IN ('completed', 'failed')
    ELSE false
  END;
  IF NOT ok THEN
    RAISE EXCEPTION 'promotion_request %: cannot go from % to %', OLD.id, OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.status = 'approved' THEN
    -- Only the sponsoring owner approves. A principal never does (there is no approval policy yet).
    SELECT * INTO s FROM work_session WHERE id = NEW.work_session_id;
    IF NEW.approved_by IS DISTINCT FROM 'creator:' || s.sponsor_id::text OR NEW.approved_at IS NULL THEN
      RAISE EXCEPTION 'promotion_request %: only the sponsoring owner can approve', OLD.id USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  IF NEW.status = 'completed' AND (NEW.completed_at IS NULL OR NEW.previous_tip IS NULL OR NEW.evaluation_at_completion IS NULL
                                   OR (NEW.evaluation_at_completion ->> 'ready') IS DISTINCT FROM 'true') THEN
    RAISE EXCEPTION 'promotion_request %: completion needs the time, the previous tip and evidence that was still ready', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_promotion_request_guard BEFORE INSERT OR UPDATE OR DELETE ON promotion_request FOR EACH ROW EXECUTE FUNCTION promotion_request_guard();
