-- ---------------------------------------------------------------------------------------------------------
-- Phase 6: evidence (docs/integration/PHASE6_DESIGN.md).
--
--   evidence_requirement  what the request says must be shown, and WHICH registered principal may show it. Written with the request, never changed.
--   evidence_submission   a signed statement by that principal about one commit of the session. Written once, never changed.
--
-- The database refuses a submission that names an issuer the request did not name, a key that is not the issuer's, a commit the session
-- did not produce, a session that is not running, or a specification other than the one the request pinned. The application checks the
-- same things first and gives better messages; these are the backstop.
-- ---------------------------------------------------------------------------------------------------------

CREATE TABLE evidence_requirement (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  work_session_id UUID NOT NULL REFERENCES work_session (id) ON DELETE CASCADE,
  evidence_type TEXT NOT NULL CHECK (evidence_type ~ '^[a-z][a-z0-9_.-]{0,63}$'),
  is_required BOOLEAN NOT NULL DEFAULT true,
  issuer_principal_id UUID NOT NULL REFERENCES service_principal (id),   -- always a registered principal, never a free string
  tied_to_commit BOOLEAN NOT NULL DEFAULT true,
  specification_hash CHAR(64) CHECK (specification_hash IS NULL OR specification_hash ~ '^[0-9a-f]{64}$'),
  max_age_seconds INTEGER CHECK (max_age_seconds IS NULL OR max_age_seconds BETWEEN 60 AND 31536000),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_evidence_requirement UNIQUE (work_session_id, evidence_type)
);

-- Only with the request: the session is still waiting for approval, an automated one, and the issuer belongs to the same creator and may submit evidence.
CREATE FUNCTION evidence_requirement_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM work_session s
      JOIN project p ON p.id = s.project_id
      JOIN service_principal sp ON sp.id = NEW.issuer_principal_id
     WHERE s.id = NEW.work_session_id AND s.session_type = 'automated_work_session' AND s.status = 'requested' AND s.approved_at IS NULL
       AND sp.creator_id = p.creator_id AND 'evidence:submit' = ANY (sp.allowed_scopes)
  ) THEN
    RAISE EXCEPTION 'evidence_requirement: only with a pending request, naming a principal of the same owner that may submit evidence'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_evidence_requirement_guard BEFORE INSERT ON evidence_requirement
  FOR EACH ROW EXECUTE FUNCTION evidence_requirement_guard();

CREATE TABLE evidence_submission (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  work_session_id UUID NOT NULL REFERENCES work_session (id) ON DELETE CASCADE,
  evidence_type TEXT NOT NULL,
  issuer_principal_id UUID NOT NULL REFERENCES service_principal (id),
  signature_key_id UUID NOT NULL REFERENCES service_principal_key (id),
  subject_commit CHAR(40) NOT NULL CHECK (subject_commit ~ '^[0-9a-f]{40}$'),
  status TEXT NOT NULL CHECK (status IN ('pass', 'fail', 'inconclusive')),
  specification_hash CHAR(64) NOT NULL CHECK (specification_hash ~ '^[0-9a-f]{64}$'),
  evidence_hash CHAR(64) NOT NULL CHECK (evidence_hash ~ '^[0-9a-f]{64}$'),
  payload_sha256 CHAR(64) NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
  issued_at TIMESTAMPTZ NOT NULL,
  signature_algorithm TEXT NOT NULL CHECK (signature_algorithm IN ('Ed25519', 'ES256')),
  signature_value TEXT NOT NULL CHECK (signature_value ~ '^[A-Za-z0-9_-]{86}$'),
  raw_payload JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(raw_payload) = 'object'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_evidence_once UNIQUE (work_session_id, evidence_type, subject_commit, evidence_hash)
);
CREATE INDEX idx_evidence_submission_session ON evidence_submission (work_session_id, evidence_type, issued_at DESC);

CREATE FUNCTION evidence_submission_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  req evidence_requirement%ROWTYPE;
  committed timestamptz;
BEGIN
  SELECT * INTO req FROM evidence_requirement
   WHERE work_session_id = NEW.work_session_id AND evidence_type = NEW.evidence_type AND issuer_principal_id = NEW.issuer_principal_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'evidence_submission: the session did not ask this principal for this kind of evidence' USING ERRCODE = 'check_violation';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM service_principal_key k WHERE k.id = NEW.signature_key_id AND k.principal_id = NEW.issuer_principal_id AND k.algorithm = NEW.signature_algorithm) THEN
    RAISE EXCEPTION 'evidence_submission: the signing key is not a key of the issuing principal' USING ERRCODE = 'check_violation';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM work_session s WHERE s.id = NEW.work_session_id AND s.session_type = 'automated_work_session' AND s.status IN ('active', 'awaiting_evidence')) THEN
    RAISE EXCEPTION 'evidence_submission: the session is not running' USING ERRCODE = 'check_violation';
  END IF;
  SELECT created_at INTO committed FROM session_commit WHERE work_session_id = NEW.work_session_id AND real_sha = NEW.subject_commit;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'evidence_submission: the commit is not one this session produced' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.issued_at < date_trunc('second', committed) THEN
    RAISE EXCEPTION 'evidence_submission: evidence cannot be issued before the commit existed' USING ERRCODE = 'check_violation';
  END IF;
  IF req.specification_hash IS NOT NULL AND req.specification_hash <> NEW.specification_hash THEN
    RAISE EXCEPTION 'evidence_submission: not the specification the request pinned' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_evidence_submission_guard BEFORE INSERT ON evidence_submission
  FOR EACH ROW EXECUTE FUNCTION evidence_submission_guard();

-- Records: written once (session_record_immutable() is from migration 014). roles.sql also revokes UPDATE and DELETE from the application's account.
CREATE TRIGGER trg_evidence_requirement_immutable BEFORE UPDATE OR DELETE ON evidence_requirement FOR EACH ROW EXECUTE FUNCTION session_record_immutable();
CREATE TRIGGER trg_evidence_submission_immutable BEFORE UPDATE OR DELETE ON evidence_submission FOR EACH ROW EXECUTE FUNCTION session_record_immutable();
