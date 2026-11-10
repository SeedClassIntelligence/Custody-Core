-- ---------------------------------------------------------------------------------------------------------
-- Phase 7b: attestation by an external signing authority (docs/integration/PHASE7_DESIGN.md).
--
--   attestation_authority  a public key the owner has chosen to trust as a signer ("this authority may attest to my sessions' commits")
--   attestation            a detached signature by such an authority over a canonical statement about one commit of a session
--
-- No "verified" column (a stored attestation has always been verified): the signature is checked BEFORE the row is written, and the row is never
-- changed. The database cannot verify signatures; it refuses everything else (an authority of another owner, a revoked one, a commit the session
-- did not produce, a time before the commit existed).
-- ---------------------------------------------------------------------------------------------------------

CREATE TABLE attestation_authority (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  creator_id UUID NOT NULL REFERENCES creator (id) ON DELETE CASCADE,
  name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
  algorithm TEXT NOT NULL CHECK (algorithm IN ('Ed25519', 'ES256')),
  public_key_jwk JSONB NOT NULL,
  fingerprint CHAR(64) NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ,
  CONSTRAINT uq_attestation_authority_name UNIQUE (creator_id, name),
  CONSTRAINT uq_attestation_authority_key UNIQUE (creator_id, fingerprint)
);

-- A registered authority never changes, and a revocation cannot be undone (as for principal keys).
CREATE FUNCTION attestation_authority_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'attestation_authority %: cannot be deleted, only revoked', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.id <> OLD.id OR NEW.creator_id <> OLD.creator_id OR NEW.name <> OLD.name OR NEW.algorithm <> OLD.algorithm
     OR NEW.public_key_jwk IS DISTINCT FROM OLD.public_key_jwk OR NEW.fingerprint <> OLD.fingerprint OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'attestation_authority %: only revocation can change', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    RAISE EXCEPTION 'attestation_authority %: a revocation cannot be undone', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_attestation_authority_guard BEFORE UPDATE OR DELETE ON attestation_authority FOR EACH ROW EXECUTE FUNCTION attestation_authority_guard();

CREATE TABLE attestation (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  work_session_id UUID NOT NULL REFERENCES work_session (id) ON DELETE CASCADE,
  authority_id UUID NOT NULL REFERENCES attestation_authority (id),
  claim TEXT NOT NULL CHECK (claim ~ '^[a-z][a-z0-9_.-]{0,63}$'),
  subject_commit CHAR(40) NOT NULL CHECK (subject_commit ~ '^[0-9a-f]{40}$'),
  payload_sha256 CHAR(64) NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
  raw_payload JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(raw_payload) = 'object'),
  issued_at TIMESTAMPTZ NOT NULL,
  signature_algorithm TEXT NOT NULL CHECK (signature_algorithm IN ('Ed25519', 'ES256')),
  signature_value TEXT NOT NULL CHECK (signature_value ~ '^[A-Za-z0-9_-]{86}$'),
  submitted_by_creator_id UUID NOT NULL REFERENCES creator (id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_attestation_once UNIQUE (work_session_id, authority_id, claim, subject_commit, issued_at, payload_sha256)
);
CREATE INDEX idx_attestation_session ON attestation (work_session_id, subject_commit);

CREATE FUNCTION attestation_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  committed timestamptz;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM attestation_authority a JOIN work_session s ON s.id = NEW.work_session_id JOIN project p ON p.id = s.project_id
     WHERE a.id = NEW.authority_id AND a.creator_id = p.creator_id AND a.revoked_at IS NULL AND a.algorithm = NEW.signature_algorithm
       AND s.session_type = 'automated_work_session' AND p.creator_id = NEW.submitted_by_creator_id
  ) THEN
    RAISE EXCEPTION 'attestation: the authority must be an unrevoked authority of the session''s owner' USING ERRCODE = 'check_violation';
  END IF;
  SELECT created_at INTO committed FROM session_commit WHERE work_session_id = NEW.work_session_id AND real_sha = NEW.subject_commit;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'attestation: the commit is not one this session produced' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.issued_at < date_trunc('second', committed) THEN
    RAISE EXCEPTION 'attestation: cannot be issued before the commit existed' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_attestation_guard BEFORE INSERT ON attestation FOR EACH ROW EXECUTE FUNCTION attestation_guard();
CREATE TRIGGER trg_attestation_immutable BEFORE UPDATE OR DELETE ON attestation FOR EACH ROW EXECUTE FUNCTION session_record_immutable();
