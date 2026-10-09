-- 008: developer accounts, invitations and agreement signing.
--
-- A door now opens only after the invited developer has (1) signed in with their own account, which has the same
-- required authenticator-code step as creators, (2) accepted the invitation with the email address it was sent to,
-- and (3) signed the door's agreement with a key that never leaves their own device. The server checks the
-- signature, records it in the project's event record, and only then opens the door. The gateway credential is
-- given to the developer, not to the creator.
--
--   draft --invite--> awaiting_signature --developer signs--> open --close--> closed

-- A developer is a login (identity_id), like a creator. Email is contact information, not identity (see 004).
DO $$
DECLARE
  existing RECORD;
BEGIN
  FOR existing IN
    SELECT con.conname FROM pg_constraint con
      JOIN pg_attribute att ON att.attrelid = con.conrelid AND att.attnum = ANY (con.conkey)
     WHERE con.conrelid = 'developer'::regclass AND con.contype = 'u' AND array_length(con.conkey, 1) = 1 AND att.attname = 'email'
  LOOP
    EXECUTE format('ALTER TABLE developer DROP CONSTRAINT %I', existing.conname);
  END LOOP;
END
$$;

-- Signing keys a developer has registered. Only the public half is ever sent to the server. A developer has at most
-- one current key; registering a new one (a new device) retires the old one, and both stay on record.
CREATE TABLE developer_key (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  developer_id UUID NOT NULL REFERENCES developer (id) ON DELETE CASCADE,
  algorithm TEXT NOT NULL CHECK (algorithm = 'ECDSA-P256-SHA256'),
  public_key_spki TEXT NOT NULL,              -- base64 DER SubjectPublicKeyInfo
  fingerprint CHAR(64) NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),  -- SHA-256 of the DER key
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  retired_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_developer_key_current ON developer_key (developer_id) WHERE retired_at IS NULL;

CREATE FUNCTION developer_key_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.public_key_spki <> OLD.public_key_spki OR NEW.fingerprint <> OLD.fingerprint OR NEW.developer_id <> OLD.developer_id
     OR NEW.algorithm <> OLD.algorithm OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'developer_key %: a registered key cannot be changed', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at THEN
    RAISE EXCEPTION 'developer_key %: a retired key stays retired', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_developer_key_guard BEFORE UPDATE ON developer_key FOR EACH ROW EXECUTE FUNCTION developer_key_guard();

-- An invitation link. Only the SHA-256 of its secret is stored. It works only for a login with this email address.
CREATE TABLE door_invite (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  door_id UUID NOT NULL REFERENCES door (id) ON DELETE CASCADE,
  token_hash CHAR(64) NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  email TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  accepted_at TIMESTAMPTZ,
  accepted_by_developer UUID REFERENCES developer (id),
  revoked_at TIMESTAMPTZ
);
CREATE INDEX idx_door_invite_door ON door_invite (door_id);

-- The agreement is fixed when the invitation is sent: its exact text and SHA-256 are stored on the door, and the
-- developer signs that SHA-256. After signing, nothing about it can change.
ALTER TABLE door ADD COLUMN agreement_version TEXT;
ALTER TABLE door ADD COLUMN agreement_text TEXT;
ALTER TABLE door ADD COLUMN agreement_sha256 CHAR(64) CHECK (agreement_sha256 ~ '^[0-9a-f]{64}$');
ALTER TABLE door ADD COLUMN agreement_signed_at TIMESTAMPTZ;
ALTER TABLE door ADD COLUMN agreement_signed_message TEXT;   -- the exact bytes signed (UTF-8 JSON)
ALTER TABLE door ADD COLUMN agreement_signature TEXT;        -- base64, IEEE P1363 (r || s)
ALTER TABLE door ADD COLUMN agreement_key_id UUID REFERENCES developer_key (id);

CREATE FUNCTION door_agreement_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  -- Once sent (the door left draft), the agreement text is fixed.
  IF OLD.agreement_sha256 IS NOT NULL AND OLD.status <> 'draft' AND (
       NEW.agreement_text IS DISTINCT FROM OLD.agreement_text OR NEW.agreement_sha256 IS DISTINCT FROM OLD.agreement_sha256
       OR NEW.agreement_version IS DISTINCT FROM OLD.agreement_version) THEN
    RAISE EXCEPTION 'door %: the agreement cannot change after it was sent', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  -- Once signed, the signature and who signed are fixed.
  IF OLD.agreement_signed_at IS NOT NULL AND (
       NEW.agreement_signed_at IS DISTINCT FROM OLD.agreement_signed_at OR NEW.agreement_signature IS DISTINCT FROM OLD.agreement_signature
       OR NEW.agreement_signed_message IS DISTINCT FROM OLD.agreement_signed_message OR NEW.agreement_key_id IS DISTINCT FROM OLD.agreement_key_id
       OR NEW.developer_id IS DISTINCT FROM OLD.developer_id) THEN
    RAISE EXCEPTION 'door %: a signed agreement cannot change', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  -- A door opens only with a signed agreement (doors opened before 008 are left as they are).
  IF NEW.status = 'open' AND OLD.status <> 'open' AND NEW.agreement_signed_at IS NULL THEN
    RAISE EXCEPTION 'door %: cannot open without a signed agreement', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_door_agreement_guard BEFORE UPDATE ON door FOR EACH ROW EXECUTE FUNCTION door_agreement_guard();
