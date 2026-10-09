-- 006: the git gateway.
--
-- A creator connects their GitHub organization once (a GitHub App installation). A door gives one outside
-- developer a gateway credential for chosen repositories of one project. The developer's git remote is
-- Custody Core, never GitHub: the gateway checks the credential on every request, lets them push only to
-- branches under door/<door id>/, scans every push for secrets, and only then forwards it to GitHub.

-- The GitHub App installation a creator connected (one per creator). The installation id is not a secret;
-- the App's private key stays in the server's environment.
CREATE TABLE github_installation (
  creator_id UUID PRIMARY KEY REFERENCES creator (id) ON DELETE CASCADE,
  installation_id BIGINT NOT NULL CHECK (installation_id > 0),
  account_login TEXT NOT NULL,
  account_type TEXT NOT NULL,
  connected_by_github_login TEXT NOT NULL,   -- the GitHub user who proved access to the installation
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Doors are for a developer named by email; developer accounts and signing come later.
ALTER TABLE door ADD COLUMN developer_email TEXT;
ALTER TABLE door ADD CONSTRAINT chk_door_status
  CHECK (status IN ('draft', 'awaiting_signature', 'opening', 'open', 'closing', 'closed', 'failed'));
ALTER TABLE door_repository ADD CONSTRAINT chk_door_repository_access CHECK (access IN ('read', 'write'));
CREATE INDEX idx_door_repository_repository ON door_repository (repository_id);

-- A closed door stays closed: a new door is a new record.
CREATE FUNCTION door_closed_is_final() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status = 'closed' AND NEW.status <> 'closed' THEN
    RAISE EXCEPTION 'door %: a closed door cannot be reopened', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_door_closed_is_final BEFORE UPDATE ON door FOR EACH ROW EXECUTE FUNCTION door_closed_is_final();

-- The secret the developer's git client sends. Only its SHA-256 is stored; the value is shown once.
CREATE TABLE gateway_credential (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  door_id UUID NOT NULL REFERENCES door (id) ON DELETE CASCADE,
  token_hash CHAR(64) NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ
);
CREATE INDEX idx_gateway_credential_door ON gateway_credential (door_id);

-- A credential's secret and door never change, and a revocation can never be undone.
CREATE FUNCTION gateway_credential_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.token_hash <> OLD.token_hash OR NEW.door_id <> OLD.door_id OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'gateway_credential %: only last_used_at and revoked_at can change', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    RAISE EXCEPTION 'gateway_credential %: a revocation cannot be undone', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_gateway_credential_guard BEFORE UPDATE ON gateway_credential
  FOR EACH ROW EXECUTE FUNCTION gateway_credential_guard();
