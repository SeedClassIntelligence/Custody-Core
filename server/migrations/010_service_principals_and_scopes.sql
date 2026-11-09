-- ---------------------------------------------------------------------------------------------------------
-- Service principals: machine callers (an orchestrator, an IDE, CI, an automated agent) that authenticate with
-- a key they hold, instead of a person's login. Specified in docs/integration/PHASE0_SPEC.md, section 3.1.
--
-- Nothing here changes an existing table. A principal belongs to one creator (the tenant), has scopes that are
-- stored here and never read from the token it sends, registers public keys, and its client assertions are
-- recorded so a replayed one is refused.
-- ---------------------------------------------------------------------------------------------------------

CREATE TABLE service_principal (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  creator_id UUID NOT NULL REFERENCES creator(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  platform_type TEXT NOT NULL,   -- e.g. 'orchestrator', 'ide', 'ci', 'agent'
  environment TEXT NOT NULL CHECK (environment IN ('development', 'staging', 'production')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked')),
  allowed_scopes TEXT[] NOT NULL DEFAULT '{}',
  allowed_project_ids UUID[],    -- NULL = every project of this creator
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  CONSTRAINT uq_principal_name UNIQUE (creator_id, name),
  CONSTRAINT chk_principal_revoked CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE TABLE service_principal_key (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_id UUID NOT NULL REFERENCES service_principal(id) ON DELETE CASCADE,
  algorithm TEXT NOT NULL CHECK (algorithm IN ('Ed25519', 'ES256')),
  public_key_jwk JSONB NOT NULL,
  -- SHA-256 of the key's RFC 7638 JWK thumbprint input. Unique: one key cannot belong to two principals.
  fingerprint CHAR(64) NOT NULL UNIQUE CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ
);

-- A registered key can never be changed, and revoking it cannot be undone (same rule as developer_key, 008).
CREATE FUNCTION service_principal_key_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.public_key_jwk IS DISTINCT FROM OLD.public_key_jwk OR NEW.fingerprint <> OLD.fingerprint
     OR NEW.principal_id <> OLD.principal_id OR NEW.algorithm <> OLD.algorithm OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'service_principal_key %: key parameters cannot be altered', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    RAISE EXCEPTION 'service_principal_key %: revocation cannot be undone', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_service_principal_key_guard BEFORE UPDATE ON service_principal_key
  FOR EACH ROW EXECUTE FUNCTION service_principal_key_guard();

-- A revoked principal stays revoked, and a principal never changes tenant.
CREATE FUNCTION service_principal_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status = 'revoked' AND NEW.status <> 'revoked' THEN
    RAISE EXCEPTION 'service_principal %: revocation cannot be undone', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.creator_id <> OLD.creator_id THEN
    RAISE EXCEPTION 'service_principal %: the creator cannot change', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_service_principal_guard BEFORE UPDATE ON service_principal
  FOR EACH ROW EXECUTE FUNCTION service_principal_guard();

-- Client assertions already used. A jti is unique per issuer, not globally.
CREATE TABLE used_client_assertion (
  principal_id UUID NOT NULL REFERENCES service_principal(id) ON DELETE CASCADE,
  jti TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (principal_id, jti)
);
CREATE INDEX idx_used_assertion_expiry ON used_client_assertion (expires_at);

-- The application's database account has no DELETE on any table, so old rows are removed by this one narrow
-- function, which can delete only expired assertions (roles.sql grants EXECUTE to custody_app).
CREATE FUNCTION purge_expired_client_assertions() RETURNS integer
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  WITH d AS (DELETE FROM used_client_assertion WHERE expires_at < now() - interval '1 hour' RETURNING 1)
  SELECT count(*)::integer FROM d
$$;

-- Rules a creator has written to let a named principal's request be approved without a person each time.
-- Nothing reads this table yet (approval arrives in a later phase); it is created now so the rule's text
-- and hash are fixed from the start: a rule is retired and replaced, never edited.
CREATE TABLE approval_policy (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  creator_id UUID NOT NULL REFERENCES creator(id) ON DELETE CASCADE,
  principal_id UUID REFERENCES service_principal(id) ON DELETE CASCADE,  -- NULL = any of this creator's principals
  name TEXT NOT NULL,
  rule JSONB NOT NULL,
  rule_sha256 CHAR(64) NOT NULL CHECK (rule_sha256 ~ '^[0-9a-f]{64}$'),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired')),
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE FUNCTION approval_policy_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.rule IS DISTINCT FROM OLD.rule OR NEW.rule_sha256 <> OLD.rule_sha256 OR NEW.creator_id <> OLD.creator_id
     OR NEW.principal_id IS DISTINCT FROM OLD.principal_id OR NEW.name <> OLD.name THEN
    RAISE EXCEPTION 'approval_policy %: a rule cannot be edited; retire it and create a new one', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.status = 'retired' AND NEW.status <> 'retired' THEN
    RAISE EXCEPTION 'approval_policy %: a retired rule cannot be reactivated', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_approval_policy_guard BEFORE UPDATE ON approval_policy
  FOR EACH ROW EXECUTE FUNCTION approval_policy_guard();
