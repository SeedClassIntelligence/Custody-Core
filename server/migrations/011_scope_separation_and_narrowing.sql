-- ---------------------------------------------------------------------------------------------------------
-- Phase 2: scopes are enforced by the database as well as by the server.
--
--   1. Only known scopes can be stored.
--   2. Separation of duties: a principal that can approve, promote or manage cannot also be one that produces
--      work or vouches for it (request a session, submit evidence, push). Whoever does the work cannot be the one
--      who signs it off. The check lives here so that no code path, script or direct SQL can create a principal
--      that breaks it.
--   3. A principal's permissions can only be narrowed after it is created, never widened or changed in kind.
--      To give a caller more, create a new principal (with its own keys and its own record).
--
-- ALTER TABLE ... ADD CONSTRAINT checks the rows that already exist: if a principal registered under Phase 1 breaks
-- rule 1 or 2, this migration fails and changes nothing, instead of silently leaving it in place.
-- The scope list below must match ALL_SCOPES in server/servicePrincipals.ts (tests/scopes.test.ts compares them).
-- ---------------------------------------------------------------------------------------------------------

ALTER TABLE service_principal ADD CONSTRAINT chk_principal_known_scopes CHECK (
  allowed_scopes <@ ARRAY[
    'work-sessions:request', 'work-sessions:read', 'work-sessions:close-own', 'evidence:submit', 'repositories:push-session',
    'work-sessions:approve', 'repositories:promote', 'principals:manage', 'webhooks:manage'
  ]::text[]
);

ALTER TABLE service_principal ADD CONSTRAINT chk_principal_scope_separation CHECK (
  NOT (
    allowed_scopes && ARRAY['work-sessions:approve', 'repositories:promote', 'principals:manage', 'webhooks:manage']::text[]
    AND allowed_scopes && ARRAY['work-sessions:request', 'evidence:submit', 'repositories:push-session']::text[]
  )
);

-- Replaces the guard from migration 010 (a revoked principal stays revoked; the creator never changes) and adds
-- the narrowing-only rule. Suspending, reactivating, revoking and shortening the expiry are unaffected.
CREATE OR REPLACE FUNCTION service_principal_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status = 'revoked' AND NEW.status <> 'revoked' THEN
    RAISE EXCEPTION 'service_principal %: revocation cannot be undone', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.creator_id <> OLD.creator_id THEN
    RAISE EXCEPTION 'service_principal %: the creator cannot change', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.environment <> OLD.environment THEN
    RAISE EXCEPTION 'service_principal %: the environment cannot change', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF NOT (NEW.allowed_scopes <@ OLD.allowed_scopes) THEN
    RAISE EXCEPTION 'service_principal %: scopes can only be removed, never added', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.allowed_project_ids IS NOT NULL
     AND (NEW.allowed_project_ids IS NULL OR NOT (NEW.allowed_project_ids <@ OLD.allowed_project_ids)) THEN
    RAISE EXCEPTION 'service_principal %: the project list can only be made smaller, never larger', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
