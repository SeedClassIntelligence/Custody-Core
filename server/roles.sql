-- Custody Core Restricted Database Role: custody_app
-- This role has least-privilege permissions:
-- 1. Only SELECT and INSERT on the 'event' table (no UPDATE, no DELETE, no TRUNCATE, no trigger modification/ownership).
-- 2. SELECT, INSERT, UPDATE on other domain tables.
-- 3. The application runtime must connect using this role, never as the 'postgres' superuser.

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'custody_app') THEN
    CREATE ROLE custody_app WITH LOGIN PASSWORD 'CustodyAppPass702!';
  END IF;
END
$$;

-- Grant schema access
GRANT USAGE ON SCHEMA public TO custody_app;

-- Grant base table permissions
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO custody_app;

-- Strictly revoke mutation privileges on event table
-- Events are written only through append_event(), which assigns seq, prev_hash, timestamp and hash.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE event FROM custody_app;
GRANT EXECUTE ON FUNCTION append_event(uuid, text, text, text, text, text, jsonb) TO custody_app;

-- Second factor (migration 005): attempts are a record, so the app may add and read them but never change them.
-- Account events, like project events, are written only through append_account_event().
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE mfa_attempt FROM custody_app;
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE mfa_session FROM custody_app;
REVOKE DELETE, TRUNCATE ON TABLE mfa_factor FROM custody_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE account_event FROM custody_app;
GRANT EXECUTE ON FUNCTION append_account_event(text, text, text, text, jsonb) TO custody_app;

-- The app role must not be able to create objects (for example look-alike functions) in this schema.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- Grant sequence permissions for identity/auto-increment columns
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO custody_app;

-- Ensure future tables grant permissions correctly if needed
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE ON TABLES TO custody_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO custody_app;

-- The migration bookkeeping table is for the admin role only; the app must not edit it.
DO $$
BEGIN
  IF to_regclass('public.schema_migrations') IS NOT NULL THEN
    REVOKE ALL ON TABLE schema_migrations FROM custody_app;
  END IF;
END
$$;

-- ---------------------------------------------------------------------------------------------------------
-- Close Supabase's built-in REST API (Data API) to everything of ours.
--
-- On Supabase, every table and function in schema public is served at /rest/v1 to the roles anon and
-- authenticated, with the PUBLIC key that is in the browser, and new tables get full rights for those roles.
-- Custody Core never uses that API: all access goes through our server as custody_app. So those roles get
-- no access at all, and row-level security is on for every table (only custody_app has a policy; the
-- table owner and SECURITY DEFINER functions are not affected). On a plain PostgreSQL without those roles
-- the role-specific part is skipped. Re-run after every migration, so new tables are covered too.
-- ---------------------------------------------------------------------------------------------------------

-- Functions are executable by PUBLIC (every role) unless revoked. Only custody_app needs any of ours.
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
GRANT EXECUTE ON FUNCTION append_event(uuid, text, text, text, text, text, jsonb) TO custody_app;
GRANT EXECUTE ON FUNCTION append_account_event(text, text, text, text, jsonb) TO custody_app;

DO $$
DECLARE
  r text;
  t record;
BEGIN
  FOREACH r IN ARRAY ARRAY['anon', 'authenticated'] LOOP
    IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = r) THEN
      EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA public FROM %I', r);
      EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM %I', r);
      EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM %I', r);
      EXECUTE format('REVOKE ALL ON SCHEMA public FROM %I', r);
      EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM %I', r);
      EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM %I', r);
      EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM %I', r);
    END IF;
  END LOOP;

  FOR t IN
    SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
  LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t.relname);
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_policies WHERE schemaname = 'public' AND tablename = t.relname AND policyname = 'custody_app_access') THEN
      EXECUTE format('CREATE POLICY custody_app_access ON public.%I FOR ALL TO custody_app USING (true) WITH CHECK (true)', t.relname);
    END IF;
  END LOOP;
END
$$;
