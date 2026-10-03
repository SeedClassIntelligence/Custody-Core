-- ---------------------------------------------------------------------------------------------------------
-- Close Supabase's built-in REST API (Data API) to everything of ours.
--
-- On Supabase, every table and function in schema public is served at /rest/v1 to the roles anon and
-- authenticated, with the PUBLIC key that is in the browser, and new tables get full rights for those roles.
-- Custody Core never uses that API: all access goes through our server as custody_app. So those roles get
-- no access at all, and row-level security is on for every table (only custody_app has a policy; the
-- table owner and SECURITY DEFINER functions are not affected). On a plain PostgreSQL without those roles
-- the role-specific part is skipped.
--
-- It refers to no particular table or function, so it can run inside every migration's own transaction:
-- nothing a migration creates is ever committed while open. It runs again after server/roles.sql.
-- ---------------------------------------------------------------------------------------------------------

-- Functions are executable by PUBLIC (every role) unless revoked. Only custody_app needs any of ours, and
-- server/roles.sql grants it exactly those. The default-privileges line has no IN SCHEMA on purpose: a per-schema
-- default cannot take away PostgreSQL's global "PUBLIC may execute" default, so without this every function a
-- later migration creates would be callable through the REST API.
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

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
    -- (On the very first migration custody_app does not exist yet; roles.sql creates it and this runs again.)
    IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'custody_app') AND NOT EXISTS (SELECT FROM pg_catalog.pg_policies WHERE schemaname = 'public' AND tablename = t.relname AND policyname = 'custody_app_access') THEN
      EXECUTE format('CREATE POLICY custody_app_access ON public.%I FOR ALL TO custody_app USING (true) WITH CHECK (true)', t.relname);
    END IF;
  END LOOP;
END
$$;
