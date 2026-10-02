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
-- Only the operator clears a reset requirement.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE mfa_legacy_reset FROM custody_app;
GRANT EXECUTE ON FUNCTION append_account_event(text, text, text, text, jsonb) TO custody_app;

-- Code home (migration 006): received webhooks are a record; installations are never deleted, only marked removed.
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE github_webhook_delivery FROM custody_app;
REVOKE DELETE, TRUNCATE ON TABLE github_installation FROM custody_app;
REVOKE DELETE, TRUNCATE ON TABLE github_connect_state FROM custody_app;

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

-- Supabase's built-in REST API is closed to all of the above by server/lockdown.sql, which runs after this file
-- (and inside every migration).
