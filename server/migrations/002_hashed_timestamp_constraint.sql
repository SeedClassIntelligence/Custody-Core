-- 002: event.hashed_timestamp must never be empty, and must have no default.
-- Older databases were created with DEFAULT '' and/or an auto-named CHECK. Remove both, then add
-- the one named constraint the application and tests rely on.

ALTER TABLE event ALTER COLUMN hashed_timestamp DROP DEFAULT;

DO $$
DECLARE
  existing RECORD;
BEGIN
  FOR existing IN
    SELECT con.conname
    FROM pg_constraint con
    JOIN pg_attribute att
      ON att.attrelid = con.conrelid AND att.attnum = ANY (con.conkey)
    WHERE con.conrelid = 'event'::regclass
      AND con.contype = 'c'
      AND att.attname = 'hashed_timestamp'
  LOOP
    EXECUTE format('ALTER TABLE event DROP CONSTRAINT %I', existing.conname);
  END LOOP;
END
$$;

ALTER TABLE event
  ADD CONSTRAINT chk_event_hashed_timestamp CHECK (hashed_timestamp <> '');
