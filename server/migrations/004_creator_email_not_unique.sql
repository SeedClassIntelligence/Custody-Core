-- 004: creator.email is contact information, not identity.
--
-- A creator is identified by creator.identity_id (the login system's user id), never by email. Emails change,
-- and a login provider may hand an address that someone gave up to a different person later. With a UNIQUE
-- email, that second person was locked out of Custody Core for good. Remove the uniqueness; the application
-- keeps the email current instead.

DO $$
DECLARE
  existing RECORD;
BEGIN
  FOR existing IN
    SELECT con.conname
    FROM pg_constraint con
    JOIN pg_attribute att
      ON att.attrelid = con.conrelid AND att.attnum = ANY (con.conkey)
    WHERE con.conrelid = 'creator'::regclass
      AND con.contype = 'u'
      AND array_length(con.conkey, 1) = 1
      AND att.attname = 'email'
  LOOP
    EXECUTE format('ALTER TABLE creator DROP CONSTRAINT %I', existing.conname);
  END LOOP;
END
$$;
