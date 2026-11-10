-- ---------------------------------------------------------------------------------------------------------
-- Phase 7a: contribution attribution (docs/integration/PHASE7_DESIGN.md).
--
-- For every commit a session pushed (every session_commit), one record of who did what, with the roles kept apart:
--   author     the executor the session declared (and its principal): the only author a real commit can have
--   committer  always the gateway
--   sponsor    the creator who approved the session and answers for it
--   declared   what the pushed commit claimed as its author: kept as evidence, never trusted
--
-- The record is DERIVED BY THE DATABASE from the session when the commit is recorded (trigger on session_commit), so no code path
-- can write a different author, and it cannot be changed afterwards. A pushed commit can name a creator as its author, but the
-- attribution still says who really wrote it.
-- ---------------------------------------------------------------------------------------------------------

CREATE TABLE contribution_attribution (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  work_session_id UUID NOT NULL REFERENCES work_session (id) ON DELETE CASCADE,
  project_id UUID NOT NULL REFERENCES project (id),
  repository_id UUID NOT NULL REFERENCES repository (id),
  real_sha CHAR(40) NOT NULL CHECK (real_sha ~ '^[0-9a-f]{40}$'),
  view_sha CHAR(40) NOT NULL CHECK (view_sha ~ '^[0-9a-f]{40}$'),
  author_principal_id UUID NOT NULL REFERENCES service_principal (id),
  author_executor_type TEXT NOT NULL,
  author_executor_provider TEXT,
  author_executor_model TEXT,
  author_executor_external_id TEXT,
  author_executor_display_name TEXT,
  committer_kind TEXT NOT NULL DEFAULT 'gateway' CHECK (committer_kind = 'gateway'),
  sponsor_id UUID NOT NULL REFERENCES creator (id),
  declared_author TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_attribution_commit UNIQUE (work_session_id, real_sha)
);
CREATE INDEX idx_attribution_project ON contribution_attribution (project_id, created_at);

-- Backstop: whatever inserts a row, the author and sponsor must be those of the session.
CREATE FUNCTION contribution_attribution_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM work_session s
     WHERE s.id = NEW.work_session_id AND s.session_type = 'automated_work_session'
       AND s.requested_by_principal_id = NEW.author_principal_id AND s.sponsor_id = NEW.sponsor_id
       AND s.project_id = NEW.project_id AND s.repository_id = NEW.repository_id
       AND s.executor_type = NEW.author_executor_type
       AND s.executor_provider IS NOT DISTINCT FROM NEW.author_executor_provider AND s.executor_model IS NOT DISTINCT FROM NEW.author_executor_model
       AND s.executor_external_id IS NOT DISTINCT FROM NEW.author_executor_external_id AND s.executor_display_name IS NOT DISTINCT FROM NEW.author_executor_display_name
  ) THEN
    RAISE EXCEPTION 'contribution_attribution: the author and sponsor must be those of the session' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_attribution_guard BEFORE INSERT ON contribution_attribution FOR EACH ROW EXECUTE FUNCTION contribution_attribution_guard();

-- Derived from the session when its commit is recorded.
CREATE FUNCTION session_commit_attribution() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO contribution_attribution (work_session_id, project_id, repository_id, real_sha, view_sha, author_principal_id,
                                        author_executor_type, author_executor_provider, author_executor_model, author_executor_external_id, author_executor_display_name,
                                        sponsor_id, declared_author)
  SELECT s.id, s.project_id, s.repository_id, NEW.real_sha, NEW.view_sha, s.requested_by_principal_id,
         s.executor_type, s.executor_provider, s.executor_model, s.executor_external_id, s.executor_display_name,
         s.sponsor_id, NEW.declared_author
    FROM work_session s
   WHERE s.id = NEW.work_session_id AND s.session_type = 'automated_work_session' AND s.requested_by_principal_id IS NOT NULL
  ON CONFLICT (work_session_id, real_sha) DO NOTHING;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_session_commit_attribution AFTER INSERT ON session_commit FOR EACH ROW EXECUTE FUNCTION session_commit_attribution();

CREATE TRIGGER trg_attribution_immutable BEFORE UPDATE OR DELETE ON contribution_attribution FOR EACH ROW EXECUTE FUNCTION session_record_immutable();

-- Commits recorded before this migration.
INSERT INTO contribution_attribution (work_session_id, project_id, repository_id, real_sha, view_sha, author_principal_id,
                                      author_executor_type, author_executor_provider, author_executor_model, author_executor_external_id, author_executor_display_name,
                                      sponsor_id, declared_author, created_at)
SELECT s.id, s.project_id, s.repository_id, c.real_sha, c.view_sha, s.requested_by_principal_id,
       s.executor_type, s.executor_provider, s.executor_model, s.executor_external_id, s.executor_display_name, s.sponsor_id, c.declared_author, c.created_at
  FROM session_commit c JOIN work_session s ON s.id = c.work_session_id
 WHERE s.session_type = 'automated_work_session' AND s.requested_by_principal_id IS NOT NULL
ON CONFLICT (work_session_id, real_sha) DO NOTHING;
