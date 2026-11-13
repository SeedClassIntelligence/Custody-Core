-- ---------------------------------------------------------------------------------------------------------
-- Machine submission of attributions (contract "commit-attribution-submission" v1, docs/contracts/).
--
--   scope attestations:submit            held by a service principal; on its own it permits nothing
--   attestation_submission_grant         the owner's explicit grant: THIS principal may deliver statements by THIS authority for THIS project
--   attestation.submitted_by_principal_id  who carried a machine-submitted statement (NULL: the owner delivered it)
--
-- The principal is only a courier: the statement's weight comes from the owner-registered authority's signature, which is verified before anything
-- is stored. The grant bounds what a courier may carry. The database enforces the grant too (a trigger on attestation), so no code path can
-- record a machine submission without one.
-- The scope is on the "work-producing" side of the separation rule (an approver, promoter or manager cannot also carry attributions).
-- The scope list must match ALL_SCOPES in server/servicePrincipals.ts (tests/scopes.test.ts compares them).
-- ---------------------------------------------------------------------------------------------------------

ALTER TABLE service_principal DROP CONSTRAINT chk_principal_known_scopes;
ALTER TABLE service_principal DROP CONSTRAINT chk_principal_scope_separation;
ALTER TABLE service_principal ADD CONSTRAINT chk_principal_known_scopes CHECK (
  allowed_scopes <@ ARRAY[
    'work-sessions:request', 'work-sessions:read', 'work-sessions:close-own', 'evidence:submit', 'repositories:push-session', 'attestations:submit',
    'work-sessions:approve', 'repositories:promote', 'principals:manage', 'webhooks:manage'
  ]::text[]
);
ALTER TABLE service_principal ADD CONSTRAINT chk_principal_scope_separation CHECK (
  NOT (
    allowed_scopes && ARRAY['work-sessions:approve', 'repositories:promote', 'principals:manage', 'webhooks:manage']::text[]
    AND allowed_scopes && ARRAY['work-sessions:request', 'evidence:submit', 'repositories:push-session', 'attestations:submit']::text[]
  )
);

CREATE TABLE attestation_submission_grant (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  creator_id UUID NOT NULL REFERENCES creator (id) ON DELETE CASCADE,
  principal_id UUID NOT NULL REFERENCES service_principal (id),
  authority_id UUID NOT NULL REFERENCES attestation_authority (id),
  project_id UUID NOT NULL REFERENCES project (id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ,
  CONSTRAINT uq_attestation_submission_grant UNIQUE (principal_id, authority_id, project_id)
);
CREATE INDEX idx_attestation_submission_grant_principal ON attestation_submission_grant (principal_id) WHERE revoked_at IS NULL;

-- The principal, the authority and the project all belong to the granting owner; the principal holds the scope and (if it has a project list) the
-- project is on it. A grant never changes; revoking it cannot be undone (a new grant is a new row's worth of intent, so it is a new id).
CREATE FUNCTION attestation_submission_grant_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'attestation_submission_grant %: cannot be deleted, only revoked', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NOT EXISTS (
      SELECT 1 FROM service_principal sp, attestation_authority a, project p
       WHERE sp.id = NEW.principal_id AND a.id = NEW.authority_id AND p.id = NEW.project_id
         AND sp.creator_id = NEW.creator_id AND a.creator_id = NEW.creator_id AND p.creator_id = NEW.creator_id
         AND sp.status = 'active' AND 'attestations:submit' = ANY (sp.allowed_scopes)
         AND (sp.allowed_project_ids IS NULL OR NEW.project_id = ANY (sp.allowed_project_ids))
         AND a.revoked_at IS NULL
    ) THEN
      RAISE EXCEPTION 'attestation_submission_grant: the principal (active, holding attestations:submit, with the project on its list), the unrevoked authority and the project must all belong to the granting owner'
        USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.id <> OLD.id OR NEW.creator_id <> OLD.creator_id OR NEW.principal_id <> OLD.principal_id OR NEW.authority_id <> OLD.authority_id
     OR NEW.project_id <> OLD.project_id OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'attestation_submission_grant %: only revocation can change', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    RAISE EXCEPTION 'attestation_submission_grant %: a revocation cannot be undone', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_attestation_submission_grant_guard BEFORE INSERT OR UPDATE OR DELETE ON attestation_submission_grant
  FOR EACH ROW EXECUTE FUNCTION attestation_submission_grant_guard();

ALTER TABLE attestation ADD COLUMN submitted_by_principal_id UUID REFERENCES service_principal (id);

-- A statement carried by a principal: only the attribution claim, only for a session that principal requested, only under a live grant for
-- exactly this authority and project, and only while the principal is active, unexpired and still holds the scope.
CREATE FUNCTION attestation_submission_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.submitted_by_principal_id IS NULL THEN
    RETURN NEW;
  END IF;
  IF NEW.claim <> 'commit.attribution' THEN
    RAISE EXCEPTION 'attestation: a machine submission may only carry the commit.attribution claim' USING ERRCODE = 'check_violation';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM work_session s
      JOIN project p ON p.id = s.project_id
      JOIN service_principal sp ON sp.id = NEW.submitted_by_principal_id
      JOIN attestation_submission_grant g ON g.principal_id = sp.id AND g.authority_id = NEW.authority_id AND g.project_id = s.project_id AND g.revoked_at IS NULL
     WHERE s.id = NEW.work_session_id AND s.requested_by_principal_id = sp.id
       AND sp.creator_id = p.creator_id AND sp.status = 'active' AND (sp.expires_at IS NULL OR sp.expires_at > now())
       AND 'attestations:submit' = ANY (sp.allowed_scopes)
       AND (sp.allowed_project_ids IS NULL OR s.project_id = ANY (sp.allowed_project_ids))
  ) THEN
    RAISE EXCEPTION 'attestation: no live grant lets this principal deliver this authority''s statement for this session' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_attestation_submission_guard BEFORE INSERT ON attestation FOR EACH ROW EXECUTE FUNCTION attestation_submission_guard();
