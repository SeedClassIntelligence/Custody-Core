# Custody Core platform integration: Phase 0 specification (corrected)

**Status: for review. Nothing in this document is built. No migration or code change happens until the owner approves it.**
Audited against `main` at `f0c2d66` ("Support Windows in embedded postgres initdb locale"), the same commit the first draft cited. Brief: "Custody Core Platform Integration Brief"; standard: CAS /
Incremental Hardening Gate.

## 0. Corrections to the first draft

The first draft contained statements that do not match the repository, and designs that would not work as written.
They are fixed below. A reviewer comparing the two should look at these:

| # | First draft said | Reality / fix |
|---|---|---|
| C1 | (Retracted.) An earlier version of this table said commit `f0c2d66` does not exist. It does: it is the current tip of `main`. That claim came from a stale local clone. The first draft's audited commit was correct. | None needed. |
| C2 | Event hash is SHA-256 of fields concatenated with `∥` | The hash is SHA-256 of one canonical JSON object, keys in alphabetical order, containing `action, actor_id, actor_type, payload, prev_hash, project_id, seq, subject_id, subject_type, timestamp`. `hash` and `seed_signature_id` are not part of it. `docs/EVENT_HASH_FORMAT.md` is authoritative. |
| C3 | Event named `gateway.push_accepted` | The real events are `git.push`, `git.push_rejected`, `git.fetch`. |
| C4 | `custody_app` has SELECT only, plus INSERT on `event` | It has `SELECT, INSERT, UPDATE` on ordinary tables, **no** `INSERT/UPDATE/DELETE/TRUNCATE` on `event`, and `EXECUTE` on `append_event()` (`server/roles.sql`). It has **no `DELETE`** on any table. |
| C5 | `organization_id` as the tenant | There is no organization table. Tenancy is `creator_id`. Principals now belong to a creator. |
| C6 | `webhook_endpoint.secret_hash` | A hash cannot sign anything. The secret is stored encrypted (AES-256-GCM, `server/secretBox.ts` style, bound to the row id). |
| C7 | `used_client_assertion.jti` as the primary key | A `jti` is unique per issuer, not globally. Key is `(principal_id, jti)`. Expired rows need purging, and the app role cannot `DELETE` (C4), so a `SECURITY DEFINER` purge function is specified. |
| C8 | Auto-approval policy relied on by TM-01 but had no table | `approval_policy` added (migration 010). |
| C9 | Attestation `verified` flag set after insert | Records are immutable. An attestation is verified **before** it is stored and rejected if it does not verify. |
| C10 | RS256 supported | Dropped until a real integration needs it. EdDSA and ES256 only. The JWT `alg` header is pinned to the registered key's algorithm (blocks algorithm confusion, `alg: none`). |
| C11 | Machine requests land under `apiRouter.use(authenticate)` implicitly | `/api/v2` gets its own principal authentication middleware. The `/api/v1` human middleware is not touched. |
| C12 | "New tables need Data API lockdown" (my earlier message) | **Retracted.** `server/lockdown.sql` already runs inside every migration and closes the Supabase REST API to every table. What is actually needed is `server/roles.sql` changes (section 3.4) and test coverage. |
| C13 | Doors map to sessions "automatically" | Existing doors need a **backfill** in migration 012. Built as a trigger on `door` (no change to the v1 door code) plus the backfill; see 3.2. Specified in section 6. |

The first draft's example `base_commit` (`d5db881372b22bb8fa8f5c1e2b904d6e80123456`) was a short hash padded with invented digits. Examples
below use obviously fake values.

## 1. Existing-system inventory (verified)

**Database** (`server/migrations/001`..`009`, applied in order by the server):

- `creator` (identity from Supabase Auth `identity_id`; email is contact data, 004), `developer`, `developer_key` (008; ECDSA P-256 public keys,
  retirement irreversible via `trg_developer_key_guard`).
- `door` states `draft, awaiting_signature, opening, open, closing, closed, failed` (001, 006). `trg_door_closed_is_final` (a closed door never reopens),
  `trg_door_agreement_guard` (agreement text fixed once sent; signature fixed once executed). A door cannot open without a verified signature (008).
- `door_invite` (008), `gateway_credential` (006; SHA-256 of `ccg_...` bearer token, plaintext shown once, `trg_gateway_credential_guard`).
- `github_installation`, `repository` (006, 007; lock fields `locked_at`, `lock_checked_at`), `mirror_snapshot` (009; `trg_mirror_snapshot_is_final`).
- `event`: append-only per-project chain. Written only by `append_event()`, which locks the project row, assigns `seq`, `prev_hash`, timestamp and
  hash (003). `trg_event_append_only` and `trg_event_prevent_truncate` refuse UPDATE/DELETE/TRUNCATE. `seed_signature_id` exists but is unused.
- `account_event` (005): a second append-only chain per login (`account_id` = the login's user id), written by `append_account_event()`.
  Used for things that belong to an account, not a project.
- `mfa_factor`, `mfa_attempt`, `mfa_session` (005): the server's own authenticator step, with lockout.

**HTTP** (`server.ts`, `server/`):

- Unauthenticated: `GET /api/v1/health`; the GitHub App callback.
- Git gateway under `/git/` (mounted before the JSON parsers): smart-HTTP via `git http-backend`; pre-receive hook (`server/gateway/pre-receive.mjs`) limits pushes
  to `refs/heads/door/<door id>/`, runs gitleaks on every new commit (`--exit-code 42` rejects), takes a ref lease, and forwards to GitHub with an
  installation token.
- `/api/v1/*` behind `authenticate` (Supabase session **and** a passed code step): projects, events, `events/verify`, GitHub connection, door lifecycle,
  `/developer/*` (accept invite, register key, sign agreement, credential), snapshots.
- Scheduler (`server/scheduler.ts`): closes expired doors, re-checks repository locks, takes bundle snapshots on close.

**Boundaries.** Creator: login + code step, isolated by `creator_id`. Developer: login + invite email + registered device key. Gateway: SHA-256 of the
credential token, scoped to the door's branches and repositories. Database: `custody_app` role, record tables protected by triggers and revokes, REST API closed by `lockdown.sql`.

**Tests:** 21 files in `tests/`, real hashes and real signatures, throwaway database, local Supabase Auth in Docker for login tests. A GitHub Actions
workflow (`.github/workflows/test.yml`) that runs lint, build and the full suite on every pull request and push to `main` is on `main`.

## 2. Gap analysis

Classifications: **Existing and verified**, **Existing but incomplete**, **Build new**, **Requires an owner decision**.

| Brief § | Capability | Status | Reality and gap |
|---|---|---|---|
| 1 | Service principals | Build new | Only human creators and developers exist. |
| 1 | Asymmetric client assertion (RFC 7523 profile) | Build new | Needs key registry, verifier, `alg` pinning. |
| 1 | Replay prevention | Build new | `(principal_id, jti)` store with purge. |
| 2 | Fine-grained scopes | Build new | Today access is binary per door. |
| 2 | High-consequence scope separation | Build new | No policy layer. |
| 3 | Universal work session | Existing but incomplete | `door` is the human case. Add `work_session` and link 1:1. |
| 3 | Human doors preserved | Existing and verified | Passing tests; must stay unchanged. |
| 4 | Approval separation, policy | Build new | Creators open doors by hand. Add sponsor approval and `approval_policy`. |
| 5 | Repository provider abstraction | Existing but incomplete | GitHub-only (`server/github.ts`, `repositoryLock.ts`). |
| 6 | Controlled materialization with path rules | Build new | Gateway enforces branch prefix only, **not paths**. |
| 7 | Evidence contracts | Build new | Pushes record commits and scan result only. |
| 8 | Contribution attribution | Build new | Events carry `actor_id`; no author/committer/sponsor structure. |
| 8 | Owner attestation (Seed Signature) | Requires an owner decision | `seed_signature_id` is a blank column. No protocol is defined anywhere in the repo. |
| 9 | Evidence-gated promotion | Build new | Merging to default branches is not handled in-platform; the lock ruleset allows only the App to bypass. |
| 10 | Platform events | Existing but incomplete | New event names needed (section 3.5). |
| 10 | Signed outbound webhooks | Build new | No outbound delivery exists. |
| 11 | Local vault, encrypted bundles | Existing but incomplete | Bundles are stored unencrypted in `BACKUP_DIR`. |
| 12 | OpenAPI 3.1 and SDK | Build new | None. |
| 13 | Migrations and ledger | Existing but incomplete | Mechanism is sound. Extend it. |
| 14 | Backward compatibility | Existing and verified (to be preserved) | Additive `/api/v2`. |

## 3. Proposed migrations (not applied)

Conventions: `IF NOT EXISTS` is not needed (the runner records applied files). Every table gets its `server/roles.sql` treatment (3.4). `lockdown.sql`
runs automatically in each migration. Scope names are from the registry in 3.3.

### 3.1 `010_service_principals_and_scopes.sql`

```sql
CREATE TABLE service_principal (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  creator_id UUID NOT NULL REFERENCES creator(id) ON DELETE CASCADE,   -- the tenant (C5)
  name TEXT NOT NULL,
  platform_type TEXT NOT NULL,                                          -- 'orchestrator','ide','ci','agent',...
  environment TEXT NOT NULL CHECK (environment IN ('development','staging','production')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','revoked')),
  allowed_scopes TEXT[] NOT NULL DEFAULT '{}',
  allowed_project_ids UUID[],                                           -- NULL = all of this creator's projects
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
  algorithm TEXT NOT NULL CHECK (algorithm IN ('Ed25519','ES256')),     -- C10
  public_key_jwk JSONB NOT NULL,
  fingerprint CHAR(64) NOT NULL UNIQUE CHECK (fingerprint ~ '^[0-9a-f]{64}$'),  -- SHA-256 of the RFC 7638 JWK thumbprint input
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ
);
-- Guard: key material is immutable; revocation is one-way. Same pattern as trg_developer_key_guard (008).
CREATE FUNCTION service_principal_key_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.public_key_jwk IS DISTINCT FROM OLD.public_key_jwk OR NEW.fingerprint <> OLD.fingerprint
     OR NEW.principal_id <> OLD.principal_id OR NEW.algorithm <> OLD.algorithm OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'service_principal_key %: key parameters cannot be altered', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    RAISE EXCEPTION 'service_principal_key %: revocation cannot be undone', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_service_principal_key_guard BEFORE UPDATE ON service_principal_key
  FOR EACH ROW EXECUTE FUNCTION service_principal_key_guard();
-- Same one-way rule for the principal itself: a revoked principal stays revoked.
CREATE FUNCTION service_principal_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status = 'revoked' AND NEW.status <> 'revoked' THEN
    RAISE EXCEPTION 'service_principal %: revocation cannot be undone', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.creator_id <> OLD.creator_id THEN
    RAISE EXCEPTION 'service_principal %: tenant cannot change', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_service_principal_guard BEFORE UPDATE ON service_principal
  FOR EACH ROW EXECUTE FUNCTION service_principal_guard();

CREATE TABLE used_client_assertion (
  principal_id UUID NOT NULL REFERENCES service_principal(id) ON DELETE CASCADE,
  jti TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (principal_id, jti)                                       -- C7
);
CREATE INDEX idx_used_assertion_expiry ON used_client_assertion (expires_at);
-- The app role has no DELETE anywhere (C4), so expiry cleanup is a narrow SECURITY DEFINER function.
CREATE FUNCTION purge_expired_client_assertions() RETURNS integer LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  WITH d AS (DELETE FROM used_client_assertion WHERE expires_at < now() - interval '1 hour' RETURNING 1) SELECT count(*)::integer FROM d $$;

CREATE TABLE approval_policy (                                          -- C8
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  creator_id UUID NOT NULL REFERENCES creator(id) ON DELETE CASCADE,
  principal_id UUID REFERENCES service_principal(id) ON DELETE CASCADE, -- NULL = any of this creator's principals
  name TEXT NOT NULL,
  rule JSONB NOT NULL,   -- max_ttl_seconds, repository ids, allowed_write_paths, required evidence types, no promotion
  rule_sha256 CHAR(64) NOT NULL CHECK (rule_sha256 ~ '^[0-9a-f]{64}$'),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
  created_by TEXT NOT NULL,                                             -- a creator who passed login + code step
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- rule and rule_sha256 are immutable once created (guard trigger, as above). Changing a rule = retire and create.
```

### 3.2 `012_universal_work_sessions.sql`

**As built in Phase 3** (migration `012_universal_work_sessions.sql`, `server/workSessions.ts`). The SQL below is the original design; what was built
differs in these ways, each deliberate:
1. **Only `work_session`** is in this migration. The evidence tables (`evidence_requirement`, `evidence_submission`) ship with the evidence phase, in their own migration.
2. **Human doors are mirrored by a database trigger**, not by new code in the door routes. An `AFTER INSERT/UPDATE` trigger on `door` keeps one `human_door` session per door in
   step (status mapping: draft to requested, awaiting_signature to approved, opening to provisioning, open and closing to active, closed to closed or expired, failed to closed).
   No `/api/v1` door code changed. The mirror follows the door whatever it does, so it can never be the reason a door operation fails. This replaces the earlier plan that door
   creation "additionally inserts its session". Existing doors get sessions from a backfill statement in the migration itself, which writes no events.
3. **A human door has no single repository** (a door can cover several, see `door_repository`), so `repository_id`, `base_commit`, `branch_name`, `repository_access` and,
   for old doors, `expires_at` are nullable there; an automated session must have all of them (a `CHECK`).
4. **`repository_access` (`read` or `read_and_push`) is a column**; the original design had no place to store the request's access mode.
5. **Sponsors are creators only** (`sponsor_id` references `creator`); the `organization_member` option is gone with the organization model (decision 2).
6. **The database enforces the approval step**: an automated session cannot be created already approved or closed; its request (who, what, where, paths, end time) cannot be edited;
   status moves only along fixed steps with `rejected`, `closed` and `expired` final; and `approved_by` must be `creator:<sponsor id>` (or later `policy:<id>`), never the requesting principal or nobody.
7. **A human door's session has `executor_type = human_developer`, and an automated session never does** (`CHECK`), so a machine cannot pose as a human developer.
8. **Paths are default-deny and stored as given.** Matching and enforcement belong to controlled materialization (Phase 5); until then they are recorded and validated for shape only.

Original design:

```sql
CREATE TABLE work_session (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES project(id) ON DELETE CASCADE,
  repository_id UUID NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
  session_type TEXT NOT NULL CHECK (session_type IN ('human_door','automated_work_session')),
  door_id UUID UNIQUE REFERENCES door(id) ON DELETE CASCADE,
  requested_by_principal_id UUID REFERENCES service_principal(id) ON DELETE SET NULL,
  executor_type TEXT NOT NULL CHECK (executor_type IN ('human_developer','ai_assistant','ide_runtime','ci_runtime','platform_service')),
  executor_provider TEXT, executor_model TEXT, executor_external_id TEXT, executor_display_name TEXT,
  sponsor_id UUID NOT NULL REFERENCES creator(id),                       -- creators only, for now (decision 2)
  objective TEXT NOT NULL,
  base_commit CHAR(40) NOT NULL CHECK (base_commit ~ '^[0-9a-f]{40}$'),
  branch_name TEXT NOT NULL,                                             -- session/<id>/...
  allowed_read_paths TEXT[] NOT NULL DEFAULT '{}',                       -- default deny: nothing is allowed unless stated
  allowed_write_paths TEXT[] NOT NULL DEFAULT '{}',
  prohibited_paths TEXT[] NOT NULL DEFAULT '{}',
  external_context_namespace TEXT,                                       -- reverse-DNS, validated by the API
  external_context_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  status TEXT NOT NULL DEFAULT 'requested' CHECK (status IN
    ('requested','approved','provisioning','active','awaiting_evidence','completed','rejected','closed','expired')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  approved_at TIMESTAMPTZ, approved_by TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  closed_at TIMESTAMPTZ, closed_reason TEXT,
  CONSTRAINT chk_session_door CHECK ((session_type = 'human_door') = (door_id IS NOT NULL)),
  CONSTRAINT chk_session_expiry CHECK (expires_at > created_at)
);
-- Backfill: every existing door becomes a human_door session (C13). Run inside this migration; creates no events.
-- INSERT INTO work_session (...) SELECT ... FROM door JOIN door_repository ...;  (exact statement written in Phase 3)

CREATE TABLE evidence_requirement (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  work_session_id UUID NOT NULL REFERENCES work_session(id) ON DELETE CASCADE,
  evidence_type TEXT NOT NULL,
  is_required BOOLEAN NOT NULL DEFAULT true,
  issuer_principal_id UUID REFERENCES service_principal(id),             -- who may issue it (registered, not a free string)
  tied_to_commit BOOLEAN NOT NULL DEFAULT true,
  max_age_seconds INTEGER CHECK (max_age_seconds > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE evidence_submission (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  work_session_id UUID NOT NULL REFERENCES work_session(id) ON DELETE CASCADE,
  evidence_type TEXT NOT NULL,
  issuer_principal_id UUID NOT NULL REFERENCES service_principal(id),
  signature_key_id UUID NOT NULL REFERENCES service_principal_key(id),
  subject_commit CHAR(40) NOT NULL CHECK (subject_commit ~ '^[0-9a-f]{40}$'),
  status TEXT NOT NULL CHECK (status IN ('pass','fail','inconclusive')),
  specification_hash CHAR(64) NOT NULL CHECK (specification_hash ~ '^[0-9a-f]{64}$'),
  evidence_hash CHAR(64) NOT NULL CHECK (evidence_hash ~ '^[0-9a-f]{64}$'),
  issued_at TIMESTAMPTZ NOT NULL,
  signature_algorithm TEXT NOT NULL,
  signature_value TEXT NOT NULL,
  raw_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_evidence_once UNIQUE (work_session_id, evidence_type, subject_commit, evidence_hash)
);
-- Immutable: BEFORE UPDATE OR DELETE trigger raises (as in the first draft), and roles.sql revokes UPDATE/DELETE/TRUNCATE.
```

### 3.3 Scope registry (checked by the API; the database stores the strings)

Execution scopes (a principal may hold these): `work-sessions:request`, `work-sessions:read`, `work-sessions:close-own`, `evidence:submit`,
`repositories:push-session`.
High-consequence scopes (**never grantable to a principal that also holds `work-sessions:request` for the same project, and never self-applicable**):
`work-sessions:approve`, `repositories:promote`, `principals:manage`, `webhooks:manage`.
Approval and promotion by a principal are possible only through an active `approval_policy` rule that names it (decision recorded with the policy hash).

**As built in Phase 2 (migration `011_scope_separation_and_narrowing.sql`).** The rule is enforced by the database (a `CHECK`), not only
by the registry code, and it is stricter than the sentence above in two ways, deliberately:
1. It is per **principal**, not per project: a principal that holds any high-consequence scope can hold none of `work-sessions:request`,
   `evidence:submit` or `repositories:push-session`. (Scopes are stored per principal; "same project" would need a per-project grant table and
   would let one principal both do and sign off work in different projects.) A principal may still read sessions (`work-sessions:read`).
   Whoever needs both roles uses two principals.
2. `evidence:submit` and `repositories:push-session` are included with `work-sessions:request`: they produce or vouch for the work.
Also built: only known scopes are accepted (`CHECK`, compared with the registry by `tests/scopes.test.ts`), and a principal's permissions can only
be **narrowed** after creation (fewer scopes, a smaller project list; the environment never changes). A trigger enforces it, so a script or direct
SQL cannot widen a principal either. To give a caller more, create a new principal. The approval-by-policy logic itself arrives with the
approval endpoints (Phase 3 and 8); nothing can approve or promote yet.

### 3.4 `server/roles.sql` changes (C4, C12)

Default privileges give `custody_app` `SELECT, INSERT, UPDATE` on new tables. Migrations 010 to 014 therefore require explicit lines:
- `REVOKE UPDATE, DELETE, TRUNCATE` on `evidence_submission`, `contribution_attribution`, `attestation`, `webhook_delivery` (records the app may add but never change; `webhook_delivery` gets a narrow `SECURITY DEFINER` function for attempt updates, or is moved to an insert-per-attempt design).
- `GRANT EXECUTE ON FUNCTION purge_expired_client_assertions() TO custody_app`.
- Tests: extend `tests/data_api_exposure.test.ts` and `tests/schema_and_tenant.test.ts` to cover every new table.

### 3.5 `014_attestation_promotion_and_webhooks.sql` (summary of changes from the first draft)

- `contribution_attribution`: as drafted, `sponsor_id UUID REFERENCES creator(id)`, immutable. `author_*` is whatever the principal declares, and is never allowed
  to name a creator unless the work session's sponsor is that creator and the commit arrived through a session credential.
- `attestation`: no `verified` columns (C9); inserted only after the signature verifies; immutable.
- `promotion_request`: `UNIQUE (work_session_id, target_branch, commit_hash)`; status machine `pending → approved → completed | rejected`; completion and failure recorded as events.
- `webhook_endpoint`: `creator_id UUID`, `url TEXT CHECK (url ~ '^https://')`, `secret_ciphertext TEXT` (C6), `subscribed_events TEXT[]`.
- `webhook_delivery`: `event_id UUID NOT NULL`, `UNIQUE (endpoint_id, event_id, attempt)`, `payload_sha256`, `next_attempt_at`, `last_error`.
  Idempotency key sent to the receiver: the ledger event id.
- New event names (dotted, matching the existing style): `service_principal.registered`, `service_principal.key_added`, `service_principal.suspended`,
  `service_principal.revoked`, `work_session.requested`, `.approved`, `.rejected`, `.opened`, `.closed`, `evidence.submitted`, `attribution.recorded`,
  `attestation.recorded`, `promotion.requested`, `.completed`, `.rejected`. Session, evidence and promotion events go on the **project** chain via
  `append_event()`. Principal registration, key and revocation events are creator-level and go on the **account** chain via `append_account_event()`
  (`account_id` = the creator's login id). Owner confirmation requested in section 9.

## 4. API contracts (`/api/v2/*`, all new; `/api/v1/*` unchanged)

### 4.1 Authentication
`Authorization: Bearer <client assertion JWT>` verified by a new middleware mounted only on `/api/v2`. Checks, all required:
1. Header `alg` is `EdDSA` or `ES256`, **equal to the registered algorithm of the key named by `kid`**. Anything else (including `none`) is 401.
2. `iss` = `sub` = a `service_principal.id`; principal `active`, not expired; key not revoked, not expired.
3. `aud` = `custody-core` exactly.
4. `iat` not in the future (30 s skew), `exp` in the future, `exp - iat <= 300`.
5. `jti` present and not already recorded for this principal; recorded with its `exp`, in the same statement that checks it (`INSERT ... ON CONFLICT DO NOTHING`, 0 rows = replay = 401).
6. The caller's scopes come from the **database record**, never from the token.

(RFC 7523 defines this assertion for a token endpoint. Using it per request is a deliberate profile. If the owner prefers, the same verifier can sit behind
`POST /api/v2/token` issuing 5-minute opaque tokens, which reduces signing load. Open question, section 9.)

### 4.2 Endpoints
`POST /api/v2/work-sessions` (request), `POST /api/v2/work-sessions/:id/evidence`, `POST /api/v2/work-sessions/:id/promote`, plus `GET`
reads, `POST .../close`, and human-facing approve/reject under `/api/v1` (requires a creator with a passed code step; this is what keeps approval human).

**Built in Phase 3:** `POST /api/v2/work-sessions` (scope `work-sessions:request`), `GET /api/v2/work-sessions` and `GET /api/v2/work-sessions/:id` (`work-sessions:read`),
`POST /api/v2/work-sessions/:id/close` (`work-sessions:close-own`), and for the creator `GET /api/v1/projects/:id/work-sessions`, `POST .../:sid/approve` and `POST .../:sid/reject`.
The request is strict: unknown fields are refused, `external_context` and `evidence_requirements` are refused as "not accepted yet" (Phases 4 and 6), a human executor type is refused, and
at most 25 requests may wait for approval per principal. A principal sees only the sessions it asked for; one that holds `work-sessions:approve` sees those of the projects it can reach.
There is no machine route that approves or rejects; a principal can only ask for a promotion, and only with repositories:promote. Details: `docs/WORK_SESSIONS.md`.
Request and response shapes are as in the first draft, with these changes: `sponsor.id` is a creator id and must be the owner of the project (else 403);
`signature.key_id` is a `service_principal_key.id`; examples use fake hashes; `event_hash` in the response is the hash of the `work_session.requested` event.

## 5. Threat model

| ID | Threat | Mitigation |
|---|---|---|
| TM-01 | Self-approval escalation | Execution and high-consequence scopes separated (3.3); approval endpoint is human-only unless a named active policy rule applies; tested in `scopes.test.ts`. |
| TM-02 | Assertion replay / interception | 300 s max lifetime, `(principal_id, jti)` recorded atomically, TLS required; replay returns 401. |
| TM-03 | Branch escape or path escape | Pre-receive limits refs to `session/<id>/` (as it does today for doors) **and, new in Phase 5, checks every changed path** against the session's allow/deny lists, before objects leave quarantine. Path enforcement does not exist yet. |
| TM-04 | Author impersonation | Author, committer (always the gateway) and sponsor are separate fields; creator authorship is only recordable under that creator's own sponsored session. |
| TM-05 | Secrets in pushed code | gitleaks on every new commit, as today. |
| TM-06 | Ledger tampering | Existing: no `INSERT/UPDATE/DELETE/TRUNCATE` on `event` for the app, `append_event()` only. New record tables get the same treatment (3.4). |
| TM-07 | Algorithm confusion | `alg` pinned to the registered key (4.1). |
| TM-08 | Webhook SSRF and secret theft | `https` only, resolved address must be public (no private, loopback, link-local), no redirects followed, secret encrypted at rest (C6), signature over timestamp + body, receivers told to reject old timestamps. |
| TM-09 | Evidence reuse | Evidence is bound to session, commit and specification hash, and expires by `max_age_seconds`; a pass on one commit never satisfies another. |
| TM-11 | A secret pasted into a request (objective, executor name, context) is written into the permanent record, which cannot be edited | Every free-text field of a session request is scanned with the git gateway's scanner (gitleaks) **before** anything is recorded. A finding refuses the request and names only the rule, never the secret. No scanner, or a scanner that fails, also refuses (fail closed). |
| TM-12 | A caller claims another platform's namespace (for example `com.seedclass.srt1`) to make its context look official | The namespace is documented as a label, not an identity. What identifies the sender is the principal the session was requested by, recorded in the request and in the ledger (`actor_id = principal:<id>`). Nothing in Custody Core trusts or branches on a namespace; the only special case is the reserved first label `custody`. |
| TM-10 | New tables exposed through the database's public REST API | Prevented already by `lockdown.sql` in every migration; verified by test coverage extended to new tables. |

## 6. Compatibility with existing doors

- No existing table is altered destructively. `work_session.door_id` links 1:1 to `door`.
- Migration 012 **backfills** a `human_door` session for each existing door, and a trigger on `door` keeps them in step. Nothing in the `/api/v1` door code changed (an earlier plan had door creation insert the session; the trigger replaces that). `developer_signing.test.ts`, `git_gateway.test.ts` and `scheduler.test.ts` pass unchanged next to the new tests.
- Gateway: door credentials keep `refs/heads/door/<door id>/`; session credentials use `refs/heads/session/<session id>/`. Matching is by credential type, never by guessing.
- The web app keeps calling `/api/v1/*`; no client change is needed.

## 7. Capability ledger and tests

| ID | Capability | Classification | Test |
|---|---|---|---|
| CL-01 | SHA-256 event chain | Existing and verified | `append_event.test.ts`, `hashchain.test.ts` |
| CL-02 | Creator login with required code step | Existing and verified | `auth_api.test.ts`, `second_factor.test.ts` (need Docker) |
| CL-03 | Human door invites and P-256 signatures | Existing and verified | `developer_signing.test.ts` |
| CL-04 | Git gateway and secret scanning | Existing and verified | `git_gateway.test.ts` |
| CL-05 | Scheduler and snapshots | Existing and verified | `scheduler.test.ts`, `bundle.test.ts` |
| CL-06 | Principal and key registry | Build new | `service_principal.test.ts` |
| CL-07 | Assertion auth, replay, alg pinning | Build new | `assertion_auth.test.ts` |
| CL-08 | Scope enforcement | Build new | `scopes.test.ts` |
| CL-09 | Work session lifecycle, human approval | Built (Phase 3) | `work_sessions.test.ts`. The spec's "gateway credential generation" is **not** part of it: see Phase 5. |
| CL-10 | Namespaced context | Built (Phase 4) | `external_context.test.ts` |
| CL-11 | Materialization and path enforcement | Build new | `materialization.test.ts` |
| CL-12 | Evidence | Build new | `evidence.test.ts` |
| CL-13 | Attribution, non-impersonation | Build new | `attribution.test.ts` |
| CL-14 | Evidence-gated promotion | Build new | `promotion.test.ts` |
| CL-15 | Signed webhooks, SSRF rules | Build new | `webhooks.test.ts` |
| CL-16 | Encrypted vault | Built (Phase 11) | `vault.test.ts` |
| CL-17 | OpenAPI and SDK | Built (Phase 10) | `openapi.test.ts`, `sdk.test.ts` |
| CL-18 | External signing authority | Built protocol-neutral (Phase 7b); a named service still needs its owner's protocol | `attestation.test.ts` |
| CL-19 | New tables: roles and REST closure | Build new | extend `data_api_exposure.test.ts`, `schema_and_tenant.test.ts` |
| CL-20 | Human door regression | Existing and verified | existing door tests must pass unchanged at every phase |
| CL-21 | The whole external flow, and the record verified without our code | Built (Phase 12) | `end_to_end.test.ts` |

## 8. Sequenced plan

Precondition (met): the CI workflow is on `main`, so every phase's gate runs on every PR. Each phase ends with its gate green **in CI** before the next starts.

1. Principals, keys, assertion auth (010, `servicePrincipalAuth.ts`, `roles.sql`). Gate: CL-06, CL-07, CL-19.
2. Scopes, revocation, tenant isolation. Gate: CL-08.
3. Work sessions, backfill, human approval. Gate: CL-09, CL-20. (Built without issuing credentials, on purpose: a credential handed out before the allowed and prohibited paths can be enforced would grant more than the request asked for. Session credentials arrive in Phase 5, together with path enforcement.)
4. Namespaced context in the ledger. Gate: CL-10. (Built as migration 013; because the context is plain data that the platform must never act on, the same phase also puts **every free-text field of a session request through the secret scanner** before it is recorded: the record is permanent.)
5. Repository provider interface, materialization, **path enforcement in pre-receive**, and **session credentials** (a `ccs_` credential, in its own table so door credentials stay untouched, bound to an approved session and accepted only for `session/<id>/` and its allowed paths; see `PHASE5_DESIGN.md`). Gate: CL-11.
6. Evidence. Gate: CL-12.
7. Attribution and attestations (014, part). Gate: CL-13 (attestation gated by decision 3).
8. Promotion. Gate: CL-14.
9. Webhooks. Gate: CL-15.
10. OpenAPI and SDK. Gate: CL-17.
11. Vault. Gate: CL-16.
12. End-to-end external flow: register principal, request session, push to `session/<id>/*` through the gateway, submit signed evidence, human approval, promote, close, then verify the chain independently with the documented hash format.

## 8a. Progress

- Phase 1 (principals, keys, assertion login): built. See `docs/SERVICE_PRINCIPALS.md`. Registered actor type for operator-run
  provisioning is `system` (the account-event function accepts only creator, developer, system, gateway), with the operator in the actor id.
- Phase 2 (scopes, separation of duties, narrowing, project access): built. Migration 011; `requireScope`, `requireProjectAccess`, `narrowPrincipal`;
  `npm run principal -- narrow`. Later migrations are renumbered: work sessions are 012, external context is 013, attribution/attestation/promotion/webhooks are 014.
  Gate `tests/scopes.test.ts` (27 tests). The spec's "organization isolation" is tenant (creator) isolation, tested there.
- Phase 3 (work sessions, doors mirrored, human approval): built. Migration 012, `server/workSessions.ts`, `docs/WORK_SESSIONS.md`. Gate `tests/work_sessions.test.ts` (33 tests)
  with the existing door tests unchanged. **Deviation from CL-09:** an approved session does not get a gateway credential yet; see the Phase 3 and 5 entries in section 8.
- Phase 4 (namespaced external context): built. Migration 013, `server/externalContext.ts`, `server/textScan.ts`; gate `tests/external_context.test.ts` (27 tests).
  Deviations from the original design: the context columns are nullable and all-or-nothing (the design had `payload NOT NULL DEFAULT '{}'`), a SHA-256 binds namespace and data, numbers in the
  context must be whole numbers within 2^53 - 1 (anything else is sent as text, so the ledger can always re-derive the hash), and every free-text field of a request is scanned for secrets (TM-11).
- Phase 5: **design note written, awaiting the owner's decisions**: `docs/integration/PHASE5_DESIGN.md`, with a reproducible prototype of the filtered-view and push-translation plumbing in
  `docs/integration/phase5-spike/` (24 of 24 checks pass). Owner accepted decisions D1 to D9 on the condition of alignment with the plan (checked in the note, section 9). **5a built** (provider interface, behavior-preserving); **5b built** (path rules and the filtered-view builder, as libraries: 120 tests, a property test against an independent matcher, a 20 000-file benchmark); **5c built** (migration `014`; credentials, provisioning, the session gateway and push hook, replay onto the real history, cleanup; 28 new tests in `tests/materialization.test.ts`). **Phase 6 built** (migration `015`; evidence requirements and signed submissions, evaluation; 22 tests in `tests/evidence.test.ts`; `docs/integration/PHASE6_DESIGN.md`). **Phase 7a built** (migration `016`; contribution attribution derived by the database; 7 tests in `tests/attribution.test.ts`; `docs/integration/PHASE7_DESIGN.md`). **Phase 7b built** (migration `017`; generic signing authorities and verified, immutable attestations; 11 tests in `tests/attestation.test.ts`). Decision 3 is answered for the protocol-neutral design only: a named service such as Seed Signature is still to be specified by its owner. **Phase 8 built** (migration `018`; evidence-gated promotion, owner-approved, fast-forward only; 12 tests in `tests/promotion.test.ts`; `docs/integration/PHASE8_DESIGN.md`). **Phase 9 built** (migration `019`; signed webhooks with the SSRF rules; 25 tests in `tests/webhooks.test.ts`; `docs/WEBHOOKS.md`, `docs/integration/PHASE9_DESIGN.md`). **Phase 10 built** (OpenAPI 3.1 description served at `/api/v2/openapi.json` and kept true by tests against the real server; TypeScript client; 19 tests in `tests/openapi.test.ts` and `tests/sdk.test.ts`; `docs/INTEGRATION.md`, `docs/integration/PHASE10_DESIGN.md`). **Phase 11 built** (encrypted backups: chunked AES-256-GCM, envelope keys, key change, integrity check, plain restore; 22 tests in `tests/vault.test.ts`; `docs/VAULT.md`, `docs/integration/PHASE11_DESIGN.md`). **Phase 12 built** (the whole external flow as one test, and `scripts/verify-chain.mjs`, a dependency-free verifier of the record and of webhook deliveries; 13 tests in `tests/end_to_end.test.ts`; `docs/integration/PHASE12_DESIGN.md`). **Every phase of the plan is built.** Open: a named signing service for CL-18 (its owner must specify the protocol).
- Phases 6 to 12: not started.

## 9. Owner decisions

| # | Question | Recommendation | State |
|---|---|---|---|
| 1 | Assertion algorithms | EdDSA and ES256 only; add RS256 only for a named integration that requires it. | Approved |
| 2 | Organization model | No organization UI. Tenant is `creator_id`. Principals provisioned by script in Phase 1. Revisit teams only if multi-person creators are needed. | Approved |
| 3 | External signing authority transport (Seed Signature) | REST endpoint with a detached signature verified against a published public key (verifiable offline). | **Open: needs the Seed Signature owner. No protocol exists in this repo.** |
| 4 | Per-request assertion vs token exchange (4.1) | Per-request for Phase 1 (simplest, stateless). | Approved |
| 5 | Where principal-level events are recorded (3.5) | Account chain for registration and revocation; project chain for sessions, evidence and promotion. | Approved |

This document changes nothing until approved.
