# Work sessions

Phase 3 of `docs/integration/PHASE0_SPEC.md`. A work session is one bounded piece of work on a project. There are two kinds,
in one table (`work_session`):

| | Human door | Automated session |
|---|---|---|
| Who works | an invited developer, with a signed agreement | a service principal (a machine caller), see `docs/SERVICE_PRINCIPALS.md` |
| Who decides | the creator invites; the developer signs | a person: the sponsoring creator approves or rejects |
| How it is created | by the door routes, as before. A database trigger mirrors every door into a session | `POST /api/v2/work-sessions` |
| Repositories | one or more (`door_repository`) | exactly one |
| Changed by this phase? | **No.** Door routes, tables, triggers and tests are unchanged | new |

## What an automated session is

```
requested --(creator approves)--> approved --> provisioning --> active --> awaiting_evidence --> completed --> closed
    |                                  |             |            |
    +--(creator rejects)--> rejected   +-------------+------------+--(closed by requester, or the end time passes)--> closed / expired
```

`rejected`, `closed` and `expired` are final. `requested`, `approved`, `provisioning`, `active`, `rejected`, `closed` and `expired` are reachable today;
`awaiting_evidence` and `completed` exist for what comes next (evidence, promotion).

An approved session gets a credential and a working copy only when its requester asks for them (next section). Until then nothing can touch the repository.

## Working in a session (machine caller)

`POST /api/v2/work-sessions/:id/credential`, scope `repositories:push-session`, **only the principal that requested the session**:

- **First call** (session `approved`): the gateway fetches the real repository, checks that `base_commit` is part of the default branch, builds a **filtered view** and issues one credential.
  The view is a separate repository with **one commit, no history, and only the files the session may read** (regular files; no symlinks or submodules). Everything else (including files that exist only in old history)
  is not in it, and a clone cannot ask for it. Limits: 20 000 files and 500 MiB in the view. The response (`201`) holds the git address, the credential (`ccs_...`, shown **once**, stored only as a hash),
  its expiry (the session's), the branch prefix and the view's commit. Any failure returns the session to `approved` with nothing issued, so the call can simply be repeated.
- **Later calls** (session `active`): a replacement credential (`200`); the old one stops working at once. At most 10 per session.
- Errors: `403` no scope; `404` not this principal's session; `409` not approved yet, being prepared, finished, or expired; `422` the base commit is missing or not on the default branch, or the rules leave nothing to read, or too much;
  `502`/`503` the repository host cannot be reached or is not configured.

```
git clone http://x:<credential>@<app>/git/sessions/<session id>/<owner>/<repo>.git     # any user name; the credential as the password
git push origin HEAD:session/<session id>/<name>
```

**What a push does.** The gateway checks it, then replays it onto the real history, where the creator can see it on the branch `session/<session id>/<name>`:

1. **Branches**: only `session/<session id>/...`. No tags, no deletes, no history rewriting (fast-forward only; to start over, use a new branch name), no other branch, never the default branch.
2. **Shape**: a straight line from the commit the session was given (no merges, no new roots). At most 200 commits, 5 000 changed paths per commit, 25 MiB per file, 100 MiB per push (configurable: `SESSION_PUSH_MAX_COMMITS`, `_MAX_PATHS`, `_MAX_FILE_BYTES`, `_MAX_BYTES`).
3. **Paths**: every changed path (a rename counts as a delete plus an add) must be writable by the request's rules (`docs/integration/PHASE5_DESIGN.md`, 4.2): inside an allowed write path, readable, not prohibited in any spelling (case, Unicode forms,
   trailing dots), never `.git` or `.gitmodules`, and a CI or pipeline file (`.github/`, `.gitlab-ci.yml`, ...) only if a write pattern names it. Only regular files; the executable bit may change.
   A new file may not take the place of something in the real tree the session cannot see (a symlink, say), and a changed or deleted file must be what the real tree holds.
4. **Secrets**: the new commits are scanned with gitleaks; no scanner, no push. The secret is never shown or recorded.
5. **Replay**: each commit becomes a real commit. **The author is the session's declared executor** (the name and address come from the request, never from the push); the pushed author is kept only in a `Custody-Declared-Author` trailer,
   so a session cannot commit as the creator or anyone else. **The committer is the gateway** (`Custody Core <gateway@custody.invalid>`), and every commit carries `Custody-Work-Session: <id>`. Dates come from the pushed commit.
   The result is a pure function of the push: pushing the same commits again gives the same real commits.
6. **Push to the real repository** atomically; if someone changed the branch there in the meantime the push is refused (`upstream_changed`). Only then does the executor's push succeed.

The push output lists each `view -> real` commit pair; `GET /api/v2/work-sessions/:id/commits` (scope `work-sessions:read`) lists them later. Events: `work_session.provisioned` (counts only: never the names or sizes of what was left out),
`session_credential.issued` / `.revoked`, `git.fetch`, `git.push` (with the pairs) and `git.push_rejected` (the reason and, for paths and secrets, which ones, never the secret), all in the project's tamper-evident record.

**Ending.** Closing, expiring (the scheduler also does this) or rejecting a session revokes its credential in the same step and deletes the gateway's copy; the next git request is refused. The branches already pushed stay in the creator's repository.
A session left half-prepared by a crash is put back to `approved` by the scheduler after 15 minutes.

**What this does not do, plainly.** A session can copy out anything it is allowed to read: the read rules limit what it sees, not what it does with it. A stolen credential *is* the session until it ends (so: short lifetimes, revoked on close, shown once).
File names and sizes inside the allowed set are visible. The secret scan checks what is pushed (file contents), not commit messages, and not what the session was allowed to read. Whether the work is *good* is evidence (a later phase), and promoting a session branch
to the default branch is a later phase too. If the gateway's disk copy of a session is lost, the session cannot continue (close it and request a new one); the work already replayed is in the repository.

## Requesting (machine caller)

`POST /api/v2/work-sessions`, with scope `work-sessions:request`. The sponsor must be the owner of the project (the creator the principal belongs to).

```json
{
  "project_id": "<project id>",
  "repository_id": "<repository id, of that project>",
  "executor": { "type": "ai_assistant", "provider": "example-ai", "model": "model-1", "external_id": "agent_99", "display_name": "Refactor Engine" },
  "sponsor": { "type": "creator", "id": "<the creator's id>" },
  "objective": "Harden the authorization routes",
  "base_commit": "<40-character lowercase commit id>",
  "access": {
    "repository": "read_and_push",
    "allowed_read_paths": ["server/**", "shared/**"],
    "allowed_write_paths": ["server/gateway/**"],
    "prohibited_paths": ["server/migrations/**", ".env*"]
  },
  "expires_in_seconds": 3600
}
```

- `executor.type`: `ai_assistant`, `ide_runtime`, `ci_runtime` or `platform_service`. A human developer works through a door, so `human_developer` is refused. Other executor fields are optional text up to 200 characters.
- `access.repository`: `read` (then no write paths) or `read_and_push` (then write paths are required). Read paths are always required: nothing is allowed unless listed.
- Paths are relative to the repository root: no leading `/` or `~`, no `..`, no empty or `.` segments, no backslashes or control characters, at most 200 characters, at most 50 per list. They are recorded as given; matching is decided where they are enforced.
- `expires_in_seconds`: a whole number from 60 to 86400 (default 3600).
- Unknown fields are refused, and `evidence_requirements` is refused with "not accepted yet": it arrives in a later phase, and a field that is silently ignored would be worse than one that is refused.
- `external_context` is optional: see "External context" below.
- `base_commit` is recorded, not yet checked against the repository (that needs the checkout).

Response `202`:

```json
{ "session_id": "...", "status": "requested", "requires_approval": true, "sponsor_id": "...",
  "branch_prefix": "session/<session id>/", "expires_at": "...", "event_hash": "..." }
```

`event_hash` is the hash of the `work_session.requested` event in the project's tamper-evident record.

Errors: `400` the request is not valid (the message says what); `401` no valid credential; `403` no `work-sessions:request` scope, or the sponsor is not the project's owner;
`404` the project or repository is not reachable by this principal (a project that does not exist, belongs to another creator, or is outside the principal's project list all answer alike);
`429` this principal already has 25 requests waiting for approval (so it cannot bury its creator's approval queue).

## Reading and closing (machine caller)

- `GET /api/v2/work-sessions` (filters `project_id`, `status`) and `GET /api/v2/work-sessions/:id`, scope `work-sessions:read`. A principal sees the sessions **it** requested.
  A principal that also holds `work-sessions:approve` sees the sessions of every project it can reach. Human doors are never shown here.
- `POST /api/v2/work-sessions/:id/close`, scope `work-sessions:close-own`: the requester closes its own session. Closing a closed session is harmless and records nothing more;
  a rejected or expired one answers `409`.

There is no machine route that approves, rejects or promotes. A principal cannot approve its own request, and the database backs this: an automated session cannot be created
already approved, and an approval must name `creator:<the sponsor>`, never the requesting principal.

## External context

A caller can attach `"external_context": { "namespace": "com.seedclass.srt1", "context": { "project_id": "srt1_proj_44", "workcell_id": "cell_09" } }` so that its own platform can find its way
back to the session. Custody Core **never acts on it**: it does not authorize, route or decide anything from it, and no code branches on a namespace. It is stored with the session, shown to whoever approves it, and
recorded in the project's permanent record. Sessions without it work exactly as before (`external_context: null` is the same as leaving it out).

- **Namespace:** lowercase reverse-DNS with at least two labels (`com.example.orchestrator`): letters, digits and inner hyphens, no empty labels, at most 100 characters. The first label `custody` is reserved for the platform.
  The namespace is a **label, not an identity**: anyone can claim any name. What identifies the sender is the principal the session was requested by, which the session and the record both carry.
- **Context:** a JSON object, at most 8 levels deep, 1000 values and 16 KiB once written canonically; keys 1 to 100 characters, text up to 2000 characters, lists up to 200 items; no NUL characters or unpaired surrogates; no `__proto__` key.
  **Numbers must be whole numbers within +/- 9007199254740991.** Send anything else (decimals, larger numbers) as text: JavaScript cannot hold them exactly, and the ledger must always be able to re-derive its own hashes
  (`docs/EVENT_HASH_FORMAT.md`).
- **Hash:** `sha256` of the canonical JSON of `{ "context": ..., "namespace": ... }` is stored with the session and written into the record, so the two copies can be matched. The database computes the same value (`canonical_jsonb`).
- **In the record:** `work_session.requested` carries `external_context` (namespace, context, sha256); `work_session.approved` carries the namespace and sha256, so what was approved is tied to exactly what was requested.
  Changing the context in the record afterwards is detected by the record's hash chain.
- **Immutable:** the context cannot be changed after the request. The three columns are all set or all empty, only automated sessions have them, and the database checks the namespace, the hash format and that the data is an object.
- Treat it as untrusted data wherever you show it (never as HTML or as instructions).

## Secrets are kept out of the record

Everything the caller wrote in a session request (objective, executor details, paths, context) is permanent once recorded, so it is scanned for secrets first with the scanner the git gateway uses (gitleaks). A finding refuses
the request (`400`) naming only the rule that matched, never the secret, and nothing is recorded. With no scanner installed, or one that cannot run, the request is refused (`503`): it fails closed, like pushes.
The Dockerfile installs the scanner; `/api/v1/health` shows `secret_scanner: installed` or `missing`.

## Evidence (Phase 6)

A request can say what must be shown before its work is trusted, and **which registered principal** may show it:

```json
"evidence_requirements": [
  { "type": "tests", "issuer_principal_id": "<a principal of the same owner holding evidence:submit>",
    "required": true, "tied_to_commit": true, "specification_hash": "<optional sha256 the evidence must carry>", "max_age_seconds": 3600 }
]
```

At most 10, one per type (lowercase letters, digits, `_` `.` `-`). `required` and `tied_to_commit` default to true. The issuer must be an active principal of the project's owner, hold `evidence:submit` and be allowed to act on the project, or the request is refused (`422`);
it cannot be added or changed afterwards (the database enforces this). The owner sees the requirements, and whether the issuer is the same principal that asked for the work (`issuer_is_requester`), when approving.

**Submitting** (`POST /api/v2/work-sessions/:id/evidence`, scope `evidence:submit`, only the named issuer; anyone else gets `404`), while the session is running:

```json
{ "evidence_type": "tests", "subject_commit": "<a real commit id from GET .../commits>", "status": "pass | fail | inconclusive",
  "specification_hash": "<sha256>", "evidence_hash": "<sha256 of the report or artifact>", "issued_at": "2026-01-31T12:00:00Z",
  "payload": { "optional": "plain JSON, whole numbers only" },
  "signature": { "key_id": "<one of your keys>", "algorithm": "Ed25519 | ES256", "value": "<base64url>" } }
```

The signature is over the UTF-8 bytes of the canonical JSON (`docs/EVENT_HASH_FORMAT.md`) of `{ format: "custody-core.evidence.v1", work_session_id, evidence_type, subject_commit, status, specification_hash, evidence_hash, payload_sha256, issued_at }`
where `payload_sha256` is the SHA-256 of the canonical JSON of `payload` (`{}` if none). Ed25519 signs the bytes directly; ES256 is the raw 64-byte `r || s` form. `issued_at` is UTC to the second. The commit must be one this session produced, and the statement cannot be dated before that commit existed or in the future.
A pinned `specification_hash` must match. The payload is scanned for secrets (the record is permanent) and kept; the project's record carries only hashes (`evidence.submitted`). Sending the identical statement again changes nothing (`200`); a different result for the same `evidence_hash`
is a conflict (`409`): a recorded statement is never replaced, issue a new one. Errors carry a `code`.

**Evaluating** (`GET /api/v2/work-sessions/:id/evidence[?commit=<sha>]`, scope `work-sessions:read`; the owner has the same under `/api/v1/projects/:id/work-sessions/:sid/evidence`) says, per requirement, `satisfied`, `failed`, `inconclusive`, `missing`, `stale` (older than `max_age_seconds`)
or `issuer_unavailable` (the principal is no longer active, or the key is revoked or expired: a revocation cannot say whether the key was already compromised, so what it signed stops counting). Rules: only the named issuer; only this commit (unless the requirement is not tied to a commit);
the newest counting statement decides, so a later fail overrides a pass; `ready` means every required requirement is satisfied. The default commit is the session's newest. **Nothing acts on this yet**: promotion (a later phase) is what will require `ready`.

## Approving (the project's creator)

Under the full person login (password and authenticator code), `/api/v1/projects/:id/work-sessions`:

- `GET /` lists the project's sessions (doors included), with who asked.
- `POST /:sid/approve`: only a `requested` session that has not expired. Records `approved_by = creator:<id>` and the event `work_session.approved`.
- `POST /:sid/reject`, optional `{ "reason": "..." }` (up to 500 characters): records `work_session.rejected`.

Deciding twice is refused (`409`). Another creator's request gets `404`.

## Expiry

The scheduler (every 30 seconds, like doors) expires automated sessions past their end time, whether or not they were approved, and records `work_session.closed`
with reason `expired` by `system / scheduler`. An expired request can no longer be approved.

## The record

Every step is an event in the project's tamper-evident record, with the session as the subject: `work_session.requested` (actor `system`, id `principal:<id>`, with the full request),
`work_session.approved` and `work_session.rejected` (actor `creator`), `work_session.closed`. The ledger's actor types are fixed (creator, developer, system, gateway), so a principal is recorded as `system`
with its id in the actor id.

## What the database enforces, whoever writes

- A session cannot be created already approved, rejected or closed.
- An automated session is complete: repository, commit, a branch under its own id (`session/<id>/...`), an end time, at least one read path, and write paths exactly when it may push.
- Its request cannot be edited afterwards: who, what, where, paths and end time.
- Status moves only along the steps above; `rejected`, `closed`, `expired` are final. An approval, once given, cannot be rewritten.
- The application's database account cannot delete sessions.
- The external context cannot be changed, and is all-or-nothing (namespace, data, hash).

## Human doors

Nothing about doors changes. A trigger on `door` creates a `human_door` session for every new door and keeps its status in step (draft is requested, invited is approved, opening is provisioning,
open is active, closed is closed or expired). Doors that existed before the migration got theirs from a backfill that writes no events. The mirror follows the door whatever it does and can never
be the reason a door operation fails.

## Tests

Neither needs Docker (the secret scanner is downloaded by the test if it is not installed, as for the gateway tests).

- `tests/work_sessions.test.ts` (33 tests): door mirroring through the real lifecycle and the migration's own backfill; request validation (38 refusals, nothing written); scopes, sponsor, project and repository checks;
  the pending limit under 35 simultaneous requests; approval and rejection; no machine route approves; visibility; closing; scheduler expiry; what the database refuses; and that the projects' records still verify.
- `tests/external_context.test.ts` (27 tests): namespace and data validation including every limit at its edge; platform neutrality (different platforms and hostile-looking content behave identically and grant nothing);
  the hash computed three ways (this code, plain SHA-256 of the canonical text, and the database) over unicode, nesting and boundary numbers; the context in the project's record and detection of tampering with it; secrets in
  the context and in other fields; and the database's own checks.
- The door tests (`developer_signing`, `git_gateway`, `scheduler`) run unchanged beside them.
