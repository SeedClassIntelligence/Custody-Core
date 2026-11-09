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

`rejected`, `closed` and `expired` are final. In Phase 3 only `requested`, `approved`, `rejected`, `closed` and `expired` are reachable;
the middle steps exist for what comes next (sessions that get a checkout and a credential, evidence, promotion).

**An approved session does not get a git credential or a checkout yet.** That is deliberate: the request names which paths may be read and
written, and nothing can enforce that yet. Handing out a credential first would grant more than was asked for. Credentials arrive with controlled
materialization, together with enforcement of the paths.

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
