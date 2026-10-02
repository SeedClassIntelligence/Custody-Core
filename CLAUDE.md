# Custody Core — project instructions

## What this is

Custody Core lets non-technical creators give outside developers access to their code without losing control of it. The creator works only in this app's dashboard and never touches GitHub, cloud consoles, or other services directly.

The creator lives through four moments:

1. **Claim it**: their code home is created and locked in their name.
2. **Open a door**: a developer gets narrow, temporary, signed access.
3. **Work gets watched**: every change is recorded and reviewed before it's accepted.
4. **Close the door**: one action ends access, revokes credentials, destroys the workspace, and preserves the work.

Every action is written to an append-only, hash-chained event log. Seed Signature, a separate signing service that already exists, will sign those events in a later phase. The log is the spine of the product: if it can be faked, edited, or wiped, the product is worthless.

The app started as a Google AI Studio build. The database layer and event log are real and were independently verified against a live PostgreSQL. Much of the frontend still holds leftover demo code. Treat every screen as suspect until verified.

## Rules that override everything else

1. **Never fake anything.** No invented values: no made-up commit SHAs, storage URIs, file sizes, signature hashes, IDs, latencies, or metrics. No success messages for things that didn't happen. If a feature isn't built, its screen shows "Not connected yet" plus one plain sentence on what it will do.
2. **No hardcoded success.** Every check (door open, branch allowed, secret found, tenant allowed) runs real code on real input and must be able to fail.
3. **Tests must be real.** Each test runs real code against a real database and asserts on real results. Never make a failing test pass by weakening it, renaming it, or adding a shortcut to the product code. If a test is supposed to fail until a later milestone, it stays failing and its name says so.
4. **Identity never comes from the browser.** A creator's identity comes only from a verified login session, never from a header, query parameter, or body field the client sends.
5. **Never claim done without proof.** "Done" means you ran it and showed the output. A report is not evidence; command output is.
6. **If something can't be built here, say so and stop.** Don't simulate it.

## Hard constraints

- **Do not change** `.env`, `DATABASE_URL`, the `custody_app` role password, or how the app connects to the live database. Adding new variables is fine.
- **Never commit `.env`.** Confirm it's in `.gitignore` and not tracked (`git ls-files .env` returns nothing). If it was ever committed, tell me; don't rewrite git history on your own.
- **Never run tests against the live Supabase database.** Its event log is permanent by design: test events committed there can never be removed by the app. Tests use a local throwaway Postgres through `TEST_DATABASE_URL`. The test setup must refuse to run if the test database URL contains `supabase.co` or matches `DATABASE_URL`.
- **Shell environment wins over `.env`.** Use `dotenv.config()` without `override: true`, so a database URL passed in from the shell is respected.
- **Work on a branch.** One branch per milestone, small commits with clear messages. Don't push or merge without asking me.

## Local test database

Use the `embedded-postgres` npm package as a dev dependency so tests get a real PostgreSQL without Docker. (Docker is fine instead if it's already installed.) Add an `npm run test:db` script that starts it, and make `npm test` run the full suite against it. Every test that opens a transaction rolls back and releases the connection in a `finally` block.

## Current architecture (keep it)

- React + Vite frontend. Express server in TypeScript (`server.ts`, `server/`). Shared hashing code in `shared/crypto.ts`.
- PostgreSQL. Migrations in `server/migrations/`. The app connects as the restricted role `custody_app` (SELECT and INSERT only on `event`; no UPDATE, DELETE, TRUNCATE, or ownership). The `postgres` admin owns every table and runs migrations.
- `event` table: append-only, enforced by a row trigger (UPDATE, DELETE), a statement trigger (TRUNCATE), and grants. Each event's hash covers every field except `hash` and `seed_signature_id`, including `project_id`, `actor_type`, `actor_id`, `subject_type`, `subject_id`, `payload`, `prev_hash`, `seq`, and the exact timestamp string stored in `hashed_timestamp`. Each project has its own chain, starting from 64 zeros.
- Only server code creates events, and only from real actions. The browser never computes or stores event hashes.

## Milestone 1 — finish it

Milestone 1 is mostly done. First audit the repo against this list and report what's present, with file and line evidence, **before changing anything**. Then fix whatever is missing.

1. `GET /api/v1/projects` must not filter by any `x-creator-id` header or `creator_id` query parameter. Remove both.
2. The tenant isolation test sends no creator header, is named `... (fails until Milestone 2)`, and **fails**.
3. Versioned migrations: a `schema_migrations` table records applied migrations; the runner applies only new ones, each in a transaction. `002_hashed_timestamp_constraint.sql` drops any default on `hashed_timestamp` and adds the named constraint `chk_event_hashed_timestamp CHECK (hashed_timestamp <> '')`, replacing any auto-named version. A test builds the database from `001` alone, runs the runner, and confirms the default is gone and the named constraint exists.
4. The test that inserts an empty or missing `hashed_timestamp` expects the correct constraint name and passes.
5. Remove every remaining invented value in the frontend, including:
   - The backup screen's fallback `s3://darnell-custody-vault...` and the "Hardware Versioning Active" check.
   - The prefilled darnell values (GitHub org, bucket, user ID) on the setup screen.
   - "Simulate Developer Sign" on the door screen (should read "Not connected yet").
   - Placeholder "simulated" git bundles in the export. Until real bundles exist, export contains the event log, project data, and a hash manifest only, and the screen says bundles aren't connected yet.
   - Search the whole `src/` tree for: `simulat`, `Math.random`, `darnell`, `Aether`, `Alex Rivers`, hardcoded hashes, `s3://`, and fixed byte sizes. Fix every hit or justify it.
6. `dotenv.config()` without `override: true` in every file.
7. The local test database is set up as described above, with the `supabase.co` safety check.

**Done when:** `npm test` against the local database passes everything except the tenant test, which fails on purpose, and you show the full output.

## Milestone 2 — login with required multifactor authentication

1. Use Supabase Auth. Tell me exactly which keys to add (the anon key for the browser, the service role key for the server only) and where to find them in the Supabase dashboard. The service role key must never appear in the browser bundle; grep the built JS to prove it.
2. Creators sign up or sign in, then must enroll and verify an authenticator-app code (TOTP) before reaching any project screen.
3. The server verifies the session token on every `/api/v1` request except `/health`. No valid token returns 401. A session below MFA level `aal2` returns 403.
4. Link each Supabase user to a `creator` row through `creator.identity_id`, created on first verified login. Remove the default-creator auto-provisioning in `POST /projects`.
5. Scope every query by the logged-in creator. A request for another creator's project returns 404, so it can't confirm the project exists.
6. The tenant isolation test now passes for real: two real users, both with TOTP enrolled and verified (generate codes with `otplib`), each signed in, proving A cannot list or read B's project or events. Remove "(fails until Milestone 2)" from its name. Add tests for 401 (no token) and 403 (aal1 session).
7. Every event records the real creator ID as `actor_id`.

For tests, use a Supabase test project or the Supabase CLI's local stack, never the live project's auth users. If neither is available, tell me what you need rather than mocking the auth server.

## Milestone 3 — Code home

**Goal:** a creator connects GitHub once, then claims a project, and the platform creates locked private repositories in the creator's own organization. The creator never visits GitHub after the connection step.

a. **GitHub App registration.** Write click-by-click steps for me to register the GitHub App under my account: name, permissions (repository Administration, Contents, Pull requests: read and write; Metadata: read; organization Administration: read and write), webhook events (installation, push, pull_request, repository, member, organization), and a webhook secret. The app's private key and webhook secret go in .env as GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY and GITHUB_WEBHOOK_SECRET, server side only. Grep the browser bundle to prove they're absent.

b. **Connection flow.** "Connect your code home" explains in plain words that the code will live in a GitHub organization the creator owns, then guides them through creating a free organization (GitHub doesn't allow creating one through the API) and installing the app. The installation is linked to the logged-in creator only through a verified installation callback or webhook, never a value the browser sends. Store the installation ID, never tokens.

c. **Lock the organization.** On install: base member permission none, members can't create repositories, forking of private repos off. After each change, read the setting back from GitHub and record what GitHub reports in the event, not what we asked for.

d. **Claim it.** Creates each private repository through the API (with a separate core repository if the creator chooses), turns off forking, and applies the branch ruleset (no deletion, no force-push, updates only through the app). Read every setting back and record the real values. Check the current GitHub docs on which of these features a free organization supports for private repositories. If a feature needs a paid plan, the dashboard shows that honestly ("Branch rules: needs GitHub Team, not active") rather than pretending, and the event records it as not applied.

e. **Existing code.** The creator can claim with an empty repo or upload a zip of existing code, pushed as the initial commit using a short-lived installation token.

f. **Webhooks.** Verify every webhook's signature against GITHUB_WEBHOOK_SECRET and reject failures. Handle installation removal: if the creator uninstalls the app, the dashboard shows the connection as broken and records it.

g. **Tokens.** Request installation tokens per operation, narrowed to the repositories involved. Never store or log them.

h. **Tests.** Unit and integration tests for the logic, plus a real end-to-end run against a dedicated test organization I'll create on GitHub, never my real one. Tell me exactly what to set up. Don't mock GitHub in the end-to-end run. Signature verification is tested with real HMAC signatures.

**Done when:** from the dashboard, a creator connects GitHub and claims a project, real locked repositories appear in the test organization, every setting in the event log matches what GitHub reports, and the independent review passes.

## Later milestones (detailed specs come when we get there)

4. **Git gateway**: a smart-HTTP git server between workspaces and GitHub. It checks on every request that the door is open, allows pushes only to `door/<door-id>/*`, scans pushes for secrets with real rules, forwards to GitHub with short-lived tokens, and logs fetch and push events. Closing a door takes effect within 5 seconds.
5. **Doors**: invites, developer accounts, embedded agreement signing, open and close workflows that roll back cleanly on failure, expiration, accepting work.
6. **Mirror and export**: real `git bundle` snapshots to creator-owned storage, and full export with a hash manifest that can be restored with `git clone`.
7. **Workspaces and polish**: browser workspaces with network restrictions, plain-language copy everywhere, closing report, full acceptance run.

## How to report at the end of every milestone

1. **What now works for real**, each with the command or test that proves it.
2. **How I can check it myself**, in plain steps.
3. **What is still not connected.**
4. The full test output.

Then run an **independent review** before calling the milestone done: start a fresh subagent that hasn't seen your work, give it this file and the milestone's requirements, and have it try to break your claims by running the code. That means adversarial checks, not just the test suite. Examples: send requests as the wrong user, try to modify or delete events as `custody_app`, search for leftover fakes. Fix whatever it finds before reporting.

## Deferred to the end of the project (don't do these now)

- Move the `custody_app` password into a secret instead of code.
- Rotate the Supabase database password.
- Point any remaining tests away from the live database.

When the platform is complete to spec, remind me of this list.

## Communication

I'm not a developer. Explain what you did and found in plain language. Put technical detail (file names, commands) in code blocks or lists, not in the middle of explanations.
