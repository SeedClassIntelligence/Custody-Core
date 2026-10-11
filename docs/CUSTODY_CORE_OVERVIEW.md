# Custody Core: what it is and what it does

A complete description of Custody Core as built on `main` (October 2026), written so someone who has never seen the
code can judge how it relates to SRT-1. Every capability below exists in code and is covered by tests unless it is
listed under "Not built".

---

## 1. The one-sentence version

Custody Core lets a code owner give an outside developer narrow, temporary, signed access to private code, enforced
on a server the developer does not control, with every action written to a tamper-evident record, and then take the
access away completely.

## 2. The problem it solves

When you hire someone to work on private code, the usual way is to add them to the GitHub organization. From then
on they hold a credential to the whole repository, can clone it anywhere, push anywhere their role allows, and keep
access until someone remembers to remove it. Nothing records what they did except git history, which they can
rewrite on their own branches.

Custody Core replaces that with a **door**: a scoped, time-limited permission that exists only through Custody Core.
The developer never gets a GitHub credential at all.

**Trust model.** Custody Core assumes the outside developer is *not* trusted. Everything it enforces runs on the
Custody Core server, never on the developer's machine. This is the essential difference from tools that run on the
worker's computer (an IDE, a local agent, SRT-1 Core): those can guide and observe a cooperative user, but the person
at the keyboard can switch them off. Custody Core's checks cannot be switched off by the developer.

## 3. The people

| Role | Who | What they do in Custody Core |
|---|---|---|
| Creator | The code owner | Connects their GitHub organization, claims projects, adds repositories, opens and closes doors, reads the record. |
| Developer | An outside person | Accepts an invitation, signs the agreement, gets a git credential, clones and pushes through the gateway. |
| Operator | Whoever runs the server | Sets up the GitHub App, the database, secrets and hosting. |

Creators and developers use the same login: email and password (Supabase Auth), a confirmed email address, and a
required authenticator-app code that **Custody Core's own server** checks, with a lockout after 5 wrong codes in 15
minutes (lasting 15 minutes), recorded in the database so it survives restarts and applies across server instances.

## 4. The lifecycle of a door

```
draft --invite--> awaiting_signature --developer signs--> open --close (creator) or end date (scheduler)--> closed
```

1. **Claim and connect.** The creator claims a project, connects their GitHub organization once (installs the
   Custody Core GitHub App), and adds repositories from the ones the App can see. Each added repository is
   **locked on GitHub** right away (section 7).
2. **Create.** The creator creates a door: developer's email, job description, rights type (contribute, license,
   transfer, maintain), end date, and per repository either read-only or read-and-push.
3. **Invite.** The agreement text is generated from the door and **fixed** (text and SHA-256 stored; the database
   refuses any later change). The creator gets an invitation link, shown once (only its hash is stored), valid 7
   days or until the door's end date. It works only for an account with the invited email address.
4. **Sign.** The developer signs up (with the authenticator step), reads the agreement, types their name, gives
   consent, and signs with an ECDSA P-256 key created in their own browser. The private key is non-exportable and
   never leaves their device. The server checks that the signed statement names exactly this agreement's SHA-256,
   this door, this account and email, the consent text, and a time within 10 minutes; then verifies the signature.
   Only then does the door open. The database refuses to open a door without a signed agreement.
5. **Work.** The developer gets their own git credential (shown once to them; the creator never sees it). They
   clone and push through the gateway (section 6).
6. **Close.** The creator presses Close, or the end date passes. The credential is revoked (the very next git
   request is refused), any unused invitation is withdrawn, the gateway's copies of the code are deleted, a backup
   snapshot is taken, and it is all recorded. A closed door can never be reopened (the database enforces it).

## 5. The tamper-evident record

Every project has an append-only event chain in PostgreSQL. Each event's hash covers its fields and the previous
event's hash. The database itself assigns the sequence number, timestamp and hash (function `append_event()`);
the application's database account cannot insert, update or delete events directly, and triggers reject any update,
delete or truncate. Anyone can recompute the chain (`docs/EVENT_HASH_FORMAT.md`), and the app has a "Check this
record" button that does.

Events recorded per project: `project.claimed`, `repository.added`, `repository.locked`, `repository.lock_verified`,
`repository.lock_missing`, `repository.lock_failed`, `door.created`, `door.invited`, `door.invite_accepted`,
`agreement.signed`, `door.opened`, `credential.issued`, `credential.revoked`, `git.fetch`, `git.push`,
`git.push_rejected`, `door.closed`, `mirror.written`, `mirror.delayed`, `mirror.failed`.

Per person (account record, same chaining): `account.second_factor_enrolled`, `account.second_factor_locked`,
`account.github_connected`, `developer.key_registered`.

Every event has a `seed_signature_id` field, empty today, reserved for Seed Signature.

## 6. The git gateway

The developer's git remote is Custody Core, never GitHub:

```
https://<app>/git/<door id>/<owner>/<repo>.git     (user name: anything; password: the door credential)
```

On **every** request the gateway checks in the database: the credential exists and is not revoked, it belongs to
this door, the door is open and before its end date, the repository is part of the door, and pushes need write
access on it. So closing a door takes effect on the next request.

- **Per-door copies.** Each door gets its own copy of each repository on the gateway, refreshed from GitHub on every
  fetch and push. A copy never contains other doors' branches, so a developer can never download another
  developer's work.
- **Push policy.** Pushes may only create, update or delete branches under `door/<door id>/`. No `main`, no other
  branch, no tags.
- **Secret scan.** Every new commit in a push, including ones later "fixed", is scanned with gitleaks (pinned version
  8.28.0, checksum-verified). One finding refuses the whole push. The developer is told the file, line and rule,
  never the secret, and neither is the record. If the scanner is missing, every push is refused.
- **Forwarding.** An accepted push is forwarded to GitHub atomically, using a short-lived GitHub App token limited
  to that one repository, and only if GitHub still has what the gateway last saw. If GitHub refuses, the
  developer's push fails too.
- **Recorded.** One `git.fetch` per clone or fetch; `git.push` with the exact refs and commits; `git.push_rejected`
  with the reason (wrong branch, secret found, scanner missing, GitHub refused).

Implementation: `git http-backend` (git's own server program) behind Express; a pre-receive hook does the branch
policy, scan and forwarding while the pushed objects are still in quarantine.

## 7. GitHub connection and repository lock

- **GitHub App.** One App, created once by the operator. A creator installs it on their organization from inside
  Custody Core. The server proves with GitHub (OAuth during install, then `/user/installations`) that the person
  who installed it really has access to that installation; an installation number alone proves nothing.
- **Lock.** Each repository added to a project gets a ruleset named "Custody Core lock" on its default branch: it
  cannot be deleted or force-pushed by anyone, organization owners included, except the Custody Core App. Forking
  is turned off where GitHub has the setting. A repository counts as locked only after the ruleset has been read
  back from GitHub and matches exactly.
- **Re-checks.** Every 6 hours (and on demand) the lock is read back. If someone removed or weakened it on GitHub,
  that is recorded and the lock is put back. On GitHub's free plan, private repositories cannot have rulesets: the
  repository is shown "not locked" with that reason, and the message explains that developers still cannot reach the
  code on GitHub (they have no GitHub access), while the lock is an extra layer against direct changes by people who
  do have GitHub access.

## 8. The scheduler

Runs inside the server process; safe with several servers (`SELECT ... FOR UPDATE SKIP LOCKED`).

- **End dates.** Every 30 seconds, and at startup **before the server serves anything**, every door past its end
  date is closed (reason `expired`), including doors whose end date passed while the server was down. The gateway
  already refuses an expired door to the second, so the interval never extends access.
- **Backup snapshots.** When an open door closes, a snapshot is due: for each repository, the default branch and the
  door's branches are fetched from GitHub into a git bundle, verified (`git bundle verify`), stored, and recorded
  with its SHA-256 and exact refs. It restores with plain `git clone`. Retries with growing delays up to 8 attempts
  if GitHub or storage is unavailable; closing never waits for it. The creator downloads bundles from the door page.
- **Lock checks** as in section 7.

## 9. Security properties, summarized

- The developer never holds a GitHub credential; the GitHub App's private key never leaves the server.
- All enforcement is server-side: credential, door state, end date, repository scope, branch prefix, secret scan.
- Revocation is effective on the next request; closing is final.
- Secrets in pushes never reach GitHub, the developer's screen output, or the record.
- Agreements are fixed before signing and signatures are verifiable without trusting the server
  (`docs/AGREEMENT_SIGNATURES.md` shows the OpenSSL commands).
- The record is append-only and chained in the database itself.
- Supabase's built-in REST API is closed to every Custody Core table and function (row-level security, revoked
  grants); the app connects as a restricted database account (`custody_app`) whose password is not in any file.
- Authenticator keys are encrypted (AES-256-GCM) with a server-only key.

## 10. What it is made of

- **Server:** Node.js 22, TypeScript, Express, `pg`. About 20 server modules (`server/`), the gateway
  (`server/gateway/`), 9 SQL migrations.
- **Database:** PostgreSQL (Supabase-hosted in production).
- **Login:** Supabase Auth for email and password; Custody Core's own server for the authenticator code.
- **Browser app:** React + Vite + Tailwind (project home, doors, developer view, event chain, export).
- **Tools on the server:** git, gitleaks.
- **Deployment:** Dockerfile; one-click Render Blueprint (`render.yaml`, `docs/deploy/RENDER.md`).

API surface (all under `/api/v1`, all behind the full login except `/health` and the code-step endpoints):

| Area | Endpoints |
|---|---|
| Health | `GET /health` |
| Code step | `GET /mfa/status`, `POST /mfa/enroll`, `POST /mfa/verify` |
| Account | `GET /me`, `GET /account/events` |
| Projects | `GET /projects`, `POST /projects`, `GET /projects/:id/events`, `GET /projects/:id/events/verify` |
| GitHub | `GET /github`, `POST /github/install`, `GET /github/repositories`, browser callback `GET /github/callback` |
| Repositories | `POST /projects/:id/repositories`, `POST /projects/:id/repositories/:repositoryId/lock` |
| Doors (creator) | `GET/POST /projects/:id/doors`, `POST .../doors/:doorId/invite`, `GET .../doors/:doorId/agreement`, `POST .../doors/:doorId/close` |
| Developer | `GET /developer/invites/:token`, `POST /developer/invites/:token/accept`, `POST /developer/keys`, `GET /developer/doors`, `POST /developer/doors/:doorId/sign`, `POST /developer/doors/:doorId/credential` |
| Snapshots | `GET /projects/:id/snapshots`, `GET /projects/:id/snapshots/:snapshotId/bundle` |
| Gateway | `/git/<door id>/<owner>/<repo>.git/...` (smart HTTP) |

## 11. How it is tested

- About 160 automated tests against a real PostgreSQL, real git, real gitleaks and real WebCrypto signatures. GitHub
  is replaced by a local stand-in that verifies the App's signed tokens, serves real git repositories only to tokens
  it issued, and keeps rulesets the way GitHub documents.
- Includes a test that starts a real server process after a door's end date passed and checks it is closed before
  the server listens, then snapshotted, and that the bundle restores with `git clone`.
- The login tests need the local Supabase Auth stack (Docker).
- Not yet verified: the screens clicked through by a signed-in person, the Docker image build, and real github.com
  (a manual live check is in `docs/GITHUB_APP_SETUP.md`).

## 12. Not built

- Limiting a door to specific folders or files (work cells). Today a door's scope is whole repositories: read the
  whole repository, push only to the door's branches.
- Hiding parts of a repository from a developer (would need a filtered copy or a hosted workspace).
- Hosted workspaces (an editor running on the operator's server).
- Hours worked (only git activity is recorded: when they fetched and pushed).
- Sending emails (the creator sends the invitation link).
- Storage the creator owns for snapshots (today a directory on the server).
- Seed Signature (the field is reserved on every event).

## 13. Relationship to SRT-1 (the open question)

Concepts that overlap:

| Custody Core | SRT-1 |
|---|---|
| Door (scoped, time-limited permission for one job) | WorkCell / execution lease |
| Invitation to a developer | Seat |
| Door's repositories and push rules | WorkCell owned / related / restricted paths |
| Event record | WorkCell activity events, audit event contract |
| Developer view, door page | PWA dashboard, review surfaces |

What Custody Core has that SRT-1 Core does not, as described in SRT-1 Core's own README and code:

- enforcement on a server the developer does not control (SRT-1 Core is local-first and runs on its user's machine;
  its IDE launch commands bind to `127.0.0.1`);
- a git gateway, so the developer never holds a GitHub credential;
- the GitHub App connection, repository locks and their re-checks;
- server-checked signed agreements before access;
- a database-enforced, hash-chained record;
- server-side revocation, end-date closing and backup snapshots.

The decision on the table: add this enforcement to SRT-1 (as the hosted, team-facing layer behind seats) rather than
keep Custody Core as a separate product. The pieces that would move are sections 5 to 8. They are server components
with no dependency on Custody Core's browser app.
