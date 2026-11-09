# Phase 5 design note: controlled materialization, path enforcement, session credentials

**Status: decisions D1 to D9 accepted by the owner on the condition that the design is in alignment with the platform's purpose and the build plan (section 9 is that check). Building has started with 5a.** It changes the part of the git gateway that stops pushes, so it
needs the owner's decisions (section 9) before anything is built. Companion to `docs/integration/PHASE0_SPEC.md` (Phase 5 and
sections 5 and 6 there). A runnable prototype of the riskiest part is in `docs/integration/phase5-spike/`.

## 1. What this phase delivers, and what it does not

**After Phase 5, an approved automated session can actually work**, and only within what its request said:

- it gets **its own git credential** (shown once), valid only for its repository, only while the session is active, ending when the session ends;
- it can **clone a filtered view** of the repository: only the paths it may read, none of the paths it may not, and none of the history;
- it can **push to its own branches** (`session/<id>/...`), and the gateway checks every changed path against the session's write rules, scans for secrets,
  and **replays** the work onto the real history; nothing else can reach the creator's repository.

It does **not** deliver: evidence (Phase 6), attribution records (Phase 7, though this phase records the facts they need), promotion to `main` (Phase 8), webhooks,
a vault, any screen. Human doors are **unchanged**: their routes, tables, credentials and tests are not touched (CL-20).

## 2. What exists today (verified in the code)

- `server/gateway/router.ts`: routes `/git/<door id>/<owner>/<repo>.git`; one credential kind (`ccg_...`, hash in `gateway_credential`, keyed to a **door**); every request is
  checked against the database; pushes run through the mirror's `pre-receive` hook.
- `server/gateway/mirror.ts`: one bare **mirror per door and repository**, refreshed from GitHub, holding GitHub's branches and tags minus other doors' branches. Its own comment
  states the limit that drives this design: *"Git cannot reliably hide objects that are in a repository, so a developer can only ever download what is in their own door's mirror."*
- `server/gateway/pre-receive.mjs`: (1) refs must be under `door/<door id>/`; (2) gitleaks on every new commit; (3) atomic push to GitHub with a lease per ref.
- `server/github.ts`, `repositoryLock.ts`, `lockService.ts`: everything GitHub-specific (installation tokens, repository lock ruleset) is called directly by the gateway and the door
  routes; there is no provider seam.
- Phase 3 stored each session's `allowed_read_paths`, `allowed_write_paths`, `prohibited_paths`, `base_commit`, and `branch_name` (`session/<id>/work`), but **nothing enforces them**.
  Phase 3 deliberately issues no credential for that reason.

## 3. The central problem, and what the prototype proved

**Reading cannot be restricted over ordinary git.** If a session can clone the repository, it gets every file, every old version of every file, and every historical secret.
A request that says "read only `server/**`" would be a promise nothing keeps. So there are only three honest ways to treat `allowed_read_paths`:

| Option | How reads are handled | Verdict |
|---|---|---|
| **A. Write rules only** | The session clones the full repository; only pushes are checked. | `allowed_read_paths` would be advisory, shown to the approver as a limit it is not. **Rejected**: dishonest. (Could be made honest by refusing any session whose reads are narrower than the whole repository, which makes most useful requests impossible.) |
| **B. A filtered view** (recommended) | The gateway builds a separate repository containing **only** the allowed files, as **one synthetic commit with no history**. The session clones that. Its pushes are **replayed onto the real history** by the gateway. | The only option that enforces reads. More machinery; proven feasible below. |
| **C. A file API instead of git** | The session reads and writes files over HTTP. | Breaks "push through the gateway" (spec Phase 12) and every git-based tool. Rejected. |

**Prototype result** (`bash docs/integration/phase5-spike/run.sh`, plain git 2.43 and Python 3, a temporary directory, **24 of 24 checks pass**):

- The view is **deterministic**: building it twice gives the identical commit hash (fixed identity and dates). A lost cache can be rebuilt to the same commit.
- The view holds exactly the allowed files and **none** of the excluded content: not the prohibited migration, not a `.env` that exists only in old history. One commit, no ancestry.
- Work done in a clone of the view can be **replayed onto the real repository** by a `pre-receive` hook: new tree on the real parent, author kept, committer set to the gateway, file modes preserved,
  real history intact, upstream gains exactly the allowed changes.
- **Twelve hostile pushes were refused and upstream stayed unchanged**: a prohibited name (`.env`), a write outside the area, modifying and deleting a read-only file, a file under migrations,
  a case trick on a prohibited path, a symlink, `.gitmodules`, moving a read-only file into the area, a merge commit, a push to `main`, a push to another session's branch.

**What the prototype also found (design requirements, not footnotes):**

1. A hook runs with the *view* repository's object directory and quarantine variables set. Every command on the *real* repository must run with a **clean `GIT_*` environment** and explicit alternates;
   otherwise it silently reads the wrong repository. (This is how the first attempt failed.)
2. **A second push must not re-translate from the base.** The prototype replayed every commit since the view base on every push, with the committer date "now", so the second push produced different real
   commits and upstream refused it as a non-fast-forward. The design therefore (a) keeps a persistent **map from view commit to real commit** and translates only new commits from the mapped parent, and
   (b) makes translation **deterministic** (committer date taken from the pushed commit), so a retry after a crash produces identical commits and the map is always rebuildable.
3. Pushing to the provider from inside a hook needs the quarantine variables removed ("ref updates forbidden inside quarantine environment").

**Not proven by the prototype** (so the build starts with them): behavior with GitHub as the upstream (the prototype used a local bare repository; the existing door code already pushes to GitHub with leases and is
tested against the repository's GitHub stand-in); performance on a large repository; the path-matching dialect below (the prototype used `fnmatch`); git versions older than 2.43 (the Docker image's Debian git is
older: the build adds a check on the image's version).

## 4. Design

### 4.1 Repository provider interface (spec section 5)

A small seam, behavior-preserving, introduced **first** and merged on its own:

```ts
interface RepositoryProvider {
  readonly kind: 'github';                         // 'local' arrives with the vault (Phase 11)
  /** Where the gateway fetches from and pushes to, and how it authenticates. Nothing GitHub-specific leaks past this. */
  remote(repository: RepositoryRef): Promise<{ url: string; extraHeader?: string }>;
  /** Lock status and repair (the GitHub ruleset today); a provider without a lock says so. */
  lock: { ensure(...): Promise<LockResult>; verify(...): Promise<LockResult> };
}
```

`repository.provider` (default `'github'`) selects it. The door gateway, the lock service and the scheduler call the interface instead of `github.ts`. **Gate: the existing suite passes unchanged**
(`git_gateway`, `repository_lock`, `scheduler`, `developer_signing`). A provider double that points at a local bare repository is added for tests only, so the new gateway can be tested against real git with no GitHub stand-in.
A production local-filesystem provider (spec section 5) is deferred to the vault phase, because it needs its own safety rules (it must not become a path-traversal hole).

### 4.2 Path rules

One pure module (`server/pathRules.ts`), no git, tested to exhaustion before anything uses it.

**Dialect.** `*` matches any run of characters except `/`; a whole segment `**` matches zero or more whole segments, except that a **final** `**` needs at least one (`docs/**` is everything under `docs/`, not a file that happens to be called `docs`); `?` matches one character except `/`; everything else is literal. No character classes, no braces, no negation,
nothing clever. Patterns are validated at request time (Phase 3 already rejects `..`, absolute paths, backslashes, control characters).

**Anchoring.** Patterns are anchored at the repository root, with one exception: a **prohibited** pattern with no `/` (for example `.env*`) matches that name **at any depth**, as `.gitignore` does. Someone who writes `.env*` means every `.env`.

**Matching is strict where it grants and conservative where it denies.** Allow patterns match exactly (case-sensitive). Prohibited patterns match case-insensitively and after Unicode normalization (both NFC and NFD forms, case-folded), so
`server/MIGRATIONS/x` is refused when `server/migrations/**` is prohibited. (The prototype refuses this case.) Prohibited wins over allowed.

**Reads** = allowed read paths minus prohibited. **Writes** = allowed write paths minus prohibited, and writes outside the readable set are also refused (you cannot write what you cannot read).

**Always refused, whatever the lists say:** any path component `.git` (any case, and the Windows and macOS lookalikes git itself checks), `.gitmodules`, symlinks (mode 120000), submodules (mode 160000), paths that are not valid UTF-8 or contain control
characters or `\`. Symlinks and submodules are not copied into a view at all.

**Sensitive CI paths are refused unless named.** `.github/`, `.gitlab-ci.yml`, `.circleci/`, `.buildkite/`, `Jenkinsfile`, `azure-pipelines.yml` (list in code, extendable): a session that can edit a workflow file can run code with the creator's secrets on GitHub.
A broad pattern (`**`, `*`) never covers them; an allowed write pattern must **name** them (for example `.github/workflows/ci.yml`) to include them. This is the one default I recommend beyond the stated rules (decision D6).

### 4.3 Data model (migration `014`; attribution and webhooks in the spec move to `015`)

- `session_credential(id, work_session_id, token_hash, created_at, last_used_at, revoked_at)`: a **separate table** from `gateway_credential`, so the door path is not touched at all. Same guard rules (hash and session never change, a revocation is final).
  Token prefix **`ccs_`** (doors use `ccg_`), checked on both sides, so a token of one kind is never accepted as the other even if a URL is edited.
- `session_view(work_session_id, base_commit, default_branch_tip, view_commit, view_tree, file_count, total_bytes, excluded_count, built_at)`: what was provisioned, written once.
- `session_commit(work_session_id, view_sha, real_sha, parent_view_sha, author_declared, created_at)`: the view-to-real map. Immutable. It is a **cache of a pure function** (translation is deterministic), kept for queries
  and as the base for Phase 7's attribution records.
- `repository.provider TEXT NOT NULL DEFAULT 'github'`.
- The guard from migration 013 gains one transition: `provisioning` back to `approved` (a failed build must be retryable). Nothing else about the lifecycle changes.

### 4.4 Provisioning and the credential

`POST /api/v2/work-sessions/:id/credential`, scope **`repositories:push-session`** (D2: for every credential, read-only ones included), **only the requesting principal**, only for a session that is `approved` (first time) or `active` (a replacement).

1. `approved` becomes `provisioning`. Unapproved, expired, rejected or closed sessions get nothing.
2. **Fetch the real repository** into the gateway's full mirror (one per repository, `real/<repository id>.git`, mode 0700, never served to anyone).
3. **Verify `base_commit`**: it must exist and be an **ancestor of (or equal to) the default branch tip** (D9). A base on someone else's unreviewed branch is refused. (Phase 3 stored it unchecked; this is where it is checked.)
4. **Build the view**: list the base tree; keep regular files (modes 100644 and 100755) that the rules allow to be read; write one synthetic commit (fixed identity and dates); pack only those objects into `sessions/<id>/view.git`. Limits (D8): at most 20 000 files and 500 MiB; beyond that, refuse and say why.
5. Record `session_view` and the event **`work_session.provisioned`** (base commit, tip, view commit and tree, counts; **counts only** for excluded files, never their names).
6. Issue **one active credential** (a new one revokes the old, shown once, like doors), `provisioning` becomes `active`. Response: the git address, the credential, its expiry (the session's), the view's commit.

A failure at any step returns the session to `approved`, records nothing misleading, and leaves no credential. The credential's life **is** the session's: closing, rejecting, expiring, or a scheduler tick past `expires_at` revokes it and deletes `sessions/<id>/`.

### 4.5 The session gateway

A new route **`/git/sessions/<session id>/<owner>/<repo>.git`**, matched before and separately from the door route; the credential lookup is `session_credential` joined to `work_session`, requiring: credential not revoked, status `active`, `expires_at` in the future, the repository named is the session's, `ccs_` prefix. The door route and its lookup are unchanged.

**Fetch and clone** are served from `sessions/<id>/view.git` **only**; the real mirror is never reachable. Fetches are recorded (`git.fetch`, actor `session:<id>`).

**Push** (read-only sessions refuse all pushes), in a new hook `pre-receive-session.mjs` that works in this order, refusing the whole push at the first failure and writing the outcome to a result file for the server to record, exactly as doors do:

1. **Refs**: only `refs/heads/session/<id>/...`; no tags, no deletes, no other refs; fast-forward only (no history rewriting: to start over, use a new branch name).
2. **Shape**: linear history from the view base (no merges, no new roots); at most 200 commits, 5 000 changed paths per commit, 25 MiB per file, 100 MiB per push.
3. **Paths**: for every pushed commit, the changed paths against its parent **with rename detection off** (a rename is a delete plus an add, both checked); every path against 4.2; modes limited to regular files; the executable bit may change.
4. **Secrets**: gitleaks over the new commits, as for doors.
5. **Translate** (deterministic, clean `GIT_*` environment, alternates for the quarantine): for each new commit, the mapped real parent's tree plus the commit's changes becomes a real tree; the real commit keeps the message, **author is set by the gateway from the session's declared executor** (the pushed author is kept only as a trailer; D3),
   **committer is the gateway**, committer date is derived from the pushed commit, and two trailers are added: `Custody-Work-Session: <id>` and `Custody-Declared-Author: <name <email>>`.
6. **Push upstream** atomically to the same branch name with a lease on the previous real tip (the commit point). Only then does the hook exit 0 and the view branch advance.
7. The push output tells the executor each **view to real** pair; `GET /api/v2/work-sessions/:id/commits` lists them. Events `git.push` (with the pairs) or `git.push_rejected` (reason and findings, never the secret), actor `session:<id>`.

Crash safety falls out of determinism: if the upstream push succeeded and the process died before the view ref advanced, the executor retries, translation reproduces the **same** real commits, the push upstream is a no-op, and the map rows are rewritten identically.

### 4.6 What the real history looks like afterwards

The session's branch exists in the **creator's own repository** at `session/<id>/<name>`, on top of the real base commit, every commit committed by the gateway, carrying the trailers. Closing a session removes the gateway's copies and the credential, **not** the branch: the work is preserved where the creator can see it.
(A snapshot bundle of closed sessions, as doors have, is not in this phase; it belongs with the vault.) Promoting that branch to the default branch, and what happens when the default branch has moved since `base_commit`, is Phase 8's problem and is named there, not solved here.

## 5. Security properties of this phase

**Guaranteed** (and tested): a session reads nothing outside its allowed paths and sees no history; it writes only within its write paths; the only refs it can touch are its own branches; no symlinks, submodules, `.git` content or `.gitmodules`;
every push is scanned; commits in the creator's repository are committed by the gateway and cannot claim the creator as author; a credential works only while its session is active and for its one repository; closing is immediate (the next request is refused); door behavior is unchanged.

**Not guaranteed, stated plainly:**

- A session **can copy out anything it is allowed to read**. That is the point of allowing it. Read restrictions limit what it can see, not what it does with that.
- A **stolen credential is the session** until it ends. Mitigations: short lifetimes (the request's `expires_in_seconds`, at most 24 hours), revocation on close, shown once, stored as a hash only.
- **File names and sizes** inside the allowed set are visible; names, sizes and existence of excluded files are not (only a count is recorded).
- Allowed files may contain secrets that already exist in the repository; the scanner checks what is **pushed**, not what the session is allowed to read. Creators should keep secrets out of readable paths (they can prohibit them).
- Correctness or safety of the **content** a session writes is Phase 6's evidence question, not this phase's.

## 6. Testing plan (gate CL-11: `tests/materialization.test.ts`, and the unit tests below)

Real git throughout; a provider double over local bare repositories for most tests; the existing GitHub stand-in for one end-to-end pass; the database for credentials and events.

1. **Path engine** (pure, hundreds of cases): the dialect at every edge, anchoring, the any-depth rule for slash-less prohibited patterns, case and Unicode tricks, the sensitive-CI rule, always-refused names, and the property "prohibited beats allowed".
2. **View builder**: deterministic (same commit twice); exactly the allowed files; none of the excluded content, including blobs that exist only in old history; no history; symlinks and submodules omitted; limits enforced with clear errors; a rebuilt view after the cache is deleted is identical.
3. **Provisioning**: only the requester, only approved or active, never unapproved or expired; base commit missing, not an ancestor of the default branch, or on another branch: refused; a failure leaves the session `approved` and no credential; one active credential; a replacement revokes the old; every refusal writes nothing.
4. **Credentials**: shown once, only the hash stored; `ccs_` and `ccg_` are not interchangeable; revoked on close, reject, expiry and scheduler tick; wrong session, wrong repository, expired: refused; door credentials still work and cannot reach sessions, and the reverse.
5. **Fetch**: serves the view only; the real mirror and its objects are unreachable (including by asking for a known object id); no other session's branches.
6. **Push, accepted**: edits, additions, deletes and the executable bit inside the write area; several commits at once; a second push and a third; a retry after a simulated crash produces identical commits.
7. **Push, refused** (the prototype's twelve cases plus): force push, new root, tag, delete, over-limit commits and files, a secret (never echoed or recorded), renames across the boundary, Unicode and case variants, `.github/workflows` unless named, a read-only session pushing anything.
8. **Real history**: committer and trailers, declared author only in the trailer, the chain reaches the real base, upstream gains exactly the allowed changes and nothing else, the map and the events match.
9. **Regression (CL-20)**: the door tests pass unchanged after the provider refactor and after the session gateway lands.
10. The prototype is kept and run in CI as an independent cross-check of the plumbing.

## 7. How it will be built and merged

Three pull requests, each green on GitHub before the next starts:

- **5a. Provider interface. Built.** `server/repositoryProvider.ts` (the interface, `RepositoryRef`, the two error kinds, the registry) and `server/githubProvider.ts` (GitHub behind it). The gateway, the backup snapshots, the lock service, the scheduler and the door routes now ask the provider. Behavior-preserving: **no existing test file was changed** and all of them pass; 15 new tests cover the seam (what it returns and throws, that the returned remote really lets git in and a wrong one does not, read-only credentials, unreachable and unconfigured GitHub, the lock, and a check that those modules no longer import GitHub's functions). The GitHub *connection* flow (listing what the App can see, OAuth) deliberately stays in the GitHub modules: it is not repository access.
- **5b. Path engine and view builder. Built.** `server/pathRules.ts` (pure) and `server/viewBuilder.ts`, with `npm run bench:view`. No endpoint, no migration, nothing wired into the gateway yet.
  - `tests/path_rules.test.ts` (90 tests): every rule of the dialect and every refusal, Unicode and case tricks, `.git` in eleven spellings, the CI-file rule, hostile patterns, and a **property test that checks the matcher against a second, independently written one on 15 000 random pairs** plus invariants over random rule sets (write implies read, prohibited beats allowed, no `.git` component is ever writable).
  - `tests/view_builder.test.ts` (30 tests, real git repositories): exactly the allowed files; none of the excluded **objects** (including a `.env` that exists only in old history), checked by object id and by trying to fetch them from a clone; one commit and no history; deterministic (twice, after deletion, and independent of how the rules are written); symlinks, submodules and non-UTF-8 names omitted and counted but never named; limits at their exact edges; base-commit checks including a commit that exists only on a side branch.
  - **Benchmark** (`npm run bench:view`, this container): a 20 000-file repository, session allowed to read 7 111 of them: view built in 2.0 s cold, 0.6 s rebuilt, 1.1 MiB on disk; allowed to read **all** 20 000 (the file limit, the worst case): 0.8 s, identical commit on rebuild. The risk "large repositories make the build slow" is small at the design's limits.
  - **Decisions made while building, for review:** a final `**` needs at least one segment (above); a write needs the path to be *readable* too (no blind writes), as the design said; sensitive CI names match at any depth; the "view" branch is named `main` whatever the real default branch is called.
- **5c. Credentials, provisioning, the session gateway, events, cleanup.** Migration 014, the endpoint, the hook, the route, the scheduler cleanup, and the end-to-end tests.

## 8. Risks

| Risk | Handling |
|---|---|
| Translation is subtle and security-critical | Prototype first (done); path engine and view builder tested in isolation before they are wired; the hostile matrix is the primary test, not an afterthought |
| Large repositories make the build slow | Hard limits with clear refusals; benchmark in 5b; the build runs once per session and is cached (deterministic, rebuildable) |
| An older `git` in the Docker image behaves differently from 2.43 | The build checks and records the version; the hostile matrix runs against the image's git in CI |
| GitHub-specific behavior not covered by the local prototype | Same push code path and lease semantics as doors, which are already tested against the GitHub stand-in; one end-to-end test through the stand-in |
| A mistake exposes more than the request allowed | Failure refuses; the credential exists only after a successful build; a leak test asserts the view's object list, not just its file list |

## 8a. Things building 5b added to the list for 5c

1. **An added file must not overwrite a real one.** The view lacks symlinks, submodules and unreadable files, but the real tree has them. A session that "adds" a path that exists in the real parent tree as a symlink or submodule would silently replace it when its commit is replayed. Translation must refuse an **add** whose path exists in the real parent, a **modify or delete** whose path is not a regular file there, and any change whose real parent differs in mode from what the view showed.
2. **The request check must start using `patternProblem`.** Phase 3 refuses control characters but not invisible or separator ones (zero-width, bidirectional overrides, line separators); `PathRules` refuses them, so a request that Phase 3 accepts could fail at provisioning. A test records this one known difference; wiring `patternProblem` into the request check closes it.
3. **The path rules and the push check must be the same code**, so one decision serves the view and the push: `PathRules.explainWrite` is the single place a push path is judged.

## 9. Alignment with the platform's purpose and the build plan

Checked against the text of the plan (`PHASE0_SPEC.md`: gap rows 5 and 6, threat rows TM-03 and TM-04, section 8, the Phase 5 and Phase 12 steps) and the platform's stated purpose (`README.md`: creators "give outside developers access to their code without losing control of it";
`metadata.json`: "creator-owned code custody, git gateway access control, and tamper-evident append-only event logging").

| Plan or purpose | In this design | Result |
|---|---|---|
| Phase 5: provider interface, materialization, path enforcement in pre-receive, session credentials; gate CL-11 (temporary checkouts, base commit validation, path isolation) | 4.1 to 4.5; the test plan in section 6 is CL-11 | Aligned |
| TM-03: refs limited to `session/<id>/`, every changed path checked **before objects leave quarantine** | The hook checks refs and paths before anything is translated or pushed (4.5, steps 1 to 3) | Aligned |
| TM-04: author, committer (always the gateway) and sponsor separate; nobody can commit as the creator | Committer is always the gateway; author set from the declared executor (D3), stronger than the plan | Aligned, stronger |
| Phase 12: push through the gateway to `session/<id>/*` with a secret scan; later promote | Same route shape, same scanner; the translated real branch is exactly what promotion needs | Aligned |
| Creator control, nothing lost to outsiders; tamper-evident record | Work lands in the creator's own repository, committed by the gateway; every step is an event; the real history is never exposed to a session | Aligned |
| Platform-neutral universal service | Provider seam, no platform-specific logic, context stays opaque | Aligned |

**Three deliberate differences from the plan's wording, so none is a surprise:**

1. **Session credentials use the prefix `ccs_` and their own table**, where the plan said `ccg_` (the door prefix). Same prefix would let one kind of token be mistaken for the other at lookup; separate tables keep the door path untouched (CL-20).
2. **The local-filesystem provider is not in Phase 5.** The plan's gap table asks for an abstraction that supports GitHub, local filesystem and custody-managed storage; the Phase 5 step itself only names the interface. The interface supports them; the implementations other than GitHub arrive with the vault (Phase 11), because a filesystem provider needs its own path-safety rules. Tell me if you want it earlier.
3. **Sessions get a filtered view with no history** (D1). Not a conflict with the plan, but it is a consequence a reader of the plan would not guess.

**Two things the plan leaves open that this design surfaces** (neither blocks Phase 5):

- **Evidence (Phase 6) needs the real commit.** Sessions push through the view and receive the real commit ids, but the plan gives evidence issuers (separate principals holding `evidence:submit`) no way to read the real tree.
  Either issuers build from the creator's repository directly (outside Custody Core, as the Phase 12 example with an external builder implies) or a later phase gives them a read path. Decide this when Phase 6 is designed.
- **Promotion (Phase 8) when the default branch has moved** since `base_commit`: merge, rebase, or refuse? The plan does not say. Phase 5 leaves the session's branch exactly on its base so any of the three remains possible.

**Not in the plan, and not added:** path-level limits for **human doors**. The plan keeps doors as they are (section 6); they continue to give a developer the repository under `door/<id>/` as today.

## 10. Decisions (accepted, subject to section 9)

| # | Question | Recommendation |
|---|---|---|
| D1 | Enforce reads with a filtered view (option B)? | **Yes.** It is the only way "allowed read paths" can be true. Consequence: a session sees **no history** (one synthetic commit); `git log`, `blame` and `bisect` are not available to it. |
| D2 | Scope for a session credential | `repositories:push-session` for **every** credential, including read-only sessions (it already sits with the work-producing scopes). |
| D3 | Authorship | The gateway sets the **author from the session's declared executor**; the pushed author is kept only as a `Custody-Declared-Author` trailer. This implements the spec's rule that nobody can commit as the creator. Alternative: keep the pushed author (the prototype's behavior), recording it as self-declared. |
| D4 | Push rules | Fast-forward only, linear history, no merges, no tags, no deletes, no force. |
| D5 | Provider scope | Interface and the GitHub implementation now; the local-filesystem provider with the vault (Phase 11). |
| D6 | Sensitive CI paths (`.github/` and similar) refused unless a write pattern names them | **Yes.** Otherwise `**` lets a session rewrite the creator's CI. |
| D7 | Three pull requests (5a, 5b, 5c) | **Yes.** |
| D8 | Limits | View: 20 000 files and 500 MiB. Push: 200 commits, 5 000 paths per commit, 25 MiB per file, 100 MiB total. Configurable. |
| D9 | `base_commit` must be an ancestor of the default branch tip | **Yes.** |

Anything not listed here follows section 4 as written. If D1 is "no", this phase shrinks to write-path enforcement on full clones, and `allowed_read_paths` should then be removed from the request, because it would not be true.
