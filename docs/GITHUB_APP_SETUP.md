# Setting up the GitHub App and the git gateway

Custody Core reaches a creator's code through **one GitHub App that you (the operator) create once**. Each
creator then installs it on their own organization from inside Custody Core. Developers never get a GitHub
credential: their git remote is Custody Core's gateway.

## 1. Create the App (once, on github.com)

GitHub > your profile or organization > **Settings** > **Developer settings** > **GitHub Apps** > **New GitHub App**.

| Field | Value |
|---|---|
| GitHub App name | anything, e.g. `Custody Core` (its URL name becomes `GITHUB_APP_SLUG`) |
| Homepage URL | your app's address, e.g. `https://custody.example.com` |
| Callback URL | `https://custody.example.com/github/callback` |
| Expire user authorization tokens | on (default) |
| **Request user authorization (OAuth) during installation** | **on**. Required: this is how Custody Core proves the person installing really has access to the installation. |
| Setup URL | leave empty (with the option above on, GitHub uses the Callback URL) |
| Webhook > Active | **off** (not used) |
| Repository permissions > **Contents** | **Read and write** |
| Repository permissions > **Metadata** | Read-only (always required) |
| Repository permissions > **Administration** | **Read and write** (to put the lock on each repository and turn off forking) |
| Every other permission | No access |
| Where can this GitHub App be installed? | **Any account** if creators have their own organizations; "Only on this account" for your own use |

Create it, then on its settings page:

1. Note the **App ID** and the **Client ID**.
2. **Generate a new client secret**, copy it.
3. **Generate a private key**: a `.pem` file downloads. Keep it like a password.

## 2. Give the server its settings

```
GITHUB_APP_ID="123456"
GITHUB_APP_SLUG="custody-core"            # from the App's public URL: github.com/apps/<slug>
GITHUB_APP_CLIENT_ID="Iv23li..."
GITHUB_APP_CLIENT_SECRET="..."
GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----\n"
APP_URL="https://custody.example.com"     # the git addresses given to developers start with this
```

`GITHUB_APP_PRIVATE_KEY` can be the file's contents (literal `\n` for line breaks is fine, for hosts that only
take one line) or a path to the file. All of these are server-only: never give them a `VITE_` prefix.

The server also needs **git** and the secret scanner **gitleaks**. The Dockerfile installs both. Without Docker:
`npm run tools:gitleaks` downloads a pinned gitleaks release (checked against its published SHA-256) into
`.tools/`. If gitleaks is missing, the gateway still serves clones and fetches but **refuses every push**:
it never lets code through unscanned. `/api/v1/health` shows `"secret_scanner": "installed"` or `"missing"`.

## 3. A creator connects their organization (in Custody Core)

1. Top bar > **Connect GitHub** (or Code Home > Connect your GitHub organization).
2. On GitHub: choose the organization and **only the repositories** Custody Core should manage, then install.
   GitHub asks the person to authorize the App: accept.
3. They land back in Custody Core: "GitHub is connected."

If an organization member without owner rights installs it, GitHub turns it into a request; an owner approves
it on GitHub, then the creator connects again.

## 4. Locking repositories

Each repository added to a project is locked on GitHub right away:

- a repository ruleset named **Custody Core lock** on the default branch: it cannot be **deleted** or
  **force-pushed** by anyone (organization owners included) except the Custody Core GitHub App;
- **forking turned off** where GitHub has the setting (private repositories of an organization).

It counts as locked only after Custody Core has read the ruleset back from GitHub and checked it. The project page
shows each repository as **locked** or **not locked** with the reason, and a **check** button that reads it back
again: if someone removed or weakened the ruleset on GitHub, that is recorded (`repository.lock_missing`) and the
lock is put back (`repository.locked`). Every attempt and check is in the project's record (`repository.locked`,
`repository.lock_verified`, `repository.lock_failed`).

Two things GitHub decides:
- **Plan.** GitHub only allows rulesets on **private** repositories on a paid plan (Pro, Team or Enterprise). On the
  free plan the repository stays "not locked" with that reason; upgrade, then press **lock**. What that does and does
  not change: developers given a door still cannot reach the code on GitHub, because they get no GitHub access at all,
  only a gateway credential, and the gateway only accepts their pushes to their own door branches. The GitHub lock is
  an extra layer against changes made directly on GitHub by people who do have GitHub access (organization members and
  outside collaborators); without it, they can delete or force-push the default branch there.
- **Organization owners** can still edit or delete rulesets on GitHub. The lock stops everyone else, and accidents;
  a removal by an owner is caught the next time the lock is checked, not prevented.

If you created the App before this permission was added: add **Administration: Read and write** in the App's
settings. GitHub then asks each organization that installed it to accept the new permission (organization
settings > GitHub Apps > Custody Core > review request). Until they do, locking says the permission is missing.

## 5. Doors

1. Project page > Code Home > **Add repositories from GitHub**: pick from the repositories the App can see.
2. **Open a Door**: developer's email, the job, rights, how many days, and per repository: read, or read and push.
   **Create and invite** gives a link, shown once. Send it to the developer.
3. The developer signs up with that email address (with an authenticator app, like creators), reads the agreement
   and signs it with a key from their own device. The door opens, and they get their own git credential: the creator
   never sees it. Details and how to check a signature: `docs/AGREEMENT_SIGNATURES.md`.
4. The developer:
   ```
   git clone https://custody.example.com/git/<door id>/<owner>/<repo>.git
   # user name: anything; password: the credential
   git push origin HEAD:door/<door id>/my-change
   ```
5. **Close the door** on its page: the very next git request with that credential is refused, any unused invitation
   link stops working, and the gateway's copies of the repositories are deleted.

What the gateway enforces on every request:
- the credential exists, is not revoked, and belongs to this door; the door is open and not past its end date;
- the repository is part of the door; pushes need write access on that repository;
- pushes may only create, update or delete branches under `door/<door id>/` (no tags, no `main`);
- every new commit is scanned with gitleaks; one finding refuses the whole push (the developer is told the file,
  line and rule, never the secret, and neither is the record);
- the push is forwarded to GitHub atomically, and only if GitHub still has what the gateway last saw;
- a developer never downloads another door's branches: each door has its own copy holding only GitHub's
  branches and tags plus that door's own branches.

Every clone or fetch (`git.fetch`), accepted push (`git.push`) and refused push (`git.push_rejected`, with the
reason) is an event in the project's tamper-evident record, next to `door.created`, `door.opened`,
`credential.revoked` and `door.closed`.

## Not built yet

- Checking locks on a schedule (today they are checked when added and whenever the creator presses check).
- Closing doors automatically at their end date (the gateway already refuses an expired door).
- Sandboxed developer workspaces with restricted network access.
- A backup snapshot when a door closes.

## How this is tested

`tests/git_gateway.test.ts` runs real `git clone` and `git push` through the real gateway, real database and real
gitleaks. GitHub is replaced by a local stand-in (`tests/support/githubStandIn.ts`) that checks the App's signed
JWT with the App's public key and serves real git repositories only to installation tokens it issued, for the
repositories each token covers. `tests/repository_lock.test.ts` checks the lock against the same stand-in, which keeps
rulesets and repository settings and refuses what GitHub documents it refuses (rulesets on private repositories
without a paid plan, requests beyond the installation's permissions). What that cannot prove is GitHub's own behaviour, so after setting up a real App:
connect a test organization, open a door on a scratch repository, clone, push to `door/<id>/test`, try a push to
`main` (refused), and close the door (the next `git fetch` is refused). For the lock: as an organization member
(not through Custody Core), `git push --force` to the default branch of a locked repository and try deleting it in
the GitHub web page; both must be refused. Then delete the "Custody Core lock" ruleset on GitHub, press **check** in
Custody Core, and see `repository.lock_missing` followed by `repository.locked`.
