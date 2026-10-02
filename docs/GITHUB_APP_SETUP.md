# Code home: registering the GitHub App

Custody Core creates and locks repositories in each creator's own GitHub organization through a **GitHub App**
that you register once, under your own GitHub account. These are the exact steps.

You need: the address where Custody Core runs (below called `APP_URL`, for example `https://custody.example.com`,
or `http://localhost:3000` for the end-to-end test on your computer).

> Register **two** apps: one for testing (with `http://localhost:3000` addresses, used with your test
> organization), and later one for the real deployment (with its real address). An app's addresses can be changed
> later, but keeping them separate means a test can never touch a real creator's organization.

## 1. Open the registration form

1. Sign in to GitHub.
2. Click your profile picture (top right) > **Settings**.
3. Scroll to the bottom of the left menu > **Developer settings**.
4. **GitHub Apps** > **New GitHub App**.

## 2. Fill in the form, top to bottom

| Field | What to enter |
|---|---|
| **GitHub App name** | `Custody Core` plus something unique, for example `Custody Core Test (yourname)`. GitHub requires the name to be unique across all of GitHub. |
| **Homepage URL** | `APP_URL` |
| **Identifying and authorizing users** > **Callback URL** | `APP_URL/api/v1/github/callback` |
| **Expire user authorization tokens** | leave **ticked** |
| **Request user authorization (OAuth) during installation** | leave **unticked** (Custody Core asks for it itself, right after installation) |
| **Enable Device Flow** | leave unticked |
| **Post installation** > **Setup URL** | `APP_URL/api/v1/github/setup` |
| **Redirect on update** | **tick** |
| **Webhook** > **Active** | **tick** |
| **Webhook URL** | `APP_URL/api/v1/github/webhook` (for a test on your computer, see "Webhooks on your computer" below) |
| **Webhook secret** | a long random value. Generate one with `openssl rand -hex 32` and keep it for step 4. |

### Permissions

Under **Repository permissions**, set:

| Permission | Access |
|---|---|
| **Administration** | Read and write |
| **Contents** | Read and write |
| **Pull requests** | Read and write |
| **Metadata** | Read-only (GitHub sets this automatically) |

Everything else under Repository permissions: **No access**.

Under **Organization permissions**, set:

| Permission | Access |
|---|---|
| **Administration** | Read and write |
| **Members** | Read-only |

Everything else: **No access**.

**Members: Read-only is an addition to the original permission list.** When a creator connects, Custody Core asks
GitHub "is the person who just installed this an owner of the organization?" GitHub answers that question for an
app only if the app may read the organization's members; without it GitHub refuses (and the dashboard then says
exactly that: the app is missing "Members: Read-only"). It only allows reading who belongs to the organization. The
same permission is what makes the Member and Organization events available below. (I could not confirm this from
GitHub's documentation in my environment; the end-to-end `--connect` run checks it against real GitHub.)

### Subscribe to events

Tick: **Member**, **Organization**, **Pull request**, **Push**, **Repository**.

- **Installation** events (install, uninstall, suspend) are always sent to an app; there is no box for them.
- If the **Member** and **Organization** boxes are greyed out, check that Organization permissions > **Members** is
  set to **Read-only** (above). Custody Core only reads these events.

### Where can this GitHub App be installed?

Choose **Any account**, for both apps. ("Only on this account" would allow installing it only on your personal
account, and Custody Core needs it on an organization.)

Click **Create GitHub App**.

## 3. Collect the values

On the app's **General** page you just landed on:

1. **App ID** (a number near the top) > this is `GITHUB_APP_ID`.
2. **Client ID** (starts with `Iv`) > `GITHUB_APP_CLIENT_ID`.
3. **Client secrets** > **Generate a new client secret** > copy it now (GitHub shows it once) > `GITHUB_APP_CLIENT_SECRET`.
4. The app's address name: the last part of `https://github.com/apps/<this-part>` (shown under "Public link") > `GITHUB_APP_SLUG`.
5. Scroll to **Private keys** > **Generate a private key**. Your browser downloads a `.pem` file > `GITHUB_APP_PRIVATE_KEY`.

## 4. Put them in `.env` (server only)

Add these lines to `.env` (never with a `VITE_` prefix: `VITE_` values are copied into the browser):

```
APP_URL="https://custody.example.com"
GITHUB_APP_ID="123456"
GITHUB_APP_SLUG="custody-core-test-yourname"
GITHUB_APP_CLIENT_ID="Iv23li..."
GITHUB_APP_CLIENT_SECRET="..."
GITHUB_WEBHOOK_SECRET="the value from openssl rand -hex 32"
GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n"
```

For the private key, open the `.pem` file in a text editor and paste its whole content between the quotes, writing
each line break as `\n` (as above), or paste it across several lines inside the quotes; both work.

Proof that none of these reach the browser: `tests/bundle.test.ts` builds the real browser bundle with these values
set and fails if any value, or any of these variable names, or a private key header, appears in it.

Restart the app after changing `.env`. Until all of them are set, the dashboard says the code home is "Not connected
yet" and the connection endpoints answer 503; nothing pretends to work.

## What a creator does (once)

On the dashboard, **Your code home** > **Connect your code home**:

1. **Create a free GitHub organization** (GitHub does not allow creating one through its API, so this one step is on
   GitHub's site). Skip if they already have one.
2. **Install Custody Core** on that organization: choose the organization, **All repositories**, **Install**, then
   **Authorize**. GitHub sends them straight back to the dashboard.

What happens then, on the server:

- GitHub's redirect after installing includes an installation number that anyone could type, so it is **not**
  trusted. Custody Core asks GitHub, with a one-time token for the person who just clicked Authorize, whether that
  person can see that installation and is an **owner** of the organization. Only then is the installation linked to
  the signed-in creator. The one-time token is then revoked. Only the installation's number is stored.
- The connection only completes in the same browser that started it (a one-time code in a cookie), so nobody can
  send a creator a link that attaches someone else's organization to their account.
- The organization is locked, then every setting is read back from GitHub and recorded as GitHub reports it:
  members see no repository by default, members cannot create repositories, private repositories cannot be forked.

## Claim it

When a creator claims a project with a connected code home, Custody Core creates a private repository (and a
separate `-core` repository if they choose) in their organization, optionally with an uploaded zip of existing code
as the first commit, turns off forking, and asks for branch rules (no deletion, no force-push, updates only through
the app). Every value is read back from GitHub and recorded in the project's event log.

**What a free organization supports for private repositories** (from GitHub's own documentation, checked 2026-10-02):

| Feature | Free organization, private repository |
|---|---|
| Private repositories | Yes |
| Turn off forking of private repositories (organization and repository) | Yes (new organizations already have it off) |
| Members' base permission "No permission" | Yes |
| Stop members from creating repositories | Yes |
| **Rulesets / protected branches** (no deletion, no force-push, restrict updates) | **No.** Only on public repositories, or with GitHub Pro, Team or Enterprise. |

So on a free organization the dashboard shows **"Branch rules: needs GitHub Team, not active"**, and the event records
GitHub's refusal and `applied: false`. Nothing claims the rules are on when GitHub says they are not.

## Before each change on GitHub

Before creating or re-locking repositories, Custody Core asks GitHub whether the app is still installed and not
suspended, follows a renamed organization, and checks that the GitHub user who connected the organization is still
an owner of it. If not, nothing is done and the dashboard says why.

If creating a repository fails partway, nothing is hidden: a repository GitHub created is recorded with what did
and did not happen, and **Check again with GitHub and finish locking** applies whatever is missing (or pushes the
uploaded code again into a repository GitHub reports as still empty). Each repository's description carries a
marker (`Custody Core <project id>`) so that, if GitHub's answer to "create" is lost, Custody Core can recognise
its own repository; a repository without that marker is never taken over.

## Tokens

- The app's own login is a short JWT signed with the private key, made for each call.
- Installation tokens are requested **per operation**, narrowed to the repositories involved and the permissions
  needed (for example, contents-write on the one new repository for the first push), and **revoked** as soon as the
  operation ends. They are never stored or logged. A test checks that no token GitHub issued appears in the database
  or in the server's log.

## Webhooks

Every webhook's `X-Hub-Signature-256` is checked against `GITHUB_WEBHOOK_SECRET` over the exact bytes received;
anything else is refused (401) and not used. Each delivery is handled once. A webhook is only taken as a hint:
anyone holding an old signed delivery could send it again, so before anything is changed or recorded Custody Core
asks GitHub what is true now (is the app still installed, suspended, what is the repository's name and
visibility), and records what GitHub reports. When the app is uninstalled (or
suspended) on GitHub, the dashboard shows **Connection broken** and the account record gets
`github.connection_broken`. Repositories deleted, renamed, made public and so on are recorded in their project's log.

## End-to-end test (real GitHub, test organization)

### Set up (once)

1. **Create a dedicated test organization** on GitHub: profile picture > **Your organizations** > **New
   organization** > **Free**. Name it something like `yourname-custody-test`. Never use your real organization: the
   test changes its settings and creates repositories in it. The script refuses to run if the organization holds
   any repository it did not create (names starting with `cc-e2e-`).
2. **Register the test app** (steps 1 to 4 above) with `APP_URL` = `http://localhost:3000`.
3. **Install the test app on the test organization**: on the app's page > **Install App** > next to your test
   organization > **Install** > **All repositories** > **Install**. (If GitHub then shows Custody Core's address and
   it cannot be reached, that is fine for this step.)
4. **Find the installation number**: GitHub > the test organization > **Settings** > **GitHub Apps** > **Configure**
   next to the app. The address ends in `/installations/<number>`.
5. Add to `.env`:
   ```
   GITHUB_E2E_ORG="yourname-custody-test"
   GITHUB_E2E_INSTALLATION_ID="<number>"
   GITHUB_REAL_ORG="your-real-org"        # optional: the script refuses to run against this one
   ```
6. Docker must be running (the test uses the local login stack and a throwaway database, never the live database).

### Run

```
npm run github-e2e                 # automatic part
npm run github-e2e -- --connect    # the connection step, with you in the browser
npm run github-e2e -- --cleanup    # delete the test repositories (cc-e2e-*) afterwards, if you want
```

- **Automatic part:** locks the test organization through the real API, claims a project with an uploaded zip and a
  core repository, then reads everything back from GitHub **independently** and compares it with the event log, one
  line per setting (`MATCH` / `MISMATCH`). It ends with `END-TO-END PASSED` only if every value matches. The created
  repositories stay in the test organization so you can look at them.
- **`--connect`:** starts the app at `http://localhost:3000`, creates a throwaway test login and prints its email,
  password and the current 6-digit code. You sign in, click **Connect your code home**, install and authorize on
  GitHub's real pages, claim a project, then uninstall the app on GitHub. The script checks each step against
  GitHub.
- `GITHUB_E2E_SELFTEST=1 npm run github-e2e` only checks the script itself against the local stand-in used by the
  tests; it prints clearly that it is not the end-to-end run.

### Webhooks on your computer

GitHub cannot send webhooks to `localhost`. For the uninstall check in `--connect` mode, give the test app a
forwarding address: open <https://smee.io>, click **Start a new channel**, put that address in the app's **Webhook
URL**, and run, in a second terminal:

```
npx smee-client --url https://smee.io/<your-channel> --target http://localhost:3000/api/v1/github/webhook
```
