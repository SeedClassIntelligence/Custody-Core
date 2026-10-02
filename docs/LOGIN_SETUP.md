# Login setup (Supabase Auth)

Creators sign in with an email and password (handled by Supabase Auth), and must also enter a 6-digit code from
an authenticator app before they can see any project. **The code step is run by Custody Core's own server, not by
Supabase**, so that wrong codes can be limited (see below). The server enforces both steps on every request.

## What the app needs, and where to find it

The app needs **two values** from your Supabase project. Both are in the Supabase dashboard under
**Project Settings > API** (older dashboards: **Settings > API Keys**).

| Value | Where it is | Used by | Secret? |
|---|---|---|---|
| **Project URL** (`https://<ref>.supabase.co`) | Project Settings > API > *Project URL* | browser and server | No |
| **Anon / public key** | Project Settings > API > *Project API keys* > `anon` `public` (newer dashboards: the *publishable* key, `sb_publishable_...`) | browser and server | No: it is designed to be public |

Set them as environment variables for both the server and the build of the browser app:

```
SUPABASE_URL="https://<ref>.supabase.co"
SUPABASE_ANON_KEY="<anon / public key>"
VITE_SUPABASE_URL="https://<ref>.supabase.co"      # already present in your .env
VITE_SUPABASE_ANON_KEY="<anon / public key>"
```

`VITE_` values are copied into the browser bundle when you run `npm run build` (or start the dev server), so
rebuild after changing them.

### The service-role key is not used

Do **not** add the `service_role` key (or the newer `secret` key) to this app. The server checks a session by
asking Supabase Auth to validate the token, which needs only the public key. A secret that is never added
cannot leak. `tests/bundle.test.ts` builds the real browser bundle and fails if any service-role value, its
variable name, or a database connection string appears in it.

## The server key for the code step: `MFA_ENCRYPTION_KEY`

The server keeps each person's authenticator key in the database, encrypted (AES-256-GCM) with a key only the
server holds. Generate it once and add it to the **server's** environment (your `.env`, or your host's secret
settings):

```
openssl rand -base64 32
MFA_ENCRYPTION_KEY="<the output>"
```

- Never give it a `VITE_` prefix: it must not reach the browser. `tests/bundle.test.ts` builds the real browser
  bundle with this key set and fails if its value or its name appears.
- Without it, the code step answers 503 and nobody gets past the password step. It never skips the step.
- If it is lost or changed, stored authenticator keys can no longer be read and everyone must set up their
  authenticator again. Keep a copy wherever you keep the database password.

Supabase's own TOTP multifactor is **not used** by this app and does not need to be turned on. Even if a session
has Supabase's `aal2` level, the API still requires the code step on this server.

**Turn Confirm email ON** (Authentication > Sign In / Providers > Email > *Confirm email*). This is required, not
optional. With it on, a new account must click the link in an email before it can sign in, so nobody can register
with someone else's address, and the person who owns the address is the one who sets up the authenticator. With it
off, anyone can register an address they do not own, set up their own authenticator, and be "that person" in
Custody Core. The server also refuses any account whose email is not confirmed (403), as a second line of defence.
The local test stack has confirmation off only so tests can sign up without an email server.

Sign-up is open: anyone who can reach the app can create an account (and, once they pass the code step, a creator
record). If you want invitation-only, turn off **Allow new users to sign up** and create accounts yourself.

## Wrong-code limit

- After **5 wrong codes within 15 minutes**, the authenticator is **locked for 15 minutes**. While locked, every
  code is refused without being checked, even the right one, so guessing during a lock reveals nothing.
- Every attempt (accepted, wrong, reused, refused while locked) is a row in `mfa_attempt` in the database, not in
  server memory. The lock is a timestamp on the authenticator (`mfa_factor.locked_until`). Both survive a server
  restart and apply across every server instance.
- Attempts are checked one at a time per authenticator (a database row lock), so sending many codes at once
  cannot slip past the count: of 20 simultaneous wrong codes, exactly 5 are checked and 15 are refused.
- Wrong codes from different sessions of the same person add up to the same lock.
- A code that was already accepted cannot be used again.
- Each lockout is written to the account's tamper-evident record (`account_event`, action
  `account.second_factor_locked`), which the creator can read at `GET /api/v1/account/events`.
- Why the check moved here: Supabase's own hook for limiting wrong codes ("MFA Verification Attempt") is only
  available on the Team and Enterprise plans, and Supabase's code-check endpoint is public, so a limit in front of
  it could be bypassed by calling Supabase directly.

## What the code step protects, and what it does not

It does protect: nobody gets in with only a password. The API returns 403 until a code has been checked by this
server for that session; once an authenticator is set up, a password-only session cannot set up another one.

It does not protect, and you should know:

- **Whoever first holds the password for an account that has not finished setup becomes its owner.** The setup
  screen lets that person set up an authenticator. Confirmed email (above) is what keeps this to the real owner.
- **Someone who knows the password can lock the real owner out for 15 minutes** by entering wrong codes. That is the
  price of the limit; it cannot get them in.
- **Removing an authenticator is not available yet.** Losing the phone means asking the operator to reset it.
- **The server trusts the login service** for the password step. If it is unreachable the API answers 503 and
  lets nobody in; it never guesses. Anyone who holds your project's JWT secret could mint tokens, so keep that
  secret out of every file and chat, as with the database password.

## Accounts made before this change

Authenticators set up with Supabase's own multifactor are not used any more. Each person sets up their
authenticator again the next time they sign in (the app shows the setup screen automatically).

## How the server decides

Every `/api/v1` route except `/health` requires `Authorization: Bearer <access token>`:

- no token, a malformed token, or one the auth server rejects (forged, expired, signed out): **401**
- a valid token for a session that has not passed the code step on this server: **403** (whatever Supabase's
  own assurance level says)
- a valid token for a session that passed the code step on this server (`mfa_session`): allowed

The code-step endpoints themselves (`/api/v1/mfa/status`, `/enroll`, `/verify`) need only the password step.

The first time a person gets in, a `creator` row is created and linked to their Supabase user
through `creator.identity_id`. Every project, event and query is then scoped to that creator. Asking for
another creator's project returns 404, the same as asking for one that does not exist.
