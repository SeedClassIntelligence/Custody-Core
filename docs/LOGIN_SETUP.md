# Login setup (Supabase Auth)

Creators sign in with an email and password, and must also enter a 6-digit code from an authenticator app
before they can see any project. The server enforces this on every request, not just the browser.

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

## Turn on authenticator-app (TOTP) multifactor in the hosted project

Dashboard > **Authentication** > **Sign In / Providers** (or **Multi-Factor**): make sure **TOTP** is enabled
for both enrolling and verifying. Hosted projects usually have it on already; the local test stack has it set in
`supabase/config.toml`.

**Turn Confirm email ON** (Authentication > Sign In / Providers > Email > *Confirm email*). This is required, not
optional. With it on, a new account must click the link in an email before it can sign in, so nobody can register
with someone else's address, and the person who owns the address is the one who sets up the authenticator. With it
off, anyone can register an address they do not own, set up their own authenticator, and be "that person" in
Custody Core. The server also refuses any account whose email is not confirmed (403), as a second line of defence.
The local test stack has confirmation off only so tests can sign up without an email server.

Sign-up is open: anyone who can reach the app can create an account (and, once they pass the code step, a creator
record). If you want invitation-only, turn off **Allow new users to sign up** and create accounts yourself.

## What the multifactor step protects, and what it does not

It does protect: nobody gets in with only a password. The API returns 403 until a code has been verified; a
password-only session cannot enroll a second authenticator or remove the first (the login service requires the
code for both).

It does not protect, and you should know:

- **Whoever first holds the password for an account that has not finished setup becomes its owner.** The setup
  screen lets that person enroll an authenticator. Confirmed email (above) is what keeps this to the real owner.
- **Wrong codes are not limited by this app.** In testing, 300 wrong codes in a row did not stop a correct one
  afterwards on the local stack. A 6-digit code is 1 in a million per guess, so the practical defence is the
  login service's own rate limits: check **Authentication > Rate Limits** in your project and keep them
  tight. The app cannot add its own limit because the browser talks to the login service directly.
- **A valid code can be used twice** within its 30-second window.
- **After someone removes their authenticator, access tokens they already hold keep working until they expire**
  (an hour by default). Signing out ends a session immediately; unenrolling does not. If that matters to you,
  lower **JWT expiry** (Authentication > Sessions or JWT settings), for example to 900 seconds.
- **The server trusts the login service.** If the service is unreachable the API answers 503 and lets nobody in;
  it never guesses. Anyone who holds your project's JWT secret could mint tokens, so keep that secret out of
  every file and chat, as with the database password.

## How the server decides

Every `/api/v1` route except `/health` requires `Authorization: Bearer <access token>`:

- no token, a malformed token, or one the auth server rejects (forged, expired, signed out): **401**
- a valid token for a session that has only used the password (assurance level `aal1`): **403**
- a valid token for a session that also verified an authenticator code (`aal2`): allowed

The first time a person gets in with `aal2`, a `creator` row is created and linked to their Supabase user
through `creator.identity_id`. Every project, event and query is then scoped to that creator. Asking for
another creator's project returns 404, the same as asking for one that does not exist.
