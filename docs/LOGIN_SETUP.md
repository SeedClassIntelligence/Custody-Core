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

Also decide about **Confirm email** (Authentication > Sign In / Providers > Email). If it is on, a new account
must click the link in a confirmation email before it can sign in, and the app tells the person so.

## How the server decides

Every `/api/v1` route except `/health` requires `Authorization: Bearer <access token>`:

- no token, a malformed token, or one the auth server rejects (forged, expired, signed out): **401**
- a valid token for a session that has only used the password (assurance level `aal1`): **403**
- a valid token for a session that also verified an authenticator code (`aal2`): allowed

The first time a person gets in with `aal2`, a `creator` row is created and linked to their Supabase user
through `creator.identity_id`. Every project, event and query is then scoped to that creator. Asking for
another creator's project returns 404, the same as asking for one that does not exist.
