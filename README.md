# Custody Core

Lets non-technical creators give outside developers access to their code without losing control of it.
See `CLAUDE.md`-style project instructions kept alongside this repo for the rules the code follows
(nothing is faked; unbuilt features say "Not connected yet").

## Run locally

1. `npm install`
2. Copy `.env.example` to `.env` and fill in `DATABASE_URL` and `APP_DB_PASSWORD` (never commit `.env`).
3. `npm run dev`

Values already set in your shell take priority over `.env`.

## Tests

`npm test` starts a throwaway local PostgreSQL (the `embedded-postgres` package, no Docker needed), points the
app at it through `TEST_DATABASE_URL`, and runs the whole suite. The test setup refuses to run if that URL contains
`supabase.co` or matches `DATABASE_URL`, so tests can never touch the live database.

`npm run test:db` starts the same kind of database and leaves it running, printing a `TEST_DATABASE_URL` you can reuse.

`npm run browser-check` runs the real app in a headless browser (Playwright/Chromium) against the same kind of local
database: it loads every screen, claims a project, verifies its record, tampers with it, downloads an export and
verifies that too. Screenshots land in `docs/screenshots/milestone-1/`.


## Event log

Events are written only through the database function `append_event()`. The database assigns the sequence
number, timestamp and hash; the application's database account has no `INSERT` on the `event` table. The exact
hash format, so anyone can verify a chain, is in `docs/EVENT_HASH_FORMAT.md`.

## Login tests (Supabase Auth, local)

Login is tested against a real Supabase Auth server running locally in Docker (the Supabase CLI's local stack).
Nothing is mocked: users are created and signed in by the auth server, authenticator codes are generated with
`otplib`, and this app's own server checks them, including the wrong-code limit (`tests/second_factor.test.ts`). Tests never touch a hosted Supabase project or its users.

- `npm test` starts the stack by itself if Docker is running (the first start downloads images and takes a few minutes).
- If Docker is not available, only the login tests fail, with that reason; the rest of the suite still runs.
- `npm run auth-stack:start | auth-stack:stop | auth-stack:status` control it by hand.

## Git gateway

Developers clone and push through Custody Core, never GitHub: `<app>/git/<door id>/<owner>/<repo>.git`. Setup of the
GitHub App, what the gateway enforces, and what is not built yet: `docs/GITHUB_APP_SETUP.md`. The gateway needs `git`
and `gitleaks` on the server (`npm run tools:gitleaks`; the Dockerfile installs both).

## Developers and agreements

A door opens only after the invited developer signs its agreement with a key from their own device, on an account with
the same authenticator-code step as creators. `docs/AGREEMENT_SIGNATURES.md`.

## Scheduler and backups

Doors close by themselves at their end date (also any missed while the server was down), a backup snapshot (git
bundle) is taken when a door closes, and repository locks are re-checked every few hours. `docs/SCHEDULER.md`.

## Deploying

`npm run build` then `npm start` (or the `Dockerfile`). Step by step, with every setting the host needs:
`docs/deploy/README.md`, section "Deploying the app".

## Deploying the database upgrade without network access

`docs/deploy/README.md` has two scripts to paste into the Supabase dashboard's SQL Editor (one applies the upgrade, one
checks it) with click-by-click steps and the result to expect from each.

## Checking a deployed database

`npm run migrate` applies pending migrations as the admin role. `npm run verify-live` then checks, as the application's
own database account, that it cannot `INSERT` into `event` and that `append_event()` works. Its only write runs inside a
transaction that is always rolled back, so it is safe against a database whose event log is permanent. It never prints
connection strings.

## Migrations

SQL files in `server/migrations/` are applied in order by the server on start (or `npm run migrate`).
Applied files are recorded in the `schema_migrations` table and are never re-run.
