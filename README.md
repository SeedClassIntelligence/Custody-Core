# Custody Core

Lets non-technical creators give outside developers access to their code without losing control of it.
See `CLAUDE.md`-style project instructions kept alongside this repo for the rules the code follows
(nothing is faked; unbuilt features say "Not connected yet").

## Run locally

1. `npm install`
2. Copy `.env.example` to `.env` and fill in `DATABASE_URL` (never commit `.env`).
3. `npm run dev`

Values already set in your shell take priority over `.env`.

## Tests

`npm test` starts a throwaway local PostgreSQL (the `embedded-postgres` package, no Docker needed), points the
app at it through `TEST_DATABASE_URL`, and runs the whole suite. The test setup refuses to run if that URL contains
`supabase.co` or matches `DATABASE_URL`, so tests can never touch the live database.

`npm run test:db` starts the same kind of database and leaves it running, printing a `TEST_DATABASE_URL` you can reuse.

The tenant-isolation test is expected to fail until Milestone 2 (login) is built.

## Migrations

SQL files in `server/migrations/` are applied in order by the server on start (or `npm run migrate`).
Applied files are recorded in the `schema_migrations` table and are never re-run.
