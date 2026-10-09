# The scheduler: end dates, lock checks and backup snapshots

Runs inside the server process. Nothing to install; several servers can run it at once (every door and repository is
taken with `SELECT ... FOR UPDATE SKIP LOCKED`, so nothing happens twice).

## Doors close at their end date

- Checked every 30 seconds, and **when the server starts, before it serves anything**: a door whose end date passed
  while the server was down is closed then (the log says `closed N door(s) that passed their end date while the
  server was down`).
- Closing revokes the developer's credential, withdraws any unused invitation link, deletes the gateway's copies, and
  records `door.closed` with reason `expired`, by `system / scheduler`, including how many seconds after the end date
  it happened.
- The gateway refuses an expired door from the exact second regardless of when the scheduler runs, so the 30-second
  interval never extends access.
- Drafts and doors still waiting for a signature are closed too when their end date passes.

## Backup snapshot when a door closes

- When a door that was **open** closes (by the creator or at its end date), a snapshot is due. Closing never waits
  for it.
- For each of the door's repositories, the server fetches the default branch and the door's own branches
  (`door/<door id>/...`) from GitHub, writes a git bundle, checks it with `git bundle verify`, stores it in
  `BACKUP_DIR`, and records its SHA-256 and the exact branches and commits (`mirror.written`). The record cannot
  be changed afterwards (the database refuses).
- If GitHub or the storage is unavailable, it is retried after 1, 2, 4, 8 ... minutes (at most 6 hours apart), up to 8
  attempts. The first failure is recorded (`mirror.delayed`), and so is giving up (`mirror.failed`).
- The creator downloads each bundle from the door's page. It restores with plain git: `git clone <file>.bundle`.
  Check the download: `sha256sum <file>.bundle` must match the SHA-256 shown and recorded.

**Where snapshots are stored:** a directory on the server, `BACKUP_DIR`. Put it on persistent storage (the Dockerfile
uses `/data/backups`; mount a volume on `/data`). If it is not set, snapshots go to the system temp directory and the
server warns at start, because those can disappear on restart. Storage the creator owns (their own S3 bucket or
Google Drive) is not connected yet.

## Repository locks are re-checked

Every `LOCK_CHECK_HOURS` (default 6), each repository's lock is read back from GitHub. A lock removed or weakened on
GitHub is recorded (`repository.lock_missing`) and put back (`repository.locked`), by `system / scheduler`. An
unchanged lock only updates its check time, and a repository GitHub keeps refusing to lock (for example the free
plan) is not recorded again each time.

## Checking it is running

`/api/v1/health` shows `"scheduler": {"started_at": ..., "last_tick_at": ..., "ok": true}`.
