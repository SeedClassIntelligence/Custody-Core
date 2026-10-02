# Applying the database upgrade from the Supabase dashboard

Two scripts live next to this file. You run them in the Supabase dashboard, so nothing has to reach your
database from outside.

| File | What it does | Changes data? |
|---|---|---|
| `verify-migrations.sql` | Checks the database and prints one row per check. | **No.** It only reads. |
| `apply-pending-migrations.sql` | Upgrades the database (migrations 002 onward) and sets the app account's permissions. | Changes the database's structure and permissions. **Never adds, edits or deletes an event, project or creator.** |

They are generated from the real migration files (`npm run build:deploy-sql`), and a test fails if they ever drift.

## Before you start
1. **Reset the database password first** if you have not already (Project Settings > Database > Reset database
   password), and put the new one in your `.env`. The old password was in a file that is public in the repository.
2. Pick a quiet moment. The upgrade takes well under a second, but it briefly locks the tables it changes.

## Steps

### 1. Get the scripts
On GitHub, open `docs/deploy/verify-migrations.sql`, click **Raw**, select all, copy. (The "Copy raw file" button
at the top right of the file view does the same.)

### 2. Look at the "before" picture (optional but useful)
1. Supabase dashboard > your project > **SQL Editor** (left sidebar) > **New query**.
2. Paste `verify-migrations.sql` and press **Run** (or Ctrl+Enter / Cmd+Enter).
3. **Expect:** a table. The first row says `N FAILED`, where N is a number. Rows for the old setup are `FAIL`, such as
   *schema_migrations lists...* (it says the table is missing) and *custody_app can EXECUTE append_event*.
   Do not worry about the exact number; you are just seeing the starting point.

### 3. Apply the upgrade
1. **New query** again. Paste the contents of `apply-pending-migrations.sql`.
2. Press **Run**. Supabase may pop up a warning such as *"Potential issue detected: destructive operations"*
   (the script drops an old constraint and replaces it). That is expected: choose **Run this query**.
3. **Expect:** `Success. No rows returned.`
4. **If you see a red error instead,** nothing was changed (the script is all-or-nothing). Send me the exact
   message. The two you might meet:
   - `Stop: migration 001 has not been applied to this database...` means this is not the right project or
     database.
   - `check constraint "chk_event_hashed_timestamp" ... is violated by some row` means an old event has an empty
     timestamp. Tell me; we will look at it together. Do not edit events by hand.

It is safe to run this script a second time; it skips what is already done.

### 4. Check the result
1. **New query**, paste `verify-migrations.sql`, **Run**.
2. **Expect:** the first row says **`ALL PASS`**, and every row below it says `PASS`. The last row (`INFO`) shows
   how many events were written the old way and how many by the database, for example `42 / 0` right after the
   upgrade (new events appear as the second number).
3. If the first row says anything like `2 FAILED`, find the rows marked `FAIL` and send me them.

What the checks prove, in plain words:
- the app's database account **cannot insert, change or delete events** directly;
- it **can** use the one controlled way to add events (`append_event`), and nobody else can;
- the safety triggers and constraints are in place;
- all four migrations are recorded, so `npm run migrate` will see them as done;
- every project's events still have unbroken sequence numbers and links.

### 5. Optional: the same check from the app's side
With your `.env` pointing at the database, run `npm run verify-live`. It connects as the app's account, confirms a
direct `INSERT` is refused and `append_event` works, and rolls its one write back, so it leaves nothing behind.

## Afterwards
- `npm run migrate` will report nothing to do. If a future migration is added, run `npm run build:deploy-sql`
  and use the new `apply-pending-migrations.sql`, or run `npm run migrate` from a machine that can reach the database.
