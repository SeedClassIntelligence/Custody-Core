# Event hash format

Every event belongs to one project's chain. The database assigns the sequence number, previous hash,
timestamp and hash when it writes the event (`append_event()`, migration `003`); the application cannot
supply any of them. Anyone with the stored rows can recompute every hash outside the database.

Two formats exist, told apart by the `hash_version` column. Events written before migration 003 are
`hash_version = 1` and keep verifying; every new event is `hash_version = 2`.

## Version 2 (written by the database)

The hash is the lowercase hex SHA-256 of the UTF-8 bytes of this text, with no whitespace anywhere:

```
{"action":<string>,"actor_id":<string>,"actor_type":<string>,"payload":<canonical_payload>,
 "prev_hash":<string>,"project_id":<string>,"seq":<integer>,"subject_id":<string>,
 "subject_type":<string>,"timestamp":<string>}
```

(Shown on two lines for reading; the real text is one line.)

- Keys appear in exactly this alphabetical order.
- `<string>` is a JSON string, escaped as JavaScript `JSON.stringify` does: `"` `\` and the control
  characters `\b \f \n \r \t` use short escapes; other characters below U+0020 are `\u00xx` with
  lowercase hex; everything else, including non-ASCII, DEL and U+2028/U+2029, is written as is.
- `seq` is a plain decimal integer.
- `prev_hash` is the previous event's `hash`, or 64 zeros for the first event of a project.
- `project_id` is the lowercase hyphenated UUID text.
- `timestamp` is the stored `hashed_timestamp`: UTC, millisecond precision, `YYYY-MM-DDTHH:MM:SS.mmmZ`.
- `<canonical_payload>` is the stored `canonical_payload` column, inserted verbatim. It is the exact text
  the database hashed, so a verifier never has to re-derive it.
- `hash` and `seed_signature_id` are not part of the hash.

### Canonical payload text

The database writes the payload as canonical JSON:

- Objects: keys sorted by Unicode code point (UTF-8 byte order), no whitespace. Duplicate keys in the
  input collapse to the last one.
- Arrays: order preserved.
- Strings: escaped as above.
- Numbers: exact decimal, no exponent, no trailing zeros, no `+`, and `-0` becomes `0`
  (`100.0` -> `100`, `1e3` -> `1000`, `1e-7` -> `0.0000001`).
- `true`, `false`, `null` as literals.
- The payload must be a JSON object. A NUL character (`\u0000`) in a string is rejected.

### Where JavaScript can and cannot re-derive the payload text

`canonicalJsonV2` (in `shared/crypto.ts`) produces the same text as the database for strings, nesting,
unicode, key order, booleans, null, integers up to 2^53 - 1 and decimals that survive a round trip
through a double (for example `0.1`, `2.25`, `100.0`). It cannot match for numbers JavaScript cannot
hold exactly or prints in exponent form:

| Payload value | Database writes | JavaScript prints |
|---|---|---|
| `9007199254740993` | `9007199254740993` | `9007199254740992` |
| `12345678901234567890123` | exact digits | `1.2345678901234568e+22` |
| `123456789.123456789` | exact digits | `123456789.12345679` |
| `1e-7` | `0.0000001` | `1e-7` |
| `1e21` | `1000000000000000000000` | `1e+21` |

This is why the text is stored: the hash covers `canonical_payload` byte for byte, and a verifier uses
that column, not a re-serialisation of the parsed payload. Producers that need exact large numbers should
send them as strings, because a JavaScript caller loses precision before the value reaches the database.
`verifyHashChain` also checks that the separate `payload` column means the same as `canonical_payload`,
and a database constraint (`chk_event_v2_canonical_payload`) keeps the two equal.

## Version 1 (before migration 003)

Written by application code. The hash covers the same fields, serialised with `canonicalJson` (keys sorted
by UTF-16 code unit, numbers as JavaScript prints them) over an object that includes the parsed
`payload`. These events are never changed, and `verifyHashChain` still checks them this way.

## What the hash does not cover, and what verification cannot detect

Verification recomputes every hash and checks each link. It proves that the stored fields of an event, and
their order, are what the database hashed. It does not prove more than that:

- **Not covered by the hash:** `id`, `created_at`, `updated_at`, `hash_version`, `seed_signature_id`, and
  `hash` itself. Changing `created_at` or `updated_at` is not detected. (`hash_version` is fixed per row;
  flipping a version 2 event to 1 is harmless for ordinary payloads because both versions then hash the
  same bytes.)
- **Deleting the newest events is not detected.** Hash links only point backwards, so a chain with its last
  N events removed is still a valid chain. Detecting this needs something outside the table, such as the
  latest hash recorded elsewhere or signed by Seed Signature. That does not exist yet.
- **Only the application's database account is locked out.** The table owner or a superuser can disable
  the triggers and rewrite rows; the chain then reveals the change, but cannot prevent it.
- **Seed Signature has no path to attach to an existing event yet.** `append_event` writes
  `seed_signature_id` empty and updates are blocked, so signatures will need a separate table or a
  dedicated function in a later milestone.

## Limits of `append_event`

- The payload must be a JSON object of at most 1 MiB (text form). A NUL character, a lone surrogate or a
  number outside PostgreSQL's `numeric` range is rejected before anything is written.
- Very deeply nested payloads (somewhere between 300 and 1000 levels) fail with a stack-depth error.
- Every call locks the project row for the duration of the insert, so a very large payload briefly blocks
  other writers to the same project.
- Any caller allowed to execute the function can write to any existing project. Per-creator authorization
  arrives with login (Milestone 2).

## Account events (migration 005)

Some things belong to a login rather than to one project, for example "this account's authenticator was
locked after too many wrong codes". They go in a separate chain per account, table `account_event`, written
only by the database function `append_account_event()` (the application's database account has no `INSERT`,
`UPDATE` or `DELETE` on the table, and the table rejects updates, deletes and truncation for everyone).

Each account's chain starts with `prev_hash` = 64 zeros and `seq` = 1. The hash is SHA-256 (lower-case hex) of
these UTF-8 bytes, with no whitespace, keys in this fixed order:

```
{"account_id":<JSON string>,"action":<JSON string>,"actor_id":<JSON string>,"actor_type":<JSON string>,
 "payload":<canonical_payload, byte for byte>,"prev_hash":<JSON string>,"seq":<integer>,"timestamp":<JSON string>}
```

(shown on two lines here; the real input is one line). `timestamp` is `hashed_timestamp`
(`YYYY-MM-DDTHH:MM:SS.mmmZ`, UTC), `canonical_payload` is produced by the same `canonical_jsonb()` as project
events. `account_id` is the login system's user id. `verifyAccountChain` in `shared/crypto.ts` checks a chain;
`GET /api/v1/account/events` returns the signed-in creator's chain and the result of that check.

Actions written so far:

| action | actor | payload |
|---|---|---|
| `account.second_factor_enrolled` | `creator` (the user id) | `{ factor_id }` |
| `account.second_factor_locked` | `system` / `second-factor-guard` | `{ factor_id, wrong_codes, window_minutes, locked_minutes, locked_until }` |

The same limits apply as for project events: deleting the newest events is not detected, and the table owner
can still bypass the triggers (the chain then reveals the change).
