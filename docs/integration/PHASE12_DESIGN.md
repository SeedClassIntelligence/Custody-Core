# Phase 12 design note: the whole external flow

Gate: `tests/end_to_end.test.ts` (CL-21). No migration.

## What it is

One test that does what an outside platform and an owner would really do, with nothing stubbed that a real deployment would not also have, and then checks the project's record with a tool that shares no code with the server.

1. An operator registers the platform as principals with the **command-line tool** (`npm run principal`): real key generation, real registration; an agent that could both do and release work is refused.
2. The owner registers a **webhook** (to a real local HTTPS receiver with a real certificate, over the real pinned transport) and a **signing authority**.
3. The platform, through the **SDK**, asks for a session (with an evidence requirement and external context); it cannot be prepared before the owner approves.
4. With **ordinary git through the gateway**: a write outside the allowed paths is refused, a pushed secret is refused (and never repeated), and the real work, committed in the creator's name, is accepted and replayed with the executor as author and the gateway as committer.
5. Promotion is refused without evidence; a CI principal (ES256) **signs evidence**; the authority's attestation is delivered; a release principal asks; the agent cannot; the owner approves; the default branch moves; the session completes.
6. The platform closes the session; its credential is dead; the release principal is revoked from the command line and stops working.
7. The record contains the whole story in order and none of the secrets involved.
8. **Webhooks** arrived at the receiver: every event after the endpoint existed, in order, each signature valid, each `record.hash` equal to the chain's.
9. `scripts/verify-chain.mjs` (Node's `crypto` only; a test checks its imports) verifies the exported record, and the newest hash the webhooks reported, and **catches** eleven ways of altering it and forged deliveries.

## Decisions made while building, for review

- **The verifier is a separate file with no imports from the project**, written from `docs/EVENT_HASH_FORMAT.md` only. It is the answer to "do I have to trust your code to check your record?".
- **It states its own limit and gives the remedy**: cutting off the newest events leaves a valid chain, so it takes `--head <hash>` from something recorded elsewhere. The test asserts both halves (the cut chain verifies without `--head`, and fails with it).
- **The export in the test is what the route returns** (`getProjectEvents`), because the test harness mounts no login; the route is a thin wrapper around that function.
- Writing the test showed the real order of some events (a credential is issued before the "provisioned" event, `attribution.recorded` precedes `git.push`, a credential is revoked just before `promotion.completed`). These are the facts the test now pins.

## Not covered

Docker-dependent login (the owner is a test login, as in the other end-to-end tests). A live GitHub (the stand-in is real git over HTTP but not GitHub's own rules, e.g. branch protection). Those need the live checks in `docs/GITHUB_APP_SETUP.md`.
