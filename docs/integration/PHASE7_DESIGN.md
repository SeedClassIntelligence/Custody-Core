# Phase 7 design note: attribution (7a) and attestation (7b)

Gate CL-13 (`tests/attribution.test.ts`). Migration `016` (7a).

## 7a. Attribution (built)

For every commit a session pushed (`session_commit`), one immutable `contribution_attribution` row keeps the roles apart: **author** (the declared executor and its principal), **committer** (always the gateway), **sponsor** (the creator), and **declared author** (what the pushed commit claimed: evidence, never trusted).

- **Derived by the database**: a trigger on `session_commit` writes the row from the session, so no code path (including a future one) can attribute a commit to someone else. A second trigger refuses any insert whose author or sponsor is not the session's. The table is written once.
- **Non-impersonation (TM-04)**: the spec said an author may name a creator only under that creator's own sponsored session. The built rule is stricter and simpler: **an author is never a creator**. The creator appears as sponsor only. A pushed commit claiming the creator is recorded as an untrusted claim.
- **Reads**: machine callers (requester, or an approving principal) and the owner. Event `attribution.recorded` (one per push, listing the commits) goes on the project chain.
- Commits recorded before the migration are backfilled.

## 7b. Attestation (not started: decision 3)

The spec lists the owner attestation ("Seed Signature") as needing an owner decision: no protocol for it exists in this repository. Building it means choosing what an attestation is, who signs it, and how the signature is verified. See the question put to the owner; nothing is built until that is answered.
