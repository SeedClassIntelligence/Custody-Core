# Phase 7 design note: attribution (7a) and attestation (7b)

Gate CL-13 (`tests/attribution.test.ts`). Migration `016` (7a).

## 7a. Attribution (built)

For every commit a session pushed (`session_commit`), one immutable `contribution_attribution` row keeps the roles apart: **author** (the declared executor and its principal), **committer** (always the gateway), **sponsor** (the creator), and **declared author** (what the pushed commit claimed: evidence, never trusted).

- **Derived by the database**: a trigger on `session_commit` writes the row from the session, so no code path (including a future one) can attribute a commit to someone else. A second trigger refuses any insert whose author or sponsor is not the session's. The table is written once.
- **Non-impersonation (TM-04)**: the spec said an author may name a creator only under that creator's own sponsored session. The built rule is stricter and simpler: **an author is never a creator**. The creator appears as sponsor only. A pushed commit claiming the creator is recorded as an untrusted claim.
- **Reads**: machine callers (requester, or an approving principal) and the owner. Event `attribution.recorded` (one per push, listing the commits) goes on the project chain.
- Commits recorded before the migration are backfilled.

## 7b. Attestation (built; owner chose the protocol-neutral design)

Decision 3 (Seed Signature transport) is still open for any *named* service, and the owner chose the spec's recommendation: a **generic signing authority**. Nothing here knows Seed Signature or any other service; one would simply be an authority.

- **Authority**: the owner (full login) registers a signer's **public key** (Ed25519 or P-256; a private key is refused). Revoking is final. Registration and revocation go on the owner's account record.
- **Statement**: canonical JSON (the ledger's format) of `{ format: "custody-core.attestation.v1", authority_id, work_session_id, claim, subject_commit, payload_sha256, issued_at }`, signed by the authority (Ed25519 over the bytes, or ES256 raw r||s, base64url).
- **Verified before it is stored**, never after (no `verified` column), against the registered key; the stored row is immutable. Anyone can re-verify it offline from the stored fields and the authority's public key (a test does exactly that with plain `crypto`).
- **Bound to the session's own commits**, not before the commit existed, not in the future; payload scanned for secrets (fail closed); identical repeat is a no-op.
- **Delivery**: the owner delivers the signed statement (`POST /api/v1/projects/:id/work-sessions/:sid/attestations`); the signature, not the delivery, is the proof. Reads for the owner and for machine callers that can read the session.
- **A revoked authority** is refused for new attestations, and what it signed earlier is listed with `authority.active: false` (like evidence, a revocation cannot say when a key was compromised; the consumer decides). Promotion will not count inactive ones.
- The database backstop refuses an authority of another owner, a revoked one, a wrong algorithm, an unknown commit, or a time before the commit existed. It cannot check signatures; the application does, first.

Not guaranteed: a valid attestation proves the registered key made the statement, not that the claim is true.
