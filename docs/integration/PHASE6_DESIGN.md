# Phase 6 design note: evidence

Gate CL-12 (`tests/evidence.test.ts`). Migration `015`. Built from `PHASE0_SPEC.md` section 3.2 (tables) and TM-09 (evidence reuse).

## What it delivers, and what it does not

Delivers: requirements named in a session request; signed statements by the named issuer about commits the session produced; the evaluation of whether a requirement is met. Does not deliver: promotion (Phase 8, which will call `evaluateEvidence`), the `awaiting_evidence` and `completed` lifecycle steps (they belong to promotion), attribution or attestation (Phase 7), webhooks.

## Decisions made while designing, for review

1. **The issuer is always named in the request** (`issuer_principal_id` is NOT NULL; the spec had it nullable). A requirement with no named issuer would let any principal with `evidence:submit` vouch, including the one that did the work. The owner sees the issuer at approval, with `issuer_is_requester` when they are the same principal (allowed, because the spec lets one principal hold both scopes, but never hidden).
2. **Two signatures, two jobs.** The request is authenticated by the client assertion (who is calling). The statement is signed separately by one of that principal's keys, so the stored evidence is verifiable on its own, offline, long after the request.
3. **What is signed** is canonical JSON (the ledger's format) of the session, type, commit, status, specification hash, evidence hash, a hash of the payload, the time, and a format name. Changing any of them, or reusing a signature for another session, fails.
4. **Bound to the session's own commits** (`session_commit.real_sha`), never before the commit existed, never in the future. A requirement may pin a `specification_hash`.
5. **Recorded, never replaced.** The same statement again is a no-op; a different result for the same `evidence_hash` is a conflict. Both tables are written once (trigger, plus the application account has no UPDATE or DELETE).
6. **The database is the backstop**: it refuses an issuer the request did not name, a key that is not the issuer's, a commit the session did not produce, a session that is not running, and a pinned specification that does not match.
7. **Evaluation is conservative**: a revoked or expired key, or an issuer that is no longer active, makes what it signed stop counting (`issuer_unavailable`), because a revocation cannot say when a key was compromised. Rotating keys therefore means re-issuing evidence still needed. The newest counting statement decides; stale ones (past `max_age_seconds`) are ignored.
8. **The payload is scanned for secrets** before it is recorded (fail closed), and kept; the project's record carries only hashes.
9. **Limits**: 10 requirements per session, 500 submissions per session, payload as for external context (16 KiB, whole numbers only).

## Not guaranteed, stated plainly

A valid signature proves that the named principal made the statement, not that the statement is true. Whether the issuer is trustworthy is the owner's decision when approving.
