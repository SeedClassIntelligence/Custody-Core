# Contract: commit-attribution-submission, version 1

How an unattended publisher (for example SRT-1) delivers a **detached signed statement about a commit of its own session** to Custody Core, without a person clicking anything, and gets a receipt it can check.

Contract name `commit-attribution-submission`, version `1`. Receipts say `commit-attribution-submission/1`.

## Detecting support

`GET /api/v2/openapi.json` needs no credentials. A server that implements this contract has

```json
"info": { "x-custody-contracts": { "commit-attribution-submission": {
  "version": "1", "scope": "attestations:submit",
  "route": "POST /api/v2/work-sessions/{id}/attestations", "claim": "commit.attribution",
  "document": "docs/contracts/commit-attribution-submission.v1.md" } } }
```

and `POST` under `paths["/api/v2/work-sessions/{id}/attestations"]`. A server without the key (or an older one that answers 404/405 to the POST) does not support it: report the attribution as **pending publication** and try again later. Do not fall back to the owner's route with the owner's login.

## What the owner sets up (once, on the owner's routes, with the full login)

1. Register the signer's public key: `POST /api/v1/attestation-authorities` (unchanged).
2. Register a service principal that holds the scope **`attestations:submit`** (and, to request sessions, `work-sessions:request` and `work-sessions:read`). A scope cannot be added to an existing principal; register a new one. The scope cannot be held together with `work-sessions:approve`, `repositories:promote`, `principals:manage` or `webhooks:manage`.
3. Grant it: `POST /api/v1/attestation-submission-grants` `{ "principal_id", "authority_id", "project_id" }`. One grant per principal, authority and project. Revoke with `POST /api/v1/attestation-submission-grants/{id}/revoke` (final). List with `GET /api/v1/attestation-submission-grants`. Each is recorded on the owner's account record.

The scope alone permits nothing; neither do `work-sessions:read`, `work-sessions:request`, `evidence:submit` or `repositories:push-session`. Approving a session and every other owner decision stay on their owner routes.

## The route

`POST /api/v2/work-sessions/{id}/attestations`, scope `attestations:submit`, signed client assertion as for every `/api/v2` call.

Body (exactly these fields; anything else is a 400):

```json
{
  "authority_id": "0d7376c1-8a35-465c-a00b-0483e46f77cc",
  "claim": "commit.attribution",
  "subject_commit": "9c59cceefa01998c76e56171fba5a47e6adc0d76",
  "issued_at": "2026-11-13T16:54:29Z",
  "payload": {
    "author_kind": "ai_assistant",
    "model": "m1"
  },
  "signature": {
    "algorithm": "Ed25519",
    "value": "SR3T8uxvD9QzHTwXGo0J7hxzAS26dDZ-3ns6y2cFenISkka-sIk7BAhDThCHAiuNJFynqAJ0-dBItYli9mFOCQ"
  }
}
```

- `claim` must be `commit.attribution` for this grant (422 `claim_not_allowed` otherwise). The owner's own route still accepts any claim.
- The signature is by the authority's key over the canonical JSON of `{ format: "custody-core.attestation.v1", authority_id, work_session_id, claim, subject_commit, payload_sha256, issued_at }` (`payload_sha256` is the SHA-256 of the canonical JSON of `payload`; Ed25519 over the UTF-8 bytes, or ES256 as raw r||s; base64url). It is the same statement as the owner's route (`docs/integration/PHASE7_DESIGN.md`).
- The session must be one **this principal requested**. The owner, sponsor, requester, repository and project are taken from Custody Core's records. The body cannot name them.

What is checked, in order, all before anything is stored: scope; the session is yours (404 otherwise, for another owner's, another principal's, or a missing one alike); a live grant for this principal, this authority and this session's project (403 `not_granted`); the authority is the owner's and not revoked (422 `authority_revoked`); the signature verifies (422 `bad_signature`: a changed claim, commit, payload or time lands here); the commit is one this session produced (422 `unknown_commit`); not issued in the future or before the commit existed; the payload holds no secret (400 `secret_found`). The database enforces the grant again when the row is written.

## Responses

**201** recorded; **200** the identical statement was already recorded (`recorded: false`, same receipt). A different statement about the same commit is a new attestation, never a replacement. Concurrent identical submissions record once.

Recorded (201):

```json
{
  "id": "f9a671b4-102b-4778-997c-fee5a3c0e049",
  "authority": {
    "id": "0d7376c1-8a35-465c-a00b-0483e46f77cc",
    "name": "Signer-d91d2f",
    "active": true
  },
  "claim": "commit.attribution",
  "subject_commit": "9c59cceefa01998c76e56171fba5a47e6adc0d76",
  "payload_sha256": "ae56778bfb1db872e5fa76e17f820902220b46a52c94437486e600a8b014075d",
  "payload": {
    "model": "m1",
    "author_kind": "ai_assistant"
  },
  "issued_at": "2026-11-13T16:54:29Z",
  "signature": {
    "algorithm": "Ed25519",
    "value": "SR3T8uxvD9QzHTwXGo0J7hxzAS26dDZ-3ns6y2cFenISkka-sIk7BAhDThCHAiuNJFynqAJ0-dBItYli9mFOCQ"
  },
  "recorded_at": "2026-11-13T16:54:30.332Z",
  "recorded": true,
  "receipt": {
    "contract": "commit-attribution-submission/1",
    "attestation_id": "f9a671b4-102b-4778-997c-fee5a3c0e049",
    "work_session_id": "e889ab80-aa4a-4b99-a3a0-b595297d194a",
    "authority_id": "0d7376c1-8a35-465c-a00b-0483e46f77cc",
    "claim": "commit.attribution",
    "subject_commit": "9c59cceefa01998c76e56171fba5a47e6adc0d76",
    "statement_sha256": "e7061083254be817ade524922e0bba1855e1f8b21b6f6e3bbade50d501e0991f",
    "recorded_at": "2026-11-13T16:54:30.332Z"
  }
}
```

Identical retry after a lost response (200): the same `id` and the same `receipt`, with `"recorded": false`.

### The receipt

`receipt` is stable: it is the same on every retry. `statement_sha256` is the SHA-256 of the exact signed statement (compute it yourself to check). `attestation_id` appears in the existing read path, `GET /api/v2/work-sessions/{id}/attestations[?commit=...]` (scope `work-sessions:read`), which lists the attestation with the same `id` and `recorded_at`. The event `attestation.recorded` in the project's record carries `submitted_by_principal_id`, and its actor is `system` / `principal:<id>`.

### Errors

All are `{ "error": "<words>", "code": "<stable reason>" }` (401 has no code).

| Status | Code | Meaning |
| --- | --- | --- |
| 401 | | no valid credential, or the principal is suspended/revoked |
| 403 | | the credential lacks `attestations:submit` |
| 403 | `not_granted` | no live grant for this principal, authority and project (also for an authority that does not exist or belongs to someone else: the answers are identical) |
| 404 | `not_found` | not a session this principal requested |
| 400 | `invalid` / `secret_found` | malformed body or unknown field / the payload appears to contain a secret |
| 422 | `claim_not_allowed` | the claim is not `commit.attribution` |
| 422 | `authority_revoked` | the owner revoked the authority |
| 422 | `bad_signature` | does not verify over this statement with the authority's key (or the wrong algorithm) |
| 422 | `unknown_commit` | not a commit this session produced |
| 422 | `issued_in_future` / `issued_before_commit` | `issued_at` is out of range |
| 429 | `too_many` | the session already has 200 attestations |
| 503 | `scanner_unavailable` | the secret scanner is down; retry later |

Real examples from the passing run:

No grant for this authority and project (403):

```json
{
  "error": "The owner has not granted this credential the right to deliver statements by that authority for this project.",
  "code": "not_granted"
}
```

A commit the session did not produce (422):

```json
{
  "error": "That is not a commit this session produced.",
  "code": "unknown_commit"
}
```

A claim other than `commit.attribution` (422):

```json
{
  "error": "A machine submission may only carry the \"commit.attribution\" claim.",
  "code": "claim_not_allowed"
}
```

Not your session (404):

```json
{
  "error": "No such work session."
}
```

All of the above are in `docs/contracts/commit-attribution-submission.v1.examples.json` (captured from the test run, with a disposable signer: the keys in them are worthless).

## Evidence that it works

`docs/contracts/commit-attribution-submission.v1.receipt.json` lists every test that passed and the SHA-256 of the test file, `server/attestation.ts`, the migration and `docs/openapi.json` it ran against. `tests/attestation_submission.test.ts` uses a disposable signer, repositories and database and covers: the owner's grant; an ungranted principal; a principal without the scope; a read-only principal; a wrong, ungranted or revoked authority; another project, another principal's session and another owner's session; an unknown commit (including another session's commit); a changed claim, commit, payload, time or signature; a secret in the payload; concurrent identical submissions; a suspended principal; the database-level guards; that the owner's own route still behaves as before; and that every request, receipt and error conforms to `docs/openapi.json`. `tests/attestation_submission_receipt.test.ts` fails if the receipt no longer matches the files, and `npm run contract:receipt` regenerates it.

## Changing it

Version 1 only grows by adding optional response fields. Anything else becomes version 2, with its own key under `x-custody-contracts` and its own document; version 1 keeps working.
