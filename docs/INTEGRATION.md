# Integrating with Custody Core

How an outside platform (an AI coding service, an IDE, a CI system) works on a creator's code through Custody Core, end to end. The same API in machine-readable form is `docs/openapi.json` (also served, without credentials, at `GET /api/v2/openapi.json`); a TypeScript client is `sdk/typescript/custody-core.ts`.

## The picture

```
your platform ──(signed in as a principal)──▶ /api/v2   request a session, get a credential, submit evidence, ask for promotion
the owner (a person, with the authenticator code) ──▶ /api/v1   approve the session, approve the promotion
your platform ◀── signed webhooks ── Custody Core      what happened, when
```

Your platform can never approve anything. A person (the project's owner) approves each session and each promotion. Everything that happens is written to the project's tamper-evident record.

## 1. Be a principal

The owner (or the operator) registers your platform as a **service principal** with a public key (Ed25519 or P-256) and a set of scopes (`docs/SERVICE_PRINCIPALS.md`). You keep the private key. Scopes you will meet:

| Scope | Lets you |
|---|---|
| `work-sessions:request` | ask for a work session |
| `work-sessions:read` | read the sessions you requested, and their commits, evidence, attribution, attestations |
| `work-sessions:close-own` | close a session you requested |
| `repositories:push-session` | prepare an approved session and get its git credential |
| `evidence:submit` | submit signed evidence, as an issuer the request named |
| `repositories:promote` | ask for a promotion (cannot be held together with the work scopes above) |

## 2. Sign in (every request)

Send `Authorization: Bearer <client assertion>`: a JWT you sign with your key.

- header: `{ "alg": "EdDSA" | "ES256", "typ": "JWT", "kid": "<your key id>" }`
- claims: `iss` = `sub` = your principal id, `aud` = `custody-core`, `iat`, `exp` (at most 300 s after `iat`), `jti` (a new random value every time: a repeat is refused)
- signature: Ed25519 over the bytes, or ES256 as the raw 64-byte `r || s`; base64url, no padding

What you may do comes from your recorded scopes, never from the token. `GET /api/v2/whoami` shows what the server holds about you.

## 3. Ask for a session

`POST /api/v2/work-sessions` with the project, repository, who is doing the work (`executor`), the owner as `sponsor`, an objective, the `base_commit`, and the **paths** the session may read, write and never touch.
Optionally: `evidence_requirements` (what must be shown, and which registered principal may show it) and `external_context` (a label your platform can use to find the session again; Custody Core never acts on it).
The answer is `202`: nothing can happen until the owner approves. Everything you wrote is scanned for secrets before it is recorded.

## 4. Get the credential and work with git

After approval: `POST /api/v2/work-sessions/{id}/credential`. The gateway builds a **filtered view** (one commit, no history, only the files your paths allow) and returns a git address and a credential (`ccs_...`, shown once).
`git clone` it (any user name, the credential as the password) and work. Push only to `session/<session id>/<name>`. Every push is checked: allowed write paths only, regular files only, no history rewriting, no secrets, within the size limits.
Accepted commits are replayed onto the real history **with the declared executor as author and the gateway as committer**; the push output shows each `view -> real` pair, and `GET .../commits` lists them. A rejected push says why.

## 5. Evidence

The principal named in the request signs a statement about one real commit and sends it: `POST /api/v2/work-sessions/{id}/evidence`. The text to sign is the canonical JSON of
`{ format: "custody-core.evidence.v1", work_session_id, evidence_type, subject_commit, status, specification_hash, evidence_hash, payload_sha256, issued_at }`
(canonical JSON: keys sorted by code point, no whitespace, whole numbers only; see `docs/EVENT_HASH_FORMAT.md`). `GET .../evidence` says which requirements are met for a commit. Details: `docs/WORK_SESSIONS.md`.

## 6. Promotion

With `repositories:promote`: `POST /api/v2/work-sessions/{id}/promote`. Refused unless the evidence is ready for that commit. The owner approves it as a person; the gateway then fast-forwards the repository's default branch to that commit (and fails closed if the branch has moved on). The session is then complete.

## 7. Be told

The owner registers a webhook endpoint (`docs/WEBHOOKS.md`); you receive signed events (`session approved`, `promotion completed`, ...) and verify them with the endpoint secret.

## 8. Check the record yourself

Everything above is written to the project's tamper-evident record. You do not have to trust our word that it is intact: export the events and run `node scripts/verify-chain.mjs events.json --head <the hash of the newest webhook you received>`. It uses nothing from this project (`docs/EVENT_HASH_FORMAT.md`).

## The client library

```ts
import { CustodyCoreClient } from './custody-core';
const client = new CustodyCoreClient({ baseUrl, principalId, keyId, privateKey, algorithm: 'Ed25519' });
await client.requestWorkSession({ /* ... */ });
await client.submitEvidence(sessionId, { evidence_type: 'tests', subject_commit, status: 'pass', specification_hash, evidence_hash });
```

It signs in, signs evidence, and verifies webhooks. In another language, follow sections 2 and 5 above, and check yours against the vectors: for any value, the canonical JSON and the signing text must equal what `sdk/typescript/custody-core.ts` produces (`tests/sdk.test.ts` shows the same for the server's own code).

## Errors

`{ "error": "<words>", "code": "<stable reason, where there is one>" }`. `401` credentials; `403` missing scope (or not the person allowed to decide); `404` no such thing *or not yours to see* (deliberately alike); `409` wrong state; `422` understood but refused for a reason (for example `evidence_not_ready`, with the evaluation); `429` a limit; `503` something Custody Core needs is unavailable and nothing was recorded.
