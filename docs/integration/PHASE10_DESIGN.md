# Phase 10 design note: OpenAPI description and client library

Gate CL-17 (`tests/openapi.test.ts`, `tests/sdk.test.ts`). No migration.

## What it delivers

- `server/openapi.ts`: the OpenAPI 3.1 description (the single source), written to `docs/openapi.json` by `npm run build:openapi` and served without credentials at `GET /api/v2/openapi.json` (it contains no secrets; it is how an integrator learns to sign in). It describes the machine API (`/api/v2`), the owner routes of the work-session, evidence, attribution, attestation, promotion and webhook families (`/api/v1`), and the **webhook delivery** itself (the top-level `webhooks` entry).
- `sdk/typescript/custody-core.ts`: one file, no dependencies, one method per machine operation; signs in, signs evidence, verifies webhooks, and exports the exact signing texts (so another language can match them).
- `docs/INTEGRATION.md`: the whole flow in order.

## How the description is kept true (the point of this phase)

A description that drifts is worse than none, so it is tested from both sides:

1. **Routes**: the test walks the real Express application. Every `/api/v2` route is described and every described `/api/v2` route exists; every described owner route exists, and every owner route in the documented families is described.
2. **Traffic**: the SDK test runs a whole integration (request, approve, credential, real `git` push, signed evidence, attestation, promotion, webhooks, refusals) and checks **every request body and every response, errors included, against the schemas in the document**, with a small JSON Schema checker. A field the server returns but the document omits, a status the document does not list, or a body the document would not allow all fail. It also requires that **every operation in the document was exercised**. Writing this test found three real mismatches (a `recorded` flag, delivery counts on the endpoint list, and routes documented as taking no body), now fixed.
3. **Structure**: unique operation ids, every reference resolves, path parameters match their templates, every operation names its credentials, every `required` names a real property.
4. **Parity**: the SDK's canonical JSON, evidence and attestation signing texts, payload hash and webhook check are compared with the server's own on awkward inputs (non-ASCII, astral characters, nesting), and the SDK has a method for every machine operation and no others.
5. `docs/openapi.json` must equal what the code produces.

## Decisions made while designing, for review

- **Hand-written, not generated from the routes**: Express carries no types, so the description is authored and then *proved* against the running server (above) rather than inferred.
- **Owner routes are in the same document** under a second credential scheme (`ownerSession`), tagged `Owner`/`Webhooks`, because integrators build against them too; the SDK covers only the machine API (an owner is a person with a login and the authenticator step).
- **The SDK duplicates the small canonical-JSON function** instead of importing the server's, so it stands alone; the parity test is what keeps the two identical.
- **TypeScript only.** Other languages follow `docs/INTEGRATION.md` and the parity vectors.

## Not guaranteed, stated plainly

The JSON Schema checker covers the subset the document uses; it is not a general validator. The description says what the server does today; it is not a compatibility promise beyond the version number in `info.version`.
