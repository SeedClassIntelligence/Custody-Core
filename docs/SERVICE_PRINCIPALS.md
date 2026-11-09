# Service principals (machine callers)

Phase 1 of `docs/integration/PHASE0_SPEC.md`. A service principal is a machine caller (an orchestrator, an IDE, CI, an
automated agent) that logs in to `/api/v2/*` with a signed assertion instead of a person's password and authenticator
code. The person login on `/api/v1/*` is unchanged.

## What exists in Phase 1, and what does not

| Built | Not built yet (later phases) |
|---|---|
| Principals, owned by one creator, with stored scopes | Anything a principal can *do*: work sessions, evidence, promotion |
| Public-key registry (Ed25519 and ES256), revocation, suspension | Separation rules between execution and approval scopes (Phase 2) |
| Assertion login with replay protection | A screen for managing principals (provisioning is a command-line script) |
| `GET /api/v2/whoami`, to prove the login | Limits on repeated failed attempts from one address |
| Every registration, key change and revocation on the creator's tamper-evident account record | |

Scopes are stored and returned by `whoami`, but no endpoint checks them yet. `requireScope()` exists for the next phase.

## Provisioning (operator)

Needs the server's settings (`DATABASE_URL`, `APP_DB_PASSWORD`), and the server must have started once so the database
is migrated.

```bash
# 1. a key pair for the machine caller (the private file is made readable by you only)
npm run principal -- keygen --alg Ed25519 --name build-agent --out ./keys

# 2. the principal, for a creator (their id from the creator table)
npm run principal -- create --creator <creator id> --name build-agent --platform agent \
    --env development --scopes work-sessions:request,evidence:submit

# 3. its public key; prints the kid the caller must put in its assertions
npm run principal -- add-key --principal <principal id> --public-key ./keys/build-agent.public.jwk.json

npm run principal -- list --creator <creator id>
npm run principal -- suspend  --principal <id>     # can be undone with: activate
npm run principal -- revoke   --principal <id>     # final: the database refuses to undo it
npm run principal -- revoke-key --key <kid>        # final
```

Give the **private** key file to the machine caller and nobody else. The server never sees it, and refuses a public-key
registration that contains one.

Scopes: `work-sessions:request`, `work-sessions:read`, `work-sessions:close-own`, `evidence:submit`,
`repositories:push-session` (execution), and `work-sessions:approve`, `repositories:promote`, `principals:manage`,
`webhooks:manage` (consequential; kept apart from the execution scopes in Phase 2).

## Calling the API (machine caller)

Every request carries `Authorization: Bearer <assertion>`, a new JWT signed for that request:

| Part | Value |
|---|---|
| header `alg` | `EdDSA` for an Ed25519 key, `ES256` for a P-256 key. Must match the registered key. |
| header `kid` | the key id printed by `add-key` |
| `iss` and `sub` | the principal's id |
| `aud` | exactly `custody-core` |
| `iat`, `exp` | whole seconds; `exp - iat` at most 300; `iat` not more than 30 s ahead of the server clock |
| `jti` | a new unique value for every request (up to 128 characters). Reusing one is refused. |

```js
import crypto from 'node:crypto';
const b64u = (v) => Buffer.from(JSON.stringify(v)).toString('base64url');
function assertion({ privateJwk, kid, principalId }) {
  const now = Math.floor(Date.now() / 1000);
  const input = `${b64u({ alg: 'EdDSA', typ: 'JWT', kid })}.${b64u({ iss: principalId, sub: principalId, aud: 'custody-core', iat: now, exp: now + 60, jti: crypto.randomUUID() })}`;
  const key = crypto.createPrivateKey({ key: privateJwk, format: 'jwk' });
  return `${input}.${crypto.sign(null, Buffer.from(input), key).toString('base64url')}`;
}
// fetch('https://<app>/api/v2/whoami', { headers: { Authorization: `Bearer ${assertion(...)}` } })
```

For ES256, sign with `crypto.sign('sha256', data, { key, dsaEncoding: 'ieee-p1363' })`: JWS wants the raw 64-byte
`r || s` form, not OpenSSL's default DER form (which is refused).

## What the server checks, in order

1. The header's algorithm is `EdDSA` or `ES256` and is the registered algorithm of the key `kid` names. Keys carried in the
   token itself (`jwk`, `jku`) are never used; `none` and `HS256` are refused.
2. The signature verifies with that registered public key. **Nothing is written before this passes**, so someone without the
   key cannot use up a principal's `jti` values.
3. `iss` and `sub` are the key's principal; the principal is active and unexpired; the key is not revoked or expired.
4. `aud` is `custody-core`.
5. Times are valid and the lifetime is at most 300 seconds.
6. `jti` is new for this principal. It is recorded in the same statement that checks it, so of many simultaneous requests
   with one token exactly one succeeds. Records are kept until the assertion would have expired and are cleaned up by the
   scheduler (about every 10 minutes).

Any failure is the same `401 {"error":"Invalid or missing credentials."}`. The reason is in the server log
(`[principal-auth] refused: ...`), never in the response, and never includes the token.

Suspension, revocation and expiry take effect on the next request: nothing is cached.

## Checking a record

Registrations and changes are on the creator's account record: `GET /api/v1/account/events` shows them with a chain
verification, as `service_principal.registered`, `.key_added`, `.key_revoked`, `.suspended`, `.reactivated`, `.revoked`.
Operator actions are recorded as actor `system` with `cli:<operating system user>` as the actor id.

## Tests

`tests/service_principal.test.ts` (registry, keys, guards, permissions) and `tests/assertion_auth.test.ts` (the login,
over real HTTP). Neither needs Docker.
