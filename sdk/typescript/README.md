# Custody Core client (TypeScript)

`custody-core.ts`: one file, no dependencies, Node 22 or later. Copy it into your project or import it. See `docs/INTEGRATION.md` for the whole flow.

```ts
import crypto from 'node:crypto';
import { CustodyCoreClient, verifyWebhookSignature } from './custody-core';

const client = new CustodyCoreClient({
  baseUrl: 'https://custody.example.com',
  principalId: '<your principal id>',
  keyId: '<the registered key id>',
  privateKey: crypto.createPrivateKey(process.env.CUSTODY_PRIVATE_KEY!),
  algorithm: 'Ed25519'
});

const { session_id } = await client.requestWorkSession({ /* project, repository, executor, sponsor, objective, base_commit, access */ });
// the owner approves it, as a person; then:
const grant = await client.issueSessionCredential(session_id);   // grant.git_url, grant.credential.token (shown once)
```

What it does for you: signs in (a fresh signed assertion per request), signs evidence statements (`submitEvidence`), and checks webhook deliveries (`verifyWebhookSignature`).
Errors are `CustodyCoreError` (HTTP status, the server's words, a stable `code`). `evidenceSigningInput` and `attestationSigningInput` give the exact text to sign if you sign elsewhere (an HSM, another language).
The same API in machine-readable form: `docs/openapi.json`, served at `GET /api/v2/openapi.json`.
