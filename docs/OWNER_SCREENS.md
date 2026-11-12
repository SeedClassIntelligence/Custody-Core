# Owner screens

Everything an owner decides is in the web app. Nothing here needs `curl`.

| Where | What you can do |
| --- | --- |
| **Work Sessions** (navigation bar; a number shows how many wait for you) | See every automated session of the active project. Approve or reject one waiting for you (a rejection can carry a reason). Open a session to see what it may touch, the context it arrived with (shown as plain text, never as markup: it is the requester's claim), each evidence requirement and whether it is met, who wrote each commit (decided by the gateway, not by the commit), the attestations delivered, and the promotions. |
| Evidence warning | If the system that requested a session is also the issuer of a piece of its required evidence, the screen says so: the same system is checking its own work. |
| Deliver an attestation | Pick a signing authority, a claim and a commit. The screen shows the exact text to sign (the same canonical text the server verifies). Sign it with the authority's key outside the browser, paste the signature, and record it. The browser never holds a private key. |
| Promotion | Request one for the newest or a named commit; approve or reject a pending one. Approving states plainly that it moves the repository's default branch on GitHub straight away, and asks for a second click. A failed promotion says why in words. |
| **Integrations** | Webhook endpoints: create (the signing secret is shown once, with a copy button, until you confirm you stored it), rotate the secret, disable or enable, and see the deliveries and their outcomes. Signing authorities: register a public key (JSON Web Key), revoke one. |
| **Door → Backup snapshot** | *Check this backup* opens the stored copy completely on the server and compares it with its record: intact, or damaged with the reason. *Download locked file* gives the file as it is stored (encrypted with the server's vault key); the plain download decrypts it for you. |

## Not on the screens

- A named signing service (for example Seed Signature): it needs its owner's protocol. Authorities are generic: any holder of a key.
- Your own storage (bucket or drive) for backups.

## Tests

`tests/web_screens.test.tsx` drives these screens with a simulated person (jsdom, no browser needed, so it runs in CI). The network is a small in-memory server; every request a screen makes and every answer the stand-in gives is checked against `docs/openapi.json`. The backup routes are the one exception, because the description does not cover them yet.
