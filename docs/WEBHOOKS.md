# Webhooks

Custody Core can tell your own systems when something happens in your projects: a session is requested, evidence arrives, a promotion is approved. You register an https address and say which events you want; every matching event is sent to it, signed.
(Phase 9 of `docs/integration/PHASE0_SPEC.md`; design: `docs/integration/PHASE9_DESIGN.md`.)

## Registering (the owner, signed in with the code step)

`POST /api/v1/webhook-endpoints`

```json
{ "name": "Release bot", "url": "https://hooks.example.com/custody", "events": ["promotion.*", "evidence.submitted"], "project_ids": ["<optional: only these projects>"] }
```

The answer holds the endpoint and **its signing secret, shown once** (`whsec_...`). Keep it: only an encrypted copy is stored, and it cannot be shown again (rotate it instead).

- **events**: `"*"` (everything), a family (`"promotion.*"`) or one name (`"promotion.completed"`); 1 to 20. A family matches on the dot: `promotion.*` is `promotion.requested`, not `promotion_x.foo`.
- **url**: must be `https`, with a host name (no IP address, no user name or password, no `localhost` or `.internal`), and **every address it resolves to must be public**. This is checked when you register, when you turn an endpoint back on, and **again before every delivery**, so a name that later points inside a network is refused (nothing is sent). Redirects are never followed. The certificate must be valid for the host name.
- At most 20 endpoints per owner. An endpoint cannot be edited or deleted: to change where or what, register a new one and disable the old (the secret can be rotated, and an endpoint switched off and on).
- `GET /api/v1/webhook-endpoints` lists them with delivery counts; `POST /:id/rotate-secret` (the old secret stops being used at once); `POST /:id/disable` and `/enable`; `GET /:id/deliveries` shows the last 100 deliveries and what went wrong.
- Registering, rotating and switching are recorded on your account record. A matching event is owed to an endpoint from the moment the endpoint exists (nothing before it is sent).

## What you receive

`POST` with `Content-Type: application/json` and these headers:

| Header | Meaning |
|---|---|
| `Custody-Signature` | `t=<unix seconds>,v1=<hex>`: HMAC-SHA256 of `"<t>.<raw body>"` with your secret |
| `Custody-Event-Id` | the event's id: **use it to de-duplicate** (delivery is at least once) |
| `Custody-Event-Type` | for example `promotion.completed` |
| `Custody-Delivery-Id`, `Custody-Delivery-Attempt` | this delivery, and which try this is (1 to 6) |

```json
{ "format": "custody-core.webhook.v1", "id": "<event id>", "type": "promotion.completed", "project_id": "...", "occurred_at": "2026-01-31T12:00:00.000Z",
  "actor": { "type": "gateway", "id": "promotion:..." }, "subject": { "type": "work_session", "id": "..." }, "data": { "...the event's payload..." },
  "record": { "seq": 42, "prev_hash": "...", "hash": "...", "hash_version": 2, "hashed_timestamp": "...", "canonical_payload": "..." } }
```

`record` is what the project's tamper-evident chain holds for this event, so you can recompute `hash` yourself (`docs/EVENT_HASH_FORMAT.md`) and, with the neighbours, check the chain. Every attempt of one delivery sends **exactly the same body**.

### Checking a delivery (do all of these)

1. Read the **raw** body (before any JSON parsing).
2. Take `t` and `v1` from `Custody-Signature`. Refuse if `t` is more than five minutes from your clock (a replay).
3. Compute `HMAC-SHA256(secret, t + "." + body)` as hex and compare with `v1` **in constant time**.
4. Answer `2xx` quickly (within 10 seconds) once you have stored the event id. Anything else, a redirect included, is a failure and is retried.

```js
// Node
import crypto from 'node:crypto';
function verify(secret, header, rawBody, now = Date.now() / 1000) {
  const m = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(header ?? '');
  if (!m || Math.abs(now - Number(m[1])) > 300) return false;
  const mac = crypto.createHmac('sha256', secret).update(`${m[1]}.${rawBody}`).digest();
  return crypto.timingSafeEqual(mac, Buffer.from(m[2], 'hex'));
}
```
```python
# Python
import hmac, hashlib, re, time
def verify(secret: str, header: str, raw_body: bytes) -> bool:
    m = re.fullmatch(r"t=(\d+),v1=([0-9a-f]{64})", header or "")
    if not m or abs(time.time() - int(m[1])) > 300:
        return False
    mac = hmac.new(secret.encode(), m[1].encode() + b"." + raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, m[2])
```

## Retries

A failed attempt (non-2xx, timeout, connection error, a blocked address) is retried after 1 minute, 5 minutes, 30 minutes, 2 hours and 6 hours; after the sixth failure the delivery is `dead` and is not tried again (it stays listed). Delivery is **at least once and not ordered**: use `record.seq` (per project) to order, and the event id to de-duplicate.
Deliveries are made by the server's scheduler about every 30 seconds, so the first attempt follows an event by up to about half a minute.

## What this does not do

Only project events are sent (not the account-level record of principals and webhook changes). Machine management of endpoints (the `webhooks:manage` scope) is not built: endpoints are managed by the owner. Your receiver must keep its own secret safe: anyone with it can forge deliveries.
