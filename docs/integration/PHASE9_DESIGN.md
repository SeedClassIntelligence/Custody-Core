# Phase 9 design note: signed webhooks

Gate CL-15 (`tests/webhooks.test.ts`). Migration `019`. Receiver guide: `docs/WEBHOOKS.md`.

## Decisions made while designing, for review

1. **What is owed is decided by the database, in the event's own transaction.** A trigger on `event` writes one `webhook_delivery` row per matching active endpoint of the project's owner. No code path can record an event without owing its deliveries, a rolled-back event owes nothing, and nothing is lost if the server is down. Events before an endpoint existed are not sent. `webhook_delivery.event_id` is deliberately **not** a foreign key to `event`: nothing may reference the append-only table in a way that changes how it is refused or truncated (a foreign key makes PostgreSQL refuse `TRUNCATE` with its own message before the append-only trigger runs).
2. **Mutable bookkeeping row plus immutable attempts** (instead of the spec's `UNIQUE (endpoint, event, attempt)` row per attempt): a delivery row only moves forward (`pending` to `delivered` or `dead`, attempts up by one, the signed body's hash fixed once set, final means final), and every try is also written once to `webhook_attempt`. A delivery cannot be created without being owed, and the history is complete.
3. **The secret is encrypted, never hashed** (spec C6): AES-256-GCM with the server's key, bound to the endpoint's row id, shown to the owner once. Rotating invalidates the old secret at once.
4. **SSRF (TM-08)**: https only; host name only (no IP literals, no credentials); every resolved address must be public (private, loopback, link-local, shared, documentation, multicast, reserved, IPv4-mapped, NAT64 and 6to4 all refused); checked at registration, at re-enabling and **before every attempt**; the connection is **pinned to the checked address** (no second lookup); the certificate is verified for the host name; **redirects are never followed**; 10 second timeout; the response body is never read or stored. Errors are recorded by code only, never the message.
5. **Signature**: `t=<unix>,v1=HMAC-SHA256(secret, "<t>.<body>")`, five minutes tolerance for receivers, constant-time comparison. The body is identical on every attempt and carries the event's chain record so receivers can recompute its hash.
6. **At least once, unordered, de-duplicated by event id.** Backoff 1 minute, 5 minutes, 30 minutes, 2 hours, 6 hours; dead after six attempts. A lease (the next time is pushed out before sending) stops two servers sending the same delivery.
7. **Delivery does not block the scheduler**: it runs beside the other jobs, so a slow receiver cannot hold up closing doors or checking locks.
8. **Owner-managed only.** The `webhooks:manage` scope is not given a machine route. Endpoints cannot be edited (new endpoint instead); only the secret and the enabled state change; nothing is deleted.
9. **Test-only seams** are options passed in code (`configureWebhookRuntime`), never environment variables, so production cannot be made to skip the address rules by configuration.

## Not guaranteed, stated plainly

A receiver that is slow or down for more than about nine hours loses deliveries (they go dead and stay listed). Account-level events are not sent. DNS answers can differ between the check and the connection only if the answer changes in that instant: the connection uses the checked address, so a changed answer cannot redirect it.
