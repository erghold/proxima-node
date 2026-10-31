# Durable pool authorization delivery

ADM stores desired authorization, immutable tuple/intent and site dependencies in
`pool_attachments` / `pool_attachment_dependencies`. `pool_attachment_outbox`
retains each immutable revision payload, attempts and sanitized errors. There are
no cascading deletes from legacy users, devices or grants. Both central dedicated
transactions and the legacy writer use SQLite FULL synchronous durability. This
does not solve stale-backup restore fencing or storage loss.

## Atomic authority changes

A claim validates the actual authorized manifest under `BEGIN IMMEDIATE` using
the same selection function as catalog discovery. It also rejects restrictions
that the site registry cannot express. No network call occurs inside a database
transaction. Immutable intent is identity, enrolled proof key, pool, ingress,
binding, destination site and exact policy. Same tuple recovery returns its ID.

Narrow SQLite triggers run in the **same transaction** as existing legacy writes:
account disabled/pool access removed/deleted; device revoked/deleted; pool disabled
or grant removed; dependency site access disabled, pending_delete, deleted or remote
identity remapped; resource LAN permission removed; registered LAN subnet changed;
or new groups/peer caps/quotas/speed restrictions. Actual edits to the independent
legacy `allowed_profiles` slot list also conservatively revoke pool desires, but
its existing nonempty value is not a pool restriction and is never rewritten by
claims. Explicit pool grants authorize immutable pool bindings separately from
legacy Direct slots. Dependencies
include ingress and every resource site, so resource loss revokes other ingresses.
Ordinary pending sync, password/channel/label edits do not revoke authorization.

Active-to-revoked increments the attachment's integer revision once and appends
its full revocation payload. Repeated denials do not add events. Restoring a grant
alone does not reactivate anything. A fresh authorized claim can append a higher
active revision for the same immutable intent; a changed policy needs a new
catalog binding/attachment. Revoked central devices cannot claim again.

Deletion of a registered site is refused while active or undelivered dependent
authorization needs cleanup. First revoke access, deliver the revocation, then
remove the site. The guard runs in SQLite as well as surfacing through the API;
failed deletion does not remove the site's management transport. Normal deletion
of sites without outstanding pool cleanup remains supported.

## Exact site write and receipt

The sender performs `PUT /api/vpn/pool-attachments/{attachment_uuid}` through the
registered site's management URL and encrypted administrator credential. The
narrow `management_write` transport requires verified HTTPS or literal loopback
HTTP for an already-established local tunnel. Exact `localhost` is normalized to
`127.0.0.1`, not resolved through DNS. For a configured non-loopback HTTP management
URL, it selects the **same registered site's HTTPS `public_url`** instead; the
registered URL must have no URL credentials, query or fragment. Private/VPN IP
HTTP is never broadly trusted. Selection is configuration-only, before the single
request: HTTP denial, redirects and TLS failures do not cause URL fallback.
Delivery preserves the admin bearer and disables redirects. It never establishes
SSH or uses a client-supplied URL.
Timeouts are connect 2 seconds / read 8 seconds. Legacy transport callers are
unchanged; password bootstrap still strips the admin bearer.

Each outbox row contains canonical compact JSON with these exact keys:

```json
{
  "account_id":"ACCOUNT_UUID",
  "authorization_revision":1,
  "binding_id":"BINDING_UUID",
  "device_id":"DEVICE_UUID",
  "ingress_id":"INGRESS_UUID",
  "policy":{
    "effective_lan_cidrs":["192.168.77.0/24"],
    "exit_country":"TR",
    "routing_mode":"fast"
  },
  "public_key":"CANONICAL_PADDED_ED25519_BASE64",
  "state":"active"
}
```

The proof key is not a tunnel credential. State is active/revoked; the revision is
a positive monotonic **per-attachment integer**, not a manifest hash. Lost replies
retry the same payload/revision. The site API canonicalizes JSON; JSON object
formatting on the wire does not change intent.

Only HTTP 200 with strict `ok: true` is acknowledged. The returned attachment and
all identity fields, integer revision, state, canonical policy and its SHA-256
digest must match exactly. `ready` must be false, reason must match state, and
credential generation must be a valid integer transition from the previous actual
receipt. Any malformed/mismatched response remains an error, never delivery.
Response bodies, tokens, passwords and exception strings are not persisted in
outbox metadata. Public errors are `transport_unavailable`, `site_http_error`,
`receipt_mismatch` or `http_409`.

## Ordering, uncertain outcomes and generation

Only the earliest unresolved event for an attachment is sent. Workers claim a
60-second attempt lease in SQLite; receipts use an attempt-token compare-and-set.
A crashed worker's lease can be retried. Late receipts cannot overwrite another
attempt or regress delivered revision. An in-flight active request cannot be
recalled, but the following higher-revision revocation fences it at the site.

Obsolete unsent/failed active events are superseded when a later revocation
exists. Every revocation barrier is retained and delivered before a subsequent
activation. In-flight events wait for completion/lease expiry before supersession.
HTTP 409 blocks the attachment rather than inventing a higher revision. Manual
conflict retry resumes its existing queue: retry the same intent/revision, or
supersede an obsolete active event and send its already-queued revocation instead.
No automatic retry bypasses the block or coalesces away a revocation.

Generation is reported by the site, not generated by ADM. Initial active is 1;
initial unknown revoked is 0. Revocation retains generation, and a delivered
revoked-to-active transition adds exactly one. When an earlier active attempt's
reply was lost, a revocation receipt may validly report either the previous
generation or previous+1: ADM cannot know whether that activation reached the
site. Only this narrowly recorded uncertain attempt permits that range. The
accepted revocation receipt becomes the actual baseline for later activation.
Queued desired-state changes alone never change ADM's stored generation.

The independent delivery scheduler does not wait for legacy password/user sync.
Each batch is bounded; after one site's failure its remaining work is skipped for
that batch so other sites can progress. Administrator inspection/reconcile APIs
are documented in [pool API](pool-api.md).

Delivered registry state is **not applied runtime state**. No runtime profile,
key generation, private DNS, transit, forwarding expiry, ready status or live
connectivity is implemented by ADM delivery. Partitions delay revocation; there
is no promise of instantaneous revocation or continuity of established traffic.
