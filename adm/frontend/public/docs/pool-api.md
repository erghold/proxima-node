# Pool beta management API (local foundation)

This is management-plane support only. It can record and deliver desired attachment
authorization, but creates no tunnel, peer, profile, forwarding lease or offline
expiry. Every catalog member is returned
with `eligible: false` and `reason: attachment_not_provisioned`. Empty discovery
returns `data.pools: []`. Legacy discovery, profiles and Smart Test are unchanged.

## Administrator policy

Superadmin only: `POST /api/vpn-users` or `PUT /api/vpn-users/{user_id}` accepts
`{"enable_pool_beta":true}` to write `update_channel: beta` and `allow_pools: true`
in the same identity write; false writes stable/false. Both flags require real
JSON booleans. `allow_pools` can also be changed independently, and the ordinary
`update_channel` selector remains independent. Channel selection alone never
grants pool access. Existing beta accounts migrate with `allow_pools: false`.
The dialog checkbox is driven by `allow_pools`; toggling it updates both draft
fields, saved atomically. Scoped admins cannot change pool eligibility.

No new password exists. Central `account_id` is an immutable generated UUID,
not a username or site-local numeric ID. Imports cannot set it or pool eligibility;
neither field is replicated into legacy site payloads. Only safe policy fields
are added to the existing administrator user serializer.

## Password bootstrap

`POST /api/vpn/auth/login`:

```json
{"username":"alice","password":"existing-site-password"}
```

Success envelope: `{"ok":true,"data":{"token":"pool_…","expires_at":1790000000,
"account_id":"UUID","device_id":null}}`. Expiry is Unix seconds; the enrollment
session lasts 10 minutes. All client responses have `Cache-Control: no-store`.
Use `Authorization: Bearer pool_…` on authenticated client routes.

ADM always delegates the password to an enabled, non-pending-delete grant with
a known remote identity, using the centrally registered management URL. Only
verified HTTPS or literal loopback HTTP (including an existing management tunnel)
is accepted. Exact `localhost` is normalized to `127.0.0.1`. If the configured
management URL uses non-loopback HTTP, these new pool flows instead select that
same centrally registered site's HTTPS `public_url`, validated without URL
credentials, query or fragment. Private-network HTTP is not trusted. Selection
occurs once from configuration; an HTTP denial, redirect or TLS failure never
causes a retry through another URL for that site. No SSH is initiated. No
redirects, admin bearer forwarding or cached
password/hash verification occurs. The site response must be HTTP 200, `ok: true`,
and `data.user.id` must be an integer exactly matching `remote_user_id`; username
must match exactly. Current site login omits `enabled` and rejects disabled users
before returning success; if a response supplies `enabled`, only true is accepted.
The site token is discarded. Account/policy/grant/remote identity are rechecked
inside the transaction issuing the central session.

Explicit rejection stops at 401, throttling at 429. Transient failures try another
eligible site; all unavailable returns 503 without counting a password failure.
Site password changes govern subsequent password logins, not device renewal.
Admin JWTs and site tokens do not authenticate these client APIs; client opaque
tokens do not authenticate ADM administrator APIs, even with matching usernames.

## Device proof and enrollment

Generate one Ed25519 proof key pair and lowercase canonical UUID per installation
and immutable central account.
The proof key is **not** a tunnel key. Public keys and signatures use padded,
standard RFC 4648 base64 (not base64url).

With the enrollment bearer, `POST /api/vpn/devices/challenge`:

```json
{"purpose":"enroll","device_id":"UUID","public_key":"BASE64_32_BYTES","name":"Laptop"}
```

Response data: `challenge_id`, `message`, `expires_at`. Sign the exact UTF-8 bytes
of the returned `message` string; do not reserialize its JSON. The message includes
protocol `proxima-device-v1`, random challenge ID, account, device, public key,
purpose and name. The stored enrollment challenge is additionally bound to the
issuing bearer. Challenges last 120 seconds and are consumed atomically once.

`POST /api/vpn/devices`, with the same enrollment bearer:

```json
{"challenge_id":"RETURNED_ID","signature":"BASE64_64_BYTE_SIGNATURE"}
```

HTTP 201 returns the same session data shape, now with `device_id` and a 24-hour
management token plus `created: true`. The enrollment token is consumed. Device
ID, public key and account ownership cannot be changed or reassigned, including
after revocation.

Persist the device UUID and proof key pair securely **before** sending enrollment.
If the enrollment response is lost, authenticate with that same UUID/key using
the device-renewal flow below to recover a management session. Do not generate a
new key automatically: the server may already have committed enrollment and
consumed the enrollment token. If enrollment never committed or the outcome is
uncertain, a fresh password login can obtain a new enrollment bearer. Request a
fresh `enroll` challenge for the **same persisted UUID/key**, sign it, and submit
it with that bearer. Exact same-account active identity recovery returns HTTP 200
with `created: false`; a genuinely new identity returns HTTP 201/`created: true`.
Recovery does not change the existing name, key, owner or creation time. Both
consume the enrollment bearer and proof and return a fresh management session:

```json
{"ok":true,"data":{"token":"pool_…","expires_at":1790000000,"account_id":"ACCOUNT_UUID","device_id":"DEVICE_UUID","created":false}}
```

A UUID/key collision with another owner, mismatched identity pair or a revoked
registration returns 409 `device_identity_unavailable`. Replaying a consumed
proof returns 401 `invalid_proof`, not another recovery session. Eligibility is
rechecked at submission; a disabled policy cannot use enrollment recovery.

For passwordless renewal, request a challenge without a bearer using
`purpose: authenticate`, the enrolled device UUID and public key. Sign its message
and `POST /api/vpn/auth/device` with `challenge_id` and `signature`. This never
contacts a site. It returns a fresh 24-hour management token if account policy and
the non-revoked device remain valid. Existing valid management tokens are not
invalidated by renewal. These expiries do not govern any forwarding authorization.

### Authenticated denial codes

An `authenticate` challenge may be issued for a retained UUID/key even when the
device is revoked or its account is disabled/deleted. The unsigned challenge
response never gives a policy reason. Unknown identities or wrong public keys
receive generic 401 `invalid_device`. Challenges remain bounded to 120 seconds
and 20 outstanding per retained account identity.

Only after verifying and atomically consuming a valid signature does
`POST /api/vpn/auth/device` return a precise central-policy denial. Example:

```json
{"ok":false,"error":"device_revoked"}
```

HTTP 403 codes, in precedence order: `device_revoked` means the registration is
permanently tombstoned; `account_deleted` means its immutable central account no
longer exists; `account_disabled` means that account is currently disabled;
`pool_access_disabled` means its pool capability is currently disabled. No session
is minted. Every such denial consumes the signed challenge. Wrong signatures,
expired proofs, wrong-purpose proofs and replays return generic 401
`invalid_proof`, never a policy reason. Revocation deletes previously issued
challenges, so a fresh challenge is needed for an authenticated revoked response.

Bearer endpoints remain generic 401 `unauthorized` for invalid/expired tokens or
denied policy. A client may make one bounded proof attempt to distinguish current
management policy; neither generic 401 nor any management-policy code establishes
the forwarding state at an ingress. Do not infer tunnel revocation, discard
retained profiles, or claim a data-plane update from these management responses.

Additional authenticated routes:

- `GET /api/vpn/me`: `account_id`, `update_channel`, `allow_pools`, `device` (or null).
- `GET /api/vpn/devices`: own devices only, including revoked ones. Safe device
  fields: `device_id`, `name`, `created_at`, `revoked_at`.
- `DELETE /api/vpn/devices/{device_id}`: durable tombstone, revoke all its sessions
  and outstanding challenges. Other owners receive 404. IDs and keys are retained
  even if the account is later deleted, preventing resurrection or reassignment.
- `POST /api/vpn/auth/logout`: revoke this bearer only. **The device may still
  authenticate with its proof key.** Local logout must suppress automatic proof
  renewal and ignore late responses; it does not erase the proof identity. Use
  device deletion to revoke the installation's central registration.

If a self-deletion response is lost, the resulting generic 401 alone does not
confirm revocation. Another authenticated device of the same account, or a fresh
password-authenticated enrollment bearer, can list devices and inspect
`revoked_at`, or repeat the DELETE. Successful repeat DELETE returns
`{"ok":true,"data":{"revoked":true}}` and preserves the original tombstone time.
If those management operations are unavailable, retain an uncertain outcome
rather than claiming success. An unrelated account cannot inspect or delete it.

### Account switching and explicit new registration

Device proof credentials are scoped to one immutable central account. Switching
accounts is an explicit user action: preserve the previous account's UUID/key,
authenticate the new account, and enroll a **separately generated** UUID/key for
that account. Never reuse one global proof key across accounts or silently
overwrite the previous identity. Retained identities may later authenticate
their respective accounts, subject to current policy.

A revoked registration is permanently tombstoned. The user may explicitly choose
"register this installation as a new device" under a freshly authenticated,
currently pool-enabled account. Persist a fresh UUID/key and use normal enrollment;
no replacement endpoint is needed. This creates a distinct registration, does
not restore the old one, and never bypasses disabled capability or guarantees
data-plane admission. It is not an automatic response to errors. Password login,
recovery enrollment and new registration are management operations requiring
management/site authentication availability, not offline reconnect guarantees.

## Authoritative catalog (initially API-only)

All `/api/pool-catalog` routes require an ADM **superadmin JWT**, not a client token.
`GET` lists definitions and their enabled state. `POST` creates immutable generated
pool/resource/member/binding IDs and policy/resource revisions. Example:

```json
{
  "label":"Türkiye",
  "exit_country":"TR",
  "routing_mode":"fast",
  "resources":[{"site_id":4,"cidrs":["192.168.77.0/24"]}],
  "members":[{
    "site_id":4,
    "bindings":[{"connection_type":"vless_reality","routing_mode":"fast","profile_format":"sing_box"}]
  }]
}
```

Site IDs are existing ADM registrations, not client URLs. CIDRs must be subnets
of the registered site's LAN subnet. `resources: []` is supported. Fast requires
an explicit ISO country and no Internet bypass. `lan_only` requires null country
and represents no managed Internet egress. Recognized *candidate* combinations:
vless_reality/fast/sing_box, amneziawg/fast/awg, amneziawg/lan_only/awg. None grants
readiness or asserts a provisioned site capability. Smart Test is not a pool mode.

`PUT /api/pool-catalog/{pool_id}` accepts only `{"enabled":true|false}`. Semantic
edits require a new pool; old IDs are never recycled. `PUT
/api/pool-catalog/{pool_id}/users/{central_numeric_user_id}` accepts
`{"enabled":true|false}` to grant/revoke that account's pool selection.

`GET /api/vpn/pools` with a client bearer returns data containing `schema_version:1`,
`account_id`, content-based `authorization_revision` and `pools`. Only explicit
central pool grants are included. Members are intersected with enabled,
non-pending-delete site grants having known remote IDs. A pool with any unauthorized
LAN resource is omitted entirely, never silently weakened. LAN resources also
require the site's `lan_access` grant. Public member URLs come only from registered
HTTPS `public_url`, never the private management URL. Pools without visible members
are omitted. Every member remains ineligible; administrators cannot force it ready.

## Desired attachment authorization

Only a **device-bound central management bearer** may claim an attachment.
Password enrollment tokens, site tokens and ADM administrator JWTs cannot claim.
First fetch the current authorized manifest, then call
`POST /api/vpn/pools/{pool_id}/attachments` with exactly:

```json
{
  "ingress_id":"MANIFEST_MEMBER_UUID",
  "binding_id":"MANIFEST_BINDING_UUID",
  "authorization_revision":"CURRENT_MANIFEST_CONTENT_HASH",
  "policy_revision":"CURRENT_POOL_POLICY_UUID"
}
```

Account, device and proof key come from the session/database, never the request.
An eligible-ready member is not required: this operation requests **registry
authorization only**, not a connection. All current members remain ineligible.
Both revisions must match current authorized selection. Errors: 400
`invalid_attachment_claim`, 401 `device_session_required`, 403 `pool_access_denied`
or `binding_access_denied`, 409 `manifest_stale`, `unsupported_attachment_policy`
or `immutable_attachment_intent`. Unsupported policy is rejected, never weakened.
`unsupported_attachment_policy` additionally includes a safe `reason` code:
`unsupported_site_restrictions`, `unsupported_binding`, `unsupported_lan_scope`
or `ambiguous_lan_scope` (cross-site overlapping CIDRs).

The current site registry cannot enforce assigned groups, peer caps, bandwidth
quotas or speed limits. Claims with any such restriction on
the ingress or a resource-site grant are rejected. Even zero quotas are not
silently treated as unlimited. LAN policy must fit each resource site's **current**
registered subnet and contain canonical IPv4 RFC1918 CIDRs only. Cross-site
overlapping/same CIDRs are ambiguous and rejected rather than deduplicated. Private
DNS, IPv6, aliasing and other unexpressed scope are not supported by this claim.

`allowed_profiles` is the independent legacy Direct-profile **slot-ID allowlist**,
not a pool-binding policy. A valid nonempty slot list does not block an explicitly
granted pool, and pool enrollment never clears, changes or expands that list.
Pool authorization still requires `allow_pools`, an explicit central pool grant,
an enabled matching site assignment and all other account/device/resource checks.
A slot grant alone never exposes or authorizes a pool; a pool grant alone never
authorizes a legacy slot. Malformed legacy profile metadata is rejected rather
than repaired. Actual edits to the legacy slot list conservatively revoke existing
pool desires; unchanged lists during routine sync do not. Restoration still needs
a fresh authorized claim, never automatic activation.

HTTP 202 is returned for both new claims and lost-response retries. The immutable
`(account_id,device_id,ingress_id,binding_id)` tuple has one attachment ID. Example
`data` (wrapped in `{"ok":true,"data":...}`):

```json
{
  "attachment_id":"ATTACHMENT_UUID",
  "pool_id":"POOL_UUID",
  "device_id":"DEVICE_UUID",
  "ingress_id":"INGRESS_UUID",
  "binding_id":"BINDING_UUID",
  "desired_state":"active",
  "desired_revision":1,
  "delivered_state":null,
  "delivered_revision":0,
  "credential_generation":null,
  "delivery_status":"pending",
  "delivery_error":null,
  "ready":false,
  "reason":"attachment_not_provisioned"
}
```

`GET /api/vpn/attachments/{attachment_id}` returns the same safe status to an
authenticated owner account (404 for another owner). `delivery_status` is pending,
delivered or error. Delivered means **the site authorization registry acknowledged
the write**, not applied runtime. `ready` is always false; a desired revoked row
has `reason: attachment_revoked`. The integer desired/delivered revision is a
per-attachment counter, distinct from the manifest content hash.

Loss of account, device, pool, site access or complete LAN authorization atomically
queues a revocation, including resource-site loss affecting a different ingress.
New unsupported grant restrictions also revoke active desires. Restoration does
not autoactivate: a fresh authorized claim is required and any pending revocation
barrier is delivered first. Exact same active tuple retries do not increment its
revision. Site cleanup is blocked with 409 `pool_attachment_cleanup_required`
while an attachment still needs that site's registration retained for cleanup.

Superadmin API-only operations: `GET /api/pool-attachments` returns up to 100
safe statuses, prioritizing undelivered work then recent records;
`POST /api/pool-attachments/reconcile` accepts
`{"limit":10,"retry_conflicts":false}` (limit 1–20). It returns delivered/error/stale
attempt counts. An independent scheduler retries every 60 seconds in bounded
batches. HTTP 409 blocks the event; an operator may retry its **unchanged payload**
using `retry_conflicts:true` after resolving the site conflict. No automatic
revision bump bypasses the site's fencing. Details: [delivery](pool-delivery.md).

Still required before connectivity: site attachment provisioning, unique tunnel
credentials per attachment, fail-closed country routing, full LAN/DNS equivalence,
runtime revocation reconciliation, client integration and real failover acceptance. No
connection or release readiness is claimed by this foundation.
