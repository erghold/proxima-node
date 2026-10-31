# Location pools: local ADM implementation

## Approved scope

Can approved the explicit purpose-based definition and continued implementation.
Pools are ordered existing SITE+route references, arbitrary names and mixed exit
transports. Kinds: smart, lan_only, full_tunnel. Do not revive attachment runtimes
or infer grants/country membership. Contract: sibling proximavpn/docs/location-pools.md.
No new production deployment, commit/push or client publication authorization.

## Implemented

- Version2 definitions stored alongside unchanged v1 records. Atomic validation,
  stable member IDs, optimistic numeric revisions, explicit pool grants.
- Superadmin Pools tab: create/edit name, purpose, enabled state, select SITE routes,
  reorder members and assign users. allow_pools and site permissions stay separate.
- Existing /api/vpn/sync delivers data.pool_catalog with schema_version2 after
  remote user ID+username verification against the active origin assignment.
- Catalog intersects pool grants, current site grants, Smart/Direct/LAN permission
  and bounded route inventory. No credential-bearing metadata or arbitrary origin.
- Separate inventory cache from SITE status.pool_routes. Five-minute poll,
  six-minute expiry; observed outage invalidates availability but keeps inventory
  for editing. Older SITE without metadata provides no eligible routes.
- V1 manifest/attachment records are not reinterpreted or automatically migrated.

## Actual verification

Builder:20 new location-pool cases across final targeted runs; relevant foundation,
security and attachment regressions checked; migration regression corrected and
passed. Production frontend build passed;465 flattened locale keys/placeholders
matched. Do not infer a complete suite count from these reported separate runs.

Coordinator independently reviewed policy, sync binding and UI, then ran:
`python -m pytest tests/test_location_pools.py tests/test_sync_unreachable_site.py -q`
from adm/backend:34 passed in7.99s.

Added browser contract tests at adm/frontend/tests/test_location_pools_browser.py.
Built frontend served from adm/backend/static on localhost4178; Playwright Edge
used temporary browser contexts and intercepted ALL API calls with fixtures.
en/tr/ru tests each created arbitrary EU, selected two distinct site/exit members,
reordered them, enabled the pool, and explicitly granted a user without changing
allow_pools. Three passed in11.19s; no page errors. This is UI behavior evidence,
not live server or real transport testing. Preview process stopped afterward.

Harness setup corrections: bundled Chromium was absent (used installed Edge),
initial preview pointed at dist instead of configured backend/static, MUI select
accessible names include current values, common locale keys are flat, and an
async controlled checkbox requires click plus eventual state assertion. No
product workaround was added for those harness errors.

SITE inventory's initial get_health(slot_id) draft error was corrected by the
coordinator; seven isolated SITE tests pass. See sibling Proxima inventory note.

## Remaining

Desktop lifecycle implementation/checks in progress. Current full-tunnel pool
connections must stay blocked: Windows service has no inter-switch traffic guard.
Local Hyper-V inspection was denied by host permissions and no Windows Sandbox
executable was found; no isolated Windows leak test was run. No live grants,
network rules, installed client/service or deployments changed for this work.

Integration follow-up: desktop workspace41+6 tests and one subsequent targeted
enrollment-policy case passed; production frontend/native/service builds passed.
SITE AWG metadata now matches fallback LAN inventory;9 SITE tests pass. Smart
silent UDP loss detection and full-tunnel guard remain incomplete. See sibling
proximavpn/continuity/sessions/notes/2026-10-30-location-pools.md for exact boundaries.
