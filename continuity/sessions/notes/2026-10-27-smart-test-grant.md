# ADM Smart Test grant — 2026-10-27

## Outcome

- Added `vpn_user_access.allow_smart_test INTEGER NOT NULL DEFAULT 0`, including
  idempotent migration. No identity-level grant or changes to normal VPN modes.
- User creation and access PUT accept JSON boolean only; responses serialize a
  boolean. Missing on creation is false; missing on partial edits preserves the
  current explicit value. Existing assignments migrate to false.
- Create/update/adoption sync uses the common payload and sends explicit false
  as well as true. Import copies explicit remote boolean or integer 0/1; absent
  and malformed values fail closed. Existing pending-removal handling remains.
- Added default-off dialog checkbox and accessible pressed-state matrix toggle,
  TypeScript field and en/tr/ru label. No additional dependency.
- Changes confined to ADM backend db/API/sync/import and frontend types,
  VpnUserDialog/VpnUsersTab/locales, new test module and these continuity files.

## Verification

- Scoped backend permission and unreachable-site sync tests passed (30). After
  adding two create-user boolean cases, all 18 permission tests passed again;
  the unchanged 14 unreachable-site tests were not redundantly re-run.
- `npm run build` passed; existing >500 kB bundle warning remains.
- Flat locale-key parity passed: 438 keys in each of en/tr/ru.
- `git diff --check` passed; portable session index refreshed.
- Tests use an in-memory SQLite database and mocked site calls, never live data.
- Parent ran the full ADM backend suite:46passed. Final strict decoding in sync,
  serialization and new-row insertion rejects malformed stored values;25focused
  permission tests passed afterward. Independent QA accepted the final integrated
  ADM/site candidate; site full617tests and both site frontend builds also passed.

## Remaining boundary

Proxima enrollment/profile/runtime default-deny enforcement is owned by the
parent session and was not edited here. No browser interaction or live end-to-end
test; no SSH, commit, push or deploy. Install site enforcement and migration
before granting access; old site code can ignore an unknown field while ADM
records a successful sync, so re-sync affected assignments after site upgrades.
The site's dedicated host Smart Test service must also be updated and explicitly
restarted after migration; source synchronization alone does not reload its Python
imports. No existing account is automatically granted by migration.
The subsequent October 27 deploy request authorizes this rollout's publication
and deployment, with a strict site-first order. The ADM release owner may commit
and push now, but must wait for parent GO before any live mutation. No site update
is owned or invoked by the ADM release owner.

## Publication preparation

Read-only SSH verified `/opt/erg/proxima-node` at
`f992cfe8d9d38a25db97bdbb9110032ec53bc78e`, active `proxima-adm`, clean tracked
files, and only the retained `adm/backend/static.prev/` untracked. Node/npm exist.
The existing `adm/deploy.sh` builds into `static.new`, swaps static to static.prev,
restarts only ADM and checks service/HTTP. Before running it, preserve the existing
static.prev under a unique release backup name outside the checkout; refuse an
existing staging path rather than deleting unknown work. Fast-forward only to
the exact published candidate, then use `sudo bash adm/deploy.sh --no-pull`.
No live mutation has occurred during preparation. Accepted full46/focused25 tests,
frontend production build and438-key parity were not redundantly repeated;
release inspection found no product-code delta beyond that accepted candidate.
