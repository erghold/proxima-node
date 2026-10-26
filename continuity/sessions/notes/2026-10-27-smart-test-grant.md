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

## Deployment after parent GO

Published and deployed candidate: `dffa0f768ae7932cf8719bd25b14f494dd2dca05`.
Parent confirmed site schema, runtime and host-service enforcement before GO.
Fast-forward and old rollback preservation succeeded. The first streamed command
passed a Windows CR to `--no-pull`, rejected before build/restart; a subsequent
quoted shell wrapper failed parsing before execution. Direct canonical invocation
then completed one build/swap/service restart successfully. No product repair.

One read-only postcheck verified:
- Live full Git SHA matches candidate; tracked files clean (only static.prev untracked).
- `proxima-adm` active; canonical HTTP check200 on port5002.
- Service-selected `/opt/erg/proxima-node/adm/data/adm.db`, opened read-only:
  column `allow_smart_test INTEGER NOT NULL DEFAULT 0`;107 assignments, all0.
- Compiled `index-DHQfHbc5.js` contains `Allow Smart Test` and `allow_smart_test`.
- Index and all3 JS bundles returned200 and matched local deployed SHA256 on
  both loopback and `https://adm.prxa.net` (8 exact matches).
- Index SHA256 `4ae7bd61c65543a488e1ff485611c28dc9ceae623740c17950ea27ec507b0781`;
  main bundle SHA256 `a65a0a384f6177894d11a23a2ae9166db86702c05c03ec4775caff604f1008ef`.
- Rollback index exists in `adm/backend/static.prev` and preserved older generation
  `/opt/erg/adm-static.prev-before-dffa0f768ae7932cf8719bd25b14f494dd2dca05`.

Build npm audit reported7 dependency vulnerabilities (1 moderate,6 high), not
remediated as part of release; existing large-bundle warning remains. No site
update or account mutation invoked. Parent owns disposable-account checks;
release success is not human acceptance. This deployment evidence is a local
documentation follow-up, not an additional deployed product revision.

## Parent-owned end-to-end evidence and final state

The parent supplied the following final evidence, accepted by independent bounded
test review; the ADM release owner did not repeat these tests or change accounts:

- Disposable central user65 on SVR: default false, discovery `not_authorized`,
  enrollment403. Explicit ADM grant true synchronized successfully; enrollment
  and both profile paths returned200.
- Windows mihomo SOCKS client reached real YouTube through SMART-TEST with HTTP200
  and a live AWG handshake.
- ADM revoke false synchronized successfully; both profile paths returned403,
  discovery denied, and key absence observed within9.903s. First probe found the
  interface absent; subsequent probe found it ready and empty. The same client
  then returned YouTube HTTP000 while DIRECT nic.ru remained200.
- Removed disposable device, deleted access/4 with successful sync, then deleted
  central user. Disposable records were absent from both databases and the client
  process was stopped.
- Normal keys/policies preserved: wg1 and wg2 each40 peers; listeners
  5555/5556/8443/15558 retained.
- A concurrent external ADM grant was observed late: central user5, site4,
  remote user4, grant1 synchronized, with an existing Smart record active again.
  The parent never granted an existing account and preserved this external work.
  Final state therefore contains one legitimate existing Smart peer. Earlier
  all-off observations establish migration behavior, not perpetual final state.

Human TUN/video and new-legacy end-to-end acceptance remain pending. No credentials
or private profile payloads are included. Documentation-only publication is
authorized; deployed product remains dffa0f768ae7932cf8719bd25b14f494dd2dca05 and
must not be restarted or redeployed for this documentation commit.
