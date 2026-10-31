# ADM handoff — evidence and boundaries

## Local pool commits — 2026-10-31

User approved local commits only. d61b23c (backend/catalog and dependencies) and
92e0f42 (management UI) preserve explicit grants and existing v1 records. Isolated
index snapshot20 catalog tests passed; broad transport run timed out, not a pass.
No live changes. Local branch diverges from the already-fetched upstream by9
upstream-only commits; reconcile before push/deploy. Infrastructure experiments
remain dirty. See sessions/notes/2026-10-31-local-pool-commits.md.

Deployment follow-up2026-10-27: parent GO received after site enforcement/runtime
verification. ADM dffa0f768ae7932cf8719bd25b14f494dd2dca05 deployed canonically,
active/HTTP200; public+loopback index/three bundle hashes match. Service DB schema
is INTEGER NOT NULL DEFAULT0;107 assignments all0. No account/site mutation by
the ADM owner. See the Smart Test note for rollback paths and command recovery.

Parent's final disposable-account evidence passed independent bounded review:
default deny, central grant/sync, enrollment/profile200, real Windows SOCKS
YouTube200 with live AWG handshake, revoke/profile403 and key removal within
9.903s. Disposable account/device/process cleaned up; normal VPN state preserved.
A concurrent external existing-account grant was preserved, so final state has
one legitimate Smart peer (not all grants0). Human TUN/video and new-legacy E2E
remain pending. This is a docs-only follow-up; do not redeploy it.

Latest 2026-10-27 (publication authorized, live deployment held): per-site `allow_smart_test` grant implemented in
ADM schema/migration, API validation/serialization, sync, import and dialog/matrix
UI with en/tr/ru parity. Existing/new assignments default off; unrelated partial
edits preserve an explicit grant. Site enforcement belongs to the Proxima owner.
Read-only SSH verified ADM at f992cfe8 with clean tracked files and active service.
Commit/push is authorized; no live mutation until parent GO. Deploy site support first and re-sync grants after
upgrades if an old site ignored the field. See
`sessions/notes/2026-10-27-smart-test-grant.md` for actual checks and next steps.

Latest2026-10-13: update dialog **41a2294** live; **PROX-68 READY_FOR_REVIEW**.
Two sx edits only; no update/log lifecycle change. Build437 parity/four focused
mock states/brief QA and one after-gate pass. Current eight UI reviews waiting
for Can: PROX-58/59/60/61/62/64/67/68. Do not invent another cosmetic slice;
collect specific findings/acceptance. Broader phases remain active; no full
mutation/security proof. Details: `sessions/notes/2026-10-13-update-output.md`.

Latest2026-10-12: edit/inventory **e4b06e2** live; **PROX-67 READY_FOR_REVIEW**.
Two presentation files, build437 parity/four targeted views/brief exact-source QA.
One after-gate passed service/static5 hashes/backend32/container72/ERG Proxima
runtime/static.prev; no real update/probe. Next operation-output/update-dialog
appearance check and human acceptance consolidation. Details:
`sessions/notes/2026-10-12-edit-inventory.md`.

Latest2026-10-12: provisioning/setup **c2abe67** live; **PROX-64 READY_FOR_REVIEW**.
Build437 parity/four focused scenarios/brief QA; existing lifecycle unchanged,
running-close guard checked with mock operation only. One after-gate passed
service/static5 hashes/backend32/container72/ERG Proxima runtime/static.prev;
no real provisioning. Next EditServer/remaining inventory dialogs. Details:
`sessions/notes/2026-10-12-provisioning-setup.md`.

Latest2026-10-12: entry/registration **cc21806** live; **PROX-62 READY_FOR_REVIEW**.
Two style-only files, build437 parity/four isolated views/brief QA pass. SSH
initially timed out; Can's retry request recovered the original route. One deploy
and one after-check passed service/public+loopback5 hashes/backend32/container72/
ERG Proxima runtime/static.prev. No real creation/provisioning tests. Next
provisioning/setup/edit forms. Details: `sessions/notes/2026-10-12-entry-registration.md`.

Latest2026-10-12: Documentation **5b0f931** live; **PROX-61 READY_FOR_REVIEW**.
Long URLs contained and both fenced-code formats retain lines/text. Lean gate:
build437 parity/4+2 focused views/brief QA; one after-check passed service,
loopback/public5 hashes/backend32/container72/ERG Proxima runtime/static.prev.
No command execution or broad matrix. Next remaining login/provisioning/add forms.
Details: `sessions/notes/2026-10-12-documentation.md`.

Latest2026-10-12: detail dialogs **42fc0b0** live, **PROX-60 READY_FOR_REVIEW**.
Lean local gate: one build/437 parity/eight targeted views/four baseline/brief QA;
isolated dialogs, not full-App integration. One after-gate passed service/static/
backend32/container72/ERG Proxima runtime; canonical Mounts check, no retry.
Can requests proportional verification for low-impact cosmetics; no exhaustive
matrices by default. Next ADM Documentation, then remaining forms/dialogs.
Details: `sessions/notes/2026-10-12-detail-dialogs.md`.

Latest2026-10-12: ADM Admins **14ec9ca** live; **PROX-59 READY_FOR_REVIEW**
for Can's visual confirmation. Canonical approved panel restart, final service/
loopback/public4 hashes/backend32/container72/ERG Proxima runtime pass. Runtime
verifier originally treated Mounts enumeration order as identity; independent
exact-digest reconstruction plus12 tests established the bounded correction.
No redeploy/baseline replacement or real access mutation. Site UI f260a40
retained; KLM deferred. Next remaining server dialogs/docs. Details:
`sessions/notes/2026-10-12-adm-admins-cosmetics.md`.

Latest2026-10-11: ADM Settings UI **50db405** live,
**PROX-58 READY_FOR_REVIEW** pending Can's visual confirmation.
Canonical approved panel restart; active service and loopback/public4 static
hashes verified. Backend32/container72/ERG Proxima runtime unchanged;
static.prev retained. No actual password mutation. Next ADM Admins presentation.
Site UI f260a40 retained; KLM deferred. Details:
`sessions/notes/2026-10-11-adm-settings-cosmetics.md`.

Workflow steering: use READY_FOR_REVIEW when waiting for Can's approval, answer
or verification; state what he must check. Machine QA/publication alone does not
close a pending human review. PROX-2/30 review/input waits updated; PROX-50 kept
OPEN for dedicated offline-site sync diagnosis. Wider UI phases remain active.

Latest2026-10-11: ADM VPN Users UI **f1452ce** live, **PROX-57 DONE**.
Canonical staging/swap/approved panel restart; active service and loopback/public
4 static hashes verified. Backend32/container72/ERG Proxima raw runtime unchanged;
static.prev retained. No actual grant/ACL mutations. Next ADM Settings presentation.
Proxima site UI f260a40 retained; KLM deferred. Details:
`sessions/notes/2026-10-11-vpn-users-cosmetics.md`.

Latest2026-10-11: ADM Monitoring UI **e011eae** live, **PROX-56 DONE**.
Canonical staging/swap/approved panel restart; active service and loopback/public
4 static hashes verified. Backend32/container72/ERG Proxima raw runtime unchanged.
Local cp1252 output failure happened after remote execution; verification used
UTF-8, deployment not rerun. static.prev retained. Next ADM VPN Users presentation.
Proxima site UI f260a40 retained; KLM deferred. Details:
`sessions/notes/2026-10-11-monitoring-cosmetics.md`.

Latest2026-10-11: Portal Login UI **f260a40**, managed SVR operation
**105 DONE**; all3 sites verified restart-free. PROX-55 DONE, widerP3 active;
ADM7414433 unchanged; KLM deferred. Next ADM Monitoring review. Evidence:
`sessions/notes/2026-10-11-portal-login-publication.md`.

Latest2026-10-11: User portal main-page UI **c8c42c0**, managed SVR
operation **104 DONE**; all3 sites verified restart-free. PROX-54 DONE,
widerP3 active; ADM7414433 unchanged; KLM deferred. Evidence:
`sessions/notes/2026-10-11-portal-publication.md`.

Latest2026-10-11: Login/Setup cosmetic UI **79e48b2**, managed SVR
operation **103 DONE**; ERG/SHV/SVR live checks passed without restart.
PROX-53 DONE, widerP3 active; ADM7414433 unchanged; KLM deferred. Evidence:
`sessions/notes/2026-10-11-entry-publication.md`.

Latest2026-10-11: Latency Audit cosmetic UI **636be89**, managed SVR
operation **102 DONE**, ERG/SHV/SVR live verification passed without restart.
PROX-52 DONE, broaderP3 active; ADM7414433 unchanged, KLM deferred. Evidence:
`sessions/notes/2026-10-11-latency-publication.md`.

Latest2026-10-11: Scheduled Jobs cosmetic UI **c2ef50e**, managed SVR
operation **101 DONE**, verified ERG/SHV/SVR without restart. PROX-51 DONE;
ADM7414433 unchanged, KLM deferred. Exact snapshot/evidence:
`sessions/notes/2026-10-11-scheduler-publication.md`.

Latest2026-10-11: managed ProximaVPN cosmetic page release **dba79b2**,
SVR operation **100 DONE**, ERG/SHV/SVR live read-only checks passed without
restart. ADM UI7414433 unchanged; KLM deferred. Exact managed snapshot and
verification limits: `sessions/notes/2026-10-11-vpn-page-publication.md`.

Latest2026-10-11: ADM7414433 update-dialog guard live, public4hashes verified.
SVR bounded backend feature86b52b8 operation93DONE and toolbar a218e26
operation94DONE; canonical feature playbook coordinates API-before-UI.
Two backend modules only, existing service settings/addresses/config preserved.
Details: sessions/notes/2026-10-11-feature-ui-release.md. KLM deferred.

Reviewed October 4, 2026. This file is a small retrieval aid, not a substitute
for originals and not permission to execute historical work.

## Current product work — cosmetic web batch, 2026-10-09

**Latest managed publication, 2026-10-10:** Proxima9d8b950 Groups cosmetics
published ERG/SHV/SVR without restarting site services. SVR operation92 DONE;
ADM7bd28ef remains unchanged. Current-baseline config/runtime/backend/static
checks and final independent read-only gate passed. PROX-43 closed; remaining
page phases continue. See `sessions/notes/2026-10-10-groups-publication.md`.

**2026-10-10 live update:** Dashboard UI7bd28ef deployed/public hashes verified.
Managed Proxima repeat-publication uses the exact preceding snapshot; source
0a8b7ea is published ERG/SHV/SVR and SVR operation91 DONE. Can explicitly
authorized deployment/SSH. Chained publication/rollback rehearsal passed before
canary; current service venv is required for the ADM operation wrapper. No
operation37/89/90 rewrite, no KLM work. Fresh final checks and subsequent config
drift boundaries are recorded in the new deployment note; small accepted UI
batches should be published incrementally from now on.

**2026-10-10 local update:** the Dashboard cosmetic pilot is implemented in
Dashboard.tsx, ServerCard.tsx and VpnServerCard.tsx. Header panel, card alignment,
spacing and metric groups only. Post-edit production build and437-key locale
parity passed; current ADM source hashes match full-App synthetic screenshot
evidence. Independent general-agent regression/security reviews and final QA
accepted the bounded pilot. The unavailable named Bugbot/security-review agents
were not run. PROX-39 records the pre-existing update-dialog early-dismissal
observability issue. No functional fix or live change. See
`sessions/notes/2026-10-10-dashboard-pilot.md`; broader UI renewal continues.

**Current decision:** Can reaffirmed autonomous rollout preserving the working
current state. Restart-free static publication replaces the earlier recreation
approach. The versioned `playbooks/publish-proxima-web.yml` uses the Proxima
publisher, fresh complete snapshots and safe metadata parser; no installer,
call-home, VPN or service restart. Isolated Docker/PWA/recovery rehearsal and
independent QA passed for ERG canary. Earlier historical HostConfig attribution
remains unresolved; the new method does not modify HostConfig. Final live
publication results follow actual serial execution.

**Final live result:** Proxima UI0e765b8 is published on ERG/SHV/SVR. Independent
read-only checks confirm raw Config/HostConfig, ID/Image/StartedAt, full mounts/
networks and backend manifests equal fresh snapshots; all40 management +8 portal
files per site pass HTTP/hash and DNS queries pass. Only later peer fetch
timestamps changed in config. ADM UI362a746 stays live, public index/main hashes
verified and no ADM restart after source operations commits25ec5ee.
SVR op89 failed only metadata reporting after publisher success; status retained.
KLM op90 unreachable/changed0; KLM offline through known paths before this work,
last positive sampleOct6. No KLM mutation. Do not close the entire rollout.

**Subsequent authorized deployment:** release **362a746** is live. Canonical
deploy script staged the new frontend, retained static.prev and restarted ADM;
service active and public HTTP 200. Served index/main-bundle hashes match files.
Proxima release **0e765b8** was pushed but is not released across sites: ERG's
web-only overlay failed runtime preservation. Exact old backend/image and 70
other container IDs were recovered, management/portal/status return 200 and DNS
works, but HostConfig differs from the initial aggregate fingerprint. Field-level
original data is unavailable; hold remaining sites and do not report full runtime
rollback. Source/auth/app builds cannot resolve that runtime evidence gap.

Subsequent read-only investigation proved the protected Config discrepancy is
unique-key Env ordering only, reproducing the exact overlay hash without changing
values; independent QA confirmed. HostConfig remains unexplained: current
settings match retained Compose/daemon source, but complete original inspect was
not saved. Retained-artifact search and36,424 bounded candidates did not reconstruct
the original. No new deployment occurred; Proxima rollout still held. Detailed
source/evidence note is in Proxima continuity/sessions/notes/2026-10-09-hostconfig-readonly-investigation.md.

Can authorized phased presentation-only implementation with separate agents and
an orchestrator. Proxima Punchlist UI parent PROX-32; P1 PROX-36, continuous QA
PROX-37. First ADM patch touches only `sx` in Dashboard/ServerCard/VpnServerCard.
Header/action wrapping, stacked groups, text/chip containment and metric shrink
preserve all state, APIs, permission checks, handlers and polling.

Production build passed before and after changes; locale parity 437 keys passed.
Independent QA accepted after correcting an introduced desktop chip-compression
regression. Fresh synthetic browser remedy evidence: 48 cases, 168 chip samples,
480 actionable button checks; no document overflow or fragmented/clipped labels.
Existing nested-button React warning remains. Full shell/auth and real backend
were excluded; no live infrastructure access or deployment occurred. Next work
is broader visual evidence and small cosmetics-only foundation/page batches.
See `sessions/notes/2026-10-09-web-ui-cosmetics.md` for artifacts and boundaries.

## Source convention

`memory/<name>:L` means the original file under
`C:\Users\caner\.claude\projects\d--Nextcloud-Projects-proxima\memory\`.
`<session>:L` means the original `<session>.jsonl` in that same project store.
Resolve either path with `scripts/continuity.py`. These are mixed historical
containers, attributed through exact cwd/structured path and import-parent
evidence, not through the store's encoded name.

## Verified locally now

- Root/repository: `D:\Nextcloud\Projects\proxima-node`,
  `canergunay/proxima-node`. HEAD `6e8baf3`; its parent is `dd780bc`.
  Initial Git status had only untracked `GOC.md`. All 196 tracked files were
  captured and remain byte-identical. No previous local continuity layout existed.
- ADM is a control plane: Ansible provisioning, node monitoring/alerts,
  site registration, VPN-account distribution and management. It is not the
  site-server data plane or the desktop VPN client. See `README.md:3–5`,
  `CLAUDE.md:3–6,66–95`. `adm/backend`, `adm/frontend`, `agent`, `roles`,
  `playbooks` and `inventory` hold the relevant implementations.
- React 19/Vite 6/MUI 6/i18next are confirmed by
  `adm/frontend/package.json:10–29`; English-default en/tr/ru requirements are
  in `CLAUDE.md:25–30`. No new mobile/formatting rule was inferred from sibling
  client notes. Deployment remains versioned and requires current authorization.
- Source checks confirm `PUSH_TIMEOUT=(5,30)`, a 60-second down-site memory and
  the `SiteGate` implementation (`adm/backend/core/proxima_client.py:33–50,179–218`).
  Pending sync retry runs in the 300-second scheduler loop
  (`adm/backend/core/scheduler.py:35,62–78`). This is source inspection, not a
  new runtime test.
- `vpn_users` and `vpn_user_access` are central account/grant data; site IDs
  differ, so remote identities must not be merged by numeric ID. ADM owns
  grants/limits, while users own their devices and may change their own login
  secret. Source: `adm/backend/core/vpn_user_sync.py:1–20,41–59,67–78,124–130`;
  historical rationale: `memory/adm-central-user-management.md:17–37`.
- Account-management scope and site-panel login access are separate powers:
  `admin_server_scope` versus `admin_server_access` (`adm/backend/core/db.py:76–112`;
  `memory/adm-panel-admins.md:18–26`). Do not conflate ADM operators, VPN users
  or local DNS device-auth users. `adm/frontend/public/docs/user-management.md:5`
  explicitly distinguishes the latter two.
- Direct grants are serialized through `allowed_profiles`
  (`adm/backend/core/vpn_user_sync.py:41–59`); an empty central list is an actual
  push payload, not "leave the site's local grants unchanged."

## Last ADM-focused human request and result

On **September 29 at 19:48:57 UTC**, Can requested fixing the synchronization
error: session `88824aa7-bbbe-47c2-bc5d-d55b7ea5d7d4:3174`, UUID
`a11aa772-568c-4ada-a77f-53238fdff40b`. The original record and its queue/parent
context were reopened during migration. The preceding report at line 3129 said
that a down site such as KLM appeared to prevent other ADM syncs.

The **dated result** is PROX-17, `dd780bc` followed by `6e8baf3`:
`memory/adm-sync-site-gate.md:11–23`. The local Git history and current code
agree on the implementation. Session lines 3412 and 3427 report revision and
deployment results. The deployment output also contains a failed ad-hoc probe
(`StopIteration`), so it is not evidence that every historical check succeeded.
The service environment issue is recorded separately below.

**Corrected diagnosis:** an early code-only explanation claimed the request
exceeded the reverse-proxy timeout and prevented healthy-site updates.
The recorded logs contradicted it: healthy sites did update, there was no NPM
504, and the measured problem was repeated 30-second waits, error messages and
the dialog remaining open. Keep the fix and the corrected explanation separate
(`memory/adm-sync-site-gate.md:18–23`; current `SiteGate` docstring).

Later historical human instructions asked to update KLM first and report before
ERG (`88824aa7-bbbe-47c2-bc5d-d55b7ea5d7d4:3534`). Subsequent "continue" messages
concerned the site-server rollout. They are neither an ADM backlog assignment
nor authorization today. No live tracker connection is available to confirm
PROX-17's current state or the next assigned task.

## Superseded instructions and operational lessons

1. **ADM deployment changed.** `CLAUDE.md:109–123` and the older
   `memory/adm-stale-source-checkout.md:47–49` describe local build + scp and
   claim no Node on the server. Current `adm/deploy.sh:3–18,60–114` builds into
   staging, swaps the UI, restarts and checks the service on the target;
   `adm/Makefile:7–11` invokes it. `memory/MEMORY.md:13` explicitly marks the
   old scp procedure obsolete. Do not execute either during this migration.
2. **Database path comes from the service.** Current `adm/adm.service:13`
   points to `/opt/erg/proxima-node/adm/data/adm.db`. The default in
   `adm/backend/core/config.py:6` points elsewhere. A September 29 ad-hoc probe
   silently read a stale empty database without the service environment
   (`memory/adm-adhoc-python-needs-service-env.md:11–21`). Production file
   existence/content was not checked now.
3. **Permanent userspace was a false implementation claim.** Can chose that
   direction on September 27 (`96ed35d2-52b3-4fbf-aea3-4a5115d1aa12:669`).
   The corrected note explains that `awg-quick` tries the kernel first and the
   environment variable only selects fallback; a later update overwrote newer
   tools. Current copy tasks use `force: false`
   (`playbooks/setup-proxima.yml:127`, `roles/mgmt-tunnel/tasks/main.yml:60`).
   Read the **correction at lines 65–73**, not just the original claim at
   lines 19–26, in `memory/adm-bare-box-callhome-userspace.md`.
4. **Stale source checkout was fixed, not merely documented.** The old "nothing
   calls refresh" observation is superseded by the hourly and startup path in
   `adm/backend/core/scheduler.py:32,42,74,81–108`; historical fix `d748a25`,
   `memory/adm-stale-source-checkout.md:34–45`.
5. **Machine-caller expiry is a distinct failure class.** Source now has renewal
   logic and a 30-day lead time (`adm/backend/core/proxima_client.py:60–112`;
   scheduler lines 43,75,111 onward). The September 20 historical note records
   recovery/alerting work, not today's credential validity. It also corrects a
   wrong sibling commit reference (`memory/adm-site-tokens-expire.md:44–55`).
   Never extract historical credentials to reconnect.
6. **Direct-profile decisions changed.** The August design requested per-device
   minting; the September 5 handoff records Can accepting user/route minting
   (`memory/direct-profiles-design.md:29–37` versus
   `memory/direct-profiles-where-we-left-off.md:56–64`). The latter also labels
   Fast-mode UI behavior as an assistant decision, not Can's approval (30–37).
   These client/server mechanisms are dependencies, not instructions to edit
   sibling workspaces. Original user-message verification for this September
   decision was not independently matched in this migration.

## Open or uncertain — confirm before assigning work

- **Claimed provisioning retry:** the September 27 note identifies no claim-aware
  retry endpoint/UI after asynchronous failure. Current update endpoint still
  calls `start_provision(..., claim=False)`
  (`adm/backend/api/vpn_servers.py:458–488`;
  `memory/adm-bare-box-callhome-userspace.md:41–49`). A comment saying the
  operator can retry is not proof this workflow is implemented.
- **Manual source refresh UI:** the backend endpoint exists
  (`adm/backend/api/vpn_servers.py:502–510`); the historical note says it was
  not connected to the UI. Hourly refresh exists. The UI-gap claim was not
  exhaustively rechecked; treat it as a candidate, not a freshly verified bug.
- **Central Direct-grant drift:** the September 5 handoff reports an empty
  ADM grant list could overwrite a local site grant on the next edit
  (`memory/direct-profiles-where-we-left-off.md:97–101`). The payload mechanism
  remains visible in source; the live rows and whether this was reconciled are
  unknown. Do not repeat the stale note's suggested account change.
- **SHV endpoint/DNS follow-up:** the September 29 note records slow resolution
  of the old public name (`memory/adm-sync-site-gate.md:29–30`). Current ADM DB
  values and today's resolution were not accessed.
- **Control-plane hosting:** the July 31 note says hosting ADM at Can's home
  was accepted temporarily and moving to office/VPS deferred
  (`memory/team-working-method.md:118–128`). This is a historical decision,
  not a verified current infrastructure inventory.
- Company-network documents were split into `bc-network` according to
  `memory/team-working-method.md:88–116`. Keep that project's decisions and
  the site/client backlog with their owners. The shared master plan is a
  dependency at `D:\Nextcloud\Projects\proximavpn\TEMP\master-plan.md`;
  it was not edited or adopted as a live ADM task queue.

## Development entry points

`adm/Makefile` defines build/install/dev/deploy. Frontend `npm run build` runs
`tsc -b && vite build` (`adm/frontend/package.json:5–8`). Backend tests are under
`adm/backend/tests`, including `test_sync_unreachable_site.py`. No application
test, frontend build or deployment ran for this history-only migration. Check
current task scope and dependencies before running product checks later.
