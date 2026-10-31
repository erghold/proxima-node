# ADM continuity — start here

## Local upstream reconciliation — 2026-10-31

Can authorized local reconciliation. Integration branch
`integrate/location-pools-20261031` combines local pool commits with fetched
`origin/main` 7ac777d in an isolated worktree, preserving the original dirty main.
Conflicts retain v2 catalog/authorization and upstream pending-deletion migration,
types, user-management behavior and locale strings. Verification and final status:
`continuity/sessions/notes/2026-10-31-pool-reconciliation.md`.
No publication, deployment, live grants or Windows service transition authorized.

## Local pool commits — 2026-10-31

Can authorized local commits only. d61b23c records v2 catalogs/authorized sync plus
required v1 identity/revocation dependencies;92e0f42 records pool management UI.
An index-only backend snapshot passed20 location-pool cases. An initial broader
transport run timed out at120s without reported assertions; not claimed as passing.
Provisioning/watchdog/strategy work remains preserved and uncommitted. No push or
deployment. Existing upstream ref has9 commits absent locally; reconcile before
publication rather than overwriting newer deployed history. See
`continuity/sessions/notes/2026-10-31-local-pool-commits.md`.

## Dedicated ERG VLESS exit provisioning — 2026-10-29

c594e9b is pushed/live as provisioning tooling. Existing clients/Reality keys are
preserved; dedicated per-slot ERG credentials have protected backup/recovery and
ERG-only IPv4 domain egress. Seventeen independent checks and actual Xray parser/
Ansible runs passed. SITE migrated six exit slots; HOMELAB access remains blocked,
and Hetzner public VLESS is excluded despite management-path success. No beta or
paid resource. See `continuity/sessions/notes/2026-10-29-erg-exit-identities.md`.

## Starting from a copied folder

### Local Smart Test permission — 2026-10-27

Deployment completed after parent GO: ADM `dffa0f768ae7932cf8719bd25b14f494dd2dca05`
is live, service active; loopback/public index and three bundle hashes match.
Read-only service-database check found107 assignments, all grant0, with the
INTEGER NOT NULL DEFAULT0 column. Both previous static generations are retained.
Account/site tests remain parent-owned; human acceptance is not implied.

Parent's subsequent disposable-account end-to-end checks passed independent
review: default denial, ADM grant/sync, profile enrollment, real Windows SOCKS
YouTube traffic, and revoke/denial/key removal. Disposable records/process were
removed; normal VPN keys/policies remained intact. A concurrent external grant
to an existing account was preserved, leaving one legitimate Smart peer; the
earlier107/all0 result is migration evidence, not the final grant count.
Human TUN/video and new-legacy end-to-end acceptance remain pending. Details in
the Smart Test session note; documentation publication requires no redeployment.

ADM now stores `allow_smart_test` per VPN user/site assignment, default false
for new and migrated rows. API accepts only JSON booleans; sync always sends
an explicit boolean, including revocation. Import preserves an explicit remote
boolean/SQLite integer grant and defaults missing or malformed values to false.
The assignment dialog and matrix expose Allow Smart Test in en/tr/ru.
Publication authorized on October 27; ADM deployment is held for the parent
session's GO after site enforcement/migration and host runtime restart. Site
enforcement is separately owned in Proxima. Deploy site support before grants,
then re-sync assignments if an older site previously ignored the field.
Verification and scope: `continuity/sessions/notes/2026-10-27-smart-test-grant.md`.

## The deploy now carries the revision that was pushed — 2026-10-21

ADM ran as root while the checkout `/opt/erg/proxima-src` belonged to the user
whose SSH key GitHub accepts, so the source refresh failed with "Could not
read from remote repository" and the deploy continued with whatever the
checkout held. The operation was recorded as a success. It bit twice in one
session (2026-10-20, ADM operations 111 and 114 on SVR): both reported
`done` and shipped the previous revision, and only the site's
`config/version.json` said what had actually been deployed.

Fixed: the git calls run as the owner of the checkout (`runuser -u <owner>`),
so the working credentials and the ownership of the objects are the ones that
already worked. A refresh that still fails is now written into the operation
output instead of only into the service log, because a stale deploy is
exactly the case the operator has to see. The deploy still continues on a
failed refresh — a box that cannot reach GitHub should still be able to
re-deploy what it has.

Checks: 28 ADM tests pass (3 new, in `adm/backend/tests/test_source_refresh_owner.py`).
Verified on the ADM host: a source refresh as root now reaches GitHub, and
the checkout keeps its ownership.

## Active cosmetic web work — 2026-10-10

### Update dialog published — 2026-10-13, visual acceptance next

ADM **41a2294** live; **PROX-68 READY_FOR_REVIEW**. Exactly two Dashboard sx
changes fix long update headings/footer spacing. OutputViewer already fits and
is unchanged. Build437 parity/four full-App mock states/brief QA and one live
after-gate passed service/static5 hashes/backend32/container72/ERG Proxima runtime.
Pending/running close guards and exact stripped log text checked; no real site
update from fixtures. Next Can's visual acceptance, not more generic polish.
Fresh UI review queue: PROX-58/59/60/61/62/64/67/68. Parent phases stay active;
native/functional/network work separate. Details/checklist:
`continuity/sessions/notes/2026-10-13-update-output.md`.

### Edit/inventory published — 2026-10-12

ADM **e4b06e2** live; **PROX-67 READY_FOR_REVIEW**. Edit field grid/error/footer
and inventory metadata/local table readability only; update and observation
semantics preserved. Build/437-key parity/four isolated views/brief QA passed.
One deploy/after-check passed service/5 file hashes/backend32/container72/ERG
Proxima runtime/static.prev. No actual update or service probe by verification.
Next bounded operation-output/update-dialog appearance check, then pending visual
acceptance consolidation. Evidence: `continuity/sessions/notes/2026-10-12-edit-inventory.md`.

### Provisioning/setup published — 2026-10-12

ADM **c2abe67** live; **PROX-64 READY_FOR_REVIEW**. Two presentation files:
compact desktop provisioning grid/mobile stack, setup headings/range labels/
footer/error wrapping. Operation lifecycle/payloads/password/close rules retained.
Build437 parity/four isolated scenarios/two baseline/brief QA pass; mock setup
start/poll tested running-close protection, no real installation. One deploy/
after-gate passed service/public+loopback5 hashes/backend32/container72/ERG Proxima
runtime/static.prev. Next EditServer form and remaining inventory/dialog views.
Evidence: `continuity/sessions/notes/2026-10-12-provisioning-setup.md`.

### Entry/registration forms published — 2026-10-12

ADM **cc21806** live; **PROX-62 READY_FOR_REVIEW**. Login/AddVpnServerDialog
presentation only: padded dynamic card, wrapped errors and deliberate registration
grid/footer. Build437 parity/four targeted isolated views/two baseline/brief QA
passed. Initial ERG SSH timeouts resolved after Can asked to retry; original
route worked, then one canonical deploy/approved panel restart and one after-gate
passed service/5 file hashes/backend32/container72/ERG Proxima runtime/static.prev.
No successful auth/account/server creation/provisioning proof. Next provisioning,
setup and edit forms. Evidence: `continuity/sessions/notes/2026-10-12-entry-registration.md`.

### Documentation published — 2026-10-12

ADM **5b0f931** live; **PROX-61 READY_FOR_REVIEW**. Docs.tsx contains long
URLs and fixes untagged fenced-code blocks while retaining exact text/navigation/
fetch/plugins. Final build437 parity, four focused views plus two table-correction
views and brief source-bound QA passed. One live after-check passed service,
index/3 bundles/introduction.md hashes on loopback/public (5 per origin), backend32/
container72/ERG Proxima runtime/static.prev; no retry. Next remaining ADM login,
provisioning and add forms. Evidence:
`continuity/sessions/notes/2026-10-12-documentation.md`.

### Detail dialogs published — 2026-10-12, lean verification

ADM **42fc0b0** live; **PROX-60 READY_FOR_REVIEW** for Can's visual confirmation.
Exit/VPN detail presentation only: headings/copy labels/public-IP and SSH grids,
long table text/local scroll and footer spacing. One local build/437-key parity,
four baseline+eight targeted dialog views and a brief independent review passed.
One live after-check passed service/public+loopback4 hashes/backend32/container72/
ERG Proxima runtime/static.prev; canonical Mounts comparison, no retry. No real
operational mutations. Next ADM Documentation, then remaining forms/dialogs.
Can questioned excessive smoke volume: low-impact cosmetics use proportionate
build/parity/critical visuals/source review; broaden only for concrete risk/failure.
Evidence: `continuity/sessions/notes/2026-10-12-detail-dialogs.md`.

### ADM Admins published — 2026-10-12, human review pending

ADM UI **14ec9ca** live; **PROX-59 READY_FOR_REVIEW** awaits Can's visual
confirmation. Admins.tsx presentation only: responsive header, bounded matrix/
pinned identity, wrapped scope/site labels and account/delete/revoke dialogs.
Build/437-key parity,112 synthetic cases and independent source-bound QA passed.
Canonical approved panel restart succeeded. Final public/loopback4 hashes,
service/backend32/container72/ERG Proxima runtime checks passed; static.prev
retained. Initial runtime hash failures were Mounts-order false positives:
independent diagnosis and12 guard tests support the bounded verifier correction,
without another deployment or original-baseline replacement. Site UI f260a40
retained; no real account/access mutations; KLM deferred. Next remaining ADM
server dialogs/docs. Evidence:
`continuity/sessions/notes/2026-10-12-adm-admins-cosmetics.md`.

### ADM Settings delivered — 2026-10-11

ADM UI **50db405** live, **PROX-58 READY_FOR_REVIEW** pending Can's visual
confirmation. Settings.tsx presentation only:
deliberate desktop language/password columns, narrow stacking, wrapped errors
and aligned controls/cards. Password/language/state/storage behavior preserved.
Build/437-key parity,55 synthetic cases and independent bounded-page QA passed.
Canonical publication with approved panel restart succeeded; actual service,
loopback/public4 hashes/backend32/container72/ERG Proxima runtime passed;
static.prev retained. No real password change. Proxima site UI remainsf260a40,
KLM deferred; next ADM Admins table/dialog/permission presentation. Evidence:
`continuity/sessions/notes/2026-10-11-adm-settings-cosmetics.md`.

Can's updated workflow: READY_FOR_REVIEW for approval/answer/verification waits,
with the exact human action in the item comment. QA/publication and human
acceptance are distinct. PROX-2/30 also wait for native review/device evidence;
they remain unreleased. PROX-50 offline-site sync report remains OPEN for diagnosis.

### ADM VPN Users delivered — 2026-10-11

ADM UI **f1452ce** live, **PROX-57 DONE**. Three presentation files: bounded
matrix names/pinned user identity, wrapped server/profile/revoke dialogs and
responsive footer/card layout. Original roles, grants, validation, payloads and
sync semantics preserved. Build/437-key parity,112 synthetic cases and independent
local QA passed. Canonical publication with approved panel restart succeeded;
actual loopback/public4 hashes/service/backend32/container72/ERG Proxima runtime
passed, static.prev retained. No real account/access mutation test.
Proxima site UI remains f260a40; KLM deferred; wider phases active. Next ADM
Settings presentation, then Admins/remaining dialogs/docs. Evidence:
`continuity/sessions/notes/2026-10-11-vpn-users-cosmetics.md`.

### ADM Monitoring delivered — 2026-10-11

ADM UI **e011eae** is live through canonical deployment; **PROX-56 DONE**.
MonitoringTab.tsx only: chart surfaces/responsive grids, wrapped series filters,
aligned alert fields/actions and readable local history table. Original metric,
filter/range/tooltip and alert/Telegram behavior preserved. Build/437-key parity,
98 full-App synthetic cases and independent local QA passed.
Actual checks: ADM active after approved panel restart, loopback/public index+
3 bundle hashes match,32 backend files/72 running container IDs and protected
ERG Proxima runtime unchanged; static.prev retained. Local output encoding failed
after remote execution; read-only verification confirmed success, no deploy retry.
Proxima site UI remains f260a40; KLM deferred. Next ADM VPN Users presentation.
Details: `continuity/sessions/notes/2026-10-11-monitoring-cosmetics.md`.

Latest2026-10-11: Portal Login UI **f260a40**, managed SVR **105 DONE**;
ERG/SHV/SVR restart-free. Runtime/backend/config/IDs,69 management+11 portal
HTTP hashes/status/DNS passed. PROX-55 DONE; ADM7414433 unchanged; KLM deferred.
Next ADM Monitoring review and remaining page/dialog batches. Note
`continuity/sessions/notes/2026-10-11-portal-login-publication.md`.

Latest2026-10-11: User portal main-page UI **c8c42c0**, managed SVR **104 DONE**;
ERG/SHV/SVR restart-free. Runtime/backend/config/IDs,69 management+10 portal
HTTP hashes/status/DNS passed. PROX-54 DONE; ADM7414433 unchanged; KLM deferred.
Next portal Login review, then ADM batches. Note2026-10-11-portal-publication.md.

Latest2026-10-11: Login/Setup UI **79e48b2**, managed SVR **103 DONE**;
ERG/SHV/SVR restart-free. Runtime/backend/config/IDs,69 management+9 portal
HTTP hashes/status/DNS passed. PROX-53 DONE; ADM7414433 unchanged; KLM deferred.
Next user portal review, then ADM batches. Note2026-10-11-entry-publication.md.

Latest2026-10-11: Latency Audit UI **636be89**, managed SVR **102 DONE**;
ERG/SHV/SVR restart-free, runtime/backend/config/IDs and66 management+9 portal
HTTP hashes/status/DNS passed. PROX-52 DONE; ADM7414433 unchanged; KLM deferred.
Next Proxima management batch: Login/Setup. Note2026-10-11-latency-publication.md.

Latest2026-10-11: Scheduled Jobs UI **c2ef50e**, managed SVR **101 DONE**;
ERG/SHV/SVR restart-free, runtime/backend/config/IDs,64 management+9 portal
HTTP hashes/status/DNS passed. PROX-51 DONE; ADM7414433 unchanged; KLM deferred.
Next proposed Proxima page: Latency Audit. Note2026-10-11-scheduler-publication.md.

Latest2026-10-11: ProximaVPN page UI **dba79b2**, managed SVR **100 DONE**;
ERG/SHV/SVR published restart-free. Runtime/backend/config/IDs, 62 management
and 9 portal HTTP hashes, status and DNS passed. PROX-49 DONE, broader P3 active;
ADM7414433 unchanged, KLM deferred. Note2026-10-11-vpn-page-publication.md.

Latest2026-10-11: ProximaAdminsUIbe32c04 managedSVR99DONE, all3sites
restart-free/runtime/config/backend/60management+9portal hashes/healthPASS.
ADM7414433 unchanged; PROX-48DONE, broaderP3active; nextProximaVPN. KLMdeferred.

Latest2026-10-11: correctedSettingsUIcc886cd managedSVR98DONE, all3sites
runtime/backend/58management+9portal/health verified. Firstdesktopdesign rejected
byCan; new3address/2DNS/DDNS2x2 proposal accepted. SHVfirsttryrolledback;
peerfetch-onlydrift diagnosed, freshsnapshotretry passed; JSONnotrestored.

Latest2026-10-11: ProximaSettingsUIcde45dd managedSVR97DONE; ERG/SHV/SVR
runtime/config/backend/56management+9portal hashes/health preserved, no restart.
ADM7414433 unchanged, PROX-47 DONE; nextProximawebpageAdmins. KLM deferred.

Latest2026-10-11: Logs UI6bd0823 managedSVR96DONE, ERG/SHV/SVR verified
restart-free,54management+9portal HTTP hashes and runtime/config/health preserved.
ADM7414433 unchanged. PROX-46 DONE; nextwebscreenSettings. KLM deferred.

Latest2026-10-11: managed Proxima Keys UI63eecc3 published SVR95DONE;
ERG/SHV/SVR verification passed without restart. ADM7414433 unchanged.
PROX-45 closed; parentP3 active. KLM deferred; nextwebpageLogs.

### Current feature/UI outcome — 2026-10-11

ADM7414433 dialog guard deployed/public hashes verified; PROX-39 DONE.
Managed Proxima feature86b52b8 via publish-proxima-feature.yml: only2backend
modules over exact live images, raw runtime cloned, API verified before UI.
SVR operation93 DONE; subsequent toolbar a218e26 hot release operation94 DONE.
ERG/SHV/SVR live verification passed; KLM deferred. No full-main catch-up.
PROX-20/22/26 also closed; IPv6 work44 separate. See the new feature/UI note.

### Managed Groups publication — 2026-10-10

Proxima UI9d8b950 Groups batch is published restart-free on ERG/SHV/SVR.
Managed SVR operation92 is DONE. ADM UI/service was not redeployed for this
Proxima-only batch and remains7bd28ef. Independent live QA verified fresh
runtime/backend/static/config/ID baselines,46 management+9 portal hashes/site,
status/DNS, and queried92 from current service DB read-only. PROX-43 DONE;
parent P3 active. KLM deferred. Details in the new managed Groups note.

### Published Dashboard pilot and fresh recheck — 2026-10-10

ADM7bd28ef is committed/pushed/live via canonical deploy.sh; public index/three
bundle hashes and active service verified, previous UI privately retained.
Proxima0a8b7ea published restart-free on ERG/SHV/SVR; managed SVR operation91
DONE. Native optional argv/JSON envelope and Ansible syntax checks passed;
metadata9/wrapper10 tests passed. Use current ADM service venv for the operation
wrapper: system Python failed imports before creating an operation. Existing37
and historical89/90 untouched; KLM explicitly deferred.
Fresh user-requested checks at14:01–14:02UTC passed runtime/backend/static/DNS
and ADM identity. Later configuration changed through peer/self-service and
other paths; do not claim perpetual byte equality or erase that work. Details:
`continuity/sessions/notes/2026-10-10-dashboard-deployment.md`. Incremental
publication is now the requested pattern for later accepted cosmetic batches.

### Earlier local-only Dashboard checkpoint — 2026-10-10

Current cosmetic pilot changes Dashboard, ServerCard and VpnServerCard only:
header/action panel, tab spacing, coherent card heights/surfaces and metric
grouping. Build and437-key en/tr/ru parity passed. Actual App-shell synthetic
evidence216 cross-product cases, retained ADM subset; independent diff/security
reviews found no introduced issue. Final QA accepted scope after a separate
Proxima desktop chip correction. Existing ADM early deployment-dialog dismissal
is now LOW BUG PROX-39; not fixed in cosmetics. Details in the new pilot note.
PROX-36 is DONE with Can's current authorization; broader renewal remains open.
No commit/push/SSH/publication in this batch. Next ADM work: remaining foundation
and page/dialog batches, preserving current behavior. KLM remains deferred.

### Deployment checkpoint — current, 2026-10-09

**Final reachable-site outcome:** ADM UI362a746 public hashes verified. Proxima
UI0e765b8 published restart-free on ERG/SHV/SVR; raw runtime/ID/StartedAt,
backend manifests and network/mount settings match fresh complete snapshots.
All management40/portal8 HTTP hashes per site and DNS checks passed. Later peer
profile-fetch timestamps advanced normally; other config semantics unchanged.

Canonical managed playbook/parser commits6e85301/4783a41/25ec5ee were pulled
without restarting ADM. SVR operation89 FAILED at metadata reporting after
successful publisher exit0; do not rewrite its status or rerun publication.
The native-stdin/Python-repr issue was reproduced and fixed with a JSON envelope.
KLM operation90 UNREACHABLE, changed0; last online2026-10-06T23:00:29Z, no live
call-home handshake. KLM remains pending, no network workaround or site mutation.
Operation37 remains unchanged. Punchlist connector unauthorized; local handoff
is current, tracker backfill pending. See the new restart-free session note.

Can subsequently authorized commit/push/deploy and SSH. ADM **362a746** is
published and deployed via `adm/deploy.sh`; service active, local/public HTTP
200. Public index and main bundle hashes match the deployed build. Previous
static output remains in `adm/backend/static.prev` for rollback. No ADM backend
product-code delta was introduced by this cosmetic release.

Proxima **0e765b8** is pushed but its rollout is blocked. ERG frontend-only canary
recovered the original backend image/files and all 70 other running container
IDs; panel/portal/status HTTP 200 and DNS NOERROR. HostConfig differs from the
initial aggregate snapshot, with no original field-level snapshot to identify
the change. Independent QA recommends holding SHV/SVR/KLM. No managed-site
publication operation was started. ADM inventory discovery also found pre-existing
operation 37 (`enable_singbox`) still marked running; it was not altered or closed.

Can authorized agent-delegated, orchestrated cosmetic changes to ADM and Proxima
web only. Punchlist Proxima UI roadmap: PROX-32, P0–P4 PROX-33/36/35/34/37.
The full portable roadmap lives in Proxima `continuity/WEB-UI-ROADMAP.md`; master
plan Section 24. Maintain this ADM handoff locally rather than importing site
runtime assumptions. Current audit found a clean pre-change tree at `a392738`.

First local ADM batch: presentation-only `sx` in Dashboard, ServerCard and
VpnServerCard. Wrapping actions, stacked card headers, readable long text/chips
and metric shrink safeguards; all handlers/API/polling/permissions retained.
Independent QA first rejected compressed desktop status labels, then accepted
the corrected batch after fresh visual checks. Pre/post production builds passed;
437 en/tr/ru keys matched. Synthetic isolated component checks covered 48 remedy
cases (eight widths, three locales, two server tabs), 168 readable chip samples,
480 successful actionability trials and no page overflow. Full app-shell/auth,
live backend and deployment behavior were not tested. Existing nested-button
console warning remains outside this cosmetic patch. No commit/push/SSH/deploy.

Next: complete evidence-led cross-page review, then page hierarchy/spacing and
dialog/matrix/monitoring/docs cosmetic batches. See the dated
[session note](continuity/sessions/notes/2026-10-09-web-ui-cosmetics.md) and HANDOFF.

Open [the session catalog](continuity/sessions/INDEX.md) to choose a conversation;
[session instructions](continuity/SESSIONS.md) explain native restoration and
cross-agent readable continuation. Project state remains in this file and HANDOFF.

Read [AGENTS.md](AGENTS.md), this file and [HANDOFF.md](continuity/HANDOFF.md).
All required startup context is local. The old archive and absolute paths below
are optional historical references; no old AI installation or sibling workspace
is needed. Extended documentation is already inside
[adm/frontend/public/docs](adm/frontend/public/docs/).

Install Node.js 22.12+ and Python 3.12. For Linux provisioning work, also use a
Linux/WSL environment with Ansible; ordinary UI/backend edits do not require
connecting to managed servers. From this copied root:

```powershell
npm --prefix adm/frontend ci
npm --prefix adm/frontend run build
python -m venv .venv
```

Activate `.venv`, then run:

```powershell
python -m pip install -r adm/backend/requirements.txt pytest
```

Run `python -m pytest` from `adm/backend/`. Frontend development uses
`npm --prefix adm/frontend run dev`: port 3002, `/api` proxy to localhost:5002.
The backend entry is `adm/backend/app.py`; use a separate local test database
configured via `ADM_DB_PATH`, not a production database/service environment.
Source maps: `adm/backend/` API/core, `adm/frontend/src/` UI, `agent/` remote agent,
`roles/` and `playbooks/` provisioning. Deployment is documented by
`adm/deploy.sh` and the correction in HANDOFF; it needs a separate current request.

No fresh-machine build/test is claimed here. Keep current decisions, real check
results and the next task in these local documents as work proceeds.

## Identity and current state

Workspace/Git root: `D:\Nextcloud\Projects\proxima-node`.
Repository: `canergunay/proxima-node`; local HEAD **`6e8baf3`**, September 29,
2026. Verified locally on October 4; no remote fetch or runtime verification.

ADM provisions and monitors exit/DPI nodes and manages Proxima site servers,
central VPN accounts and access synchronization. Python/Flask, SQLite, Ansible,
React 19, TypeScript, MUI 6 and Vite 6. Sources: `CLAUDE.md:3–6,42–62`,
`adm/frontend/package.json`, `adm/backend/core/vpn_user_sync.py`.

Read `continuity/HANDOFF.md` before resuming product work. The last ADM-focused
request was to fix synchronization when a site is unavailable. The local code
contains that fix; historical records report deployment on September 29.
Current production status is unknown. The handoff separates unfinished work,
superseded assumptions, current code and historical observations.

## Optional private original archive — old machine

`C:\Users\caner\AppData\Local\OpenCode\continuity\proxima-node-0ffefe2adcf7`

`owner.json` binds this archive to this workspace. `current.json` selects
snapshot **`20261004T171914672859Z`**. Raw originals live in SHA-256-addressed
`objects/`; manifests and the sanitized SQLite search index live under
`snapshots/<snapshot>/`. The archive has a user+SYSTEM SID allow-list and is
outside the synchronized repository. This is **not an off-site backup**.

**Migration is partial against the full GOC criteria.** All 916 manifested raw
entries are preserved and their archive hashes pass. Twelve original temporary
files disappeared after successful initial capture; their verified archived
bytes survive. Thus 904 sources still match and `verify` intentionally exits 1.
Missing older revisions/origin sessions and unverified cloud resources are
listed in `continuity/MIGRATION.md` and private `verification.json`.

## Retrieval (PowerShell, from this root; Python 3.11+)

```powershell
python scripts/continuity.py search SiteGate --session 88824aa7-bbbe-47c2-bc5d-d55b7ea5d7d4 --limit 5
python scripts/continuity.py open --source 'C:\Users\caner\.claude\projects\d--Nextcloud-Projects-proxima\88824aa7-bbbe-47c2-bc5d-d55b7ea5d7d4.jsonl' --line 3174 --context 1
python scripts/continuity.py humans 88824aa7-bbbe-47c2-bc5d-d55b7ea5d7d4 --latest --limit 10
python scripts/continuity.py resolve 'D:\Nextcloud\Projects\proxima-node\adm\backend\core\proxima_client.py' --limit 5
python scripts/continuity.py locations image --session 96ed35d2-52b3-4fbf-aea3-4a5115d1aa12 --limit 3
python scripts/continuity.py verify
python scripts/continuity_verify.py
```

Search supports SQLite FTS5 expressions. `open` requires an exact original
source path and line, verifies/reopens the raw object and emits sanitized text
with raw location/hash. Context is measured in original source lines.
`locations tool_result` locates raw tool output; `sessions` provides session
source/date/count metadata. `resolve` also uses cwd-backed relative file-history
paths. Missing results exit 1; malformed queries/operation errors exit 2.

`verify` exits 1 for source loss or integrity mismatches. The detailed verifier
currently exits 0 when archive/retrieval checks pass and the **explicitly recorded
12 source losses** are the only source differences. Its success does not mean
full GOC completion. `--record` writes a new verification report; plain retrieval
and verification are read-only. `discover`, `capture`, and `index` are explicit
archive-writing commands, not startup actions.

Redaction is best-effort and deliberately conservative. Structured sensitive
fields are withheld before flattening; multiline documents are sanitized before
line indexing. Never dump raw objects or raw settings into chat or Git.
The full mixed containers are searchable, but results carry scope labels;
`ADM-path-evidence` is path attribution, not a claim that every message under
that cwd is an ADM decision. Parent UUIDs, queue/resume records and raw metadata
are retained; imported/queued copies are not unique human conversations.

## Further reading

- `continuity/HANDOFF.md`: source-backed current/historical/uncertain context.
- `continuity/MIGRATION.md`: measured preservation, checks, limitations and files.
- `CLAUDE.md`: original project instructions, unchanged. Its scp deployment
  instructions are superseded by the checked-in `adm/deploy.sh`; see handoff.
