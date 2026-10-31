# Dedicated ERG exit identities

Can authorized SSH, implementation, commit/push and provisioning, including shared
Xray restart interruptions. Revisions dde5caf/9dba496/c594e9b are pushed and present
in the live ADM checkout. This deploys provisioning tooling, not a web-service
restart or beta publication.

`playbooks/add-xray-client.yml` adds a dedicated stable erg-slot-N identity to an
existing listener, with protected profiles, exact parser validation, transactional
backup/recovery and idempotence. Original clients and Reality keys are retained;
normal installation preserves existing configuration rather than rendering a
singleton over it. Install output no longer prints credentials.

Ten dedicated identities were created across Yotta/Hetzner/TR Fast/Hostkey/PL/FI.
Existing keys/configuration were compared to pre-task backups. Only new ERG
identities on the five usable exits receive an IPv4 domain-resolution outbound;
legacy outbound/routing behavior is unchanged. Hetzner's public8443 path failed,
although the same listener/credential/numeric target worked through management;
its two new identities are prepared but unused in ERG production pools.

The initial staged-file parser rejected extensionless files before any config
replacement or restart. Explicit `-format json` fixed it; actual Xray25.4.30 parser
checks passed. Independent17transaction/isolation tests passed, as did Ansible
syntax and live provisioning. Existing node backups are under
`/root/erg-exit-pre-migration-20261029/xray.tar.gz`; profiles are0600 in
`/opt/xray-reality/client-profiles/`. Credentials remain off chat and git.

HOMELAB management10.12.12.106 is reachable but configured SSH access failed,
including one attempt using the current ADM credential vault. Do not recover
credentials from history or disable host verification. Working access is needed
for its remaining AWG exit. No paid resource was created.

SITE release986fbb7 migrated six slots in place, preserves24 original peers and
users/grants, and records traffic/LAN/fail-closed/restart results in its continuity
note. Three-round measurements do not establish a general VLESS speed advantage.
Full reboot, long soak, automatic scheduler timing and human acceptance remain
open. No changes to SVR/SHV routing; only authorized exit-service interruptions.
