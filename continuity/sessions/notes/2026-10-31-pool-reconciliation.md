# Local pool reconciliation

Can authorized local reconciliation. Fetched origin and merged 7ac777d into local
pool history on `integrate/location-pools-20261031`, in
`C:/Users/caner/AppData/Local/Temp/opencode/adm-pools-reconciled-20261031`.
Original dirty main remains untouched. No push, deployment or live mutation.

Resolved additive conflicts by keeping v2 catalog semantics, the v1 manifest
schema filter and routes-cache migration, together with upstream deletion_pending
migration/types and all user-deletion translations. Both continuity histories stay.
Upstream provisioning, durable user deletion and update-channel fixes are retained.

Verification:
- Full backend suite: 372 passed, 8 skipped in 375.26 seconds.
- The 8 skips were companion-checkout discovery. Re-ran the unchanged integration
  fixtures with a temporary pytest plugin pointing SITE_BACKEND at the actual
  reconciled SITE backend and removing that path-only skip: 8 passed in 10.64s.
  The plugin is Temp/opencode/test-reconciled-pair.py; no sockets/live DBs involved.
- Frontend production build passed; en/tr/ru parity passed with 474 keys.
- Independent read-only review found no merge-introduced production regression in
  deletion guards, durable revocation, migrations or v1/v2 authorization separation.
- Whitespace/conflict checks passed. No product source correction beyond conflict
  resolution was required. Live failover and human acceptance remain pending.

Use this integration branch for future release preparation. Original main was not
fast-forwarded through its unrelated uncommitted infrastructure/history changes.
Publication, production grants and installed Windows service changes require their
own authority; local reconciliation does not authorize them.
