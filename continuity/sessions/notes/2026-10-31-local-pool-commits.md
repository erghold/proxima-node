# Local pool commits

Current authority is local commits only. d61b23c contains v2 catalog/sync and its
required v1 pool identity/revocation helpers, regression fixtures and API docs.
92e0f42 contains ADM management UI, explicit member order/grants and en/tr/ru.
No server restart, grant change, remote fetch/push or deployment occurred.

An index-only archive tested the actually staged backend without local untracked
dependencies:20 location cases passed in19.22s. An initial combined transport run
reached120s after progress without reported assertion failures; no full-pass claim.
Frontend files staged are exactly the previously built/tested working-tree files.

Provisioning, management watchdog, strategy probes and historical cross-repo runtime
fixtures remain preserved and unstaged. The existing upstream ref contains9 commits
absent from this older local branch. Future release preparation must reconcile that
history; these commits are not permission to overwrite current deployed code.
