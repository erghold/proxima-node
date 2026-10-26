"""Push central VPN users down to the Proxima instances.

Every access row marked `pending` is created or updated on its instance, and
every row marked `pending_delete` has its remote account removed.

Ownership is split rather than exclusive. ADM decides who exists, where they
are authorized, and the limits; the user owns their own devices and may
change their own password from the client. So the push is authoritative for
every field *except* the password, which it carries only when ADM set it more
recently than the last push delivered one — see _password_is_ours.

Revocation deletes the remote account **with its peers**. A WireGuard peer
keeps working on its own keys regardless of whether the owning account still
exists — leaving the peers behind would mean "revoked" access that still
carries traffic. Use disable (enabled=0) when the intent is to suspend an
account without destroying its devices.

A site that does not answer holds up nobody but itself. Its rows are set
aside as *waiting* — still pending, retried by the scheduler — and the run
goes on to the sites that are up. See SiteGate.
"""

import json
import logging

from core.db import (
    delete_user_access,
    get_all_vpn_servers,
    get_all_vpn_users,
    get_pending_access,
    get_user_access,
    mark_access_error,
    mark_access_synced,
    update_vpn_user,
)
from core.proxima_client import SiteGate, waiting_note

log = logging.getLogger("adm.vpn_user_sync")


def _remote_payload(row: dict) -> dict:
    """Fields a Proxima instance stores for a user."""
    try:
        groups = json.loads(row.get("assigned_groups") or "[]")
    except (ValueError, TypeError):
        groups = []
    try:
        profiles = json.loads(row.get("allowed_profiles") or "[]")
    except (ValueError, TypeError):
        profiles = []
    return {
        "max_peers": row["max_peers"],
        "bandwidth_quota": row["bandwidth_quota"],
        "speed_download": row["speed_download"],
        "speed_upload": row["speed_upload"],
        "assigned_groups": groups,
        "allowed_profiles": profiles,
        "lan_access": bool(row["lan_access"]),
        "allow_smart_test": type(row.get("allow_smart_test")) in (bool, int)
        and row["allow_smart_test"] == 1,
    }


def _effective_enabled(row: dict) -> bool:
    """A user is active on a server only if both the account and the grant are."""
    return bool(row["user_enabled"]) and bool(row["enabled"])


def _password_is_ours(row: dict) -> bool:
    """Should this push carry the password?

    Only when ADM set it more recently than the last push that delivered it.
    Users may change their own password from the client, and a push triggered
    by something unrelated — a peer limit, a LAN toggle — must not silently
    put the old one back. An admin who sets a new password bumps the stamp
    and wins on the next push, which is the intended precedence.
    """
    changed = row.get("password_changed_at") or 0
    synced = row.get("password_synced_at") or 0
    return changed > synced


def _password_for_new_grant(row: dict, servers: dict, gate: SiteGate) -> str:
    """The hash to seed a brand-new account on a site with.

    ADM's stored hash is not always the current one: a user may have changed
    their password from the client since it was issued. Adding them to a
    second site should give them the password they actually use, so the hash
    is copied from a site they already have — which carries the password
    without ADM ever learning it.

    ADM's own hash wins when the admin set a password that has not reached
    any site yet; that is a deliberate reset and must not be undone.
    """
    access = get_user_access(row["user_id"])
    synced = [
        a for a in access
        if a["vpn_server_id"] != row["vpn_server_id"]
        and a.get("remote_user_id") is not None
        and a["sync_status"] == "synced"
    ]
    if not synced:
        return row["password_hash"]

    changed = row.get("password_changed_at") or 0
    last_push = max((a.get("password_synced_at") or 0) for a in synced)
    if changed > last_push:
        return row["password_hash"]

    for a in synced:
        srv = servers.get(a["vpn_server_id"])
        if not srv:
            continue
        data, error = gate.call(srv, "GET", "/api/vpn/users")
        if error or not isinstance(data, list):
            continue
        for user in data:
            if user.get("username") == row["username"] and user.get("password_hash"):
                log.info(f"[SYNC] Seeding '{row['username']}' from {a['server_name']} "
                         "so the password they use today keeps working")
                return user["password_hash"]

    return row["password_hash"]


def _find_remote_by_username(server: dict, username: str, gate: SiteGate) -> int | None:
    """Look up an existing remote account by username."""
    data, error = gate.call(server, "GET", "/api/vpn/users")
    if error or not isinstance(data, list):
        return None
    for user in data:
        if user.get("username") == username:
            return user.get("id")
    return None


def _push_delete(server: dict, row: dict, gate: SiteGate) -> tuple[bool, str | None, str]:
    remote_id = row.get("remote_user_id")
    if remote_id is None:
        delete_user_access(row["user_id"], row["vpn_server_id"])
        return True, None, "removed"

    _, error = gate.call(
        server, "DELETE", f"/api/vpn/users/{remote_id}?cascade=true"
    )
    # Already gone remotely is the desired end state, not a failure.
    if error and "not found" not in error.lower():
        return False, error, "removed"

    delete_user_access(row["user_id"], row["vpn_server_id"])
    log.info(f"[SYNC] Removed '{row['username']}' from {row['server_name']} "
             f"(remote id {remote_id}, peers deleted)")
    return True, None, "removed"


def _push_create(server: dict, row: dict, servers: dict,
                 gate: SiteGate) -> tuple[bool, str | None, str]:
    body = {
        "username": row["username"],
        "password_hash": _password_for_new_grant(row, servers, gate),
    }
    body.update(_remote_payload(row))

    data, error = gate.call(server, "POST", "/api/vpn/users", body=body)

    if error and "already exists" in error.lower():
        # Adopt the existing account rather than failing — this happens when a
        # previous run created it but could not record the id. Report it as an
        # adoption, not a creation: nothing new appeared on the instance.
        remote_id = _find_remote_by_username(server, row["username"], gate)
        if remote_id is None:
            return False, "Remote user exists but could not be located", "adopted"
        ok, err, _ = _push_update(server, {**row, "remote_user_id": remote_id},
                                  servers, gate)
        return ok, err, "adopted"

    if error:
        return False, error, "created"

    remote_id = (data or {}).get("id")
    if remote_id is None:
        return False, "Create succeeded but returned no id", "created"

    # Proxima creates users enabled; suspend right away when the grant says so.
    if not _effective_enabled(row):
        _, err = gate.call(server, "PUT", f"/api/vpn/users/{remote_id}",
                           body={"enabled": False})
        if err:
            return False, f"Created but could not disable: {err}", "created"

    mark_access_synced(row["id"], remote_user_id=remote_id, password_pushed=True)
    log.info(f"[SYNC] Created '{row['username']}' on {row['server_name']} "
             f"(remote id {remote_id})")
    return True, None, "created"


def _push_update(server: dict, row: dict, servers: dict,
                 gate: SiteGate) -> tuple[bool, str | None, str]:
    remote_id = row["remote_user_id"]
    send_password = _password_is_ours(row)
    body = {"enabled": _effective_enabled(row)}
    if send_password:
        body["password_hash"] = row["password_hash"]
    body.update(_remote_payload(row))

    _, error = gate.call(server, "PUT", f"/api/vpn/users/{remote_id}", body=body)

    if error and "not found" in error.lower():
        # Deleted on the instance behind ADM's back — recreate it.
        log.warning(f"[SYNC] '{row['username']}' missing on {row['server_name']}, "
                    "recreating")
        ok, err, _ = _push_create(server, {**row, "remote_user_id": None},
                                  servers, gate)
        return ok, err, "recreated"

    if error:
        return False, error, "updated"

    mark_access_synced(row["id"], remote_user_id=remote_id,
                       password_pushed=send_password)
    log.info(f"[SYNC] Updated '{row['username']}' on {row['server_name']}"
             + ("" if send_password else " (password left as-is)"))
    return True, None, "updated"


def reconcile_passwords() -> dict:
    """Carry a self-service password change to the user's other sites.

    A user changes their password on whichever instance their client is
    talking to, which leaves the others behind. Left alone that is fine
    today — people log into each site separately — but the planned client
    logs in once and expects one credential everywhere, so the sites have to
    converge.

    ADM cannot compare passwords (hashes are salted, and it holds no
    plaintext), so it compares *when* each site last had one set and copies
    the newest hash to the rest. That moves the password without ADM ever
    learning it.
    """
    servers = {s["id"]: s for s in get_all_vpn_servers()}
    gate = SiteGate()

    # Remote records per (server, username), fetched once.
    remote: dict[int, dict[str, dict]] = {}
    unreachable: list[str] = []
    for sid, srv in servers.items():
        data, error = gate.call(srv, "GET", "/api/vpn/users")
        if error or not isinstance(data, list):
            unreachable.append(srv["name"])
            continue
        remote[sid] = {u["username"]: u for u in data if u.get("username")}

    propagated, skipped = [], []

    for user in get_all_vpn_users():
        present = [
            (a, remote[a["vpn_server_id"]][user["username"]])
            for a in get_user_access(user["id"])
            if a["vpn_server_id"] in remote
            and user["username"] in remote[a["vpn_server_id"]]
        ]
        if len(present) < 2:
            continue

        hashes = {r.get("password_hash") for _, r in present}
        if len(hashes) <= 1:
            continue  # already identical, nothing to do

        # Newest wins. Without a timestamp on every side there is no safe
        # way to pick, so leave it rather than guess and clobber someone.
        stamped = [(a, r) for a, r in present if r.get("password_changed_at")]
        if len(stamped) != len(present):
            skipped.append({
                "username": user["username"],
                "reason": "an instance did not report password_changed_at",
            })
            continue

        newest_access, newest = max(stamped, key=lambda ar: ar[1]["password_changed_at"])
        winning_hash = newest["password_hash"]

        for access, record in present:
            if record.get("password_hash") == winning_hash:
                continue
            srv = servers[access["vpn_server_id"]]
            _, error = gate.call(srv, "PUT", f"/api/vpn/users/{record['id']}",
                                 body={"password_hash": winning_hash})
            target = f"{user['username']}@{access['server_name']}"
            if error:
                skipped.append({"username": user["username"], "reason": error})
                log.warning(f"[RECONCILE] {target}: {error}")
                continue
            propagated.append({
                "target": target,
                "from": newest_access["server_name"],
            })
            log.info(f"[RECONCILE] {target} <- password from "
                     f"{newest_access['server_name']}")

        # Keep ADM's copy in step so its own pushes do not undo this.
        if winning_hash != user["password_hash"]:
            update_vpn_user(user["id"], {"password_hash": winning_hash})

    if propagated or skipped:
        log.info(f"[RECONCILE] propagated={len(propagated)} skipped={len(skipped)}")

    return {
        "propagated": propagated,
        "skipped": skipped,
        "unreachable_servers": unreachable,
    }


def sync_pending(vpn_server_id: int | None = None,
                 user_id: int | None = None,
                 allowed_server_ids: list[int] | None = None,
                 gate: SiteGate | None = None) -> dict:
    """Reconcile pending rows, optionally narrowed to a server or user.

    allowed_server_ids confines the push to what the caller is entitled to
    write. A site admin editing someone who also belongs to another site
    would otherwise flush that other site's pending changes too — an
    out-of-scope write they never asked for.

    Rows of a site that does not answer come back under `deferred`, not
    `failed`: nothing was refused, the change is still queued, and the sites
    that are up were served regardless.
    """
    gate = gate or SiteGate()
    rows = get_pending_access(vpn_server_id)
    if user_id is not None:
        rows = [r for r in rows if r["user_id"] == user_id]
    if allowed_server_ids is not None:
        rows = [r for r in rows if r["vpn_server_id"] in allowed_server_ids]

    servers = {s["id"]: s for s in get_all_vpn_servers()}

    # Keyed by what actually happened on the instance, not by what was
    # attempted — an adoption or a recreate must not be reported as a create.
    done: dict[str, list[str]] = {
        "created": [], "adopted": [], "updated": [], "recreated": [], "removed": [],
    }
    failed: list[dict] = []
    deferred: list[dict] = []

    def defer(row: dict, label: str, reason: str) -> None:
        note = waiting_note(reason)
        # The scheduler comes back to a waiting row every few minutes; do not
        # rewrite the same sentence into the database each time.
        if row.get("sync_error") != note:
            mark_access_error(row["id"], note)
        deferred.append({"target": label, "server": row["server_name"], "error": reason})

    for row in rows:
        server = servers.get(row["vpn_server_id"])
        label = f"{row['username']}@{row['server_name']}"

        if not server:
            mark_access_error(row["id"], "VPN server missing")
            failed.append({"target": label, "error": "VPN server missing"})
            continue

        # A revocation that never reached the site needs no network at all;
        # everything else waits if the site is already known to be down.
        local_only = (row["sync_status"] == "pending_delete"
                      and row.get("remote_user_id") is None)
        reason = None if local_only else gate.down_reason(server)
        if reason:
            defer(row, label, reason)
            continue

        if row["sync_status"] == "pending_delete":
            ok, error, action = _push_delete(server, row, gate)
        elif row.get("remote_user_id") is None:
            ok, error, action = _push_create(server, row, servers, gate)
        else:
            ok, error, action = _push_update(server, row, servers, gate)

        if ok:
            done[action].append(label)
        elif gate.is_down(server):
            # This row is the one that found the site down.
            defer(row, label, gate.down_reason(server))
        else:
            mark_access_error(row["id"], error or "Unknown error")
            failed.append({"target": label, "error": error, "action": action})
            log.warning(f"[SYNC] Failed {label} ({action}): {error}")

    unreachable = sorted({d["server"] for d in deferred})
    summary = (" ".join(f"{k}={len(v)}" for k, v in done.items())
               + f" failed={len(failed)} deferred={len(deferred)}"
               + (f" (waiting for {', '.join(unreachable)})" if unreachable else ""))
    if failed or any(done.values()):
        log.info(f"[SYNC] {summary}")
    else:
        log.debug(f"[SYNC] {summary}")

    return {**done, "failed": failed, "deferred": deferred,
            "unreachable_servers": unreachable}
