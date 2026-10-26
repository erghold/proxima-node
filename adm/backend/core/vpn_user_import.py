"""One-time import of the per-server VPN users into the central table.

Reads `/api/vpn/users` from every registered Proxima instance and folds the
rows into central identities keyed by **username** — never by id. The same
person can have different local ids on different servers (adil.caglayan is
id 5 on ERG and id 6 on SHV), and two people can coincidentally share an id.

Existing password hashes are carried over verbatim so that nobody has to
change their password because of the migration. Where the same username
exists on several servers with *different* passwords, one has to win; those
cases are reported up front instead of being resolved silently.
"""

import json
import logging
from concurrent.futures import ThreadPoolExecutor

from core.db import (
    create_vpn_user,
    get_access,
    get_all_vpn_servers,
    get_vpn_user_by_username,
    mark_access_synced,
    upsert_user_access,
)
from core.proxima_client import call

log = logging.getLogger("adm.vpn_user_import")

# Per-server limit fields copied verbatim from the remote user row.
LIMIT_FIELDS = ("max_peers", "bandwidth_quota", "speed_download", "speed_upload")


def _fetch_server_users(server: dict) -> dict:
    """Fetch the VPN users of one Proxima instance."""
    data, error = call(server, "GET", "/api/vpn/users", timeout=20)
    if error is None and not isinstance(data, list):
        # Treating an unexpected shape as "zero users" would silently import
        # nothing from this server and look like success.
        error = f"Unexpected response shape: {type(data).__name__}"
    return {
        "vpn_server_id": server["id"],
        "server_name": server["name"],
        "server_display_name": server["display_name"],
        "online": error is None,
        "error": error,
        "users": data if error is None else [],
    }


def fetch_all() -> list[dict]:
    """Fetch users from every registered Proxima instance, in parallel."""
    servers = get_all_vpn_servers()
    if not servers:
        return []
    with ThreadPoolExecutor(max_workers=min(len(servers), 5)) as pool:
        return list(pool.map(_fetch_server_users, servers))


def _source_from_remote(fetched: dict, user: dict) -> dict:
    return {
        "vpn_server_id": fetched["vpn_server_id"],
        "server_name": fetched["server_name"],
        "server_display_name": fetched["server_display_name"],
        "remote_user_id": user["id"],
        "enabled": bool(user.get("enabled", 1)),
        "lan_access": bool(user.get("lan_access", 1)),
        "allow_smart_test": type(user.get("allow_smart_test")) in (bool, int)
        and user["allow_smart_test"] == 1,
        "peer_count": user.get("peer_count", 0),
        "max_peers": user.get("max_peers"),
        "bandwidth_quota": user.get("bandwidth_quota"),
        "speed_download": user.get("speed_download"),
        "speed_upload": user.get("speed_upload"),
        "assigned_groups": user.get("assigned_groups") or [],
        "_password_hash": user.get("password_hash"),
        "_password_plain": user.get("password_plain"),
    }


def build_preview() -> dict:
    """What the import would do, without changing anything."""
    fetched = fetch_all()

    by_username: dict[str, list[dict]] = {}
    for f in fetched:
        for user in f["users"]:
            username = (user.get("username") or "").strip()
            if username:
                by_username.setdefault(username, []).append(_source_from_remote(f, user))

    entries = []
    for username, sources in sorted(by_username.items()):
        sources.sort(key=lambda s: s["vpn_server_id"])
        central = get_vpn_user_by_username(username)

        # Same password everywhere? Only decidable when every server could
        # produce the plaintext; otherwise it stays unknown and the operator
        # has to make the call.
        plains = [s["_password_plain"] for s in sources]
        if len(sources) < 2:
            passwords_match = True
        elif any(p is None for p in plains):
            passwords_match = None
        else:
            passwords_match = len(set(plains)) == 1

        # Default to the server where the user has the most peers — that is
        # almost always their primary site.
        primary = max(sources, key=lambda s: (s["peer_count"], -s["vpn_server_id"]))

        entries.append({
            "username": username,
            "already_central": central is not None,
            "central_user_id": central["id"] if central else None,
            "conflict": len(sources) > 1,
            "passwords_match": passwords_match,
            "suggested_primary_server_id": primary["vpn_server_id"],
            "sources": [
                {k: v for k, v in s.items() if not k.startswith("_")}
                for s in sources
            ],
        })

    return {
        "servers": [
            {k: v for k, v in f.items() if k != "users"} | {"user_count": len(f["users"])}
            for f in fetched
        ],
        "entries": entries,
        "summary": {
            "total": len(entries),
            "conflicts": sum(1 for e in entries if e["conflict"]),
            "already_central": sum(1 for e in entries if e["already_central"]),
            "password_mismatch": sum(
                1 for e in entries if e["conflict"] and e["passwords_match"] is not True
            ),
        },
    }


def apply_import(selections: list[dict]) -> dict:
    """Import the selected usernames.

    `selections` is a list of {username, primary_server_id}. Data is re-read
    live from the instances rather than trusted from the request body.
    """
    wanted = {
        (s.get("username") or "").strip(): s.get("primary_server_id")
        for s in selections
        if (s.get("username") or "").strip()
    }
    if not wanted:
        return {"created": [], "linked": [], "skipped": [], "password_overrides": []}

    fetched = fetch_all()
    offline = [f["server_name"] for f in fetched if not f["online"]]

    by_username: dict[str, list[dict]] = {}
    for f in fetched:
        for user in f["users"]:
            username = (user.get("username") or "").strip()
            if username in wanted:
                by_username.setdefault(username, []).append(_source_from_remote(f, user))

    created, linked, skipped, overrides = [], [], [], []

    for username, primary_server_id in wanted.items():
        sources = by_username.get(username)
        if not sources:
            skipped.append({"username": username, "reason": "not found on any server"})
            continue

        # The primary supplies the central password, so it has to be a source
        # that actually returned a hash — fall back rather than drop the user.
        candidates = [s for s in sources if s["_password_hash"]]
        if not candidates:
            skipped.append({"username": username, "reason": "no password hash returned"})
            continue
        primary = next(
            (s for s in candidates if s["vpn_server_id"] == primary_server_id),
            candidates[0],
        )

        central = get_vpn_user_by_username(username)
        if central:
            user_id = central["id"]
            linked.append(username)
        else:
            user_id = create_vpn_user({
                "username": username,
                "password_hash": primary["_password_hash"],
                "enabled": primary["enabled"],
                "note": "imported",
            })
            created.append(username)

        plains = {s["vpn_server_id"]: s["_password_plain"] for s in sources}
        primary_plain = plains.get(primary["vpn_server_id"])

        for src in sources:
            # A revocation waiting to be pushed must not be undone by a re-run.
            existing = get_access(user_id, src["vpn_server_id"])
            if existing and existing["sync_status"] == "pending_delete":
                skipped.append({
                    "username": username,
                    "reason": f"access on {src['server_name']} is pending removal",
                })
                continue

            access_id = upsert_user_access(user_id, src["vpn_server_id"], {
                "remote_user_id": src["remote_user_id"],
                "enabled": 1 if src["enabled"] else 0,
                "lan_access": 1 if src["lan_access"] else 0,
                "allow_smart_test": int(src["allow_smart_test"]),
                "assigned_groups": json.dumps(src["assigned_groups"]),
                **{f: src[f] for f in LIMIT_FIELDS},
            })

            # The remote row already matches the central record when it is the
            # primary, or when both plaintexts are known to be identical.
            # Anything else needs a push that will overwrite the remote
            # password — surface it instead of doing it quietly.
            same_password = (
                src["vpn_server_id"] == primary["vpn_server_id"]
                or (primary_plain is not None
                    and plains[src["vpn_server_id"]] == primary_plain)
            )
            if same_password:
                mark_access_synced(access_id, remote_user_id=src["remote_user_id"])
            else:
                overrides.append({
                    "username": username,
                    "server_name": src["server_name"],
                    "vpn_server_id": src["vpn_server_id"],
                })

    log.info(f"[IMPORT] created={len(created)} linked={len(linked)} "
             f"skipped={len(skipped)} password_overrides={len(overrides)}")

    return {
        "created": created,
        "linked": linked,
        "skipped": skipped,
        "password_overrides": overrides,
        "offline_servers": offline,
    }
