"""Version two pools select existing site routes, never attachment runtimes."""

import json
import time
import uuid
from urllib.parse import urlsplit

# The existing inventory poll runs every five minutes; failed polls invalidate immediately.
CACHE_MAX_AGE = 360
KINDS = {"smart", "lan_only", "full_tunnel"}


def routes(site):
    try:
        cached = json.loads(site.get("routes_cache") or "[]")
    except (ValueError, TypeError):
        cached = []
    if not isinstance(cached, list):
        cached = []
    stamp = site.get("routes_cached_at")
    fresh = type(stamp) is int and 0 <= time.time() - stamp <= CACHE_MAX_AGE
    return [{"route_id": r["route_id"], "label": r["label"], "kind": r["kind"],
             "enabled": r.get("enabled") is True, "available": fresh and r.get("available") is True,
             "stale": not fresh}
            for r in cached if isinstance(r, dict) and isinstance(r.get("route_id"), str)
            and isinstance(r.get("label"), str) and isinstance(r.get("kind"), str) and r["kind"] in KINDS]


def definition(conn, data, previous=None):
    fields = {"schema_version", "label", "kind", "enabled", "members"}
    if previous:
        fields.add("policy_revision")
    if set(data) != fields or type(data.get("schema_version")) is not int or data["schema_version"] != 2:
        raise ValueError("invalid_v2_pool_fields")
    if not isinstance(data["label"], str) or not data["label"].strip() or len(data["label"]) > 100:
        raise ValueError("invalid_label")
    if not isinstance(data["kind"], str) or data["kind"] not in KINDS or type(data["enabled"]) is not bool:
        raise ValueError("invalid_kind_or_enabled")
    if not isinstance(data["members"], list) or not 1 <= len(data["members"]) <= 64:
        raise ValueError("invalid_members")
    old = {(m["site_id"], m["route_id"]): m for m in (previous or {}).get("members", [])}
    members, seen = [], set()
    for member in data["members"]:
        if not isinstance(member, dict) or set(member) != {"site_id", "route_id"} or type(member["site_id"]) is not int or not isinstance(member["route_id"], str):
            raise ValueError("invalid_member")
        key = member["site_id"], member["route_id"]
        if key in seen:
            raise ValueError("duplicate_member")
        seen.add(key)
        site = conn.execute("SELECT * FROM vpn_servers WHERE id=?", (member["site_id"],)).fetchone()
        if not site:
            raise ValueError("unknown_site")
        route = next((r for r in routes(dict(site)) if r["route_id"] == member["route_id"] and r["kind"] == data["kind"]), None)
        if not route and not (key in old and previous["kind"] == data["kind"]):
            raise ValueError("unknown_route")
        members.append({"id": old[key]["id"] if key in old else str(uuid.uuid4()), **member})
    return {"schema_version": 2, "id": previous["id"] if previous else str(uuid.uuid4()),
            "policy_revision": previous["policy_revision"] + 1 if previous else 1,
            "label": data["label"].strip(), "kind": data["kind"], "members": members}


def authorized_catalog(conn, user_id):
    output = {"schema_version": 2, "pools": []}
    user = conn.execute("SELECT * FROM vpn_users WHERE id=?", (user_id,)).fetchone()
    if not user or user["enabled"] != 1 or user["allow_pools"] != 1 or dict(user).get("deletion_pending"):
        return output
    access = {a["vpn_server_id"]: dict(a) for a in conn.execute(
        "SELECT * FROM vpn_user_access WHERE user_id=? AND enabled=1 AND sync_status='synced' "
        "AND typeof(remote_user_id)='integer' AND remote_user_id>0", (user_id,))}
    for row in conn.execute("SELECT c.* FROM pool_catalog c JOIN pool_grants g ON g.pool_id=c.id WHERE g.account_id=? AND c.enabled=1 ORDER BY c.id", (user["account_id"],)):
        pool = json.loads(row["definition"])
        if type(pool.get("schema_version")) is not int or pool["schema_version"] != 2:
            continue
        members = []
        for member in pool["members"]:
            grant = access.get(member["site_id"])
            site = conn.execute("SELECT * FROM vpn_servers WHERE id=?", (member["site_id"],)).fetchone()
            if not grant or not site:
                continue
            route = next((r for r in routes(dict(site)) if r["route_id"] == member["route_id"] and r["kind"] == pool["kind"] and r["enabled"] and r["available"]), None)
            try:
                url = urlsplit(site["public_url"] or "")
                if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
                    continue
                profiles = json.loads(grant["allowed_profiles"] or "[]")
                groups = json.loads(grant["assigned_groups"] or "[]")
            except (ValueError, TypeError):
                continue
            if not route:
                continue
            if pool["kind"] == "smart" and (grant["allow_smart_test"] != 1 or groups != [] or any(grant[k] is not None for k in ("speed_download", "speed_upload", "bandwidth_quota"))):
                continue
            if pool["kind"] == "lan_only" and grant["lan_access"] != 1:
                continue
            if pool["kind"] == "full_tunnel" and (not isinstance(profiles, list) or member["route_id"] not in profiles):
                continue
            members.append({**member, "public_url": site["public_url"].rstrip("/"), "label": route["label"]})
        if members:
            output["pools"].append({k: pool[k] for k in ("id", "label", "kind", "policy_revision")} | {"members": members})
    return output
