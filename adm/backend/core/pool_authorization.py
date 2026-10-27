"""One effective catalog selection for discovery and attachment authorization."""

import hashlib
import ipaddress
import json
from urllib.parse import urlsplit

COMBINATIONS = {("vless_reality", "fast", "sing_box"),
                ("amneziawg", "fast", "awg"), ("amneziawg", "lan_only", "awg")}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def authorized_manifest(conn, user):
    access = {a["vpn_server_id"]: a for a in conn.execute(
        "SELECT a.* FROM vpn_user_access a JOIN vpn_servers s ON s.id=a.vpn_server_id "
        "WHERE a.user_id=? AND a.enabled=1 AND a.sync_status!='pending_delete' "
        "AND typeof(a.remote_user_id)='integer' AND a.remote_user_id>0", (user["id"],))}
    pools = []
    for row in conn.execute("SELECT c.* FROM pool_catalog c JOIN pool_grants g ON g.pool_id=c.id WHERE g.account_id=? AND c.enabled=1 ORDER BY c.id", (user["account_id"],)):
        pool = json.loads(row["definition"])
        if any(r["site_id"] not in access or access[r["site_id"]]["lan_access"] != 1
               for r in pool["lan_resource_set"]["resources"]):
            continue
        members = []
        for member in pool["members"]:
            if member["site_id"] not in access:
                continue
            site = conn.execute("SELECT public_url FROM vpn_servers WHERE id=?", (member["site_id"],)).fetchone()
            url = site[0] if site else None
            try:
                parsed = urlsplit(url or "")
            except ValueError:
                continue
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                continue
            members.append({**member, "api_url": url.rstrip("/"), "eligible": False,
                            "reason": "attachment_not_provisioned"})
        if members:
            pool["members"] = members
            pools.append(pool)
    # Preserve the existing manifest revision encoding.
    revision = hashlib.sha256(json.dumps(pools, sort_keys=True).encode()).hexdigest()
    return {"schema_version": 1, "account_id": user["account_id"],
            "authorization_revision": revision, "pools": pools}, access


def attachment_policy(conn, pool, member, binding, access):
    combo = tuple(binding[k] for k in ("connection_type", "routing_mode", "profile_format"))
    if (combo not in COMBINATIONS or pool["routing_modes"] != [binding["routing_mode"]]
            or set(binding) != {"id", "connection_type", "routing_mode", "profile_format"}
            or pool["local_lan"] != "preserve"
            or pool["internet_bypass"] != ("none" if binding["routing_mode"] == "fast" else "unmanaged")):
        raise ValueError("unsupported_binding")
    if set(pool["lan_resource_set"]) != {"id", "revision", "resources"}:
        raise ValueError("unsupported_lan_scope")
    resources = pool["lan_resource_set"]["resources"]
    if any(set(r) != {"id", "site_id", "cidrs"} for r in resources):
        raise ValueError("unsupported_lan_scope")
    needed = {member["site_id"]} | {r["site_id"] for r in resources}
    dependencies = []
    cidrs = set()
    scopes = []
    private = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    for sid in sorted(needed):
        grant = access[sid]
        # Legacy Direct slots and explicit pool bindings are independent grants.
        profiles = json.loads(grant["allowed_profiles"] if grant["allowed_profiles"] is not None else "[]")
        if (any(grant[k] is not None for k in ("max_peers", "bandwidth_quota"))
                or any(grant[k] not in (None, "") for k in ("speed_download", "speed_upload"))
                or json.loads(grant["assigned_groups"] if grant["assigned_groups"] is not None else "[]") != []
                or not isinstance(profiles, list) or any(not isinstance(p, str) or not p.strip() for p in profiles)):
            raise ValueError("unsupported_site_restrictions")
        site = conn.execute("SELECT * FROM vpn_servers WHERE id=?", (sid,)).fetchone()
        needs_lan = any(r["site_id"] == sid for r in resources)
        dependencies.append((sid, grant["user_id"], grant["remote_user_id"], int(needs_lan), site["lan_subnet"]))
        for resource in (r for r in resources if r["site_id"] == sid):
            for cidr in resource["cidrs"]:
                network = ipaddress.ip_network(cidr)
                if (network.version != 4 or str(network) != cidr
                        or not any(network.subnet_of(p) for p in private)
                        or not site["lan_subnet"] or not network.subnet_of(ipaddress.ip_network(site["lan_subnet"]))):
                    raise ValueError("unsupported_lan_scope")
                if any(other_site != sid and network.overlaps(other) for other_site, other in scopes):
                    raise ValueError("ambiguous_lan_scope")
                scopes.append((sid, network))
                cidrs.add(cidr)
    if len(cidrs) > 256:
        raise ValueError("unsupported_lan_scope")
    return {"exit_country": pool["exit_country"], "routing_mode": binding["routing_mode"],
            "effective_lan_cidrs": sorted(cidrs)}, dependencies
