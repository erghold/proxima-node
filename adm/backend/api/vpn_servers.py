"""VPN server management API — CRUD + generic Proxima proxy."""

import logging
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests as http_requests
from flask import Blueprint, g, jsonify, request

from core.auth import encrypt_value
from core.db import (
    count_access_for_server,
    create_vpn_server,
    delete_vpn_server,
    get_all_vpn_servers,
    get_vpn_server,
    parse_server_profiles,
    update_vpn_server,
)
from core.authz import scoped_server_ids, superadmin_only
from core.proxima_client import PROBE_TIMEOUT, request as _proxima_request, token_expiry, token_state
from core import mgmt_network as mgmt
from core.subnets import validate_for_server

log = logging.getLogger("adm.vpn_servers")
bp = Blueprint("vpn_servers", __name__)


def _fetch_vpn_server_status(server: dict) -> dict:
    """Fetch live status from a single Proxima instance."""
    result = {
        "id": server["id"],
        "name": server["name"],
        "display_name": server["display_name"],
        "url": server["url"],
        "public_url": server.get("public_url", ""),
        # What single-login discovery will actually hand to clients: the DB
        # value, never the live-reported one merged in below. The UI warns
        # on this field — warning on the merged public_url would hide the gap.
        "discovery_url": server.get("public_url", ""),
        "has_token": bool(server.get("api_token_enc")),
        "token_state": token_state(server),
        "token_expires_at": token_expiry(server),
        "online": False,
        "proxima_status": None,
        "connectivity": None,
        "error": None,
    }

    if not server.get("api_token_enc"):
        result["error"] = "No API token configured"
        return result

    try:
        resp = _proxima_request(server, "GET", "/api/status",
                                timeout=PROBE_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        if data.get("ok"):
            result["online"] = True
            status_data = data.get("data") or {}
            result["proxima_status"] = status_data
            # Prefer public_url from live Proxima status over DB value
            live_url = status_data.get("public_url", "")
            if live_url:
                result["public_url"] = live_url
        else:
            result["error"] = data.get("error", "Unknown error")
    except http_requests.exceptions.ConnectionError:
        result["error"] = "Connection refused"
    except http_requests.exceptions.Timeout:
        result["error"] = "Timeout"
    except Exception as e:
        result["error"] = str(e)

    # Fetch connectivity check results (same source as ProximaVPN client dots)
    if result["online"]:
        try:
            cresp = _proxima_request(server, "GET",
                                     "/api/vpn/self/connectivity",
                                     timeout=PROBE_TIMEOUT)
            if cresp.status_code == 200:
                cdata = cresp.json()
                if cdata.get("ok") and cdata.get("data"):
                    result["connectivity"] = cdata["data"]
        except Exception:
            pass  # Connectivity data is optional, don't fail status

    return result


# ── CRUD Endpoints ───────────────────────────────────────────────────────

@bp.get("/api/vpn-servers")
def list_vpn_servers():
    """List all VPN servers with live Proxima status (parallel fetch)."""
    servers = get_all_vpn_servers()
    # A scoped admin only ever sees the sites they administer.
    allowed = scoped_server_ids()
    if allowed is not None:
        servers = [s for s in servers if s["id"] in allowed]
    if not servers:
        return jsonify({"ok": True, "data": []})

    results = []
    with ThreadPoolExecutor(max_workers=min(len(servers), 5)) as pool:
        futures = {pool.submit(_fetch_vpn_server_status, s): s for s in servers}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                s = futures[future]
                results.append({
                    "id": s["id"], "name": s["name"],
                    "display_name": s["display_name"], "url": s["url"],
                    "public_url": s.get("public_url", ""),
                    "discovery_url": s.get("public_url", ""),
                    "has_token": bool(s.get("api_token_enc")),
                    "online": False, "proxima_status": None,
                    "connectivity": None, "error": str(e),
                })

    # Sort by original DB order
    order = {s["id"]: i for i, s in enumerate(servers)}
    results.sort(key=lambda r: order.get(r["id"], 999))

    # Management-tunnel state, read once for the whole list. Reported beside
    # `online` rather than folded into it: a node answering on its public
    # address while its tunnel is dead is exactly the state that has to be
    # visible, and merging the two would hide it.
    peers = mgmt.peer_status()
    by_id = {s["id"]: s for s in servers}
    for r in results:
        r["mgmt_tunnel"] = mgmt.tunnel_for(by_id.get(r["id"], {}), peers)

    return jsonify({"ok": True, "data": results})


@bp.post("/api/vpn-servers")
def add_vpn_server():
    """Register a new VPN server (Proxima instance)."""
    body = request.get_json(force=True, silent=True) or {}
    name = (body.get("name") or "").strip().lower()
    display_name = (body.get("display_name") or "").strip()
    url = (body.get("url") or "").strip().rstrip("/")

    if not name:
        return jsonify({"ok": False, "error": "name is required"}), 400
    if not url:
        return jsonify({"ok": False, "error": "url is required"}), 400
    if not display_name:
        display_name = name.upper()

    public_url = (body.get("public_url") or "").strip().rstrip("/")

    vpn_subnet = (body.get("vpn_subnet") or "").strip()
    lan_subnet = (body.get("lan_subnet") or "").strip()
    conflict = validate_for_server(vpn_subnet, lan_subnet)
    if conflict:
        return jsonify({"ok": False, "error": conflict}), 409

    data = {
        "vpn_endpoint": (body.get("vpn_endpoint") or "").strip(),
        "name": name,
        "display_name": display_name,
        "url": url,
        "public_url": public_url,
        "vpn_subnet": vpn_subnet,
        "lan_subnet": lan_subnet,
    }

    api_token = (body.get("api_token") or "").strip()
    if api_token:
        data["api_token_enc"] = encrypt_value(api_token)

    try:
        server_id = create_vpn_server(data)
    except Exception as e:
        if "UNIQUE" in str(e):
            return jsonify({"ok": False, "error": "VPN server with this name already exists"}), 409
        raise

    return jsonify({"ok": True, "data": {"id": server_id}})


@bp.get("/api/vpn-servers/<int:vpn_server_id>")
def get_vpn_server_detail(vpn_server_id: int):
    """VPN server detail (token not exposed, just has_token boolean)."""
    server = get_vpn_server(vpn_server_id)
    if not server:
        return jsonify({"ok": False, "error": "VPN server not found"}), 404

    result = {
        "id": server["id"],
        "name": server["name"],
        "display_name": server["display_name"],
        "url": server["url"],
        "public_url": server.get("public_url", ""),
        "has_token": bool(server.get("api_token_enc")),
        # How Ansible reaches the box. Empty means the site is not in
        # proxima_sites at all: write_hosts_yml() skips any server without an
        # ssh_host, so without these there is no way to see, let alone change,
        # why a site has no update path.
        "ssh_host": server.get("ssh_host") or "",
        "ssh_port": server.get("ssh_port") or 22,
        "ssh_user": server.get("ssh_user") or "root",
        "created_at": server["created_at"],
        "updated_at": server["updated_at"],
    }

    return jsonify({"ok": True, "data": result})


@bp.put("/api/vpn-servers/<int:vpn_server_id>")
def update_vpn_server_endpoint(vpn_server_id: int):
    """Update VPN server metadata or token."""
    server = get_vpn_server(vpn_server_id)
    if not server:
        return jsonify({"ok": False, "error": "VPN server not found"}), 404

    body = request.get_json(force=True, silent=True) or {}
    updates = {}

    for field in ("name", "display_name", "url", "public_url",
                  "vpn_subnet", "lan_subnet", "vpn_endpoint", "server_code"):
        if field in body:
            val = body[field]
            updates[field] = val.strip() if isinstance(val, str) else val

    # How Ansible reaches the box. These have always been storable — they are in
    # update_vpn_server()'s allowed set — but only the provisioning flow could
    # set them, and that flow also installs, opens a call-home tunnel and claims
    # the instance. A site that was installed by hand therefore had no way in:
    # without ssh_host, write_hosts_yml() skips it as "registered by hand, not
    # provisioned by ADM", and there is nothing else to set it with. This is the
    # adopt path — set reachability on a row that already exists and leave the
    # install alone.
    for field in ("ssh_host", "ssh_user"):
        if field in body:
            val = body[field]
            updates[field] = val.strip() if isinstance(val, str) else val
    if "ssh_port" in body:
        try:
            port = int(body["ssh_port"] or 22)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "ssh_port must be a number"}), 400
        updates["ssh_port"] = port

    if "url" in updates:
        updates["url"] = updates["url"].rstrip("/")
    if "public_url" in updates:
        updates["public_url"] = updates["public_url"].rstrip("/")

    if "vpn_subnet" in updates or "lan_subnet" in updates:
        # Checked against everything except this server's own current values —
        # otherwise a range would be found to conflict with itself.
        conflict = validate_for_server(
            updates.get("vpn_subnet", server.get("vpn_subnet") or ""),
            updates.get("lan_subnet", server.get("lan_subnet") or ""),
            exclude_server_id=vpn_server_id)
        if conflict:
            return jsonify({"ok": False, "error": conflict}), 409

    api_token = (body.get("api_token") or "").strip()
    if api_token:
        updates["api_token_enc"] = encrypt_value(api_token)

    if not updates:
        return jsonify({"ok": False, "error": "No valid fields to update"}), 400

    update_vpn_server(vpn_server_id, updates)

    # Ansible reads the inventory, not the database, and hosts.yml is generated.
    # Changing reachability without regenerating would leave the play still
    # pointed wherever this server was before — or absent, if it had no SSH
    # fields until now.
    if {"ssh_host", "ssh_port", "ssh_user"} & updates.keys():
        try:
            from core.db import get_all_servers
            from core.inventory_writer import write_hosts_yml
            write_hosts_yml(get_all_servers(), get_all_vpn_servers())
        except Exception:
            log.exception("[INVENTORY] Regeneration failed after editing %s",
                          server["name"])

    return jsonify({"ok": True})


@bp.delete("/api/vpn-servers/<int:vpn_server_id>")
def delete_vpn_server_endpoint(vpn_server_id: int):
    """Remove a VPN server."""
    server = get_vpn_server(vpn_server_id)
    if not server:
        return jsonify({"ok": False, "error": "VPN server not found"}), 404

    # Access rows cascade on delete — dropping them here would strand the
    # matching accounts (and their peers) on the instance itself.
    authorized = count_access_for_server(vpn_server_id)
    if authorized:
        return jsonify({"ok": False, "error":
                        f"{authorized} VPN user(s) are still authorized on this "
                        "server — revoke their access first"}), 409

    # The database guard is atomic with removal; never remove management access
    # first when a concurrent attachment still needs its revocation delivered.
    try:
        delete_vpn_server(vpn_server_id)
    except sqlite3.IntegrityError as exc:
        if "pool_attachment_cleanup_required" not in str(exc):
            raise
        return jsonify({"ok": False, "error": "pool_attachment_cleanup_required"}), 409

    # Take it off the management network too. Leaving the peer would keep an
    # address allocated and a tunnel accepted for a site ADM no longer knows.
    from core.mgmt_network import forget_peer
    try:
        forget_peer(vpn_server_id)
    except Exception as e:  # noqa: BLE001 — the row still has to go
        log.warning(f"[VPN] Could not remove {server['name']} from the "
                    f"management network: {e}")

    name = server["name"]

    # Otherwise the host stays in the inventory and its host_vars file — with
    # whatever credentials it held — outlives the server it belonged to, and a
    # later playbook run happily targets a machine ADM no longer knows about.
    from core.db import get_all_servers
    from core.inventory_writer import remove_host_vars, write_hosts_yml
    write_hosts_yml(get_all_servers(), get_all_vpn_servers())
    remove_host_vars(name)

    return jsonify({"ok": True})


# ── Generic Proxima Proxy ────────────────────────────────────────────────

@bp.route("/api/vpn-servers/<int:vpn_server_id>/proxima/<path:subpath>",
          methods=["GET", "POST", "PUT", "DELETE"])
def proxy_to_proxima(vpn_server_id: int, subpath: str):
    """Forward any request to the Proxima instance's API."""
    server = get_vpn_server(vpn_server_id)
    if not server:
        return jsonify({"ok": False, "error": "VPN server not found"}), 404

    if not server.get("api_token_enc"):
        return jsonify({"ok": False, "error": "No API token configured"}), 400

    method = request.method
    body = None
    if method in ("POST", "PUT"):
        body = request.get_json(force=True, silent=True)

    try:
        resp = _proxima_request(server, method, f"/api/{subpath}", body=body, timeout=30)
        # Pass through the Proxima response as-is
        return (resp.content, resp.status_code, {"Content-Type": resp.headers.get("Content-Type", "application/json")})
    except http_requests.exceptions.ConnectionError:
        return jsonify({"ok": False, "error": "Cannot reach Proxima instance"}), 502
    except http_requests.exceptions.Timeout:
        return jsonify({"ok": False, "error": "Proxima request timed out"}), 504
    except Exception as e:
        log.error(f"Proxima proxy error for {server['name']}: {e}")
        return jsonify({"ok": False, "error": str(e)}), 502


# ── Provisioning ─────────────────────────────────────────────────────────

@bp.get("/api/vpn-servers/<int:vpn_server_id>/services")
def server_services(vpn_server_id: int):
    """What a site actually runs, asked of the site itself.

    ADM could guess most of this from what it provisioned, and would be wrong
    in the way that matters: it would list what should be there rather than
    what is. The point of looking is to catch the difference before a box
    ships, not to have it confirmed back.
    """
    server = get_vpn_server(vpn_server_id)
    if not server:
        return jsonify({"ok": False, "error": "VPN server not found"}), 404

    try:
        r = _proxima_request(server, "GET", "/api/services", timeout=20)
    except Exception as e:  # noqa: BLE001
        return jsonify({"ok": False, "error": str(e)}), 502

    if r.status_code != 200:
        return jsonify({"ok": False, "error": f"HTTP {r.status_code}"}), 502

    data = (r.json() or {}).get("data") or {}
    # The addresses are ADM's to report: the site knows its own LAN address but
    # not the one it was given on the management network.
    data["management_address"] = server.get("callhome_ip") or ""
    data["public_url"] = server.get("public_url") or ""
    return jsonify({"ok": True, "data": data})


@bp.get("/api/vpn-servers/management-network")
@superadmin_only
def management_network():
    """The management network's state — which sites are actually dialled in.

    This is where the call-home tunnels are looked at now. They are not in
    wg-easy any more, and deliberately so: nobody adds or removes entries by
    hand here, which is what made them disappear when they lived there.
    """
    from core.mgmt_network import status
    return jsonify({"ok": True, "data": status()})


@bp.get("/api/vpn-servers/profiles")
def list_server_profiles():
    """Direct profiles each site publishes, keyed by server id.

    Served from the poller's cache rather than fetched live: granting a user
    a profile must not depend on the site answering at that moment, and the
    users page must not fan out one request per site to draw its checkboxes.
    `cached_at` is returned so the UI can say how stale the list is.
    """
    servers = get_all_vpn_servers()
    allowed = scoped_server_ids()
    if allowed is not None:
        servers = [s for s in servers if s["id"] in allowed]
    return jsonify({"ok": True, "data": {
        str(s["id"]): {
            "server_name": s["name"],
            "server_display_name": s["display_name"],
            "cached_at": s.get("profiles_cached_at"),
            "profiles": parse_server_profiles(s),
        }
        for s in servers
    }})


@bp.get("/api/vpn-servers/subnets")
def list_subnets():
    """Every range ADM knows about, so whoever picks the next one can see them.

    The register lived in a document, which meant it drifted from what was
    actually deployed. Reading it from the servers themselves cannot.
    """
    from core.subnets import MANAGEMENT_NETWORK, existing_ranges
    return jsonify({"ok": True, "data": {
        "management_network": MANAGEMENT_NETWORK,
        "ranges": existing_ranges(),
    }})


@bp.post("/api/vpn-servers/provision")
@superadmin_only
def provision_vpn_server():
    """Register a site server and install Proxima on it.

    The SSH password is held only until the install succeeds; the response
    returns an operation id whose log carries the playbook output.
    """
    from core.db import get_all_servers
    from core.vpn_provision import start_provision

    body = request.get_json(silent=True) or {}

    name = (body.get("name") or "").strip().lower()
    ssh_host = (body.get("ssh_host") or "").strip()
    ssh_password = (body.get("ssh_password") or "").strip()

    if not name:
        return jsonify({"ok": False, "error": "name is required"}), 400
    if not ssh_host:
        return jsonify({"ok": False, "error": "ssh_host is required"}), 400
    # The password is optional on purpose. A box prepared in the workshop, or
    # one being reinstalled, already carries ADM's key — demanding a password
    # there would force the operator to keep a site password around, which is
    # the exposure this whole flow exists to remove.
    # Ansible host names must be unique across the whole inventory, and both
    # kinds of server write host_vars/<name>.yml — a clash would have one
    # silently overwrite the other's credentials.
    if any(s["name"] == name for s in get_all_servers()):
        return jsonify({"ok": False, "error":
                        f"An exit node is already named {name}"}), 409
    if any(v["name"] == name for v in get_all_vpn_servers()):
        return jsonify({"ok": False, "error":
                        f"A VPN server is already named {name}"}), 409

    # The site's ranges come from the router step, so they are known before
    # this runs. Refused here rather than after the box is built.
    vpn_subnet = (body.get("vpn_subnet") or "").strip()
    lan_subnet = (body.get("lan_subnet") or "").strip()
    conflict = validate_for_server(vpn_subnet, lan_subnet)
    if conflict:
        return jsonify({"ok": False, "error": conflict}), 409

    server_code = (body.get("server_code") or name).strip().upper()[:5]
    data = {
        "vpn_subnet": vpn_subnet,
        "lan_subnet": lan_subnet,
        "vpn_endpoint": (body.get("vpn_endpoint") or "").strip(),
        "name": name,
        "display_name": (body.get("display_name") or "").strip() or name.upper(),
        # Filled in once the instance is claimed over the management tunnel.
        "url": "",
        "public_url": (body.get("public_url") or "").strip().rstrip("/"),
        "ssh_host": ssh_host,
        "ssh_port": int(body.get("ssh_port") or 22),
        "ssh_user": (body.get("ssh_user") or "root").strip(),
        "ssh_password_enc": encrypt_value(ssh_password) if ssh_password else None,
        "server_code": server_code,
    }

    server_id = create_vpn_server(data)
    # Whoever is running this becomes the new panel's admin, with the password
    # they already use here. Nothing is generated and nothing has to be
    # written down.
    op_id, error = start_provision(server_id, admin_id=g.admin["id"])
    if error:
        # Leave the row: the operator can retry without re-entering everything.
        return jsonify({"ok": False, "error": error, "id": server_id}), 400

    log.info(f"[PROVISION] Started for {name} ({ssh_host}), operation {op_id}")
    return jsonify({"ok": True, "data": {"id": server_id, "operation_id": op_id}}), 202


@bp.post("/api/vpn-servers/<int:vpn_server_id>/update")
@superadmin_only
def update_vpn_server_software(vpn_server_id: int):
    """Re-deploy the current source onto a server that is behind."""
    from core.vpn_provision import start_provision

    server = get_vpn_server(vpn_server_id)
    if not server:
        return jsonify({"ok": False, "error": "VPN server not found"}), 404
    if not server.get("ssh_host"):
        return jsonify({"ok": False, "error":
                        "This server was registered by hand and has no SSH "
                        "details; ADM cannot deploy to it"}), 400

    # Already installed and claimed, so nothing is created here — the same
    # playbook simply syncs the newer source and re-runs the installer.
    op_id, error = start_provision(vpn_server_id, claim=False)
    if error:
        return jsonify({"ok": False, "error": error}), 400
    return jsonify({"ok": True, "data": {"operation_id": op_id}}), 202


@bp.get("/api/vpn-servers/source-revision")
@superadmin_only
def get_source_revision():
    """What ADM would deploy right now — compared against each server."""
    from core.vpn_provision import source_revision
    return jsonify({"ok": True, "data": source_revision()})


@bp.post("/api/vpn-servers/source-revision/refresh")
@superadmin_only
def refresh_source_revision():
    """Pull the latest source so a later deploy carries it."""
    from core.vpn_provision import update_source
    revision, error = update_source()
    if error:
        return jsonify({"ok": False, "error": error}), 502
    return jsonify({"ok": True, "data": revision})
