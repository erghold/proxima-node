"""Silent server sync — how a signed-in client picks up a newly granted
server without its user ever retyping a password (master plan Section 22).

Section 21 made login one step, but left every *later* grant behind a
password prompt: the client deliberately stores no password, so it had
nothing to authenticate a second discovery with. It does hold a valid
token for each server it already has, and that token is proof of identity
just as good as the password.

So the same principle as /api/vpn/discover applies one level up: ADM does
not verify the token itself, it asks the instance that issued it
(`GET /api/vpn/self/me`). If that instance vouches for the user, ADM hands
back the user's full entitled server list — minting a login token, over
the admin channel it already holds, for each server the client does not
have yet.

Minting grants ADM nothing new. It already writes `password_hash` on every
instance, so it can already sign in as anyone it manages; asking the
instance for a token merely avoids ADM having to know a plaintext to do
the same thing.
"""

import logging

import requests
from flask import Blueprint, jsonify, request

from core.auth import (
    MAX_ATTEMPTS_PER_IP,
    check_rate_limit,
    clear_login_failures,
    record_login_failure,
)
from core.db import (
    get_all_vpn_servers,
    get_user_access,
    get_vpn_user_by_username,
)
from core.proxima_client import auth_headers, VERIFY_TLS

log = logging.getLogger("adm.vpn_sync")
bp = Blueprint("vpn_sync", __name__)

VERIFY_TIMEOUT = 10
MINT_TIMEOUT = 15


def _normalize(url: str) -> str:
    return (url or "").strip().rstrip("/").lower()


def _verify_token(server: dict, token: str) -> dict | None:
    """Ask an instance whether this token is one of its own.

    Returns the bound remote identity, or None. Uses the instance's
    management URL (ADM's own path to the box) with the *client's* bearer
    token — the same Flask app answers both, so no new endpoint is needed
    and the check lands on the only party that can actually make it.
    """
    url = f"{server['url'].rstrip('/')}/api/vpn/self/me"
    try:
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=VERIFY_TIMEOUT,
            verify=VERIFY_TLS,
            allow_redirects=False,
        )
    except requests.RequestException as e:
        log.warning(f"[SYNC] Cannot reach {server['name']} to verify a token: {e}")
        return None

    if resp.status_code != 200:
        return None
    try:
        payload = resp.json()
    except ValueError:
        return None
    if not isinstance(payload, dict) or not payload.get("ok"):
        return None
    identity = payload.get("data")
    if not isinstance(identity, dict) or type(identity.get("id")) is not int or identity["id"] <= 0 or not isinstance(identity.get("username"), str):
        return None
    return identity


def _mint_token(server: dict, remote_user_id: int) -> str | None:
    """Ask an instance for a login token for a user it hosts."""
    url = f"{server['url'].rstrip('/')}/api/vpn/users/{remote_user_id}/token"
    try:
        resp = requests.post(
            url, headers=auth_headers(server), timeout=MINT_TIMEOUT, verify=VERIFY_TLS,
            allow_redirects=False,
        )
    except requests.RequestException as e:
        log.warning(f"[SYNC] Cannot reach {server['name']} to mint a token: {e}")
        return None

    if resp.status_code != 200:
        log.warning(f"[SYNC] {server['name']} refused to mint a token: "
                    f"HTTP {resp.status_code}")
        return None
    try:
        payload = resp.json()
    except ValueError:
        return None
    if not payload.get("ok"):
        return None
    return (payload.get("data") or {}).get("token")


@bp.post("/api/vpn/sync")
def sync():
    """Return the caller's entitled servers, with tokens for the new ones.

    Body: {"public_url": <a server the client already has>,
           "token": <that server's token>,
           "known": [<public_url>, ...]}

    `revoked` is stated explicitly rather than left as "whatever is missing
    from `servers`": a client's list also holds manually added instances
    ADM has never heard of, and inferring removal from absence would delete
    exactly those.
    """
    ip = request.remote_addr or "unknown"

    lockout = check_rate_limit(ip, MAX_ATTEMPTS_PER_IP)
    if lockout:
        log.warning(f"[SYNC] Rate limited (address): {ip} ({lockout}s remaining)")
        return jsonify({"ok": False, "error": "Too many attempts. Try again later.",
                        "retry_after": lockout}), 429

    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("public_url"), str) or not isinstance(body.get("token"), str) or not isinstance(body.get("known", []), list) or any(not isinstance(u, str) for u in body.get("known", [])):
        return jsonify({"ok": False, "error": "Invalid sync request"}), 400
    public_url = _normalize(body.get("public_url"))
    token = (body.get("token") or "").strip()
    known = {_normalize(u) for u in (body.get("known") or []) if u}

    if not public_url or not token:
        return jsonify({"ok": False, "error": "public_url and token required"}), 400

    servers = get_all_vpn_servers()
    origin = next(
        (s for s in servers if _normalize(s.get("public_url")) == public_url), None
    )
    if not origin:
        # The client is holding a server ADM does not know — a manually
        # added instance, most likely. Nothing to sync against.
        log.info(f"[SYNC] Unknown origin '{public_url}' from {ip}")
        return jsonify({"ok": False, "error": "Unknown server"}), 404

    identity = _verify_token(origin, token)
    if not identity:
        record_login_failure(ip)
        log.warning(f"[SYNC] {origin['name']} rejected the token from {ip}")
        return jsonify({"ok": False, "error": "Invalid or expired token"}), 401

    username = identity["username"]
    user = get_vpn_user_by_username(username)
    if not user or not user["enabled"] or user.get("deletion_pending"):
        log.warning(f"[SYNC] '{username}' is unknown or disabled in ADM")
        return jsonify({"ok": False, "error": "Account not available"}), 403

    accesses = get_user_access(user["id"])
    if not any(a["vpn_server_id"] == origin["id"] and a["enabled"] == 1 and a["sync_status"] == "synced" and type(a.get("remote_user_id")) is int and a["remote_user_id"] == identity["id"] for a in accesses):
        return jsonify({"ok": False, "error": "Origin identity is not authorized"}), 403
    clear_login_failures(ip)

    by_id = {s["id"]: s for s in servers}
    result = []
    for access in accesses:
        if not access["enabled"] or access["sync_status"] != "synced":
            continue
        server = by_id.get(access["vpn_server_id"])
        if not server:
            continue
        entry_url = _normalize(server.get("public_url"))
        if not entry_url:
            # url is ADM's own path to the box and must never reach a
            # client; a server without a public URL simply cannot be synced.
            log.warning(f"[SYNC] {server['name']} has no public_url — "
                        f"hidden from '{username}'")
            continue

        entry = {
            "display_name": server.get("display_name") or server["name"],
            "public_url": (server.get("public_url") or "").rstrip("/"),
            "server_code": server.get("server_code") or server["name"],
        }
        # Only mint for servers the client lacks: a token per sync per
        # server would rotate credentials the client is using happily.
        if entry_url not in known:
            remote_id = access.get("remote_user_id")
            if remote_id is None:
                log.warning(f"[SYNC] '{username}' has no remote id on "
                            f"{server['name']} yet — not synced")
                continue
            minted = _mint_token(server, remote_id)
            if not minted:
                continue
            entry["token"] = minted
            log.info(f"[SYNC] '{username}' picked up {server['name']} silently")
        result.append(entry)

    # Only what ADM manages AND the user is no longer entitled to. A URL the
    # client holds that ADM does not manage is someone's self-hosted box and
    # is none of ADM's business.
    entitled = {_normalize(e["public_url"]) for e in result}
    managed = {_normalize(s.get("public_url")) for s in servers if s.get("public_url")}
    revoked = sorted(known & managed - entitled)
    if revoked:
        log.info(f"[SYNC] '{username}' lost access to {len(revoked)} server(s)")

    from core.location_pools import authorized_catalog
    from core.pool_db import transaction
    with transaction() as conn:
        pool_catalog = authorized_catalog(conn, user["id"])
    response = jsonify({"ok": True, "data": {
        "user": {"username": user["username"]},
        "servers": result,
        "revoked": revoked,
        "pool_catalog": pool_catalog,
    }})
    response.headers["Cache-Control"] = "no-store"
    return response
