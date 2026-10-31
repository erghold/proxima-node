"""PROX-81 management-plane authentication. No data-plane admission is issued."""

import base64
import hashlib
import json
import secrets
import time
import uuid

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from flask import Blueprint, jsonify, request

from core.auth import (MAX_ATTEMPTS_PER_IP, check_rate_limit, clear_login_failures,
                       record_login_failure)
from core.pool_db import transaction
from core.proxima_client import request as proxima_request

bp = Blueprint("pool_client", __name__)
ENROLL_TTL = 600
SESSION_TTL = 86400
CHALLENGE_TTL = 120


def error(code, status):
    return jsonify({"ok": False, "error": code}), status


def result(data, status=200):
    return jsonify({"ok": True, "data": data}), status


@bp.after_request
def no_store(response):
    response.headers["Cache-Control"] = "no-store"
    return response


def body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def bearer():
    value = request.headers.get("Authorization", "")
    return digest(value[7:]) if value.startswith("Bearer pool_") else ""


def account(conn, account_id):
    return conn.execute("SELECT * FROM vpn_users WHERE account_id=? AND enabled=1 AND allow_pools=1",
                        (account_id,)).fetchone()


def grants(conn, user_id):
    return conn.execute(
        "SELECT a.* FROM vpn_user_access a JOIN vpn_servers s ON s.id=a.vpn_server_id "
        "WHERE a.user_id=? AND a.enabled=1 AND a.sync_status!='pending_delete' "
        "AND a.remote_user_id IS NOT NULL", (user_id,)).fetchall()


def session(conn):
    row = conn.execute("SELECT * FROM pool_sessions WHERE token_hash=? AND expires_at>?",
                       (bearer(), int(time.time()))).fetchone()
    if not row:
        return None, None
    user = account(conn, row["account_id"])
    if not user:
        return None, None
    if row["device_id"] and not conn.execute(
        "SELECT 1 FROM pool_devices WHERE device_id=? AND account_id=? AND revoked_at IS NULL",
        (row["device_id"], row["account_id"]),
    ).fetchone():
        return None, None
    return row, user


def issue(conn, account_id, device_id=None):
    token = "pool_" + secrets.token_urlsafe(32)
    expires = int(time.time()) + (SESSION_TTL if device_id else ENROLL_TTL)
    conn.execute("INSERT INTO pool_sessions VALUES (?,?,?,?)",
                 (digest(token), account_id, device_id, expires))
    return {"token": token, "expires_at": expires, "account_id": account_id,
            "device_id": device_id}


@bp.post("/api/vpn/auth/login")
def login():
    data = body()
    username, password = data.get("username"), data.get("password")
    if (not isinstance(username, str) or not 0 < len(username) <= 128
            or not isinstance(password, str) or not 0 < len(password) <= 1024):
        return error("invalid_credentials_payload", 400)
    ip = request.remote_addr or "unknown"
    ident = f"pool:{ip}|{username.lower()}"
    if check_rate_limit(ip, MAX_ATTEMPTS_PER_IP) or check_rate_limit(ident):
        return error("rate_limited", 429)
    with transaction() as conn:
        user = conn.execute("SELECT * FROM vpn_users WHERE username=? AND enabled=1 AND allow_pools=1",
                            (username,)).fetchone()
        access = grants(conn, user["id"]) if user else []
        pending = user and not access and conn.execute(
            "SELECT 1 FROM vpn_user_access a JOIN vpn_servers s ON s.id=a.vpn_server_id "
            "WHERE a.user_id=? AND a.enabled=1 AND a.sync_status!='pending_delete' "
            "AND a.remote_user_id IS NULL LIMIT 1", (user["id"],)).fetchone()
        servers = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM vpn_servers")}
    if pending:
        return error("authentication_unavailable", 503)
    if not user or not access:
        record_login_failure(ident, ip)
        return error("invalid_credentials", 401)
    accepted = None
    for grant in access:
        try:
            response = proxima_request(servers[grant["vpn_server_id"]], "POST", "/api/vpn/auth/login",
                                       body={"username": username, "password": password}, timeout=10,
                                       credential_bootstrap=True)
            if response.status_code in (401, 403):
                record_login_failure(ident, ip)
                return error("invalid_credentials", 401)
            if response.status_code == 429:
                return error("rate_limited", 429)
            if response.status_code != 200:
                continue
            payload = response.json()
            remote = payload.get("data", {}).get("user", {})
            if (payload.get("ok") is True and type(remote.get("id")) is int
                    and remote["id"] == grant["remote_user_id"] and remote.get("username") == username
                    and ("enabled" not in remote or remote["enabled"] is True)):
                accepted = grant
                break
            # A successful login for another remote identity never enrolls this account.
            record_login_failure(ident, ip)
            return error("invalid_credentials", 401)
        except (requests.RequestException, ValueError, AttributeError, TypeError):
            continue
    if accepted is None:
        return error("authentication_unavailable", 503)
    with transaction() as conn:
        current = account(conn, user["account_id"])
        if not current or current["username"] != username or not any(
            a["id"] == accepted["id"] and a["remote_user_id"] == accepted["remote_user_id"]
            for a in grants(conn, current["id"])
        ):
            return error("access_revoked", 403)
        issued = issue(conn, user["account_id"])
    clear_login_failures(ident, ip)
    return result(issued)


def proof_fields(data):
    try:
        if not isinstance(data.get("device_id"), str) or len(data["device_id"]) != 36:
            raise ValueError()
        device_id = str(uuid.UUID(data["device_id"]))
        if device_id != data["device_id"]:
            raise ValueError()
        key = data["public_key"]
        if not isinstance(key, str) or len(key) != 44:
            raise ValueError()
        raw = base64.b64decode(key, validate=True)
        if len(raw) != 32 or base64.b64encode(raw).decode() != key:
            raise ValueError()
        Ed25519PublicKey.from_public_bytes(raw)
        return device_id, key
    except (KeyError, ValueError, TypeError, AttributeError):
        return None, None


def enrollment_conflict(conn, account_id, device_id, key):
    rows = conn.execute("SELECT * FROM pool_devices WHERE device_id=? OR public_key=?",
                        (device_id, key)).fetchall()
    return any(d["account_id"] != account_id or d["device_id"] != device_id
               or d["public_key"] != key or d["revoked_at"] is not None for d in rows)


@bp.post("/api/vpn/devices/challenge")
def challenge():
    data = body()
    device_id, key = proof_fields(data)
    purpose = data.get("purpose")
    name = data.get("name", "")
    if not device_id or purpose not in ("enroll", "authenticate") or not isinstance(name, str) or len(name) > 100:
        return error("invalid_challenge", 400)
    with transaction() as conn:
        conn.execute("DELETE FROM pool_challenges WHERE expires_at<=?", (int(time.time()),))
        conn.execute("DELETE FROM pool_sessions WHERE expires_at<=?", (int(time.time()),))
        if purpose == "enroll":
            auth, user = session(conn)
            if not auth or auth["device_id"]:
                return error("enrollment_session_required", 401)
            if enrollment_conflict(conn, user["account_id"], device_id, key):
                return error("device_identity_unavailable", 409)
            account_id, session_hash = user["account_id"], bearer()
        else:
            device = conn.execute("SELECT * FROM pool_devices WHERE device_id=? AND public_key=?",
                                  (device_id, key)).fetchone()
            if not device:
                return error("invalid_device", 401)
            account_id, session_hash = device["account_id"], None
            name = ""
        # Bound storage per identity; challenge issuance does not invalidate existing proofs.
        count = conn.execute("SELECT count(*) FROM pool_challenges WHERE account_id=?", (account_id,)).fetchone()[0]
        if count >= 20:
            return error("rate_limited", 429)
        challenge_id = secrets.token_urlsafe(32)
        message = json.dumps({"protocol": "proxima-device-v1", "challenge_id": challenge_id,
                              "account_id": account_id, "device_id": device_id, "public_key": key,
                              "purpose": purpose, "name": name}, sort_keys=True, separators=(",", ":"))
        expires = int(time.time()) + CHALLENGE_TTL
        conn.execute("INSERT INTO pool_challenges VALUES (?,?,?,?,?,?,?,?,?)",
                     (challenge_id, account_id, device_id, key, purpose, name, message, session_hash, expires))
    return result({"challenge_id": challenge_id, "message": message, "expires_at": expires})


def consume(conn, data, purpose):
    cid, signature = data.get("challenge_id"), data.get("signature")
    if not isinstance(cid, str) or not isinstance(signature, str) or len(signature) > 100:
        return None
    row = conn.execute("SELECT * FROM pool_challenges WHERE id=? AND purpose=? AND expires_at>?",
                       (cid, purpose, int(time.time()))).fetchone()
    if not row:
        return None
    if purpose == "enroll":
        auth, user = session(conn)
        if not auth or row["session_hash"] != bearer() or user["account_id"] != row["account_id"]:
            return None
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(row["public_key"])).verify(
            base64.b64decode(signature, validate=True), row["message"].encode())
    except (ValueError, InvalidSignature):
        return None
    conn.execute("DELETE FROM pool_challenges WHERE id=?", (cid,))
    return row


@bp.post("/api/vpn/devices")
def enroll():
    with transaction() as conn:
        proof = consume(conn, body(), "enroll")
        if not proof:
            return error("invalid_proof", 401)
        if enrollment_conflict(conn, proof["account_id"], proof["device_id"], proof["public_key"]):
            return error("device_identity_unavailable", 409)
        # Exact active identity recovery keeps the original name, key and owner.
        created = conn.execute("INSERT OR IGNORE INTO pool_devices VALUES (?,?,?,?,?,NULL)",
                               (proof["device_id"], proof["account_id"], proof["public_key"], proof["name"], int(time.time()))).rowcount == 1
        conn.execute("DELETE FROM pool_sessions WHERE token_hash=?", (bearer(),))
        issued = issue(conn, proof["account_id"], proof["device_id"])
    return result({**issued, "created": created}, 201 if created else 200)


@bp.post("/api/vpn/auth/device")
def device_login():
    with transaction() as conn:
        proof = consume(conn, body(), "authenticate")
        if not proof:
            return error("invalid_proof", 401)
        device = conn.execute(
            "SELECT * FROM pool_devices WHERE device_id=? AND account_id=? AND public_key=?",
            (proof["device_id"], proof["account_id"], proof["public_key"]),
        ).fetchone()
        if not device:
            return error("invalid_proof", 401)
        # Only a consumed valid signature may disclose current central policy.
        if device["revoked_at"] is not None:
            return error("device_revoked", 403)
        user = conn.execute("SELECT * FROM vpn_users WHERE account_id=?", (proof["account_id"],)).fetchone()
        if not user:
            return error("account_deleted", 403)
        if user["enabled"] != 1:
            return error("account_disabled", 403)
        if user["allow_pools"] != 1:
            return error("pool_access_disabled", 403)
        issued = issue(conn, proof["account_id"], proof["device_id"])
    return result(issued)


def public_device(device):
    return {k: device[k] for k in ("device_id", "name", "created_at", "revoked_at")}


@bp.get("/api/vpn/me")
def me():
    with transaction() as conn:
        auth, user = session(conn)
        if not auth:
            return error("unauthorized", 401)
        device = conn.execute("SELECT * FROM pool_devices WHERE device_id=?", (auth["device_id"],)).fetchone()
        return result({"account_id": user["account_id"], "update_channel": user["update_channel"],
                       "allow_pools": bool(user["allow_pools"]), "device": public_device(device) if device else None})


@bp.get("/api/vpn/devices")
def devices():
    with transaction() as conn:
        auth, user = session(conn)
        if not auth:
            return error("unauthorized", 401)
        return result([public_device(d) for d in conn.execute("SELECT * FROM pool_devices WHERE account_id=?",
                                                            (user["account_id"],))])


@bp.delete("/api/vpn/devices/<device_id>")
def revoke(device_id):
    with transaction() as conn:
        auth, user = session(conn)
        if not auth:
            return error("unauthorized", 401)
        changed = conn.execute("UPDATE pool_devices SET revoked_at=COALESCE(revoked_at,?) WHERE device_id=? AND account_id=?",
                               (int(time.time()), device_id, user["account_id"])).rowcount
        if not changed:
            return error("device_not_found", 404)
        conn.execute("DELETE FROM pool_sessions WHERE device_id=?", (device_id,))
        conn.execute("DELETE FROM pool_challenges WHERE device_id=?", (device_id,))
    return result({"revoked": True})


@bp.post("/api/vpn/auth/logout")
def logout():
    with transaction() as conn:
        auth, _ = session(conn)
        if not auth:
            return error("unauthorized", 401)
        conn.execute("DELETE FROM pool_sessions WHERE token_hash=?", (bearer(),))
    return result({"logged_out": True})
