"""Durable desired authorization claims, not tunnel provisioning."""

import time
import uuid

from flask import Blueprint, jsonify

from api.pool_client import bp as client_bp, body, error, result, session
from core.authz import superadmin_only
from core.pool_authorization import attachment_policy, authorized_manifest, canonical
from core.pool_db import transaction

bp = Blueprint("pool_attachments", __name__)


def status(conn, row):
    pending = conn.execute("SELECT error FROM pool_attachment_outbox WHERE attachment_id=? "
                           "AND status NOT IN ('delivered','superseded') ORDER BY revision LIMIT 1", (row["id"],)).fetchone()
    return {"attachment_id": row["id"], "pool_id": row["pool_id"], "device_id": row["device_id"],
            "ingress_id": row["ingress_id"], "binding_id": row["binding_id"],
            "desired_state": row["desired_state"], "desired_revision": row["desired_revision"],
            "delivered_state": row["delivered_state"], "delivered_revision": row["delivered_revision"],
            "credential_generation": row["credential_generation"],
            "delivery_status": "error" if pending and pending["error"] else "pending" if pending else "delivered",
            "delivery_error": pending["error"] if pending else None,
            "ready": False, "reason": "attachment_revoked" if row["desired_state"] == "revoked" else "attachment_not_provisioned"}


@client_bp.post("/api/vpn/pools/<pool_id>/attachments")
def claim(pool_id):
    data = body()
    fields = {"ingress_id", "binding_id", "authorization_revision", "policy_revision"}
    if set(data) != fields or not all(isinstance(data[k], str) and data[k] for k in fields):
        return error("invalid_attachment_claim", 400)
    with transaction() as conn:
        auth, user = session(conn)
        if not auth or not auth["device_id"]:
            return error("device_session_required", 401)
        manifest, access = authorized_manifest(conn, user)
        if data["authorization_revision"] != manifest["authorization_revision"]:
            return error("manifest_stale", 409)
        pool = next((p for p in manifest["pools"] if p["id"] == pool_id), None)
        if not pool:
            return error("pool_access_denied", 403)
        if data["policy_revision"] != pool["policy_revision"]:
            return error("manifest_stale", 409)
        member = next((m for m in pool["members"] if m["id"] == data["ingress_id"]), None)
        binding = next((b for b in member["bindings"] if b["id"] == data["binding_id"]), None) if member else None
        if not binding:
            return error("binding_access_denied", 403)
        try:
            policy, dependencies = attachment_policy(conn, pool, member, binding, access)
        except (ValueError, TypeError, KeyError) as exc:
            reason = str(exc)
            if reason not in {"unsupported_binding", "unsupported_lan_scope", "ambiguous_lan_scope", "unsupported_site_restrictions"}:
                reason = "unsupported_lan_scope"
            return jsonify({"ok": False, "error": "unsupported_attachment_policy", "reason": reason}), 409
        device = conn.execute("SELECT * FROM pool_devices WHERE device_id=?", (auth["device_id"],)).fetchone()
        template = canonical({"account_id": user["account_id"], "device_id": device["device_id"],
                              "ingress_id": member["id"], "binding_id": binding["id"],
                              "public_key": device["public_key"], "policy": policy,
                              "authorization_revision": 1, "state": "active"})
        row = conn.execute("SELECT * FROM pool_attachments WHERE account_id=? AND device_id=? AND ingress_id=? AND binding_id=?",
                           (user["account_id"], device["device_id"], member["id"], binding["id"])).fetchone()
        if row:
            if row["payload_template"] != template or row["pool_id"] != pool_id or row["site_id"] != member["site_id"]:
                return error("immutable_attachment_intent", 409)
            aid = row["id"]
            conn.execute("UPDATE pool_attachments SET desired_state='active' WHERE id=?", (aid,))
        else:
            aid = str(uuid.uuid4())
            conn.execute("INSERT INTO pool_attachments(id,account_id,device_id,pool_id,site_id,ingress_id,binding_id,payload_template,desired_state,created_at) "
                         "VALUES (?,?,?,?,?,?,?,?,'active',?)", (aid, user["account_id"], device["device_id"], pool_id,
                         member["site_id"], member["id"], binding["id"], template, int(time.time())))
        conn.execute("DELETE FROM pool_attachment_dependencies WHERE attachment_id=?", (aid,))
        conn.executemany("INSERT INTO pool_attachment_dependencies VALUES (?,?,?,?,?,?)", [(aid, *d) for d in dependencies])
        return result(status(conn, conn.execute("SELECT * FROM pool_attachments WHERE id=?", (aid,)).fetchone()), 202)


@client_bp.get("/api/vpn/attachments/<attachment_id>")
def get_attachment(attachment_id):
    with transaction() as conn:
        auth, user = session(conn)
        if not auth:
            return error("unauthorized", 401)
        row = conn.execute("SELECT * FROM pool_attachments WHERE id=? AND account_id=?", (attachment_id, user["account_id"])).fetchone()
        if not row:
            return error("attachment_not_found", 404)
        return result(status(conn, row))


@bp.get("/api/pool-attachments")
@superadmin_only
def inspect():
    with transaction() as conn:
        return result([status(conn, r) for r in conn.execute("SELECT a.* FROM pool_attachments a ORDER BY "
            "EXISTS(SELECT 1 FROM pool_attachment_outbox o WHERE o.attachment_id=a.id "
            "AND o.status NOT IN ('delivered','superseded')) DESC,a.created_at DESC,a.id LIMIT 100")])


@bp.post("/api/pool-attachments/reconcile")
@superadmin_only
def reconcile():
    data = body()
    limit, retry = data.get("limit", 10), data.get("retry_conflicts", False)
    if set(data) - {"limit", "retry_conflicts"} or type(limit) is not int or not 1 <= limit <= 20 or type(retry) is not bool:
        return error("invalid_reconcile_request", 400)
    from core.pool_attachment_sync import reconcile as deliver
    return result(deliver(limit=limit, retry_conflicts=retry))
