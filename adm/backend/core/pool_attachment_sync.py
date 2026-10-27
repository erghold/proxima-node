"""Ordered registry delivery. No runtime readiness or tunnel credentials."""

import hashlib
import json
import secrets
import time

import requests

from core.pool_authorization import canonical
from core.pool_db import transaction
from core.proxima_client import request as proxima_request

LEASE_SECONDS = 60


def take_event(excluded_sites):
    with transaction() as conn:
        now = int(time.time())
        # Never knowingly replay an obsolete activation. An attempted activation
        # may already be at the site; its revocation still must be delivered.
        conn.execute("""UPDATE pool_attachment_outbox AS o SET status='superseded',error=NULL,blocked=0
            WHERE o.state='active' AND o.status NOT IN ('delivered','superseded') AND o.blocked=0 AND o.inflight_until<=?
            AND EXISTS (SELECT 1 FROM pool_attachment_outbox r WHERE r.attachment_id=o.attachment_id
                AND r.revision>o.revision AND r.state='revoked')""", (now,))
        exclude_sql = " AND a.site_id NOT IN (" + ",".join("?" for _ in excluded_sites) + ")" if excluded_sites else ""
        rows = conn.execute("""SELECT o.*,a.site_id FROM pool_attachment_outbox o
            JOIN pool_attachments a ON a.id=o.attachment_id
            WHERE o.status NOT IN ('delivered','superseded') AND o.blocked=0 AND o.inflight_until<=?
            AND NOT EXISTS (SELECT 1 FROM pool_attachment_outbox earlier WHERE earlier.attachment_id=o.attachment_id
                AND earlier.revision<o.revision AND earlier.status NOT IN ('delivered','superseded'))
            """ + exclude_sql + " ORDER BY o.attempts,o.attachment_id,o.revision LIMIT 1", (now, *excluded_sites)).fetchall()
        row = rows[0] if rows else None
        if not row:
            return None
        token = secrets.token_hex(16)
        conn.execute("UPDATE pool_attachment_outbox SET status='inflight',attempt_token=?,inflight_until=?,attempts=attempts+1 "
                     "WHERE attachment_id=? AND revision=?", (token, now + LEASE_SECONDS, row["attachment_id"], row["revision"]))
        server = conn.execute("SELECT * FROM vpn_servers WHERE id=?", (row["site_id"],)).fetchone()
        return {**dict(row), "attempt_token": token, "server": dict(server) if server else None}


def valid_receipt(conn, event, data):
    if not isinstance(data, dict):
        return False
    payload = json.loads(event["payload"])
    for field in ("account_id", "device_id", "ingress_id", "binding_id", "state"):
        if data.get(field) != payload[field]:
            return False
    if (data.get("attachment_id") != event["attachment_id"]
            or type(data.get("authorization_revision")) is not int or data["authorization_revision"] != event["revision"]
            or data.get("ready") is not False or data.get("policy") != payload["policy"]
            or data.get("policy_digest") != hashlib.sha256(canonical(payload["policy"]).encode()).hexdigest()
            or data.get("reason") != ("attachment_revoked" if event["state"] == "revoked" else "attachment_not_provisioned")
            or type(data.get("credential_generation")) is not int):
        return False
    attachment = conn.execute("SELECT * FROM pool_attachments WHERE id=?", (event["attachment_id"],)).fetchone()
    previous = attachment["credential_generation"] or 0
    if event["state"] == "active":
        expected = previous + (attachment["delivered_state"] != "active")
        return data["credential_generation"] == expected
    # A lost activation response may precede this barrier. Its receipt, not a
    # prediction, decides whether the site advanced generation before revocation.
    uncertain_activation = attachment["delivered_state"] != "active" and conn.execute(
        "SELECT 1 FROM pool_attachment_outbox WHERE attachment_id=? AND state='active' "
        "AND revision>? AND revision<? AND attempts>0 LIMIT 1",
        (event["attachment_id"], attachment["delivered_revision"], event["revision"]),
    ).fetchone() is not None
    return data["credential_generation"] in ({previous, previous + 1} if uncertain_activation else {previous})


def record_receipt(event, response=None, failure=None):
    with transaction() as conn:
        current = conn.execute("SELECT * FROM pool_attachment_outbox WHERE attachment_id=? AND revision=?",
                               (event["attachment_id"], event["revision"])).fetchone()
        if not current or current["status"] != "inflight" or current["attempt_token"] != event["attempt_token"]:
            return "stale"
        data = None
        if failure is None:
            if response.status_code != 200:
                failure = "http_409" if response.status_code == 409 else "site_http_error"
            else:
                try:
                    envelope = response.json()
                    data = envelope.get("data") if isinstance(envelope, dict) and envelope.get("ok") is True else None
                    if not valid_receipt(conn, event, data):
                        failure = "receipt_mismatch"
                except (ValueError, TypeError, KeyError):
                    failure = "receipt_mismatch"
        if failure:
            conn.execute("UPDATE pool_attachment_outbox SET status='error',error=?,blocked=?,inflight_until=0 "
                         "WHERE attachment_id=? AND revision=?", (failure, int(failure == "http_409"), event["attachment_id"], event["revision"]))
            return "error"
        conn.execute("UPDATE pool_attachment_outbox SET status='delivered',error=NULL,inflight_until=0 "
                     "WHERE attachment_id=? AND revision=?", (event["attachment_id"], event["revision"]))
        conn.execute("UPDATE pool_attachments SET delivered_revision=?,delivered_state=?,credential_generation=? "
                     "WHERE id=? AND delivered_revision<?", (event["revision"], event["state"], data["credential_generation"],
                     event["attachment_id"], event["revision"]))
        return "delivered"


def reconcile(limit=10, retry_conflicts=False):
    if retry_conflicts:
        with transaction() as conn:
            conn.execute("UPDATE pool_attachment_outbox SET blocked=0 WHERE rowid IN "
                         "(SELECT rowid FROM pool_attachment_outbox WHERE blocked=1 ORDER BY rowid LIMIT ?)", (limit,))
    totals = {"delivered": 0, "error": 0, "stale": 0}
    failed_sites = set()
    for _ in range(limit):
        event = take_event(failed_sites)
        if not event:
            break
        try:
            if not event["server"]:
                raise ValueError("Missing site")
            response = proxima_request(event["server"], "PUT", f"/api/vpn/pool-attachments/{event['attachment_id']}",
                                       body=json.loads(event["payload"]), timeout=(2, 8), management_write=True)
        except (requests.RequestException, ValueError):
            outcome = record_receipt(event, failure="transport_unavailable")
        else:
            outcome = record_receipt(event, response=response)
        totals[outcome] += 1
        if outcome != "delivered":
            failed_sites.add(event["site_id"])
    return totals
