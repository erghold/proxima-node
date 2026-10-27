"""ADM-only durable authorization tests. Site runtime and sockets are forbidden."""

import hashlib
import json
import sqlite3
import uuid
from types import SimpleNamespace

import pytest
import requests

from core import db, pool_attachment_sync as sync
from core.pool_authorization import canonical
from core.pool_db import transaction
from tests.test_pool_foundation import env, enrolled, login, catalog_body  # noqa: F401


def setup_claim(e, resources=None, site_id=1):
    headers, _, _, device = enrolled(e)
    response = e.client.post("/api/pool-catalog", headers=e.admin, json=catalog_body(resources))
    assert response.status_code == 201, response.json
    pool = response.json["data"]
    assert e.client.put(f"/api/pool-catalog/{pool['id']}/users/{e.uid}", headers=e.admin, json={"enabled": True}).status_code == 200
    manifest = e.client.get("/api/vpn/pools", headers=headers).json["data"]
    member = next(m for m in pool["members"] if m["site_id"] == site_id)
    data = {"ingress_id": member["id"], "binding_id": member["bindings"][0]["id"],
            "authorization_revision": manifest["authorization_revision"], "policy_revision": pool["policy_revision"]}
    return SimpleNamespace(headers=headers, device=device, pool=pool, data=data,
                           path=f"/api/vpn/pools/{pool['id']}/attachments")


def claim(e, c):
    response = e.client.post(c.path, headers=c.headers, json=c.data)
    assert response.status_code == 202, response.json
    return response.json["data"]["attachment_id"]


def outbox(e, aid):
    return [dict(r) for r in e.conn.execute("SELECT * FROM pool_attachment_outbox WHERE attachment_id=? ORDER BY revision", (aid,))]


def state(e, aid):
    return dict(e.conn.execute("SELECT * FROM pool_attachments WHERE id=?", (aid,)).fetchone())


def receipt(event, generation):
    data = json.loads(event["payload"])
    data.pop("public_key")
    data.update(attachment_id=event["attachment_id"], credential_generation=generation,
                policy_digest=hashlib.sha256(canonical(data["policy"]).encode()).hexdigest(), ready=False,
                reason="attachment_revoked" if data["state"] == "revoked" else "attachment_not_provisioned")
    return SimpleNamespace(status_code=200, json=lambda: {"ok": True, "data": data})


class Registry:
    def __init__(self):
        self.rows = {}
        self.calls = []
        self.lose = False

    def put(self, server, method, path, body, **kwargs):
        assert method == "PUT" and kwargs == {"timeout": (2, 8), "management_write": True}
        aid = path.rsplit("/", 1)[1]
        self.calls.append((server["id"], canonical(body)))
        prior = self.rows.get(aid)
        if prior and body["authorization_revision"] < prior["payload"]["authorization_revision"]:
            return SimpleNamespace(status_code=409)
        generation = prior["generation"] if prior else 0
        if body["state"] == "active" and (not prior or prior["payload"]["state"] == "revoked"):
            generation += 1
        self.rows[aid] = {"payload": body, "generation": generation}
        if self.lose:
            self.lose = False
            raise requests.Timeout("do not persist this secret")
        return receipt({"payload": canonical(body), "attachment_id": aid}, generation)


@pytest.fixture
def registry(env):
    remote = Registry()
    env.monkeypatch.setattr(sync, "proxima_request", remote.put)
    return remote


def test_claim_requires_device_and_is_idempotent(env):
    c = setup_claim(env)
    for headers in (login(env), env.admin, {}):
        assert env.client.post(c.path, headers=headers, json=c.data).status_code == 401
    aid = claim(env, c)
    assert claim(env, c) == aid
    assert len(outbox(env, aid)) == 1
    status = env.client.get(f"/api/vpn/attachments/{aid}", headers=c.headers).json["data"]
    assert status["ready"] is False and status["desired_revision"] == 1
    assert status["delivery_status"] == "pending" and status["delivered_revision"] == 0
    assert "public_key" not in status and "payload" not in status
    row = outbox(env, aid)[0]
    assert row["payload"] == canonical(json.loads(row["payload"]))
    uid = db.create_vpn_user({"username": "other", "password_hash": "unused", "allow_pools": True})
    from api.pool_client import issue
    with transaction() as conn:
        token = issue(conn, db.get_vpn_user(uid)["account_id"])["token"]
    assert env.client.get(f"/api/vpn/attachments/{aid}", headers={"Authorization": "Bearer " + token}).status_code == 404


def test_claim_strict_selection(env):
    c = setup_claim(env)
    for patch, expected in [({"authorization_revision": "stale"}, 409), ({"policy_revision": "stale"}, 409),
                            ({"binding_id": "unknown"}, 403), ({"ingress_id": "unknown"}, 403), ({"device_id": c.device}, 400)]:
        assert env.client.post(c.path, headers=c.headers, json={**c.data, **patch}).status_code == expected
    db.mark_access_pending_delete(env.uid, 1)
    c.data["authorization_revision"] = env.client.get("/api/vpn/pools", headers=c.headers).json["data"]["authorization_revision"]
    assert env.client.post(c.path, headers=c.headers, json=c.data).status_code == 403
    assert env.conn.execute("SELECT count(*) FROM pool_attachments").fetchone()[0] == 0


@pytest.mark.parametrize("restriction,value", [("assigned_groups", '["group"]'),
    ("max_peers", 2), ("bandwidth_quota", 0), ("speed_download", "10mbit"), ("speed_upload", "0"), ("assigned_groups", "bad-json")])
def test_unenforceable_restrictions_rejected_without_dropping(env, restriction, value):
    c = setup_claim(env, [{"site_id": 2, "cidrs": ["192.168.77.0/24"]}])
    db.upsert_user_access(env.uid, 1, {"allowed_profiles": '["slot-11"]'})
    db.upsert_user_access(env.uid, 2, {restriction: value})
    response = env.client.post(c.path, headers=c.headers, json=c.data)
    assert response.status_code == 409 and response.json["error"] == "unsupported_attachment_policy"


@pytest.mark.parametrize("cidr", ["192.168.77.0/255.255.255.0", "192.168.77.1/24", "2001:db8::/64", "8.8.8.0/24"])
def test_site_inexpressible_cidrs_rejected(env, cidr):
    c = setup_claim(env)
    # Model an older/future definition that is not expressible by the site registry.
    definition = c.pool
    definition["lan_resource_set"]["resources"] = [{"id": "r", "site_id": 2, "cidrs": [cidr]}]
    env.conn.execute("UPDATE pool_catalog SET definition=? WHERE id=?", (json.dumps(definition), definition["id"]))
    env.conn.commit()
    c.data["authorization_revision"] = env.client.get("/api/vpn/pools", headers=c.headers).json["data"]["authorization_revision"]
    assert env.client.post(c.path, headers=c.headers, json=c.data).status_code == 409


def test_loss_retries_exact_payload_and_never_reports_ready(env, registry):
    c = setup_claim(env)
    aid = claim(env, c)
    registry.lose = True
    assert sync.reconcile()["error"] == 1
    assert state(env, aid)["delivered_revision"] == 0
    assert sync.reconcile()["delivered"] == 1
    assert registry.calls[0] == registry.calls[1]
    assert state(env, aid)["credential_generation"] == 1
    status = env.client.get(f"/api/vpn/attachments/{aid}", headers=c.headers).json["data"]
    assert status["delivery_status"] == "delivered" and status["ready"] is False
    assert all(not m["eligible"] for p in env.client.get("/api/vpn/pools", headers=c.headers).json["data"]["pools"] for m in p["members"])
    assert "secret" not in str(outbox(env, aid))


@pytest.mark.parametrize("activation_reached", [False, True])
def test_offline_revoke_regrant_preserves_barrier_and_actual_generation(env, registry, activation_reached):
    c = setup_claim(env)
    aid = claim(env, c)
    if activation_reached:
        registry.lose = True
        assert sync.reconcile()["error"] == 1
    db.update_vpn_user(env.uid, {"allow_pools": 0})
    db.update_vpn_user(env.uid, {"allow_pools": 0})
    assert [r["state"] for r in outbox(env, aid)] == ["active", "revoked"]
    db.update_vpn_user(env.uid, {"allow_pools": 1})
    assert state(env, aid)["desired_state"] == "revoked"  # Restoration alone never activates.
    assert claim(env, c) == aid
    assert [r["state"] for r in outbox(env, aid)] == ["active", "revoked", "active"]
    assert sync.reconcile()["delivered"] == 2
    assert [json.loads(p)["state"] for _, p in registry.calls][-2:] == ["revoked", "active"]
    assert state(env, aid)["credential_generation"] == (2 if activation_reached else 1)
    assert state(env, aid)["delivered_revision"] == 3


def test_every_revocation_barrier_survives_multiple_offline_cycles(env, registry):
    c = setup_claim(env)
    aid = claim(env, c)
    assert sync.reconcile()["delivered"] == 1
    for _ in range(2):
        db.update_vpn_user(env.uid, {"allow_pools": 0})
        db.update_vpn_user(env.uid, {"allow_pools": 1})
        claim(env, c)
    assert sync.reconcile()["delivered"] == 3
    assert [json.loads(p)["authorization_revision"] for _, p in registry.calls] == [1, 2, 4, 5]
    assert state(env, aid)["credential_generation"] == 2


@pytest.mark.parametrize("mutation", ["user_disable", "user_delete", "device_revoke", "pool_disable", "pool_grant_delete",
    "access_disable", "access_pending_delete", "access_delete", "remote_remap", "resource_lan", "site_lan", "restriction"])
def test_legacy_mutations_atomically_fanout_revocation(env, mutation):
    c = setup_claim(env, [{"site_id": 2, "cidrs": ["192.168.77.0/24"]}])
    aid = claim(env, c)  # Ingress 1 depends on resource site 2.
    if mutation == "user_disable":
        db.update_vpn_user(env.uid, {"enabled": 0})
    elif mutation == "user_delete":
        db.delete_vpn_user(env.uid)
    elif mutation == "device_revoke":
        assert env.client.delete(f"/api/vpn/devices/{c.device}", headers=c.headers).status_code == 200
    elif mutation == "pool_disable":
        env.client.put(f"/api/pool-catalog/{c.pool['id']}", headers=env.admin, json={"enabled": False})
    elif mutation == "pool_grant_delete":
        env.client.put(f"/api/pool-catalog/{c.pool['id']}/users/{env.uid}", headers=env.admin, json={"enabled": False})
    elif mutation == "access_disable":
        db.upsert_user_access(env.uid, 2, {"enabled": False})
    elif mutation == "access_pending_delete":
        db.mark_access_pending_delete(env.uid, 2)
    elif mutation == "access_delete":
        db.delete_user_access(env.uid, 2)
    elif mutation == "remote_remap":
        db.mark_access_synced(db.get_access(env.uid, 2)["id"], remote_user_id=99)
    elif mutation == "resource_lan":
        db.upsert_user_access(env.uid, 2, {"lan_access": False})
    elif mutation == "site_lan":
        db.update_vpn_server(2, {"lan_subnet": "192.168.78.0/24"})
    else:
        db.upsert_user_access(env.uid, 2, {"assigned_groups": '["restricted"]'})
    assert state(env, aid)["desired_state"] == "revoked"
    assert state(env, aid)["desired_revision"] == 2
    assert [r["state"] for r in outbox(env, aid)] == ["active", "revoked"]


def test_import_remote_remap_and_pending_delete_preserved(env):
    c = setup_claim(env, [{"site_id": 2, "cidrs": ["192.168.77.0/24"]}])
    aid = claim(env, c)
    from core import vpn_user_import
    env.monkeypatch.setattr(vpn_user_import, "fetch_all", lambda: [{"vpn_server_id": 2, "server_name": "two", "server_display_name": "Two", "online": True,
        "users": [{"id": 99, "username": "alice", "password_hash": "hash"}]}])
    vpn_user_import.apply_import([{"username": "alice", "primary_server_id": 2}])
    # Import's upsert retains old remote id until mark_access_synced remaps it.
    assert db.get_access(env.uid, 2)["remote_user_id"] == 99
    assert state(env, aid)["desired_state"] == "revoked"
    db.mark_access_pending_delete(env.uid, 2)
    vpn_user_import.apply_import([{"username": "alice", "primary_server_id": 2}])
    assert db.get_access(env.uid, 2)["sync_status"] == "pending_delete"
    assert len(outbox(env, aid)) == 2


def test_site_removal_retains_revocation_destination(env, registry):
    c = setup_claim(env)
    aid = claim(env, c)
    db.delete_user_access(env.uid, 1)
    response = env.client.delete("/api/vpn-servers/1", headers=env.admin)
    assert response.status_code == 409 and response.json["error"] == "pool_attachment_cleanup_required"
    assert db.get_vpn_server(1) is not None
    with pytest.raises(sqlite3.IntegrityError):
        db.delete_vpn_server(1)
    assert sync.reconcile()["delivered"] == 1
    assert db.delete_vpn_server(1)
    assert state(env, aid)["delivered_state"] == "revoked"
    # No attachment destination: preserve normal deletion behavior.
    db.delete_user_access(env.uid, 2)
    assert db.delete_vpn_server(2)


@pytest.mark.parametrize("field,value", [("attachment_id", "wrong"), ("authorization_revision", True), ("state", "revoked"),
    ("credential_generation", 2), ("credential_generation", True), ("ready", True), ("policy", {}), ("policy_digest", "wrong")])
def test_mismatched_receipts_never_ack(env, field, value):
    c = setup_claim(env)
    aid = claim(env, c)
    event = sync.take_event(set())
    response = receipt(event, 1)
    response.json()["data"][field] = value
    assert sync.record_receipt(event, response) == "error"
    assert state(env, aid)["delivered_revision"] == 0


def test_http_status_and_strict_ok_conflicts_block_without_revision_bump(env):
    c = setup_claim(env)
    aid = claim(env, c)
    event = sync.take_event(set())
    assert sync.record_receipt(event, SimpleNamespace(status_code=409)) == "error"
    assert sync.take_event(set()) is None
    assert state(env, aid)["desired_revision"] == 1
    env.monkeypatch.setattr(sync, "proxima_request", lambda *a, **k: SimpleNamespace(status_code=200, json=lambda: {"ok": 1, "data": {}}))
    assert sync.reconcile(retry_conflicts=True)["error"] == 1
    assert state(env, aid)["delivered_revision"] == 0


def test_expired_attempt_receipt_cannot_regress_state(env):
    c = setup_claim(env)
    aid = claim(env, c)
    old = sync.take_event(set())
    assert sync.take_event(set()) is None
    db.update_vpn_user(env.uid, {"allow_pools": 0})
    env.conn.execute("UPDATE pool_attachment_outbox SET inflight_until=0")
    env.conn.commit()
    revoked = sync.take_event(set())
    assert revoked["state"] == "revoked"
    assert sync.record_receipt(revoked, receipt(revoked, 1)) == "delivered"
    assert sync.record_receipt(old, receipt(old, 1)) == "stale"
    assert state(env, aid)["delivered_state"] == "revoked"
    assert state(env, aid)["delivered_revision"] == 2


def test_failed_site_does_not_block_other_sites(env, registry):
    first = setup_claim(env)
    claim(env, first)
    second = setup_claim(env, site_id=2)
    claim(env, second)
    third = setup_claim(env)
    claim(env, third)
    attempts = []
    def send(server, *args, **kwargs):
        attempts.append(server["id"])
        if server["id"] == 1:
            raise requests.Timeout()
        return registry.put(server, *args, **kwargs)
    env.monkeypatch.setattr(sync, "proxima_request", send)
    assert sync.reconcile() == {"delivered": 1, "error": 1, "stale": 0}
    assert attempts.count(1) == 1


def test_concurrent_claims_and_outbox_workers(env):
    c = setup_claim(env)
    from concurrent.futures import ThreadPoolExecutor
    def post(_):
        with env.client.application.test_client() as client:
            response = client.post(c.path, headers=c.headers, json=c.data)
            assert response.status_code == 202
            return response.json["data"]["attachment_id"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        ids = list(pool.map(post, range(2)))
        events = list(pool.map(lambda _: sync.take_event(set()), range(2)))
    assert ids[0] == ids[1] and sum(e is not None for e in events) == 1
    assert len(outbox(env, ids[0])) == 1


def test_shared_writer_rollback_rolls_back_revocation_and_event(env):
    c = setup_claim(env)
    aid = claim(env, c)
    env.conn.execute("UPDATE vpn_users SET allow_pools=0 WHERE id=?", (env.uid,))
    assert state(env, aid)["desired_revision"] == 2
    env.conn.rollback()
    assert state(env, aid)["desired_revision"] == 1 and len(outbox(env, aid)) == 1
    db.init_db()
    assert state(env, aid)["desired_revision"] == 1


def test_management_write_transport_keeps_admin_auth_and_disables_redirects(env):
    from core import proxima_client, auth
    calls = []
    env.monkeypatch.setattr(requests, "put", lambda *a, **k: calls.append((a, k)) or SimpleNamespace(status_code=307))
    server = {"url": "https://registered.invalid", "api_token_enc": auth.encrypt_value("site-admin-token")}
    path = f"/api/vpn/pool-attachments/{uuid.uuid4()}"
    proxima_client.request(server, "PUT", path, body={}, management_write=True)
    assert calls[0][1]["headers"] == {"Authorization": "Bearer site-admin-token"}
    assert calls[0][1]["allow_redirects"] is False and calls[0][1]["verify"] is True
    with pytest.raises(ValueError):
        proxima_client.request({**server, "url": "http://10.0.0.1"}, "PUT", path, management_write=True)


@pytest.mark.parametrize("second", ["192.168.77.0/24", "192.168.77.0/25"])
def test_cross_site_overlapping_scope_not_flattened(env, second):
    c = setup_claim(env, [{"site_id": 1, "cidrs": ["192.168.77.0/24"]}, {"site_id": 2, "cidrs": [second]}])
    response = env.client.post(c.path, headers=c.headers, json=c.data)
    assert response.status_code == 409 and response.json["error"] == "unsupported_attachment_policy"
    assert response.json["reason"] == "ambiguous_lan_scope"
    assert env.conn.execute("SELECT count(*) FROM pool_attachments").fetchone()[0] == 0


def test_stale_resource_scope_cannot_be_reactivated_after_site_edit(env):
    c = setup_claim(env, [{"site_id": 2, "cidrs": ["192.168.77.0/24"]}])
    aid = claim(env, c)
    db.update_vpn_server(2, {"lan_subnet": "192.168.78.0/24"})
    assert state(env, aid)["desired_state"] == "revoked"
    response = env.client.post(c.path, headers=c.headers, json=c.data)
    assert response.status_code == 409 and response.json["error"] == "unsupported_attachment_policy"
    assert state(env, aid)["desired_state"] == "revoked" and len(outbox(env, aid)) == 2


@pytest.mark.parametrize("field,value", [("assigned_groups", '["restricted"]'), ("bandwidth_quota", 123),
                                        ("speed_download", "10mbit"), ("speed_upload", "20mbit")])
def test_new_dependency_restrictions_queue_revocation(env, field, value):
    c = setup_claim(env, [{"site_id": 2, "cidrs": ["192.168.77.0/24"]}])
    aid = claim(env, c)
    db.upsert_user_access(env.uid, 2, {field: value})
    assert state(env, aid)["desired_state"] == "revoked"
    assert outbox(env, aid)[-1]["state"] == "revoked"
    db.upsert_user_access(env.uid, 2, {field: value})
    assert len(outbox(env, aid)) == 2


def test_unrelated_updates_and_pending_sync_do_not_revoke(env):
    c = setup_claim(env, [{"site_id": 2, "cidrs": ["192.168.77.0/24"]}])
    aid = claim(env, c)
    db.update_vpn_user(env.uid, {"update_channel": "beta", "password_hash": "new-hash", "full_name": "New label"})
    db.mark_all_access_pending(env.uid)
    db.update_vpn_server(2, {"display_name": "New site label"})
    db.upsert_user_access(env.uid, 2, {"assigned_groups": "[ ]"})
    assert db.get_access(env.uid, 2)["sync_status"] == "pending"
    assert state(env, aid)["desired_state"] == "active" and len(outbox(env, aid)) == 1


def test_admin_reconcile_and_inspection_are_separate_from_client_tokens(env):
    c = setup_claim(env)
    aid = claim(env, c)
    for headers, code in ((c.headers, 401), (env.scoped, 403)):
        assert env.client.post("/api/pool-attachments/reconcile", headers=headers, json={}).status_code == code
        assert env.client.get("/api/pool-attachments", headers=headers).status_code == code
    for data in ({"limit": True}, {"limit": 21}, {"limit": 0}, {"retry_conflicts": "true"}, {"site_url": "https://untrusted.invalid"}):
        assert env.client.post("/api/pool-attachments/reconcile", headers=env.admin, json=data).status_code == 400
    response = env.client.get("/api/pool-attachments", headers=env.admin)
    assert response.json["data"][0]["attachment_id"] == aid
    assert "public_key" not in str(response.json) and "api_token" not in str(response.json)


def test_authority_change_during_network_call_keeps_revoke_pending(env, registry):
    c = setup_claim(env)
    aid = claim(env, c)
    def send(server, *args, **kwargs):
        # This real legacy write would lock if the sender held a SQLite transaction.
        db.mark_access_pending_delete(env.uid, 1)
        return registry.put(server, *args, **kwargs)
    env.monkeypatch.setattr(sync, "proxima_request", send)
    assert sync.reconcile(limit=1)["delivered"] == 1
    assert state(env, aid)["desired_revision"] == 2 and state(env, aid)["desired_state"] == "revoked"
    assert state(env, aid)["delivered_revision"] == 1
    assert sync.reconcile(limit=1)["delivered"] == 1
    assert state(env, aid)["delivered_state"] == "revoked"


def test_expired_lease_retries_payload_and_cas_ignores_old_attempt(env):
    c = setup_claim(env)
    aid = claim(env, c)
    first = sync.take_event(set())
    env.conn.execute("UPDATE pool_attachment_outbox SET inflight_until=0")
    env.conn.commit()
    second = sync.take_event(set())
    assert first["payload"] == second["payload"] and first["attempt_token"] != second["attempt_token"]
    assert sync.record_receipt(first, receipt(first, 1)) == "stale"
    assert state(env, aid)["delivered_revision"] == 0
    assert sync.record_receipt(second, receipt(second, 1)) == "delivered"


def test_explicit_tr_pool_permission_preserves_legacy_slot_allowlist(env, registry):
    c = setup_claim(env, [{"site_id": 2, "cidrs": ["192.168.77.0/24"]}])
    original = '[ "slot-11", "slot-12", "slot-13", "slot-14" ]'
    for sid in (1, 2):
        db.upsert_user_access(env.uid, sid, {"allowed_profiles": original})
    assert c.pool["exit_country"] == "TR" and c.pool["routing_modes"] == ["fast"]
    aid = claim(env, c)
    assert sync.reconcile()["delivered"] == 1
    db.mark_all_access_pending(env.uid)
    for sid in (1, 2):
        db.mark_access_synced(db.get_access(env.uid, sid)["id"], remote_user_id=42)
        assert db.get_access(env.uid, sid)["allowed_profiles"] == original
    assert state(env, aid)["desired_state"] == "active"
    assert len(outbox(env, aid)) == 1

    other = env.client.post("/api/pool-catalog", headers=env.admin, json=catalog_body()).json["data"]
    manifest = env.client.get("/api/vpn/pools", headers=c.headers).json["data"]
    assert [p["id"] for p in manifest["pools"]] == [c.pool["id"]]
    member = other["members"][0]
    response = env.client.post(f"/api/vpn/pools/{other['id']}/attachments", headers=c.headers, json={
        "ingress_id": member["id"], "binding_id": member["bindings"][0]["id"],
        "authorization_revision": manifest["authorization_revision"], "policy_revision": other["policy_revision"],
    })
    assert response.status_code == 403 and response.json["error"] == "pool_access_denied"
    assert env.conn.execute("SELECT count(*) FROM pool_attachments").fetchone()[0] == 1
    assert all(db.get_access(env.uid, sid)["allowed_profiles"] == original for sid in (1, 2))


def test_upgrade_replaces_old_profile_guard_and_edits_still_revoke(env):
    c = setup_claim(env)
    db.upsert_user_access(env.uid, 1, {"allowed_profiles": '["slot-11"]'})
    aid = claim(env, c)
    # Reproduce the previous installed guard, not just a fresh database.
    env.conn.executescript("""DROP TRIGGER pool_revoke_access_change;
        CREATE TRIGGER pool_revoke_access_change AFTER UPDATE ON vpn_user_access
        WHEN NEW.allowed_profiles!='[]' BEGIN
            UPDATE pool_attachments SET desired_state='revoked' WHERE desired_state='active';
        END;""")
    db.init_db()
    db.init_db()
    db.mark_all_access_pending(env.uid)
    assert state(env, aid)["desired_state"] == "active" and len(outbox(env, aid)) == 1
    db.upsert_user_access(env.uid, 1, {"allowed_profiles": '["slot-12"]'})
    assert state(env, aid)["desired_state"] == "revoked" and len(outbox(env, aid)) == 2
    db.upsert_user_access(env.uid, 1, {"allowed_profiles": '["slot-11"]'})
    assert state(env, aid)["desired_state"] == "revoked" and len(outbox(env, aid)) == 2
    assert claim(env, c) == aid
    assert state(env, aid)["desired_revision"] == 3


@pytest.mark.parametrize("profiles", ['null', '{}', 'true', '0', '""', '[1]', '[""]'])
def test_malformed_legacy_profile_metadata_still_fails_closed(env, profiles):
    c = setup_claim(env)
    db.upsert_user_access(env.uid, 1, {"allowed_profiles": profiles})
    response = env.client.post(c.path, headers=c.headers, json=c.data)
    assert response.status_code == 409 and response.json["error"] == "unsupported_attachment_policy"
    assert env.conn.execute("SELECT count(*) FROM pool_attachments").fetchone()[0] == 0
