"""Whole-account removal retains remote cleanup until each site acknowledges it."""

import pytest
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Event

from api import vpn_users
from core import db, vpn_user_import, vpn_user_sync
from tests.test_smart_test_permission import database, client  # noqa: F401
from tests.test_pool_foundation import env  # noqa: F401
from tests.test_pool_attachment_delivery import setup_claim, claim, state, outbox


class Gate:
    def __init__(self, down=(), error=None):
        self.down = set(down)
        self.error = error
        self.calls = []

    def down_reason(self, server):
        return "offline" if server["id"] in self.down else None

    def is_down(self, server):
        return bool(self.down_reason(server))

    def call(self, server, method, path, **kwargs):
        assert method == "DELETE" and path.endswith("?cascade=true")
        self.calls.append((server["id"], path))
        return {}, self.error


def wire(monkeypatch, gate):
    monkeypatch.setattr(vpn_users, "_push_now", lambda uid: vpn_user_sync.sync_pending(user_id=uid, gate=gate))


def test_unassigned_user_can_be_removed_without_network(client, database):
    _, uid = database
    response = client.delete(f"/api/vpn-users/{uid}?cascade=true")
    assert response.status_code == 200
    assert db.get_vpn_user(uid) is None


def test_plain_delete_still_requires_explicit_cascade(client, database):
    _, uid = database
    db.upsert_user_access(uid, 1, {"remote_user_id": 41})
    assert client.delete(f"/api/vpn-users/{uid}").status_code == 409
    assert db.get_vpn_user(uid)["enabled"] == 1
    assert db.get_access(uid, 1)["sync_status"] == "pending"


def test_offline_first_site_does_not_block_deletion_and_retry_finishes(client, database, monkeypatch):
    _, uid = database
    other = db.create_vpn_user({"username": "unrelated", "password_hash": "keep"})
    db.upsert_user_access(uid, 1, {"remote_user_id": 41})
    db.upsert_user_access(uid, 2, {"remote_user_id": 42})
    gate = Gate(down=[1])
    wire(monkeypatch, gate)
    response = client.delete(f"/api/vpn-users/{uid}?cascade=true")
    assert response.status_code == 202 and response.json["data"]["pending_sync"] is True
    assert gate.calls == [(2, "/api/vpn/users/42?cascade=true")]
    assert db.get_access(uid, 2) is None
    assert db.get_access(uid, 1)["sync_status"] == "pending_delete"
    assert db.get_vpn_user(uid)["enabled"] == 0
    assert db.get_vpn_user(uid)["deletion_pending"] == 1
    db.init_db()
    assert db.get_vpn_user(uid)["deletion_pending"] == 1
    assert client.delete(f"/api/vpn-users/{uid}?cascade=true").status_code == 202
    gate.down.clear()
    vpn_user_sync.sync_pending(gate=gate)
    assert db.get_vpn_user(uid) is None
    assert db.get_user_access(uid) == []
    assert db.get_vpn_user(other)["password_hash"] == "keep"


def test_refused_remote_delete_remains_queued(client, database, monkeypatch):
    _, uid = database
    db.upsert_user_access(uid, 1, {"remote_user_id": 41})
    gate = Gate(error="Permission denied")
    wire(monkeypatch, gate)
    assert client.delete(f"/api/vpn-users/{uid}?cascade=true").status_code == 202
    assert db.get_access(uid, 1)["sync_error"] == "Permission denied"
    assert db.get_vpn_user(uid)["deletion_pending"] == 1
    gate.error = "User not found"
    vpn_user_sync.sync_pending(gate=gate)
    assert db.get_vpn_user(uid) is None


def test_never_delivered_grants_need_no_remote_delete(client, database, monkeypatch):
    _, uid = database
    db.upsert_user_access(uid, 1, {})
    gate = Gate(down=[1])
    wire(monkeypatch, gate)
    assert client.delete(f"/api/vpn-users/{uid}?cascade=true").status_code == 200
    assert db.get_vpn_user(uid) is None and gate.calls == []


def test_scope_denial_does_not_disable_or_queue_user(client, database, monkeypatch):
    _, uid = database
    db.upsert_user_access(uid, 1, {"remote_user_id": 41})
    monkeypatch.setattr(vpn_users, "may_manage_user", lambda uid: False)
    assert client.delete(f"/api/vpn-users/{uid}?cascade=true").status_code == 403
    assert db.get_vpn_user(uid)["enabled"] == 1
    assert not db.get_vpn_user(uid)["deletion_pending"]
    assert db.get_access(uid, 1)["sync_status"] == "pending"


@pytest.mark.parametrize("method,path,payload", [
    ("put", "", {"enabled": True}),
    ("post", "/password", {"password": "changed-password"}),
    ("put", "/access/2", {}),
])
def test_pending_user_cannot_be_reactivated(client, database, method, path, payload):
    _, uid = database
    db.upsert_user_access(uid, 1, {"remote_user_id": 41})
    assert client.delete(f"/api/vpn-users/{uid}?cascade=true").status_code == 202
    response = getattr(client, method)(f"/api/vpn-users/{uid}{path}", json=payload)
    assert response.status_code == 409
    assert db.get_access(uid, 2) is None
    assert db.get_vpn_user(uid)["enabled"] == 0
    assert db.get_vpn_user(uid)["password_hash"] == "test-hash"


def test_pool_revocation_outbox_survives_final_account_removal(env):
    c = setup_claim(env)
    aid = claim(env, c)
    response = env.client.delete(f"/api/vpn-users/{env.uid}?cascade=true", headers=env.admin)
    assert response.status_code == 202
    assert state(env, aid)["desired_state"] == "revoked"
    assert len(outbox(env, aid)) >= 2
    for access in db.get_user_access(env.uid):
        db.delete_user_access(env.uid, access["vpn_server_id"])
    assert db.get_vpn_user(env.uid) is None
    assert state(env, aid)["desired_state"] == "revoked"
    assert outbox(env, aid)[-1]["status"] == "pending"


def test_import_cannot_restore_a_deleting_users_access(client, database, monkeypatch):
    _, uid = database
    db.upsert_user_access(uid, 1, {"remote_user_id": 41})
    assert client.delete(f"/api/vpn-users/{uid}?cascade=true").status_code == 202
    monkeypatch.setattr(vpn_user_import, "fetch_all", lambda: [{
        "vpn_server_id": 2, "server_name": "two", "server_display_name": "Two", "online": True,
        "users": [{"id": 42, "username": "alice", "password_hash": "test-hash"}],
    }])
    vpn_user_import.apply_import([{"username": "alice", "primary_server_id": 2}])
    assert db.get_access(uid, 2) is None
    assert db.get_vpn_user(uid)["enabled"] == 0


def test_deletion_waits_for_inflight_create_and_removes_returned_remote_id(client, database, monkeypatch):
    original, uid = database
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    original.backup(conn)
    conn.execute("PRAGMA foreign_keys = ON")
    monkeypatch.setattr(db, "_shared_conn", conn)
    db.upsert_user_access(uid, 1, {})
    creating, release, authorized = Event(), Event(), Event()

    class CreatingGate(Gate):
        def call(self, server, method, path, **kwargs):
            if method == "POST":
                creating.set()
                assert release.wait(5), "test did not release create"
                return {"id": 77}, None
            return super().call(server, method, path, **kwargs)

    gate = CreatingGate()
    wire(monkeypatch, gate)
    monkeypatch.setattr(vpn_users, "may_manage_user", lambda uid: authorized.set() or True)
    try:
        with ThreadPoolExecutor(max_workers=2) as workers:
            creating_request = workers.submit(vpn_user_sync.sync_pending, user_id=uid, gate=gate)
            assert creating.wait(5)
            deleting_request = workers.submit(client.delete, f"/api/vpn-users/{uid}?cascade=true")
            try:
                assert authorized.wait(5)
                assert db.get_access(uid, 1) is not None
            finally:
                release.set()
            creating_request.result(timeout=5)
            assert deleting_request.result(timeout=5).status_code == 200
        assert gate.calls == [(1, "/api/vpn/users/77?cascade=true")]
        assert db.get_vpn_user(uid) is None
    finally:
        release.set()
        conn.close()
