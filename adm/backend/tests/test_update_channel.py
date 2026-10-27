"""Update channel belongs to the central identity, not a site grant."""

import pytest

from api import vpn_users
from core import db, vpn_user_import, vpn_user_sync
from tests.test_smart_test_permission import database, client  # noqa: F401


def test_migration_defaults_and_idempotence(database):
    conn, uid = database
    conn.execute("ALTER TABLE vpn_users DROP COLUMN update_channel")
    db.init_db()
    column = next(r for r in conn.execute("PRAGMA table_info(vpn_users)") if r["name"] == "update_channel")
    assert (column["type"], column["notnull"], column["dflt_value"]) == ("TEXT", 1, "'stable'")
    assert db.get_vpn_user(uid)["update_channel"] == "stable"
    db.update_vpn_user(uid, {"update_channel": "beta"})
    db.init_db()
    assert db.get_vpn_user(uid)["update_channel"] == "beta"
    assert "update_channel" not in {r["name"] for r in conn.execute("PRAGMA table_info(vpn_user_access)")}


@pytest.mark.parametrize("value", [None, True, False, 0, 1, [], {}, "", "Beta", " stable", "nightly"])
def test_invalid_channel_rejected_without_writes(client, database, value):
    _, uid = database
    assert client.post("/api/vpn-users", json={"username": "bob", "update_channel": value}).status_code == 400
    assert db.get_vpn_user_by_username("bob") is None
    assert client.put(f"/api/vpn-users/{uid}", json={"update_channel": value, "note": "changed"}).status_code == 400
    assert db.get_vpn_user(uid)["update_channel"] == "stable"
    assert db.get_vpn_user(uid)["note"] == ""


@pytest.mark.parametrize("channel", [None, "stable", "beta"])
def test_create_and_serialize(client, channel):
    body = {"username": "bob", "password": "test-password"}
    if channel is not None:
        body["update_channel"] = channel
    response = client.post("/api/vpn-users", json=body)
    assert response.status_code == 201
    assert response.json["data"]["update_channel"] == (channel or "stable")


def test_edit_pushes_all_sites_independently_of_smart_test(client, database, monkeypatch):
    _, uid = database
    calls = []

    class Gate:
        def call(self, server, method, path, body=None):
            calls.append((server["id"], method, body))
            return {"id": 42}, None

    for sid in (1, 2):
        aid = db.upsert_user_access(uid, sid, {"allow_smart_test": sid == 1})
        db.mark_access_synced(aid, remote_user_id=42)
    for channel in ("beta", "stable"):
        assert client.put(f"/api/vpn-users/{uid}", json={"update_channel": channel}).status_code == 200
        rows = db.get_pending_access()
        assert len(rows) == 2
        for row in rows:
            server = db.get_vpn_server(row["vpn_server_id"])
            assert vpn_user_sync._push_update(server, row, {server["id"]: server}, Gate())[0]
            assert calls[-1][2]["update_channel"] == channel
            assert calls[-1][2]["allow_smart_test"] is (server["id"] == 1)
        assert client.put(f"/api/vpn-users/{uid}", json={"note": "kept"}).json["data"]["update_channel"] == channel
    db.upsert_user_access(uid, 1, {})
    row = db.get_pending_access()[0]
    assert vpn_user_sync._push_create(db.get_vpn_server(1), row, {}, Gate())[0]
    assert calls[-1][2]["update_channel"] == "stable"


@pytest.mark.parametrize("value", [None, "", "Beta", "nightly", 1, [], {}])
def test_serialization_fails_closed(database, value):
    _, uid = database
    user = db.get_vpn_user(uid)
    user["update_channel"] = value
    assert vpn_users._public_user(user, [])["update_channel"] == "stable"
    db.upsert_user_access(uid, 1, {})
    row = db.get_pending_access()[0]
    row["user_update_channel"] = value
    row["update_channel"] = "beta"  # Never consume an assignment-column collision.
    assert vpn_user_sync._remote_payload(row)["update_channel"] == "stable"
    del row["user_update_channel"]
    assert vpn_user_sync._remote_payload(row)["update_channel"] == "stable"


def test_identity_scope_guard(client, database, monkeypatch):
    _, uid = database
    monkeypatch.setattr(vpn_users, "may_manage_user", lambda uid: False)
    assert client.put(f"/api/vpn-users/{uid}", json={"update_channel": "beta"}).status_code == 403
    assert db.get_vpn_user(uid)["update_channel"] == "stable"


def test_channel_edit_preserves_offline_revocation(client, database):
    _, uid = database
    for sid in (1, 2):
        aid = db.upsert_user_access(uid, sid, {})
        db.mark_access_synced(aid, remote_user_id=42)
    db.mark_access_pending_delete(uid, 2)
    assert client.put(f"/api/vpn-users/{uid}", json={"update_channel": "beta"}).status_code == 200
    assert db.get_access(uid, 2)["sync_status"] == "pending_delete"
    calls = []

    class Gate:
        offline = True

        def down_reason(self, server):
            return "offline" if self.offline and server["id"] == 2 else None

        def call(self, server, method, path, body=None):
            calls.append((server["id"], method, body))
            return {"id": 42}, None

    gate = Gate()
    result = vpn_user_sync.sync_pending(user_id=uid, gate=gate)
    assert len(result["updated"]) == 1
    assert len(result["deferred"]) == 1
    assert calls == [(1, "PUT", calls[0][2])]
    assert calls[0][2]["update_channel"] == "beta"
    assert db.get_access(uid, 2)["sync_status"] == "pending_delete"
    gate.offline = False
    result = vpn_user_sync.sync_pending(user_id=uid, gate=gate)
    assert len(result["removed"]) == 1
    assert calls[-1][0:2] == (2, "DELETE")
    assert db.get_access(uid, 2) is None


def test_import_cannot_override_policy_and_new_identity_defaults_stable(database, monkeypatch):
    _, uid = database
    db.update_vpn_user(uid, {"update_channel": "beta"})
    monkeypatch.setattr(vpn_user_import, "fetch_all", lambda: [{
        "vpn_server_id": 1, "server_name": "one", "server_display_name": "One", "online": True,
        "users": [
            {"id": 42, "username": "alice", "password_hash": "test-hash", "update_channel": "stable"},
            {"id": 43, "username": "bob", "password_hash": "test-hash", "update_channel": "beta"},
        ],
    }])
    vpn_user_import.apply_import([{"username": name, "primary_server_id": 1} for name in ("alice", "bob")])
    assert db.get_vpn_user(uid)["update_channel"] == "beta"
    bob = db.get_vpn_user_by_username("bob")
    assert bob["update_channel"] == "stable"
    rows = db.get_pending_access()
    assert {r["username"]: vpn_user_sync._remote_payload(r)["update_channel"] for r in rows} == {"alice": "beta", "bob": "stable"}
