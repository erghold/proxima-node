"""Smart Test is an explicit, site-local grant, never an identity default."""

import sqlite3

import pytest
from flask import Flask, g

from api import vpn_users
from core import db, vpn_user_import, vpn_user_sync


@pytest.fixture
def database(monkeypatch):
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    monkeypatch.setattr(db, "_shared_conn", conn)
    db.init_db()
    for sid in (1, 2):
        conn.execute(
            "INSERT INTO vpn_servers (id, name, display_name, url, created_at, updated_at) "
            "VALUES (?, ?, ?, 'http://test.invalid', 1, 1)", (sid, str(sid), str(sid)),
        )
    conn.commit()
    uid = db.create_vpn_user({"username": "alice", "password_hash": "test-hash"})
    yield conn, uid
    conn.close()


@pytest.fixture
def client(database, monkeypatch):
    app = Flask(__name__)
    app.register_blueprint(vpn_users.bp)

    @app.before_request
    def admin():
        g.admin = {"id": 1, "role": "superadmin"}

    monkeypatch.setattr(vpn_users, "_push_now", lambda uid: {})
    return app.test_client()


def test_defaults_migration_and_site_isolation(database):
    conn, uid = database
    db.upsert_user_access(uid, 1, {})
    db.upsert_user_access(uid, 2, {})
    conn.execute("ALTER TABLE vpn_user_access DROP COLUMN allow_smart_test")
    db.init_db()
    column = next(r for r in conn.execute("PRAGMA table_info(vpn_user_access)")
                  if r["name"] == "allow_smart_test")
    assert (column["type"], column["notnull"], column["dflt_value"]) == ("INTEGER", 1, "0")
    assert db.get_access(uid, 1)["allow_smart_test"] == 0
    db.upsert_user_access(uid, 1, {"allow_smart_test": 1})
    db.init_db()  # Repeated startup must not erase an explicit grant.
    assert db.get_access(uid, 1)["allow_smart_test"] == 1
    assert db.get_access(uid, 2)["allow_smart_test"] == 0


@pytest.mark.parametrize("value", [None, 0, 1, "true", "false", [], {}])
def test_api_rejects_non_boolean_without_writing(client, database, value):
    _, uid = database
    response = client.put(f"/api/vpn-users/{uid}/access/1", json={"allow_smart_test": value})
    assert response.status_code == 400
    assert db.get_access(uid, 1) is None
    response = client.post("/api/vpn-users", json={
        "username": "bob", "password": "test-password",
        "servers": [{"vpn_server_id": 1, "allow_smart_test": value}],
    })
    assert response.status_code == 400
    assert db.get_vpn_user_by_username("bob") is None


def test_api_grant_partial_edit_and_revoke(client, database):
    _, uid = database
    path = f"/api/vpn-users/{uid}/access/1"
    assert client.put(path, json={}).json["data"]["allow_smart_test"] is False
    for value in (True, False):
        response = client.put(path, json={"allow_smart_test": value})
        assert response.status_code == 200
        assert response.json["data"]["allow_smart_test"] is value
        assert client.put(path, json={"max_peers": 4}).json["data"]["allow_smart_test"] is value
        assert client.get(f"/api/vpn-users/{uid}").json["data"]["servers"][0]["allow_smart_test"] is value
        assert db.get_access(uid, 1)["sync_status"] == "pending"


@pytest.mark.parametrize("value", [True, False])
def test_create_user_serializes_assignment_grant(client, value):
    response = client.post("/api/vpn-users", json={
        "username": "bob", "password": "test-password",
        "servers": [{"vpn_server_id": 1, "allow_smart_test": value}],
    })
    assert response.status_code == 201
    assert response.json["data"]["servers"][0]["allow_smart_test"] is value


def test_scoped_admin_cannot_grant_other_site(client, database, monkeypatch):
    _, uid = database
    monkeypatch.setattr(vpn_users, "may_manage_server", lambda sid: False)
    assert client.put(f"/api/vpn-users/{uid}/access/1", json={"allow_smart_test": True}).status_code == 403
    assert db.get_access(uid, 1) is None


def test_create_update_sync_send_explicit_boolean(database):
    _, uid = database
    db.upsert_user_access(uid, 1, {})
    server = db.get_vpn_server(1)
    calls = []

    class Gate:
        def call(self, server, method, path, body=None):
            calls.append((method, body))
            return {"id": 42}, None

    row = db.get_pending_access()[0]
    assert vpn_user_sync._push_create(server, row, {1: server}, Gate())[0]
    assert calls[-1][1]["allow_smart_test"] is False
    for value in (1, 0):
        db.upsert_user_access(uid, 1, {"allow_smart_test": value})
        row = db.get_pending_access()[0]
        assert vpn_user_sync._push_update(server, row, {1: server}, Gate())[0]
        assert calls[-1][1]["allow_smart_test"] is bool(value)
    del row["allow_smart_test"]
    assert vpn_user_sync._remote_payload(row)["allow_smart_test"] is False


@pytest.mark.parametrize("value", [None, "true", "false", "1", 2, -1, 1.0])
def test_malformed_stored_grants_never_become_authorization(database, value):
    _, uid = database
    db.upsert_user_access(uid, 1, {"allow_smart_test": value})
    assert db.get_access(uid, 1)["allow_smart_test"] == 0
    row = db.get_pending_access()[0]
    row["allow_smart_test"] = value
    assert vpn_user_sync._remote_payload(row)["allow_smart_test"] is False
    assert vpn_users._public_access(row)["allow_smart_test"] is False


@pytest.mark.parametrize("remote, expected", [({}, False), ({"allow_smart_test": True}, True),
    ({"allow_smart_test": False}, False), ({"allow_smart_test": 1}, True),
    ({"allow_smart_test": "true"}, False)])
def test_import_preserves_only_explicit_remote_grant(database, monkeypatch, remote, expected):
    _, uid = database
    db.upsert_user_access(uid, 1, {"allow_smart_test": 1})
    monkeypatch.setattr(vpn_user_import, "fetch_all", lambda: [{
        "vpn_server_id": 1, "server_name": "one", "server_display_name": "One",
        "online": True, "users": [{"id": 42, "username": "alice", "password_hash": "test-hash", **remote}],
    }])
    preview = vpn_user_import.build_preview()
    assert preview["entries"][0]["sources"][0]["allow_smart_test"] is expected
    vpn_user_import.apply_import([{"username": "alice", "primary_server_id": 1}])
    assert db.get_access(uid, 1)["allow_smart_test"] == int(expected)
