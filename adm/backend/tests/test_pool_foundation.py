"""Isolated management-plane contract tests; no live sites or startup side effects."""

import base64
import sqlite3
import uuid
from types import SimpleNamespace

import pytest
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from core import auth, config, db
from api import pool_client, vpn_users


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "adm.db"))
    monkeypatch.setattr(db, "_shared_conn", None)
    monkeypatch.setattr(config, "REPO_ROOT", str(tmp_path))
    monkeypatch.setattr(auth, "JWT_SECRET_PATH", str(tmp_path / "jwt_secret"))
    monkeypatch.setattr(auth, "_jwt_secret", "isolated-test-secret-at-least-32-bytes")
    monkeypatch.setattr(auth, "_fail_tracker", {})
    (tmp_path / "inventory").mkdir()
    (tmp_path / "inventory" / "hosts.yml").write_text("{}")
    from core import first_boot, inventory_writer, scheduler, ssh_keys
    monkeypatch.setattr(first_boot, "import_existing_servers", lambda: None)
    def forbidden(*args, **kwargs):
        raise AssertionError("external side effect forbidden")
    monkeypatch.setattr(inventory_writer, "regenerate_inventory", forbidden)
    monkeypatch.setattr(ssh_keys, "ensure_ssh_key", lambda: None)
    monkeypatch.setattr(ssh_keys, "ensure_group_vars_ssh_key", forbidden)
    monkeypatch.setattr(scheduler, "start_scheduler", lambda: None)
    monkeypatch.setattr(requests.sessions.Session, "request", forbidden)
    monkeypatch.setattr(vpn_users, "_push_now", lambda uid: {})
    from app import create_app
    app = create_app()
    app.testing = True
    conn = db.get_conn()
    for sid in (1, 2):
        conn.execute("INSERT INTO vpn_servers(id,name,display_name,url,public_url,lan_subnet,created_at,updated_at) VALUES (?,?,?,'https://management.invalid',?,'192.168.77.0/24',1,1)",
                     (sid, str(sid), str(sid), f"https://site{sid}.invalid"))
    for name, role in (("alice", "superadmin"), ("scoped", "admin")):
        conn.execute("INSERT INTO admins(username,password_hash,role,created_at) VALUES (?,'unused',?,1)", (name, role))
    conn.commit()
    uid = db.create_vpn_user({"username": "alice", "password_hash": auth.hash_password("stale-password"), "allow_pools": True})
    for sid in (1, 2):
        aid = db.upsert_user_access(uid, sid, {"lan_access": True})
        db.mark_access_synced(aid, remote_user_id=42)
    def delegate(server, method, path, **kwargs):
        assert path == "/api/vpn/auth/login" and kwargs["body"]["password"] == "current-password"
        return SimpleNamespace(status_code=200, json=lambda: {"ok": True, "data": {"token": "discard-site-token", "user": {"id": 42, "username": "alice"}}})
    monkeypatch.setattr(pool_client, "proxima_request", delegate)
    yield SimpleNamespace(client=app.test_client(), conn=conn, uid=uid, monkeypatch=monkeypatch,
                          admin={"Authorization": "Bearer " + auth.create_token("alice")},
                          scoped={"Authorization": "Bearer " + auth.create_token("scoped")})
    conn.close()


def login(e):
    response = e.client.post("/api/vpn/auth/login", json={"username": "alice", "password": "current-password"})
    assert response.status_code == 200, response.json
    return {"Authorization": "Bearer " + response.json["data"]["token"]}


def key():
    private = Ed25519PrivateKey.generate()
    return private, base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def challenge(e, headers, private, public, device, purpose="enroll"):
    response = e.client.post("/api/vpn/devices/challenge", headers=headers,
                             json={"device_id": device, "public_key": public, "purpose": purpose, "name": "Laptop"})
    assert response.status_code == 200, response.json
    data = response.json["data"]
    return {"challenge_id": data["challenge_id"], "signature": base64.b64encode(private.sign(data["message"].encode())).decode()}


def enrolled(e):
    headers = login(e)
    private, public = key()
    device = str(uuid.uuid4())
    proof = challenge(e, headers, private, public, device)
    response = e.client.post("/api/vpn/devices", headers=headers, json=proof)
    assert response.status_code == 201, response.json
    return {"Authorization": "Bearer " + response.json["data"]["token"]}, private, public, device


def test_migration_identity_and_policy(env):
    original = db.get_vpn_user(env.uid)["account_id"]
    assert str(uuid.UUID(original)) == original
    db.init_db()
    assert db.get_vpn_user(env.uid)["account_id"] == original
    with pytest.raises(sqlite3.IntegrityError):
        env.conn.execute("UPDATE vpn_users SET account_id='changed' WHERE id=?", (env.uid,))
    env.conn.rollback()
    uid = db.create_vpn_user({"username": "old-beta", "password_hash": "hash", "update_channel": "beta"})
    assert db.get_vpn_user(uid)["allow_pools"] == 0
    assert db.get_vpn_user(uid)["account_id"] != original
    # Repeatable upgrade of an existing row, including beta accounts.
    env.conn.execute("DROP TRIGGER pool_revoke_user_policy")  # Absent in the pre-pool schema being simulated.
    env.conn.execute("ALTER TABLE vpn_users DROP COLUMN allow_pools")
    db.init_db()
    assert db.get_vpn_user(env.uid)["allow_pools"] == 0


def test_real_middleware_and_stale_hash(env):
    headers = login(env)
    token = headers["Authorization"][7:]
    assert not auth.verify_token(token)
    assert env.conn.execute("SELECT token_hash FROM pool_sessions").fetchone()[0] == pool_client.digest(token)
    for invalid in (env.admin, {"Authorization": "Bearer discard-site-token"}):
        assert env.client.get("/api/vpn/me", headers=invalid).status_code == 401
    assert env.client.get("/api/vpn-users", headers=headers).status_code == 401
    response = env.client.get("/api/vpn/me", headers=headers)
    assert response.headers["Cache-Control"] == "no-store"
    assert set(response.json["data"]) == {"account_id", "update_channel", "allow_pools", "device"}
    assert "password_hash" not in str(response.json)


@pytest.mark.parametrize("payload", [[], True, {}, {"username": [], "password": "x"}, {"username": "alice", "password": 123}])
def test_login_payload(env, payload):
    assert env.client.post("/api/vpn/auth/login", json=payload).status_code == 400


@pytest.mark.parametrize("remote", [{"id": 43, "username": "alice"}, {"id": 42, "username": "Alice"}, {"id": "42", "username": "alice"}])
def test_remote_identity_must_match(env, remote):
    env.monkeypatch.setattr(pool_client, "proxima_request", lambda *a, **k: SimpleNamespace(status_code=200, json=lambda: {"ok": True, "data": {"user": remote}}))
    assert env.client.post("/api/vpn/auth/login", json={"username": "alice", "password": "x"}).status_code == 401
    assert env.conn.execute("SELECT count(*) FROM pool_sessions").fetchone()[0] == 0


@pytest.mark.parametrize("status,expected", [(401, 401), (403, 401), (429, 429), (503, 503)])
def test_delegate_errors(env, status, expected):
    calls = []
    def delegated(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(status_code=status)
    env.monkeypatch.setattr(pool_client, "proxima_request", delegated)
    assert env.client.post("/api/vpn/auth/login", json={"username": "alice", "password": "x"}).status_code == expected
    assert len(calls) == (2 if status == 503 else 1)
    if status in (503, 429):
        assert not any(auth._fail_tracker.values())


def test_transient_retry_and_concurrent_revocation(env):
    calls = []
    def delegated(server, *args, **kwargs):
        calls.append(server["id"])
        if server["id"] == 1:
            raise requests.Timeout()
        db.mark_access_pending_delete(env.uid, 2)
        return SimpleNamespace(status_code=200, json=lambda: {"ok": True, "data": {"user": {"id": 42, "username": "alice"}}})
    env.monkeypatch.setattr(pool_client, "proxima_request", delegated)
    assert env.client.post("/api/vpn/auth/login", json={"username": "alice", "password": "x"}).status_code == 403
    assert calls == [1, 2]


def test_pending_delete_and_unknown_remote_not_delegated(env):
    db.mark_access_pending_delete(env.uid, 1)
    env.conn.execute("UPDATE vpn_user_access SET remote_user_id=NULL WHERE vpn_server_id=2")
    env.conn.commit()
    def forbidden(*args, **kwargs):
        raise AssertionError("ineligible grant called")
    env.monkeypatch.setattr(pool_client, "proxima_request", forbidden)
    assert env.client.post("/api/vpn/auth/login", json={"username": "alice", "password": "x"}).status_code == 503
    assert not any(auth._fail_tracker.values())
    db.mark_access_pending_delete(env.uid, 2)
    assert env.client.post("/api/vpn/auth/login", json={"username": "alice", "password": "x"}).status_code == 401


def test_device_replay_renewal_logout_and_tombstone(env):
    headers, private, public, device = enrolled(env)
    def forbidden(*args, **kwargs):
        raise AssertionError("device renewal must not contact sites")
    env.monkeypatch.setattr(pool_client, "proxima_request", forbidden)
    proof = challenge(env, {}, private, public, device, "authenticate")
    renewed = env.client.post("/api/vpn/auth/device", json=proof)
    assert renewed.status_code == 200
    assert env.client.post("/api/vpn/auth/device", json=proof).status_code == 401
    assert env.client.post("/api/vpn/auth/logout", headers=headers).status_code == 200
    assert env.client.get("/api/vpn/me", headers=headers).status_code == 401
    proof = challenge(env, {}, private, public, device, "authenticate")
    assert env.client.post("/api/vpn/auth/device", json=proof).status_code == 200
    headers = {"Authorization": "Bearer " + renewed.json["data"]["token"]}
    pending = challenge(env, {}, private, public, device, "authenticate")
    assert env.client.delete(f"/api/vpn/devices/{device}", headers=headers).status_code == 200
    assert env.client.get("/api/vpn/me", headers=headers).status_code == 401
    assert env.client.post("/api/vpn/auth/device", json=pending).status_code == 401
    assert env.conn.execute("SELECT revoked_at FROM pool_devices WHERE device_id=?", (device,)).fetchone()[0]


def test_single_use_and_bound_session_proof(env):
    headers = login(env)
    other = login(env)
    private, public = key()
    proof = challenge(env, headers, private, public, str(uuid.uuid4()))
    assert env.client.post("/api/vpn/devices", headers=other, json=proof).status_code == 401
    assert env.client.post("/api/vpn/auth/device", json=proof).status_code == 401
    assert env.client.post("/api/vpn/devices", headers=headers, json={**proof, "signature": "bad"}).status_code == 401
    assert env.client.post("/api/vpn/devices", headers=headers, json=proof).status_code == 201
    assert env.client.post("/api/vpn/devices", headers=headers, json=proof).status_code == 401
    assert env.client.get("/api/vpn/me", headers=headers).status_code == 401


def test_cross_account_and_revoked_reenrollment(env):
    headers, private, public, device = enrolled(env)
    second = db.create_vpn_user({"username": "bob", "password_hash": "unused", "allow_pools": True})
    from core.pool_db import transaction
    with transaction() as conn:
        issued = pool_client.issue(conn, db.get_vpn_user(second)["account_id"])
    other = {"Authorization": "Bearer " + issued["token"]}
    assert env.client.get("/api/vpn/devices", headers=other).json["data"] == []
    assert env.client.delete(f"/api/vpn/devices/{device}", headers=other).status_code == 404
    assert env.client.delete(f"/api/vpn/devices/{device}", headers=headers).status_code == 200
    for did, pub in ((device, public), (str(uuid.uuid4()), public), (device, key()[1])):
        assert env.client.post("/api/vpn/devices/challenge", headers=other, json={"device_id": did, "public_key": pub, "purpose": "enroll"}).status_code == 409


@pytest.mark.parametrize("value", [0, 1, None, "true", [], {}])
def test_strict_admin_flags(env, value):
    for field in ("allow_pools", "enable_pool_beta"):
        assert env.client.put(f"/api/vpn-users/{env.uid}", headers=env.admin, json={field: value}).status_code == 400


def test_channel_independent_and_superadmin_only(env):
    scoped = db.get_admin_by_username("scoped")
    db.set_admin_scope(scoped["id"], [1, 2])
    path = f"/api/vpn-users/{env.uid}"
    for enabled, channel in ((False, "stable"), (True, "beta")):
        res = env.client.put(path, headers=env.admin, json={"enable_pool_beta": enabled})
        assert res.status_code == 200
        assert (res.json["data"]["allow_pools"], res.json["data"]["update_channel"]) == (enabled, channel)
    assert env.client.put(path, headers=env.admin, json={"update_channel": "stable"}).json["data"]["allow_pools"] is True
    assert env.client.put(path, headers=env.admin, json={"allow_pools": False, "update_channel": "beta"}).status_code == 200
    assert env.client.post("/api/vpn/auth/login", json={"username": "alice", "password": "current-password"}).status_code == 401
    assert env.client.put(path, headers=env.scoped, json={"allow_pools": True}).status_code == 403
    assert env.client.put(path, headers=env.scoped, json={"enable_pool_beta": True}).status_code == 403
    assert env.client.post("/api/vpn-users", headers=env.scoped, json={"username": "scoped-new", "password": "test-password", "allow_pools": True, "servers": [{"vpn_server_id": 1}]}).status_code == 403
    assert env.client.put(path, headers=env.scoped, json={"note": "ordinary scoped edit"}).status_code == 200
    assert env.client.get("/api/pool-catalog", headers=env.scoped).status_code == 403


def catalog_body(resources=None):
    return {"label": "Türkiye", "exit_country": "TR", "routing_mode": "fast", "resources": resources or [],
            "members": [{"site_id": sid, "bindings": [{"connection_type": "vless_reality", "routing_mode": "fast", "profile_format": "sing_box"}]} for sid in (1, 2)]}


def test_manifest_explicit_authorization_and_unavailable(env):
    headers = login(env)
    assert env.client.get("/api/vpn/pools", headers=headers).json["data"]["pools"] == []
    created = env.client.post("/api/pool-catalog", headers=env.admin, json=catalog_body())
    assert created.status_code == 201, created.json
    pool = created.json["data"]
    assert env.client.get("/api/vpn/pools", headers=headers).json["data"]["pools"] == []
    grant = f"/api/pool-catalog/{pool['id']}/users/{env.uid}"
    assert env.client.put(grant, headers=env.admin, json={"enabled": True}).status_code == 200
    manifest = env.client.get("/api/vpn/pools", headers=headers).json["data"]["pools"][0]
    assert len(manifest["members"]) == 2
    assert all(m["eligible"] is False and m["reason"] == "attachment_not_provisioned" for m in manifest["members"])
    db.mark_access_pending_delete(env.uid, 2)
    manifest = env.client.get("/api/vpn/pools", headers=headers).json["data"]["pools"][0]
    assert [m["site_id"] for m in manifest["members"]] == [1]
    assert "management.invalid" not in str(manifest)
    assert env.client.put(f"/api/pool-catalog/{pool['id']}", headers=env.admin, json={"eligible": True}).status_code == 400
    assert env.client.put(grant, headers=env.admin, json={"enabled": False}).status_code == 200
    assert env.client.get("/api/vpn/pools", headers=headers).json["data"]["pools"] == []


def test_lan_scope_never_leaks(env):
    headers = login(env)
    pool = env.client.post("/api/pool-catalog", headers=env.admin, json=catalog_body([{"site_id": 2, "cidrs": ["192.168.77.0/25"]}])).json["data"]
    env.client.put(f"/api/pool-catalog/{pool['id']}/users/{env.uid}", headers=env.admin, json={"enabled": True})
    assert len(env.client.get("/api/vpn/pools", headers=headers).json["data"]["pools"]) == 1
    db.upsert_user_access(env.uid, 2, {"lan_access": False})
    response = env.client.get("/api/vpn/pools", headers=headers)
    assert response.json["data"]["pools"] == []
    assert "192.168.77" not in str(response.json)


@pytest.mark.parametrize("patch", [{"exit_country": "ZZ"}, {"eligible": True}, {"routing_mode": "smart"}, {"resources": [{"site_id": 2, "cidrs": ["10.0.0.0/8"]}]}])
def test_invalid_catalog(env, patch):
    assert env.client.post("/api/pool-catalog", headers=env.admin, json={**catalog_body(), **patch}).status_code == 400


@pytest.mark.parametrize("mutation", ["disabled", "no_pools", "disabled_grant", "remote_id", "pending_delete"])
def test_atomic_login_recheck(env, mutation):
    def delegated(*args, **kwargs):
        if mutation in ("disabled", "no_pools"):
            db.update_vpn_user(env.uid, {"enabled" if mutation == "disabled" else "allow_pools": 0})
        elif mutation == "pending_delete":
            db.mark_access_pending_delete(env.uid, 1)
        else:
            column = "enabled" if mutation == "disabled_grant" else "remote_user_id"
            env.conn.execute(f"UPDATE vpn_user_access SET {column}=0 WHERE vpn_server_id=1")
            env.conn.commit()
        return SimpleNamespace(status_code=200, json=lambda: {"ok": True, "data": {"user": {"id": 42, "username": "alice"}}})
    env.monkeypatch.setattr(pool_client, "proxima_request", delegated)
    assert env.client.post("/api/vpn/auth/login", json={"username": "alice", "password": "x"}).status_code == 403
    assert env.conn.execute("SELECT count(*) FROM pool_sessions").fetchone()[0] == 0


@pytest.mark.parametrize("status,ok,remote,expected", [
    (401, True, {"id": 42, "username": "alice"}, 401),
    (500, True, {"id": 42, "username": "alice"}, 503),
    (307, True, {"id": 42, "username": "alice"}, 503),
    (200, 1, {"id": 42, "username": "alice"}, 401),
    (200, True, {"id": True, "username": "alice"}, 401),
    (200, True, {"id": 42, "username": "alice", "enabled": False}, 401),
    (200, True, {"id": 42, "username": "alice", "enabled": "true"}, 401),
])
def test_strict_remote_envelope(env, status, ok, remote, expected):
    env.monkeypatch.setattr(pool_client, "proxima_request", lambda *a, **k: SimpleNamespace(status_code=status, json=lambda: {"ok": ok, "data": {"user": remote}}))
    assert env.client.post("/api/vpn/auth/login", json={"username": "alice", "password": "x"}).status_code == expected


@pytest.mark.parametrize("url,allowed", [("https://registered.invalid", True), ("http://127.0.0.1:5001", True),
    ("http://[::1]:5001", True), ("http://10.0.0.1", False), ("https://user:secret@site.invalid", False),
    ("https://site.invalid?next=evil", False), ("ftp://site.invalid", False)])
def test_bootstrap_transport_no_redirects_or_admin_token(env, url, allowed):
    from core import proxima_client
    calls = []
    env.monkeypatch.setattr(requests, "post", lambda *a, **k: calls.append((a, k)) or SimpleNamespace(status_code=307))
    server = {"url": url, "api_token_enc": "must-not-decrypt"}
    if not allowed:
        with pytest.raises(ValueError):
            proxima_client.request(server, "POST", "/api/vpn/auth/login", body={"password": "secret"}, credential_bootstrap=True)
        assert calls == []
    else:
        response = proxima_client.request(server, "POST", "/api/vpn/auth/login", body={"password": "secret"}, credential_bootstrap=True)
        assert response.status_code == 307 and len(calls) == 1
        assert calls[0][1]["allow_redirects"] is False
        assert calls[0][1]["verify"] is True
        assert calls[0][1]["headers"] == {}


def test_expired_proof_and_immutable_key(env):
    headers = login(env)
    private, public = key()
    device = str(uuid.uuid4())
    proof = challenge(env, headers, private, public, device)
    env.conn.execute("UPDATE pool_challenges SET expires_at=0")
    env.conn.commit()
    assert env.client.post("/api/vpn/devices", headers=headers, json=proof).status_code == 401
    proof = challenge(env, headers, private, public, device)
    assert env.client.post("/api/vpn/devices", headers=headers, json=proof).status_code == 201
    other_key = key()[1]
    assert env.client.post("/api/vpn/devices/challenge", json={"device_id": device, "public_key": other_key, "purpose": "authenticate"}).status_code == 401


def test_enrollment_race_single_winner(env):
    # Both requests already hold valid proofs for the same immutable identity.
    headers = login(env)
    private, public = key()
    device = str(uuid.uuid4())
    first = challenge(env, headers, private, public, device)
    second = challenge(env, headers, private, public, device)
    from concurrent.futures import ThreadPoolExecutor
    def enroll(proof):
        with env.client.application.test_client() as client:
            return client.post("/api/vpn/devices", headers=headers, json=proof).status_code
    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = list(executor.map(enroll, (first, second)))
    assert sorted(statuses) == [201, 401]
    assert env.conn.execute("SELECT count(*) FROM pool_devices").fetchone()[0] == 1


def test_import_cannot_set_pool_policy(env):
    from core import vpn_user_import
    original = db.get_vpn_user(env.uid)["account_id"]
    env.monkeypatch.setattr(vpn_user_import, "fetch_all", lambda: [{
        "vpn_server_id": 1, "server_name": "one", "server_display_name": "One", "online": True,
        "users": [{"id": 42, "username": "alice", "password_hash": "hash", "allow_pools": False, "account_id": "hostile"},
                  {"id": 43, "username": "bob", "password_hash": "hash", "allow_pools": True, "account_id": "hostile"}],
    }])
    vpn_user_import.apply_import([{"username": name, "primary_server_id": 1} for name in ("alice", "bob")])
    assert db.get_vpn_user(env.uid)["allow_pools"] == 1
    assert db.get_vpn_user(env.uid)["account_id"] == original
    assert db.get_vpn_user_by_username("bob")["allow_pools"] == 0
    assert db.get_vpn_user_by_username("bob")["account_id"] != "hostile"
    from core.vpn_user_sync import _remote_payload
    db.mark_all_access_pending(env.uid)
    payload = _remote_payload(db.get_pending_access()[0])
    assert not {"account_id", "allow_pools"} & payload.keys()
    public = env.client.get(f"/api/vpn-users/{env.uid}", headers=env.admin).json["data"]
    assert "account_id" not in public and "password_hash" not in public


def test_legacy_account_id_backfill_is_repeatable():
    from core.pool_db import migrate
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE vpn_users(id INTEGER PRIMARY KEY, update_channel TEXT)")
    conn.executemany("INSERT INTO vpn_users VALUES (?,?)", [(1, "stable"), (2, "beta")])
    migrate(conn)
    first = conn.execute("SELECT account_id,allow_pools FROM vpn_users ORDER BY id").fetchall()
    assert len({str(uuid.UUID(row[0])) for row in first}) == 2
    assert [row[1] for row in first] == [0, 0]
    migrate(conn)
    assert conn.execute("SELECT account_id,allow_pools FROM vpn_users ORDER BY id").fetchall() == first
    conn.close()


def test_rate_limit_checks_do_not_create_failure_records(env):
    assert auth.check_rate_limit("unused") is None
    assert auth._fail_tracker == {}
    for _ in range(auth.MAX_ATTEMPTS):
        auth.record_login_failure("identity")
    assert auth.check_rate_limit("identity") > 0
    auth.clear_login_failures("identity")
    assert auth.check_rate_limit("identity") is None
    assert auth._fail_tracker == {}


@pytest.mark.parametrize("policy,code", [("revoked", "device_revoked"), ("allow_pools", "pool_access_disabled"),
                                       ("enabled", "account_disabled"), ("deleted", "account_deleted")])
def test_signed_policy_denials_are_private_single_use(env, policy, code):
    headers, private, public, device = enrolled(env)
    old_proof = challenge(env, {}, private, public, device, "authenticate")
    if policy == "revoked":
        assert env.client.delete(f"/api/vpn/devices/{device}", headers=headers).status_code == 200
        assert env.client.post("/api/vpn/auth/device", json=old_proof).json["error"] == "invalid_proof"
    elif policy == "deleted":
        db.delete_vpn_user(env.uid)
    else:
        db.update_vpn_user(env.uid, {policy: 0})
    assert env.client.get("/api/vpn/me", headers=headers).status_code == 401
    assert env.client.get("/api/vpn/me", headers={"Authorization": "Bearer pool_invalid"}).json["error"] == "unauthorized"
    # Challenge issuance is identical regardless of policy; only the signature discloses it.
    proof = challenge(env, {}, private, public, device, "authenticate")
    wrong = {**proof, "signature": base64.b64encode(key()[0].sign(b"wrong")).decode()}
    assert env.client.post("/api/vpn/auth/device", json=wrong).json == {"ok": False, "error": "invalid_proof"}
    count = env.conn.execute("SELECT count(*) FROM pool_sessions").fetchone()[0]
    response = env.client.post("/api/vpn/auth/device", json=proof)
    assert response.status_code == 403 and response.json == {"ok": False, "error": code}
    assert env.conn.execute("SELECT count(*) FROM pool_sessions").fetchone()[0] == count
    assert env.client.post("/api/vpn/auth/device", json=proof).json == {"ok": False, "error": "invalid_proof"}
    if policy != "revoked":
        # A challenge obtained before policy changed reports the current signed denial too.
        assert env.client.post("/api/vpn/auth/device", json=old_proof).json["error"] == code
    for did, pub in ((str(uuid.uuid4()), public), (device, key()[1])):
        response = env.client.post("/api/vpn/devices/challenge", json={"device_id": did, "public_key": pub, "purpose": "authenticate"})
        assert response.status_code == 401 and response.json["error"] == "invalid_device"


def test_same_identity_enrollment_recovery_keeps_original_record(env):
    _, private, public, device = enrolled(env)
    original = dict(env.conn.execute("SELECT * FROM pool_devices WHERE device_id=?", (device,)).fetchone())
    headers = login(env)
    for did, pub in ((device, key()[1]), (str(uuid.uuid4()), public)):
        assert env.client.post("/api/vpn/devices/challenge", headers=headers,
                               json={"device_id": did, "public_key": pub, "purpose": "enroll"}).status_code == 409
    response = env.client.post("/api/vpn/devices/challenge", headers=headers,
                               json={"device_id": device, "public_key": public, "purpose": "enroll", "name": "Do not rename"})
    assert response.status_code == 200
    data = response.json["data"]
    proof = {"challenge_id": data["challenge_id"], "signature": base64.b64encode(private.sign(data["message"].encode())).decode()}
    response = env.client.post("/api/vpn/devices", headers=headers, json=proof)
    assert response.status_code == 200 and response.json["data"]["created"] is False
    assert dict(env.conn.execute("SELECT * FROM pool_devices WHERE device_id=?", (device,)).fetchone()) == original
    assert env.conn.execute("SELECT count(*) FROM pool_devices").fetchone()[0] == 1
    assert env.client.get("/api/vpn/me", headers={"Authorization": "Bearer " + response.json["data"]["token"]}).status_code == 200
    assert env.client.post("/api/vpn/devices", headers=headers, json=proof).status_code == 401


def test_recovery_of_never_committed_identity_and_revoked_new_registration(env):
    headers = login(env)
    private, public = key()
    device = str(uuid.uuid4())
    challenge(env, headers, private, public, device)  # Simulate a request never sent.
    proof = challenge(env, headers, private, public, device)
    response = env.client.post("/api/vpn/devices", headers=headers, json=proof)
    assert response.status_code == 201 and response.json["data"]["created"] is True
    device_headers = {"Authorization": "Bearer " + response.json["data"]["token"]}
    assert env.client.delete(f"/api/vpn/devices/{device}", headers=device_headers).status_code == 200
    headers = login(env)
    assert env.client.post("/api/vpn/devices/challenge", headers=headers,
                           json={"device_id": device, "public_key": public, "purpose": "enroll"}).status_code == 409
    # Explicit new registration uses new credentials and never clears the old tombstone.
    private2, public2 = key()
    device2 = str(uuid.uuid4())
    proof = challenge(env, headers, private2, public2, device2)
    assert env.client.post("/api/vpn/devices", headers=headers, json=proof).status_code == 201
    assert env.conn.execute("SELECT revoked_at FROM pool_devices WHERE device_id=?", (device,)).fetchone()[0]
    headers = login(env)
    private3, public3 = key()
    proof = challenge(env, headers, private3, public3, str(uuid.uuid4()))
    db.update_vpn_user(env.uid, {"allow_pools": 0})
    assert env.client.post("/api/vpn/devices", headers=headers, json=proof).status_code == 401
    assert env.conn.execute("SELECT count(*) FROM pool_devices").fetchone()[0] == 2


def test_cross_account_recovery_rejected_and_explicit_switch_separate(env):
    _, private, public, device = enrolled(env)
    uid = db.create_vpn_user({"username": "bob", "password_hash": "unused", "allow_pools": True})
    from core.pool_db import transaction
    with transaction() as conn:
        issued = pool_client.issue(conn, db.get_vpn_user(uid)["account_id"])
    headers = {"Authorization": "Bearer " + issued["token"]}
    for did, pub in ((device, public), (device, key()[1]), (str(uuid.uuid4()), public)):
        assert env.client.post("/api/vpn/devices/challenge", headers=headers,
                               json={"device_id": did, "public_key": pub, "purpose": "enroll"}).status_code == 409
    private2, public2 = key()
    device2 = str(uuid.uuid4())
    proof = challenge(env, headers, private2, public2, device2)
    assert env.client.post("/api/vpn/devices", headers=headers, json=proof).status_code == 201
    assert env.conn.execute("SELECT count(*) FROM pool_devices").fetchone()[0] == 2
    proof = challenge(env, {}, private, public, device, "authenticate")
    assert env.client.post("/api/vpn/auth/device", json=proof).status_code == 200


def test_lost_self_delete_confirmed_by_authenticated_owner(env):
    headers, _, _, device = enrolled(env)
    env.client.delete(f"/api/vpn/devices/{device}", headers=headers)  # Response lost.
    assert env.client.get("/api/vpn/me", headers=headers).status_code == 401
    fresh = login(env)
    devices = env.client.get("/api/vpn/devices", headers=fresh).json["data"]
    assert devices[0]["device_id"] == device and devices[0]["revoked_at"] is not None
    timestamp = devices[0]["revoked_at"]
    assert env.client.delete(f"/api/vpn/devices/{device}", headers=fresh).json["data"] == {"revoked": True}
    assert env.client.get("/api/vpn/devices", headers=fresh).json["data"][0]["revoked_at"] == timestamp


def test_recovery_rechecks_revocation_after_challenge(env):
    active, private, public, device = enrolled(env)
    headers = login(env)
    proof = challenge(env, headers, private, public, device)
    assert env.client.delete(f"/api/vpn/devices/{device}", headers=active).status_code == 200
    assert env.client.post("/api/vpn/devices", headers=headers, json=proof).status_code == 401
    assert env.conn.execute("SELECT revoked_at FROM pool_devices WHERE device_id=?", (device,)).fetchone()[0]
    assert env.client.post("/api/vpn/devices/challenge", headers=headers,
                           json={"device_id": device, "public_key": public, "purpose": "enroll"}).status_code == 409
