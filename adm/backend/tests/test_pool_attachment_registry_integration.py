"""Cross-repository protocol checks against the real site registry, without sockets."""

import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
from types import ModuleType, SimpleNamespace
from urllib.parse import urlsplit

from flask import Flask, g, jsonify, request
import pytest
import requests

from core import db, proxima_client
from tests.test_pool_foundation import env  # noqa: F401
from tests.test_pool_attachment_delivery import setup_claim, claim, state, outbox


SITE_BACKEND = Path(__file__).resolve().parents[4] / "proxima" / "backend"
pytestmark = pytest.mark.skipif(
    not (SITE_BACKEND / "core" / "pool_runtime.py").exists(),
    reason="Cross-repository integration requires the companion Proxima site checkout",
)


def load_site_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def site_bridge(tmp_path, monkeypatch):
    # Only the DB path is adapted; the site's validation, transactions and routes
    # execute unchanged. Separate imports prevent ADM's core package being reused.
    site_core = ModuleType("core")
    site_core.db = SimpleNamespace(DB_PATH=str(tmp_path / "site-registry.db"))
    with monkeypatch.context() as imports:
        imports.setitem(sys.modules, "core", site_core)
        registry = load_site_module("integration_site_registry", SITE_BACKEND / "core" / "pool_attachments.py")
        site_core.pool_attachments = registry
        imports.setitem(sys.modules, "core.pool_attachments", registry)
        binding = load_site_module("integration_site_binding", SITE_BACKEND / "core" / "pool_binding.py")
        imports.setitem(sys.modules, "core.pool_binding", binding)
        runtime = load_site_module("integration_site_runtime", SITE_BACKEND / "core" / "pool_runtime.py")
        routes = load_site_module("integration_site_routes", SITE_BACKEND / "api" / "pool_attachments.py")
        auth = load_site_module("integration_site_auth", SITE_BACKEND / "core" / "auth.py")
    conn = sqlite3.connect(site_core.db.DB_PATH)
    registry.init_schema(conn)
    runtime.init_schema(conn)
    conn.commit()
    conn.close()

    app = Flask("integration-site-registry")
    app.testing = True
    secret = "isolated-registry-fixture-secret-over-32-bytes"

    @app.before_request
    def authenticate():
        header = request.headers.get("Authorization", "")
        info = auth.verify_token(header[7:], secret) if header.startswith("Bearer ") else None
        if not info:
            return jsonify(ok=False, error="Unauthorized"), 401
        g.user_info = info

    app.register_blueprint(routes.bp)
    client = app.test_client()
    bridge = SimpleNamespace(
        calls=[], lose_next_reply=False, corrupt_next_reply=None,
        token=auth.create_token("adm-fixture", secret),
        client=client, registry=registry, runtime=runtime,
    )

    def dispatch(_session, method, url, **kwargs):
        parsed = urlsplit(url)
        assert parsed.scheme == "https" and parsed.hostname == "registry-site.invalid", url
        assert not parsed.query and not parsed.fragment
        assert kwargs.get("allow_redirects") is False
        assert kwargs.get("verify", True) is True
        payload = kwargs.get("json")
        bridge.calls.append((method.upper(), parsed.path, payload))
        response = client.open(parsed.path, method=method.upper(), json=payload,
                               headers=kwargs.get("headers", {}))
        data = response.get_json()
        if bridge.lose_next_reply:
            bridge.lose_next_reply = False
            raise requests.Timeout("Fixture dropped response after the real registry committed")
        if bridge.corrupt_next_reply:
            transform, bridge.corrupt_next_reply = bridge.corrupt_next_reply, None
            data = transform(data)
        reply = requests.Response()
        reply.status_code = response.status_code
        reply.headers.update(response.headers)
        reply.url = url
        reply._content = json.dumps(data).encode("utf-8")
        reply.encoding = "utf-8"
        return reply

    bridge.install = lambda: monkeypatch.setattr(requests.sessions.Session, "request", dispatch)
    return bridge


@pytest.fixture
def delivery_pair(env, site_bridge):
    env.conn.execute("UPDATE vpn_servers SET url='https://registry-site.invalid' WHERE id=1")
    env.conn.commit()
    env.monkeypatch.setattr(proxima_client, "auth_headers", lambda server: {
        "Authorization": "Bearer " + site_bridge.token,
    })
    site_bridge.install()
    return env, site_bridge


def deliver(e, **options):
    response = e.client.post("/api/pool-attachments/reconcile", headers=e.admin, json=options)
    assert response.status_code == 200, response.json
    return response.json["data"]


def test_real_registry_lost_reply_and_restart_are_idempotent(delivery_pair):
    e, site = delivery_pair
    c = setup_claim(e)
    aid = claim(e, c)
    site.lose_next_reply = True
    assert deliver(e)["error"] == 1
    assert site.registry.get(aid)["authorization_revision"] == 1
    assert state(e, aid)["delivered_revision"] == 0
    db.init_db()
    assert deliver(e)["delivered"] == 1
    assert site.calls[0] == site.calls[1]
    assert site.registry.get(aid)["credential_generation"] == 1
    status = e.client.get(f"/api/vpn/attachments/{aid}", headers=c.headers).json["data"]
    assert status["delivered_revision"] == 1 and status["delivery_status"] == "delivered"
    assert status["ready"] is False
    assert all(not m["eligible"] for p in e.client.get("/api/vpn/pools", headers=c.headers).json["data"]["pools"] for m in p["members"])


@pytest.mark.parametrize("activation_reached", [False, True])
def test_real_registry_revocation_barrier_precedes_regrant(delivery_pair, activation_reached):
    e, site = delivery_pair
    c = setup_claim(e)
    aid = claim(e, c)
    old_payload = json.loads(outbox(e, aid)[0]["payload"])
    if activation_reached:
        site.lose_next_reply = True
        assert deliver(e)["error"] == 1
    db.update_vpn_user(e.uid, {"allow_pools": 0})
    db.update_vpn_user(e.uid, {"allow_pools": 1})
    assert claim(e, c) == aid
    assert deliver(e)["delivered"] == 2
    assert [(call[2]["state"], call[2]["authorization_revision"]) for call in site.calls[-2:]] == [("revoked", 2), ("active", 3)]
    stored = site.registry.get(aid)
    assert stored["authorization_revision"] == 3
    assert stored["credential_generation"] == (2 if activation_reached else 1)
    assert state(e, aid)["credential_generation"] == stored["credential_generation"]
    stale = site.client.put(f"/api/vpn/pool-attachments/{aid}", json=old_payload,
                            headers={"Authorization": "Bearer " + site.token})
    assert stale.status_code == 409
    assert site.registry.get(aid) == stored


def test_real_registry_rejects_client_token_as_site_admin(delivery_pair):
    e, site = delivery_pair
    c = setup_claim(e)
    aid = claim(e, c)
    e.monkeypatch.setattr(proxima_client, "auth_headers", lambda server: c.headers)
    assert deliver(e)["error"] == 1
    assert site.registry.get(aid) is None
    assert state(e, aid)["delivered_revision"] == 0
    e.monkeypatch.setattr(proxima_client, "auth_headers", lambda server: {"Authorization": "Bearer " + site.token})
    assert deliver(e)["delivered"] == 1


def test_real_registry_receipt_tampering_is_not_acknowledged(delivery_pair):
    e, site = delivery_pair
    c = setup_claim(e)
    aid = claim(e, c)
    site.corrupt_next_reply = lambda value: {**value, "data": {**value["data"], "ready": True}}
    assert deliver(e)["error"] == 1
    assert outbox(e, aid)[0]["error"] == "receipt_mismatch"
    assert state(e, aid)["delivered_revision"] == 0
    assert deliver(e)["delivered"] == 1
    assert site.registry.get(aid)["credential_generation"] == 1


def test_real_registry_conflict_blocks_without_counter_inflation(delivery_pair):
    e, site = delivery_pair
    c = setup_claim(e)
    aid = claim(e, c)
    payload = json.loads(outbox(e, aid)[0]["payload"])
    payload["authorization_revision"] = 5
    response = site.client.put(f"/api/vpn/pool-attachments/{aid}", json=payload,
                               headers={"Authorization": "Bearer " + site.token})
    assert response.status_code == 200
    assert deliver(e)["error"] == 1
    assert deliver(e) == {"delivered": 0, "error": 0, "stale": 0}
    assert deliver(e, retry_conflicts=True)["error"] == 1
    assert state(e, aid)["desired_revision"] == 1
    assert site.registry.get(aid)["authorization_revision"] == 5
    assert all(call[2]["authorization_revision"] == 1 for call in site.calls)


def test_resource_site_revocation_reaches_other_ingress(delivery_pair):
    e, site = delivery_pair
    c = setup_claim(e, [{"site_id": 2, "cidrs": ["192.168.77.0/24"]}])
    aid = claim(e, c)
    db.upsert_user_access(e.uid, 2, {"lan_access": False})
    assert deliver(e)["delivered"] == 1
    assert len(site.calls) == 1 and site.calls[0][2]["state"] == "revoked"
    assert site.registry.get(aid)["credential_generation"] == 0
    assert site.registry.get(aid)["state"] == "revoked"
    assert e.client.get("/api/vpn/pools", headers=c.headers).json["data"]["pools"] == []


def test_delivered_generation_controls_real_runtime_credentials(delivery_pair):
    import base64
    import uuid
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

    e, site = delivery_pair
    c = setup_claim(e)
    aid = claim(e, c)
    entry_key, exit_key = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    b64 = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")
    binding = {
        "binding_id": c.data["binding_id"], "ingress_id": c.data["ingress_id"],
        "connection_type": "vless_reality", "routing_mode": "fast", "exit_country": "TR",
        "listener": {"address": "127.0.0.1", "port": 18443, "reality": {
            "target_ip": "1.1.1.1", "target_port": 443, "server_name": "fixture.example.com",
            "private_key": b64(entry_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
            "short_id": "0123456789abcdef"}},
        "exit": {"address": "8.8.8.8", "port": 24443, "uuid": str(uuid.uuid4()), "reality": {
            "server_name": "exit.example.com", "public_key": b64(exit_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
            "short_id": "fedcba9876543210"}},
        "dns": {"mode": "client_ipv4_via_exit", "resolver_ip": "9.9.9.9"},
    }
    site.runtime.register_binding(binding)
    assert deliver(e)["delivered"] == 1
    first, snapshot = site.runtime.prepare(binding["binding_id"])
    old_credential = first["inbounds"][0]["settings"]["clients"][0]["id"]
    db.update_vpn_user(e.uid, {"allow_pools": 0})
    assert deliver(e)["delivered"] == 1
    with pytest.raises(site.registry.Conflict):
        site.runtime.check_current(first, snapshot)
    revoked, _ = site.runtime.prepare(binding["binding_id"])
    assert revoked["inbounds"][0]["settings"]["clients"] == []
    db.update_vpn_user(e.uid, {"allow_pools": 1})
    assert claim(e, c) == aid
    assert deliver(e)["delivered"] == 1
    restored, current = site.runtime.prepare(binding["binding_id"])
    assert restored["inbounds"][0]["settings"]["clients"][0]["id"] != old_credential
    site.runtime.check_current(restored, current)
    assert current["attachments"][0]["credential_generation"] == 2
    assert site.registry.get(aid)["ready"] is False
