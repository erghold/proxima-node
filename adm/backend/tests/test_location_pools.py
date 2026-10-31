"""V2 catalog uses existing identity and route grants, not v1 attachments."""
import json
import time

import pytest

from test_pool_foundation import env
from api import vpn_sync
from core import db
from core.location_pools import CACHE_MAX_AGE, authorized_catalog, routes
from core.pool_authorization import authorized_manifest
from core.pool_db import transaction


def inventory(e):
    for sid, slot in ((1, "slot-pl"), (2, "slot-de")):
        db.set_server_profiles(sid, [], [
            {"route_id": slot, "label": slot, "kind": "full_tunnel", "enabled": True, "available": True},
            {"route_id": "smart", "label": "Smart", "kind": "smart", "enabled": True, "available": True},
            {"route_id": "lan_only", "label": "LAN", "kind": "lan_only", "enabled": True, "available": True}])
        e.conn.execute("UPDATE vpn_user_access SET allowed_profiles=?,allow_smart_test=1 WHERE user_id=? AND vpn_server_id=?", (json.dumps([slot]), e.uid, sid))
    e.conn.commit()


def create(e, **overrides):
    body = {"schema_version": 2, "label": "EU arbitrary mixed exits", "kind": "full_tunnel", "enabled": True,
            "members": [{"site_id": 2, "route_id": "slot-de"}, {"site_id": 1, "route_id": "slot-pl"}]}
    body.update(overrides)
    r = e.client.post("/api/pool-catalog", headers=e.admin, json=body)
    assert r.status_code == 201, r.json
    return r.json["data"], body


def grant(e, pool, enabled=True):
    return e.client.put(f'/api/pool-catalog/{pool["id"]}/users/{e.uid}', headers=e.admin, json={"enabled": enabled})


def catalog(e):
    with transaction() as conn:
        return authorized_catalog(conn, e.uid)


def test_ordered_mixed_routes_explicit_grant_and_v1_isolation(env):
    inventory(env)
    pool, body = create(env)
    assert catalog(env) == {"schema_version": 2, "pools": []}
    assert grant(env, pool).status_code == 200
    result = catalog(env)["pools"][0]
    assert list(result) == ["id", "label", "kind", "policy_revision", "members"]
    assert [m["site_id"] for m in result["members"]] == [2, 1]
    assert set(result["members"][0]) == {"id", "site_id", "public_url", "route_id", "label"}
    with transaction() as conn:
        user = conn.execute("SELECT * FROM vpn_users WHERE id=?", (env.uid,)).fetchone()
        assert authorized_manifest(conn, user)[0]["pools"] == []
    assert env.client.put(f'/api/pool-catalog/{pool["id"]}', headers=env.admin, json={"enabled": False}).status_code == 400
    changed = {**body, "policy_revision": 1, "members": list(reversed(body["members"]))}
    response = env.client.put(f'/api/pool-catalog/{pool["id"]}', headers=env.admin, json=changed)
    assert response.status_code == 200
    assert response.json["data"]["policy_revision"] == 2
    assert response.json["data"]["members"][0]["id"] == pool["members"][1]["id"]
    assert env.client.put(f'/api/pool-catalog/{pool["id"]}', headers=env.admin, json=changed).status_code == 409
    assert grant(env, pool, False).status_code == 200
    assert catalog(env)["pools"] == []


@pytest.mark.parametrize("sql", [
    "UPDATE vpn_users SET enabled=0", "UPDATE vpn_users SET allow_pools=0",
    "UPDATE vpn_user_access SET enabled=0", "UPDATE vpn_user_access SET sync_status='pending_delete'",
    "UPDATE vpn_user_access SET sync_status='pending'", "UPDATE vpn_user_access SET allowed_profiles='[]'",
    "UPDATE vpn_user_access SET remote_user_id=NULL", "UPDATE vpn_servers SET routes_cached_at=0",
    "UPDATE vpn_servers SET public_url='http://unsafe.invalid'", "UPDATE pool_catalog SET enabled=0",
])
def test_catalog_revocation_and_stale_fail_closed(env, sql):
    inventory(env)
    pool, _ = create(env)
    grant(env, pool)
    assert catalog(env)["pools"]
    env.conn.execute(sql); env.conn.commit()
    assert catalog(env)["pools"] == []


def test_smart_lan_and_direct_intersect_separate_permissions(env):
    inventory(env)
    for kind in ("smart", "lan_only"):
        pool, _ = create(env, kind=kind, members=[{"site_id": 1, "route_id": kind}])
        grant(env, pool)
    assert len(catalog(env)["pools"]) == 2
    env.conn.execute("UPDATE vpn_user_access SET speed_download='10',lan_access=0"); env.conn.commit()
    assert catalog(env)["pools"] == []
    direct, _ = create(env)
    grant(env, direct)
    assert catalog(env)["pools"][0]["kind"] == "full_tunnel"


def test_validation_atomic_unknown_versions_and_superadmin(env):
    inventory(env)
    pool, body = create(env)
    for patch in ({"schema_version": 3}, {"kind": []}, {"members": [{"site_id": 1, "route_id": "invented"}]}, {"members": body["members"] * 2}):
        r = env.client.put(f'/api/pool-catalog/{pool["id"]}', headers=env.admin, json={**body, "policy_revision": 1, **patch})
        assert r.status_code == 400
    assert json.loads(env.conn.execute("SELECT definition FROM pool_catalog").fetchone()[0])["policy_revision"] == 1
    assert env.client.post('/api/pool-catalog', headers=env.scoped, json=body).status_code == 403
    assert env.client.put(f'/api/pool-catalog/{pool["id"]}/users/{env.uid}', headers=env.scoped, json={"enabled": True}).status_code == 403
    env.conn.execute("UPDATE vpn_servers SET routes_cached_at=0"); env.conn.commit()
    assert env.client.put(f'/api/pool-catalog/{pool["id"]}', headers=env.admin, json={**body, "policy_revision": 1}).status_code == 200


def test_sync_identity_binding_catalog_and_no_arbitrary_origin(env, monkeypatch):
    inventory(env)
    pool, _ = create(env); grant(env, pool)
    identity = {"id": 42, "username": "alice"}
    monkeypatch.setattr(vpn_sync, "_verify_token", lambda s, t: identity)
    body = {"public_url": "https://site1.invalid", "token": "site-token", "known": ["https://site1.invalid", "https://site2.invalid"]}
    r = env.client.post('/api/vpn/sync', json=body)
    assert r.status_code == 200, r.json
    assert r.json["data"]["pool_catalog"] == catalog(env)
    assert len(r.json["data"]["servers"]) == 2 and r.json["data"]["revoked"] == []
    assert r.headers["Cache-Control"] == "no-store"
    identity["id"] = 99
    assert env.client.post('/api/vpn/sync', json=body).status_code == 403
    identity["id"] = 42; identity["username"] = "other"
    assert env.client.post('/api/vpn/sync', json=body).status_code == 403
    identity["username"] = "alice"
    env.conn.execute("UPDATE vpn_user_access SET sync_status='pending_delete' WHERE vpn_server_id=1"); env.conn.commit()
    assert env.client.post('/api/vpn/sync', json=body).status_code == 403
    assert env.client.post('/api/vpn/sync', json={**body, "public_url": "https://arbitrary.invalid"}).status_code == 404
    assert env.client.post('/api/vpn/sync', json={**body, "known": [1]}).status_code == 400


def test_malformed_inventory_is_unavailable():
    for value in ('{}', 'null', '[{"route_id":"x","label":"x","kind":[]}]', 'broken'):
        assert routes({"routes_cache": value, "routes_cached_at": int(time.time())}) == []


def test_inventory_age_matches_poll_cadence_and_expires():
    from core.scheduler import POLL_INTERVAL
    assert POLL_INTERVAL < CACHE_MAX_AGE
    cached = json.dumps([{"route_id": "slot", "label": "Exit", "kind": "full_tunnel", "enabled": True, "available": True}])
    for age, available in ((POLL_INTERVAL, True), (CACHE_MAX_AGE + 1, False), (-10, False)):
        result = routes({"routes_cache": cached, "routes_cached_at": int(time.time()) - age})
        assert result[0]["available"] is available


def test_legacy_record_and_grants_stay_legacy(env):
    inventory(env)
    body = {"label": "TR historical", "routing_mode": "fast", "exit_country": "TR", "members": [
        {"site_id": 1, "bindings": [{"connection_type": "amneziawg", "routing_mode": "fast", "profile_format": "awg"}]}]}
    r = env.client.post('/api/pool-catalog', headers=env.admin, json=body)
    assert r.status_code == 201
    old = r.json["data"]
    assert grant(env, old).status_code == 200
    assert catalog(env)["pools"] == []
    assert env.client.put(f'/api/pool-catalog/{old["id"]}', headers=env.admin, json={"enabled": False}).status_code == 200
    assert json.loads(env.conn.execute("SELECT definition FROM pool_catalog").fetchone()[0]) == old
    _, v2 = create(env)
    assert env.client.put(f'/api/pool-catalog/{old["id"]}', headers=env.admin, json={**v2, "policy_revision": 1}).status_code == 400


def test_allow_policy_is_never_implicitly_enabled(env):
    inventory(env)
    pool, _ = create(env)
    env.conn.execute("UPDATE vpn_users SET allow_pools=0"); env.conn.commit()
    assert grant(env, pool).status_code == 200
    assert db.get_vpn_user(env.uid)["allow_pools"] == 0
    assert catalog(env)["pools"] == []
    env.conn.execute("UPDATE vpn_users SET enabled=0"); env.conn.commit()
    assert grant(env, pool).status_code == 409
    assert grant(env, pool, False).status_code == 200


def test_poll_outage_retains_inventory_but_invalidates_availability(env, monkeypatch):
    from core import scheduler
    inventory(env)
    servers = db.get_all_vpn_servers()
    for s in servers:
        s["api_token_enc"] = "not-used"
    monkeypatch.setattr(scheduler, "get_all_vpn_servers", lambda: servers)
    monkeypatch.setattr(scheduler, "_poll_vpn_server", lambda s: {"online": False})
    scheduler._collect_vpn_metrics()
    site = db.get_vpn_server(1)
    assert site["routes_cache"]
    assert all(r["stale"] and not r["available"] for r in routes(site))


def test_remote_identity_verification_never_follows_redirects(env, monkeypatch):
    from types import SimpleNamespace
    def get(url, **kwargs):
        assert url == "https://registered.invalid/api/vpn/self/me"
        assert kwargs["allow_redirects"] is False
        assert kwargs["headers"] == {"Authorization": "Bearer managed-token"}
        return SimpleNamespace(status_code=200, json=lambda: {"ok": True, "data": {"id": 42, "username": "alice"}})
    monkeypatch.setattr(vpn_sync.requests, "get", get)
    assert vpn_sync._verify_token({"url": "https://registered.invalid", "name": "registered"}, "managed-token")["id"] == 42
