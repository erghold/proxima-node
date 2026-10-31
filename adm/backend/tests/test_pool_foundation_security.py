"""Independent security acceptance; real middleware, disposable SQLite, no network."""
import base64
import uuid
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
import requests

from core import db
from api import pool_client
from tests.test_pool_foundation import env, login, enrolled, key, challenge, catalog_body


@pytest.mark.parametrize("state", ["disabled", "demoted"])
def test_existing_admin_token_loses_catalog_and_policy_authority(env, state):
    column, value = ("enabled", 0) if state == "disabled" else ("role", "admin")
    env.conn.execute(f"UPDATE admins SET {column}=? WHERE username='alice'", (value,))
    env.conn.commit()
    expected = 401 if state == "disabled" else 403
    assert env.client.post('/api/pool-catalog', headers=env.admin, json=catalog_body()).status_code == expected
    assert env.client.put(f'/api/vpn-users/{env.uid}', headers=env.admin, json={'enable_pool_beta': True}).status_code == expected
    assert env.conn.execute('SELECT count(*) FROM pool_catalog').fetchone()[0] == 0


@pytest.mark.parametrize('remote_id', [True, False, 1.0, '1', None, -1, 0])
def test_remote_id_type_even_when_python_equality_matches(env, remote_id):
    env.conn.execute('UPDATE vpn_user_access SET remote_user_id=1')
    env.conn.commit()
    env.monkeypatch.setattr(pool_client, 'proxima_request', lambda *a, **k: SimpleNamespace(status_code=200, json=lambda: {'ok': True, 'data': {'user': {'id': remote_id, 'username': 'alice'}}}))
    assert env.client.post('/api/vpn/auth/login', json={'username':'alice','password':'x'}).status_code == 401
    assert env.conn.execute('SELECT count(*) FROM pool_sessions').fetchone()[0] == 0


@pytest.mark.parametrize('enabled', [None, 0, 1, 'false', [], {}])
def test_remote_enabled_never_coerced(env, enabled):
    env.monkeypatch.setattr(pool_client, 'proxima_request', lambda *a, **k: SimpleNamespace(status_code=200, json=lambda: {'ok':True,'data':{'user':{'id':42,'username':'alice','enabled':enabled}}}))
    assert env.client.post('/api/vpn/auth/login', json={'username':'alice','password':'x'}).status_code == 401


@pytest.mark.parametrize('first', [401, 403, 429, 'timeout'])
def test_mixed_verifier_outcomes(env, first):
    calls = []
    def delegate(*a, **k):
        calls.append(a[0]['id'])
        if len(calls) == 1:
            if first == 'timeout':
                raise requests.Timeout()
            return SimpleNamespace(status_code=first)
        return SimpleNamespace(status_code=401)
    env.monkeypatch.setattr(pool_client, 'proxima_request', delegate)
    response = env.client.post('/api/vpn/auth/login', json={'username':'alice','password':'x'})
    assert response.status_code == (429 if first == 429 else 401)
    assert len(calls) == (2 if first == 'timeout' else 1)
    assert env.conn.execute('SELECT count(*) FROM pool_sessions').fetchone()[0] == 0


def test_concurrent_identical_renewal_proof_has_one_winner(env):
    headers, private, public, device = enrolled(env)
    proof = challenge(env, {}, private, public, device, 'authenticate')
    def send(_):
        with env.client.application.test_client() as client:
            return client.post('/api/vpn/auth/device', json=proof).status_code
    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(send, range(2))) == [200, 401]


@pytest.mark.parametrize('mutation', ['enabled', 'allow_pools'])
def test_policy_revocation_between_challenge_and_consumption(env, mutation):
    headers, private, public, device = enrolled(env)
    proof = challenge(env, {}, private, public, device, 'authenticate')
    db.update_vpn_user(env.uid, {mutation: 0})
    response = env.client.post('/api/vpn/auth/device', json=proof)
    assert response.status_code == 403
    assert response.json['error'] == ('account_disabled' if mutation == 'enabled' else 'pool_access_disabled')
    assert env.client.get('/api/vpn/me', headers=headers).status_code == 401


def test_wrong_key_does_not_consume_valid_proof_and_expired_session_can_renew(env):
    headers, private, public, device = enrolled(env)
    proof = challenge(env, {}, private, public, device, 'authenticate')
    bad = base64.b64encode(key()[0].sign(b'not-the-message')).decode()
    assert env.client.post('/api/vpn/auth/device', json={**proof, 'signature':bad}).status_code == 401
    env.conn.execute('UPDATE pool_sessions SET expires_at=0')
    env.conn.commit()
    assert env.client.get('/api/vpn/me', headers=headers).status_code == 401
    assert env.client.post('/api/vpn/auth/device', json=proof).status_code == 200


def test_deleted_account_cannot_reassign_old_identity_or_key(env):
    headers, private, public, device = enrolled(env)
    old_account = db.get_vpn_user(env.uid)['account_id']
    env.conn.execute('DELETE FROM vpn_user_access WHERE user_id=?', (env.uid,))
    env.conn.execute('DELETE FROM vpn_users WHERE id=?', (env.uid,))
    env.conn.commit()
    new_id = db.create_vpn_user({'username':'alice','password_hash':'unused','allow_pools':True})
    assert db.get_vpn_user(new_id)['account_id'] != old_account
    assert env.client.get('/api/vpn/me', headers=headers).status_code == 401
    proof = challenge(env, {}, private, public, device, 'authenticate')
    response = env.client.post('/api/vpn/auth/device', json=proof)
    assert response.status_code == 403 and response.json['error'] == 'account_deleted'
    from core.pool_db import transaction
    with transaction() as conn:
        token = pool_client.issue(conn, db.get_vpn_user(new_id)['account_id'])['token']
    for did, pub in [(device,key()[1]), (str(uuid.uuid4()),public)]:
        assert env.client.post('/api/vpn/devices/challenge', headers={'Authorization':'Bearer '+token}, json={'purpose':'enroll','device_id':did,'public_key':pub}).status_code == 409


def test_catalog_revision_and_pool_revocation_with_existing_token(env):
    headers = login(env)
    pool = env.client.post('/api/pool-catalog', headers=env.admin, json=catalog_body()).json['data']
    path = f"/api/pool-catalog/{pool['id']}/users/{env.uid}"
    env.client.put(path, headers=env.admin, json={'enabled':True})
    before = env.client.get('/api/vpn/pools', headers=headers).json['data']
    assert before == env.client.get('/api/vpn/pools', headers=headers).json['data']
    env.client.put(path, headers=env.admin, json={'enabled':False})
    after = env.client.get('/api/vpn/pools', headers=headers).json['data']
    assert after['pools'] == [] and after['authorization_revision'] != before['authorization_revision']


def test_reupgrade_backfills_account_created_by_rolled_back_legacy(env):
    env.conn.execute("INSERT INTO vpn_users(username,password_hash,created_at,updated_at) VALUES ('legacy-after-rollback','unused',1,1)")
    env.conn.commit()
    assert db.get_vpn_user_by_username('legacy-after-rollback')['account_id'] is None
    db.init_db()
    user = db.get_vpn_user_by_username('legacy-after-rollback')
    assert str(uuid.UUID(user['account_id'])) == user['account_id']
    assert user['allow_pools'] == 0
    db.init_db()
    assert db.get_vpn_user_by_username('legacy-after-rollback')['account_id'] == user['account_id']


def test_lost_enrollment_response_recovers_using_persisted_device_key(env):
    headers = login(env)
    private, public = key()
    device = str(uuid.uuid4())
    proof = challenge(env, headers, private, public, device)
    # The server commits, but the client loses the response and its new bearer.
    assert env.client.post('/api/vpn/devices', headers=headers, json=proof).status_code == 201
    assert env.client.post('/api/vpn/devices', headers=headers, json=proof).status_code == 401
    def forbidden(*args, **kwargs):
        raise AssertionError('recovery must not delegate password or contact a site')
    env.monkeypatch.setattr(pool_client, 'proxima_request', forbidden)
    recovery = challenge(env, {}, private, public, device, 'authenticate')
    response = env.client.post('/api/vpn/auth/device', json=recovery)
    assert response.status_code == 200
    assert response.json['data']['device_id'] == device
    renewed = {'Authorization':'Bearer ' + response.json['data']['token']}
    assert env.client.get('/api/vpn/me', headers=renewed).json['data']['device']['device_id'] == device
    assert env.conn.execute('SELECT count(*) FROM pool_devices').fetchone()[0] == 1


def test_pending_provisioning_is_unavailable_not_bad_password(env):
    from core import auth
    env.conn.execute("UPDATE vpn_user_access SET remote_user_id=NULL, sync_status='pending'")
    env.conn.commit()
    def forbidden(*args, **kwargs):
        raise AssertionError('unprepared assignment must not be contacted')
    env.monkeypatch.setattr(pool_client, 'proxima_request', forbidden)
    response = env.client.post('/api/vpn/auth/login', json={'username':'alice','password':'current-password'})
    assert (response.status_code, bool(auth._fail_tracker)) == (503, False)
    assert env.conn.execute('SELECT count(*) FROM pool_sessions').fetchone()[0] == 0


@pytest.mark.parametrize('denial', ['device_revoked', 'account_deleted', 'account_disabled', 'pool_access_disabled'])
def test_policy_reason_requires_fresh_valid_signature_and_is_single_use(env, denial):
    headers, private, public, device = enrolled(env)
    if denial == 'device_revoked':
        assert env.client.delete('/api/vpn/devices/' + device, headers=headers).status_code == 200
    elif denial == 'account_deleted':
        env.conn.execute('DELETE FROM vpn_user_access WHERE user_id=?', (env.uid,))
        env.conn.execute('DELETE FROM vpn_users WHERE id=?', (env.uid,))
        env.conn.commit()
    else:
        db.update_vpn_user(env.uid, {'enabled' if denial == 'account_disabled' else 'allow_pools': 0})
    before = env.conn.execute('SELECT count(*) FROM pool_sessions').fetchone()[0]
    response = env.client.post('/api/vpn/devices/challenge', json={'purpose':'authenticate', 'device_id':device, 'public_key':public})
    assert response.status_code == 200
    assert set(response.json['data']) == {'challenge_id','message','expires_at'}
    assert denial not in str(response.json)
    data = response.json['data']
    valid = {'challenge_id':data['challenge_id'], 'signature':base64.b64encode(private.sign(data['message'].encode())).decode()}
    bad = {**valid, 'signature':base64.b64encode(key()[0].sign(data['message'].encode())).decode()}
    for payload in (bad, {**valid, 'signature':''}):
        response = env.client.post('/api/vpn/auth/device', json=payload)
        assert response.status_code == 401 and response.json == {'ok':False,'error':'invalid_proof'}
    response = env.client.post('/api/vpn/auth/device', json=valid)
    assert response.status_code == 403 and response.json == {'ok':False,'error':denial}
    assert response.headers['Cache-Control'] == 'no-store'
    replay = env.client.post('/api/vpn/auth/device', json=valid)
    assert replay.status_code == 401 and replay.json['error'] == 'invalid_proof'
    expired = challenge(env, {}, private, public, device, 'authenticate')
    env.conn.execute('UPDATE pool_challenges SET expires_at=0')
    env.conn.commit()
    response = env.client.post('/api/vpn/auth/device', json=expired)
    assert response.status_code == 401 and response.json['error'] == 'invalid_proof'
    assert env.conn.execute('SELECT count(*) FROM pool_sessions').fetchone()[0] == before
    for did, pub in [(str(uuid.uuid4()),public), (device,key()[1])]:
        response = env.client.post('/api/vpn/devices/challenge', json={'purpose':'authenticate','device_id':did,'public_key':pub})
        assert response.status_code == 401 and response.json['error'] == 'invalid_device'


def test_fresh_enrollment_recovery_preserves_identity_and_rejects_replay(env):
    _, private, public, device = enrolled(env)
    original = dict(env.conn.execute('SELECT * FROM pool_devices WHERE device_id=?', (device,)).fetchone())
    headers = login(env)
    response = env.client.post('/api/vpn/devices/challenge', headers=headers, json={'purpose':'enroll','device_id':device,'public_key':public,'name':'Do not overwrite'})
    assert response.status_code == 200
    data = response.json['data']
    proof = {'challenge_id':data['challenge_id'],'signature':base64.b64encode(private.sign(data['message'].encode())).decode()}
    response = env.client.post('/api/vpn/devices', headers=headers, json=proof)
    assert response.status_code == 200 and response.json['data']['created'] is False
    assert dict(env.conn.execute('SELECT * FROM pool_devices WHERE device_id=?', (device,)).fetchone()) == original
    assert env.client.post('/api/vpn/devices', headers=headers, json=proof).status_code == 401
    assert env.client.get('/api/vpn/me', headers=headers).status_code == 401


def test_account_switch_uses_distinct_identity_and_never_recovers_foreign_key(env):
    alice, private, public, device = enrolled(env)
    uid = db.create_vpn_user({'username':'bob','password_hash':'unused','allow_pools':True})
    from core.pool_db import transaction
    with transaction() as conn:
        issued = pool_client.issue(conn, db.get_vpn_user(uid)['account_id'])
    bob = {'Authorization':'Bearer '+issued['token']}
    for did, pub in [(device,public), (device,key()[1]), (str(uuid.uuid4()),public)]:
        response = env.client.post('/api/vpn/devices/challenge', headers=bob, json={'purpose':'enroll','device_id':did,'public_key':pub})
        assert response.status_code == 409 and response.json['error'] == 'device_identity_unavailable'
    other_private, other_public = key()
    other_device = str(uuid.uuid4())
    proof = challenge(env, bob, other_private, other_public, other_device)
    response = env.client.post('/api/vpn/devices', headers=bob, json=proof)
    assert response.status_code == 201 and response.json['data']['created'] is True
    for priv, pub, did, account_id in [(private,public,device,db.get_vpn_user(env.uid)['account_id']), (other_private,other_public,other_device,issued['account_id'])]:
        proof = challenge(env, {}, priv, pub, did, 'authenticate')
        response = env.client.post('/api/vpn/auth/device', json=proof)
        assert response.status_code == 200 and response.json['data']['account_id'] == account_id
    assert env.client.delete('/api/vpn/devices/'+other_device, headers=alice).status_code == 404


def test_revoked_identity_cannot_recover_even_with_new_password_session(env):
    headers, private, public, device = enrolled(env)
    assert env.client.delete('/api/vpn/devices/'+device, headers=headers).status_code == 200
    tombstone = dict(env.conn.execute('SELECT * FROM pool_devices WHERE device_id=?', (device,)).fetchone())
    fresh = login(env)
    for did, pub in [(device,public), (device,key()[1]), (str(uuid.uuid4()),public)]:
        assert env.client.post('/api/vpn/devices/challenge', headers=fresh, json={'purpose':'enroll','device_id':did,'public_key':pub}).status_code == 409
    assert dict(env.conn.execute('SELECT * FROM pool_devices WHERE device_id=?', (device,)).fetchone()) == tombstone
