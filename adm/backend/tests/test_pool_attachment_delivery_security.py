"""Independent delivery security checks; no real site transport."""
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from core import db, pool_attachment_sync as sync
from core.pool_db import transaction
from tests.test_pool_foundation import env
from tests.test_pool_attachment_delivery import setup_claim, claim, state, outbox, receipt


@pytest.mark.parametrize('field,value', [('account_id','foreign'),('device_id','foreign'),('ingress_id','foreign'),('binding_id','foreign'),('credential_generation',0),('credential_generation',-1),('credential_generation',1.0),('ready',0),('reason','ready')])
def test_receipt_exact_identity_types_and_generation(env, field, value):
    c = setup_claim(env)
    aid = claim(env,c)
    event = sync.take_event(set())
    response = receipt(event,1)
    response.json()['data'][field] = value
    assert sync.record_receipt(event,response) == 'error'
    assert state(env,aid)['delivered_revision'] == 0
    assert outbox(env,aid)[0]['error'] == 'receipt_mismatch'


def test_concurrent_claim_and_revocation_cannot_leave_authorized_attachment(env):
    c = setup_claim(env)
    barrier = threading.Barrier(2)
    def post():
        barrier.wait()
        with env.client.application.test_client() as client:
            return client.post(c.path,headers=c.headers,json=c.data).status_code
    def revoke():
        barrier.wait()
        with transaction() as conn:
            conn.execute('UPDATE vpn_users SET allow_pools=0 WHERE id=?',(env.uid,))
    with ThreadPoolExecutor(max_workers=2) as pool:
        posted, revoked = pool.submit(post), pool.submit(revoke)
        assert posted.result() in (202,401)
        revoked.result()
    rows = env.conn.execute('SELECT * FROM pool_attachments').fetchall()
    assert all(r['desired_state']=='revoked' for r in rows)
    for row in rows:
        assert [e['state'] for e in outbox(env,row['id'])] == ['active','revoked']


def test_revocation_lease_must_finish_before_regrant_and_old_ack_is_stale(env):
    c = setup_claim(env)
    aid = claim(env,c)
    first = sync.take_event(set())
    assert sync.record_receipt(first,receipt(first,1)) == 'delivered'
    db.update_vpn_user(env.uid,{'allow_pools':0})
    barrier = sync.take_event(set())
    db.update_vpn_user(env.uid,{'allow_pools':1})
    claim(env,c)
    assert sync.take_event(set()) is None
    assert state(env,aid)['desired_revision'] == 3
    assert sync.record_receipt(barrier,receipt(barrier,1)) == 'delivered'
    active = sync.take_event(set())
    assert active['revision'] == 3
    assert sync.record_receipt(active,receipt(active,2)) == 'delivered'
    assert sync.record_receipt(first,receipt(first,1)) == 'stale'
    assert state(env,aid)['delivered_revision'] == 3
    assert state(env,aid)['credential_generation'] == 2


def test_conflict_requires_manual_resolution_without_losing_revocation(env):
    c = setup_claim(env)
    aid = claim(env,c)
    first = sync.take_event(set())
    assert sync.record_receipt(first,SimpleNamespace(status_code=409)) == 'error'
    db.update_vpn_user(env.uid,{'allow_pools':0})
    assert sync.take_event(set()) is None
    assert [(e['revision'],e['state']) for e in outbox(env,aid)] == [(1,'active'),(2,'revoked')]
    calls = []
    def send(server, method, path, body, **kwargs):
        calls.append(body)
        event = {'payload':json.dumps(body),'attachment_id':aid}
        return receipt(event,0)
    env.monkeypatch.setattr(sync,'proxima_request',send)
    assert sync.reconcile(retry_conflicts=True)['delivered'] == 1
    assert [body['state'] for body in calls] == ['revoked']
    assert state(env,aid)['desired_revision'] == 2


def test_resource_dependency_delete_retains_ingress_destination_until_ack(env):
    c = setup_claim(env,[{'site_id':2,'cidrs':['192.168.77.0/24']}])
    aid = claim(env,c)
    db.delete_user_access(env.uid,2)
    assert state(env,aid)['desired_state'] == 'revoked'
    for sid in (1,2):
        with pytest.raises(sqlite3.IntegrityError,match='pool_attachment_cleanup_required'):
            db.delete_vpn_server(sid)
        assert db.get_vpn_server(sid) is not None


@pytest.mark.parametrize('restriction', ['null','{}','true','0','""'])
def test_non_array_access_restrictions_never_silently_disappear(env,restriction):
    c = setup_claim(env)
    db.upsert_user_access(env.uid,1,{'allowed_profiles':restriction})
    response = env.client.post(c.path,headers=c.headers,json=c.data)
    assert response.status_code == 409 and response.json['error']=='unsupported_attachment_policy'
    assert env.conn.execute('SELECT count(*) FROM pool_attachment_outbox').fetchone()[0] == 0


def test_disabled_admin_cannot_inspect_or_run_delivery(env):
    env.conn.execute("UPDATE admins SET enabled=0 WHERE username='alice'")
    env.conn.commit()
    assert env.client.get('/api/pool-attachments',headers=env.admin).status_code == 401
    assert env.client.post('/api/pool-attachments/reconcile',headers=env.admin,json={}).status_code == 401
