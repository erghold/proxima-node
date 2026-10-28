"""Persisted offline waits must not masquerade as failed site updates."""

import pytest

from core import db
from core.proxima_client import waiting_note
from tests.test_smart_test_permission import database, client  # noqa: F401


@pytest.mark.parametrize("status", ["pending", "pending_delete"])
def test_offline_wait_is_not_failure_and_does_not_hide_delivered_site(client, database, status):
    conn, uid = database
    sent = db.upsert_user_access(uid, 1, {})
    waiting = db.upsert_user_access(uid, 2, {})
    db.mark_access_synced(sent, remote_user_id=21)
    conn.execute("UPDATE vpn_user_access SET sync_status=? WHERE id=?", (status, waiting))
    conn.commit()
    db.mark_access_error(waiting, waiting_note("Cannot reach Proxima instance"))

    response = client.get("/api/vpn-users/sync/status")
    assert response.status_code == 200
    summary = response.json["data"]
    assert summary["synced"] == 1 and summary[status] == 1
    assert summary["error"] == 0 and summary["errors"] == []
    assert [r["server_name"] for r in summary["deferred"]] == ["2"]
    assert db.get_access(uid, 2)["sync_status"] == status


def test_real_failure_remains_visible_beside_offline_wait(database):
    _, uid = database
    rejected = db.upsert_user_access(uid, 1, {})
    waiting = db.upsert_user_access(uid, 2, {})
    db.mark_access_error(rejected, "Permission denied by site")
    db.mark_access_error(waiting, waiting_note("Connection timed out"))
    summary = db.get_sync_summary()
    assert summary["error"] == 1
    assert summary["errors"][0]["sync_error"] == "Permission denied by site"
    assert len(summary["deferred"]) == 1
    db.mark_access_synced(waiting, remote_user_id=22)
    summary = db.get_sync_summary()
    assert summary["synced"] == 1 and summary["deferred"] == []
    assert summary["error"] == 1
