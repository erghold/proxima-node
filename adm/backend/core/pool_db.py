"""Central management identities, not forwarding leases or tunnel credentials."""

import sqlite3
import uuid
from contextlib import contextmanager

from core import db


def migrate(conn):
    columns = {r[1] for r in conn.execute("PRAGMA table_info(vpn_users)")}
    if "account_id" not in columns:
        conn.execute("ALTER TABLE vpn_users ADD COLUMN account_id TEXT")
    if "allow_pools" not in columns:
        conn.execute("ALTER TABLE vpn_users ADD COLUMN allow_pools INTEGER NOT NULL DEFAULT 0")
    # Replace the old guard atomically before backfilling rows written by a rollback.
    with conn:
        conn.execute("SAVEPOINT pool_account_backfill")
        conn.execute("DROP TRIGGER IF EXISTS vpn_account_immutable")
        conn.execute("""CREATE TRIGGER vpn_account_immutable BEFORE UPDATE OF account_id ON vpn_users
            WHEN OLD.account_id IS NOT NULL AND OLD.account_id IS NOT NEW.account_id
            BEGIN SELECT RAISE(ABORT, 'immutable account_id'); END""")
        for row in conn.execute("SELECT id FROM vpn_users WHERE account_id IS NULL").fetchall():
            conn.execute("UPDATE vpn_users SET account_id=? WHERE id=?", (str(uuid.uuid4()), row[0]))
        conn.execute("RELEASE pool_account_backfill")
    conn.executescript("""
        CREATE UNIQUE INDEX IF NOT EXISTS vpn_account_id ON vpn_users(account_id);
        CREATE TABLE IF NOT EXISTS pool_devices (
            device_id TEXT PRIMARY KEY, account_id TEXT NOT NULL,
            public_key TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
            created_at INTEGER NOT NULL, revoked_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS pool_sessions (
            token_hash TEXT PRIMARY KEY, account_id TEXT NOT NULL,
            device_id TEXT, expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS pool_challenges (
            id TEXT PRIMARY KEY, account_id TEXT NOT NULL, device_id TEXT NOT NULL,
            public_key TEXT NOT NULL, purpose TEXT NOT NULL, name TEXT NOT NULL,
            message TEXT NOT NULL, session_hash TEXT, expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS pool_catalog (
            id TEXT PRIMARY KEY, definition TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS pool_grants (
            pool_id TEXT NOT NULL REFERENCES pool_catalog(id), account_id TEXT NOT NULL,
            PRIMARY KEY(pool_id, account_id)
        );
    """)
    conn.commit()


@contextmanager
def transaction():
    # A dedicated connection keeps legacy helpers' commits out of proof consumption.
    conn = sqlite3.connect(db.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=FULL")
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def migrate_delivery(conn):
    """Revocation events share the legacy writer's transaction, not a later scan."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS pool_attachments (
            id TEXT PRIMARY KEY, account_id TEXT NOT NULL, device_id TEXT NOT NULL,
            pool_id TEXT NOT NULL, site_id INTEGER NOT NULL, ingress_id TEXT NOT NULL,
            binding_id TEXT NOT NULL, payload_template TEXT NOT NULL,
            desired_state TEXT NOT NULL CHECK(desired_state IN ('active','revoked')),
            desired_revision INTEGER NOT NULL DEFAULT 1 CHECK(desired_revision BETWEEN 1 AND 9223372036854775807),
            delivered_state TEXT, delivered_revision INTEGER NOT NULL DEFAULT 0,
            credential_generation INTEGER, created_at INTEGER NOT NULL,
            UNIQUE(account_id,device_id,ingress_id,binding_id)
        );
        CREATE TABLE IF NOT EXISTS pool_attachment_dependencies (
            attachment_id TEXT NOT NULL, site_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
            remote_user_id INTEGER NOT NULL, needs_lan INTEGER NOT NULL, lan_subnet TEXT,
            PRIMARY KEY(attachment_id,site_id)
        );
        CREATE INDEX IF NOT EXISTS pool_dependency_site ON pool_attachment_dependencies(site_id,user_id);
        CREATE TABLE IF NOT EXISTS pool_attachment_outbox (
            attachment_id TEXT NOT NULL, revision INTEGER NOT NULL, state TEXT NOT NULL,
            payload TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0, error TEXT, blocked INTEGER NOT NULL DEFAULT 0,
            attempt_token TEXT, inflight_until INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(attachment_id,revision)
        );
        CREATE TRIGGER IF NOT EXISTS pool_attachment_insert AFTER INSERT ON pool_attachments BEGIN
            INSERT INTO pool_attachment_outbox(attachment_id,revision,state,payload)
            VALUES(NEW.id,NEW.desired_revision,NEW.desired_state,
                json_set(NEW.payload_template,'$.authorization_revision',NEW.desired_revision,'$.state',NEW.desired_state));
        END;
        CREATE TRIGGER IF NOT EXISTS pool_attachment_transition AFTER UPDATE OF desired_state ON pool_attachments
        WHEN OLD.desired_state != NEW.desired_state BEGIN
            UPDATE pool_attachments SET desired_revision=OLD.desired_revision+1 WHERE id=NEW.id;
            INSERT INTO pool_attachment_outbox(attachment_id,revision,state,payload)
            VALUES(NEW.id,OLD.desired_revision+1,NEW.desired_state,
                json_set(NEW.payload_template,'$.authorization_revision',OLD.desired_revision+1,'$.state',NEW.desired_state));
        END;
        CREATE TRIGGER IF NOT EXISTS pool_attachment_immutable BEFORE UPDATE OF
            id,account_id,device_id,pool_id,site_id,ingress_id,binding_id,payload_template ON pool_attachments
        BEGIN SELECT RAISE(ABORT,'immutable attachment intent'); END;
        CREATE TRIGGER IF NOT EXISTS pool_outbox_immutable BEFORE UPDATE OF
            attachment_id,revision,state,payload ON pool_attachment_outbox
        BEGIN SELECT RAISE(ABORT,'immutable attachment event'); END;
        CREATE TRIGGER IF NOT EXISTS pool_site_delete_guard BEFORE DELETE ON vpn_servers
        WHEN EXISTS (
            SELECT 1 FROM pool_attachments a WHERE
            (a.site_id=OLD.id OR a.id IN (SELECT attachment_id FROM pool_attachment_dependencies WHERE site_id=OLD.id))
            AND (a.desired_state='active' OR EXISTS (
                SELECT 1 FROM pool_attachment_outbox o WHERE o.attachment_id=a.id AND o.status NOT IN ('delivered','superseded')))
        ) BEGIN SELECT RAISE(ABORT,'pool_attachment_cleanup_required'); END;
    """)
    # Fixed, narrow triggers also cover import and internal helpers that commit themselves.
    triggers = [
        ("user_policy", "AFTER UPDATE OF enabled,allow_pools ON vpn_users", "NEW.enabled!=1 OR NEW.allow_pools!=1", "account_id=OLD.account_id"),
        ("user_delete", "BEFORE DELETE ON vpn_users", "1", "account_id=OLD.account_id"),
        ("device_revoke", "AFTER UPDATE OF revoked_at ON pool_devices", "NEW.revoked_at IS NOT NULL", "device_id=OLD.device_id"),
        ("device_delete", "BEFORE DELETE ON pool_devices", "1", "device_id=OLD.device_id"),
        ("pool_disable", "AFTER UPDATE OF enabled ON pool_catalog", "NEW.enabled!=1", "pool_id=OLD.id"),
        ("pool_delete", "BEFORE DELETE ON pool_catalog", "1", "pool_id=OLD.id"),
        ("grant_delete", "AFTER DELETE ON pool_grants", "1", "pool_id=OLD.pool_id AND account_id=OLD.account_id"),
        ("access_delete", "BEFORE DELETE ON vpn_user_access", "1",
         "id IN (SELECT attachment_id FROM pool_attachment_dependencies WHERE user_id=OLD.user_id AND site_id=OLD.vpn_server_id)"),
        ("access_change", "AFTER UPDATE ON vpn_user_access", "1",
         """id IN (SELECT attachment_id FROM pool_attachment_dependencies WHERE user_id=OLD.user_id AND site_id=OLD.vpn_server_id
            AND (NEW.user_id IS NOT OLD.user_id OR NEW.vpn_server_id IS NOT OLD.vpn_server_id
                OR NEW.enabled!=1 OR NEW.sync_status='pending_delete' OR NEW.remote_user_id IS NOT remote_user_id
                OR (needs_lan=1 AND NEW.lan_access!=1) OR NEW.max_peers IS NOT NULL OR NEW.bandwidth_quota IS NOT NULL
                OR COALESCE(NEW.speed_download,'')!='' OR COALESCE(NEW.speed_upload,'')!=''
                OR CASE WHEN json_valid(COALESCE(NEW.assigned_groups,'[]')) THEN
                    json_type(COALESCE(NEW.assigned_groups,'[]'))!='array' OR json_array_length(COALESCE(NEW.assigned_groups,'[]'))!=0 ELSE 1 END
                OR NEW.allowed_profiles IS NOT OLD.allowed_profiles))"""),
        ("site_scope", "AFTER UPDATE OF lan_subnet ON vpn_servers", "NEW.lan_subnet IS NOT OLD.lan_subnet",
         "id IN (SELECT attachment_id FROM pool_attachment_dependencies WHERE site_id=OLD.id)"),
    ]
    with conn:
        conn.execute("SAVEPOINT pool_revoke_trigger_upgrade")
        # Upgrade existing installations without a window missing the authority guard.
        conn.execute("DROP TRIGGER IF EXISTS pool_revoke_access_change")
        for name, event, condition, selector in triggers:
            conn.execute(f"""CREATE TRIGGER IF NOT EXISTS pool_revoke_{name} {event} WHEN {condition} BEGIN
                UPDATE pool_attachments SET desired_state='revoked' WHERE desired_state='active' AND ({selector});
            END""")
        conn.execute("RELEASE pool_revoke_trigger_upgrade")
    conn.commit()
    conn.execute("PRAGMA synchronous=FULL")
