"""SQLite database — shared connection, schema init, CRUD helpers."""

import json
import sqlite3
import threading
import time
import uuid

from core.config import DB_PATH

_conn_lock = threading.Lock()
_shared_conn: sqlite3.Connection | None = None


def get_conn() -> sqlite3.Connection:
    """Return the shared database connection (thread-safe)."""
    global _shared_conn
    if _shared_conn is None:
        with _conn_lock:
            if _shared_conn is None:
                _shared_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
                _shared_conn.row_factory = sqlite3.Row
                _shared_conn.execute("PRAGMA foreign_keys = ON")
                _shared_conn.execute("PRAGMA journal_mode = WAL")
                _shared_conn.execute("PRAGMA synchronous = NORMAL")
                _shared_conn.execute("PRAGMA busy_timeout = 5000")
    return _shared_conn


def init_db() -> None:
    """Create tables if they don't exist."""
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS servers (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            name                  TEXT NOT NULL UNIQUE,
            display_name          TEXT NOT NULL,
            ip                    TEXT NOT NULL,
            server_type           TEXT NOT NULL,
            location              TEXT NOT NULL DEFAULT '',
            provider              TEXT NOT NULL DEFAULT '',
            status                TEXT NOT NULL DEFAULT 'new',
            root_password_enc     TEXT,
            ss_password_enc       TEXT,
            agent_api_key_enc     TEXT,
            ssconf_token_enc      TEXT,
            speedtest_api_key_enc TEXT,
            ss_port               INTEGER NOT NULL DEFAULT 8388,
            ss_cipher             TEXT NOT NULL DEFAULT 'chacha20-ietf-poly1305',
            agent_port            INTEGER NOT NULL DEFAULT 5051,
            node_id               TEXT,
            install_adguard       INTEGER NOT NULL DEFAULT 0,
            traffic_limit_gb      REAL,
            traffic_period_day    INTEGER NOT NULL DEFAULT 1,
            callhome_ip           TEXT,
            callhome_pubkey       TEXT,
            callhome_privkey_enc  TEXT,
            callhome_psk_enc      TEXT,
            created_at            INTEGER NOT NULL,
            updated_at            INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS operations (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id    INTEGER,
            op_type      TEXT NOT NULL,
            status       TEXT NOT NULL DEFAULT 'running',
            playbook     TEXT,
            output       TEXT NOT NULL DEFAULT '',
            error        TEXT,
            started_at   INTEGER NOT NULL,
            completed_at INTEGER,
            FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE SET NULL
        );

        -- ADM operators. 'superadmin' may do anything; 'admin' is limited to
        -- managing VPN users on the servers listed in admin_server_scope.
        CREATE TABLE IF NOT EXISTS admins (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'superadmin',
            enabled       INTEGER NOT NULL DEFAULT 1,
            created_at    INTEGER NOT NULL
        );

        -- Which sites an operator may sign into the Proxima panel of.
        --
        -- Distinct from admin_server_scope, which says whose users an
        -- operator may edit here in ADM. Being allowed to manage a site's
        -- accounts and being able to log into that site's own panel are
        -- separate powers, and conflating them would hand every scoped
        -- operator control of the boxes they were merely administering
        -- accounts for.
        CREATE TABLE IF NOT EXISTS admin_server_access (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id      INTEGER NOT NULL,
            vpn_server_id INTEGER NOT NULL,
            sync_status   TEXT NOT NULL DEFAULT 'pending',
            sync_error    TEXT,
            synced_at     INTEGER,
            -- When the password this site holds was last written. Compared
            -- against admins.password_changed_at to decide whether a push
            -- should carry the hash.
            password_synced_at INTEGER,
            created_at    INTEGER NOT NULL,
            updated_at    INTEGER NOT NULL,
            UNIQUE (admin_id, vpn_server_id),
            FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE,
            FOREIGN KEY (vpn_server_id) REFERENCES vpn_servers(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS admin_server_scope (
            admin_id      INTEGER NOT NULL,
            vpn_server_id INTEGER NOT NULL,
            PRIMARY KEY (admin_id, vpn_server_id),
            FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE,
            FOREIGN KEY (vpn_server_id) REFERENCES vpn_servers(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS vpn_servers (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT NOT NULL UNIQUE,
            display_name    TEXT NOT NULL,
            url             TEXT NOT NULL,
            api_token_enc   TEXT,
            -- Provisioning: how ADM reaches the box to install or update it.
            -- ssh_password_enc is held only until the install succeeds and is
            -- then discarded — afterwards ADM has its key on the box and the
            -- API token, and keeping a site's password would be a liability
            -- with no remaining purpose.
            ssh_host        TEXT,
            ssh_port        INTEGER NOT NULL DEFAULT 22,
            ssh_user        TEXT NOT NULL DEFAULT 'root',
            ssh_password_enc TEXT,
            server_code     TEXT,
            callhome_ip     TEXT,
            -- The site's own ranges, decided at the router step before the box
            -- ships and recorded here rather than allocated. ADM's job is to
            -- refuse an overlap, not to pick the number: the MikroTik already
            -- has it, and a second authority deciding the same thing would
            -- only ever lose.
            vpn_subnet      TEXT,
            lan_subnet      TEXT,
            -- Where clients dial in: the site's public address and port. Also
            -- a router-step decision, and also not guessable — every box
            -- behind one connection reports the same public IP, so detecting
            -- it produces a plausible address pointing at the wrong machine.
            vpn_endpoint    TEXT,
            -- Direct profiles the site publishes, refreshed by the poller.
            -- Cached rather than fetched per request so that granting a user
            -- a profile does not depend on the site answering right then, and
            -- so the users page never fans out to every site at once.
            profiles_cache  TEXT,
            profiles_cached_at INTEGER,
            created_at      INTEGER NOT NULL,
            updated_at      INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS server_metrics (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id  INTEGER NOT NULL,
            timestamp  INTEGER NOT NULL,
            online     INTEGER NOT NULL DEFAULT 1,
            uptime     INTEGER,
            disk_pct   REAL,
            memory_pct REAL,
            cpu_pct    REAL,
            services_ok INTEGER,
            docker_ok   INTEGER,
            FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_metrics_ts ON server_metrics(server_id, timestamp);

        CREATE TABLE IF NOT EXISTS vpn_server_metrics (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            vpn_server_id   INTEGER NOT NULL,
            timestamp       INTEGER NOT NULL,
            online          INTEGER NOT NULL DEFAULT 1,
            disk_pct        REAL,
            memory_pct      REAL,
            cpu_pct         REAL,
            FOREIGN KEY (vpn_server_id) REFERENCES vpn_servers(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_vpn_metrics_ts ON vpn_server_metrics(vpn_server_id, timestamp);

        CREATE TABLE IF NOT EXISTS alert_config (
            id                 INTEGER PRIMARY KEY CHECK (id = 1),
            enabled            INTEGER NOT NULL DEFAULT 0,
            telegram_bot_token TEXT DEFAULT '',
            telegram_chat_id   TEXT DEFAULT '',
            disk_threshold     REAL DEFAULT 90.0,
            memory_threshold   REAL DEFAULT 90.0,
            cpu_threshold      REAL DEFAULT 80.0,
            offline_minutes    INTEGER DEFAULT 5
        );
        INSERT OR IGNORE INTO alert_config (id) VALUES (1);

        CREATE TABLE IF NOT EXISTS alert_history (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id  INTEGER,
            alert_type TEXT NOT NULL,
            message    TEXT NOT NULL,
            sent_at    INTEGER NOT NULL,
            FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE SET NULL
        );

        -- Central VPN user identity. ADM is the sole writer; each Proxima
        -- instance keeps a read-only replica in its own vpn_users table.
        -- Only the password hash is stored — plaintext is shown once at
        -- creation and never persisted.
        CREATE TABLE IF NOT EXISTS vpn_users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL UNIQUE,
            full_name     TEXT NOT NULL DEFAULT '',
            update_channel TEXT NOT NULL DEFAULT 'stable',
            password_hash TEXT NOT NULL,
            enabled       INTEGER NOT NULL DEFAULT 1,
            note          TEXT NOT NULL DEFAULT '',
            -- When ADM last set the password. Compared against each access
            -- row's password_synced_at to decide whether a push should carry
            -- it; a user may have changed theirs on the instance since.
            password_changed_at INTEGER,
            created_at    INTEGER NOT NULL,
            updated_at    INTEGER NOT NULL
        );

        -- Which user is authorized on which Proxima instance, plus the
        -- per-server limits. Limits are per-server by design: group ids and
        -- quotas are site-local and have no global meaning.
        -- remote_user_id is the local vpn_users.id on that Proxima — peers
        -- reference it via peer.owner, so it must never be rewritten.
        CREATE TABLE IF NOT EXISTS vpn_user_access (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER NOT NULL,
            vpn_server_id   INTEGER NOT NULL,
            remote_user_id  INTEGER,
            enabled         INTEGER NOT NULL DEFAULT 1,
            max_peers       INTEGER,
            bandwidth_quota INTEGER,
            speed_download  TEXT,
            speed_upload    TEXT,
            assigned_groups TEXT NOT NULL DEFAULT '[]',
            -- Which published Direct-profile slots this user may pick on that
            -- site, as a JSON list of slot ids. Sibling of assigned_groups and
            -- lan_access: the three are independent axes, not nested tiers —
            -- a user may hold a Direct profile without general VPN routing.
            allowed_profiles TEXT NOT NULL DEFAULT '[]',
            -- May this user's devices reach that site's LAN? Per-server by
            -- nature: someone can be trusted on one site and not another.
            lan_access      INTEGER NOT NULL DEFAULT 1,
            allow_smart_test INTEGER NOT NULL DEFAULT 0,
            sync_status     TEXT NOT NULL DEFAULT 'pending',
            sync_error      TEXT,
            synced_at       INTEGER,
            password_synced_at INTEGER,
            created_at      INTEGER NOT NULL,
            updated_at      INTEGER NOT NULL,
            UNIQUE (user_id, vpn_server_id),
            FOREIGN KEY (user_id) REFERENCES vpn_users(id) ON DELETE CASCADE,
            FOREIGN KEY (vpn_server_id) REFERENCES vpn_servers(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_vpn_user_access_user
            ON vpn_user_access(user_id);
        CREATE INDEX IF NOT EXISTS idx_vpn_user_access_server
            ON vpn_user_access(vpn_server_id);
    """)
    conn.commit()

    # Schema migrations
    _migrate(conn)
    from core.pool_db import migrate, migrate_delivery
    migrate(conn)
    migrate_delivery(conn)


def _migrate(conn: sqlite3.Connection) -> None:
    """Run schema migrations for columns added after initial release."""
    # Roles arrived after the first admins existed. Everyone who predates
    # them keeps full access — silently demoting the only operator would
    # lock them out of their own panel.
    admin_cols = {r[1] for r in conn.execute("PRAGMA table_info(admins)").fetchall()}
    if admin_cols and "role" not in admin_cols:
        conn.execute(
            "ALTER TABLE admins ADD COLUMN role TEXT NOT NULL DEFAULT 'superadmin'"
        )
        conn.execute("UPDATE admins SET role = 'superadmin'")
        conn.commit()
    if admin_cols and "enabled" not in admin_cols:
        conn.execute("ALTER TABLE admins ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")
        conn.commit()
    # An operator's ADM password is also the one their panel accounts use, so
    # a change here has to reach every site they administer. Stamped now for
    # admins who predate this, which leaves their sites holding whatever they
    # were last given rather than forcing a needless push.
    if admin_cols and "password_changed_at" not in admin_cols:
        conn.execute("ALTER TABLE admins ADD COLUMN password_changed_at INTEGER")
        conn.execute("UPDATE admins SET password_changed_at = ?", (int(time.time()),))
        conn.commit()

    # Password ownership is shared: ADM sets it, and a user may change their
    # own from the client. Tracking when each side last wrote lets a push
    # carry the password only when ADM's copy is the newer one, so routine
    # limit changes stop clobbering a password the user just chose.
    user_cols = {r[1] for r in conn.execute("PRAGMA table_info(vpn_users)").fetchall()}
    if user_cols and "deletion_pending" not in user_cols:
        conn.execute("ALTER TABLE vpn_users ADD COLUMN deletion_pending INTEGER NOT NULL DEFAULT 0")
        conn.commit()
    if user_cols and "update_channel" not in user_cols:
        conn.execute("ALTER TABLE vpn_users ADD COLUMN update_channel TEXT NOT NULL DEFAULT 'stable'")
        conn.commit()
    if user_cols and "password_changed_at" not in user_cols:
        conn.execute("ALTER TABLE vpn_users ADD COLUMN password_changed_at INTEGER")
        conn.execute("UPDATE vpn_users SET password_changed_at = updated_at")
        conn.commit()

    access_cols = {r[1] for r in conn.execute(
        "PRAGMA table_info(vpn_user_access)").fetchall()}
    if access_cols and "password_synced_at" not in access_cols:
        conn.execute("ALTER TABLE vpn_user_access ADD COLUMN password_synced_at INTEGER")
        # Rows already in sync hold the password ADM knows about, so mark them
        # current rather than forcing a pointless first push.
        conn.execute(
            "UPDATE vpn_user_access SET password_synced_at = updated_at "
            "WHERE sync_status = 'synced'"
        )
        conn.commit()

    if access_cols and "allow_smart_test" not in access_cols:
        conn.execute(
            "ALTER TABLE vpn_user_access ADD COLUMN "
            "allow_smart_test INTEGER NOT NULL DEFAULT 0"
        )
        conn.commit()

    if access_cols and "allowed_profiles" not in access_cols:
        # Empty list is the safe default: nobody gains a Direct profile by
        # migrating, they are granted explicitly.
        conn.execute(
            "ALTER TABLE vpn_user_access ADD COLUMN "
            "allowed_profiles TEXT NOT NULL DEFAULT '[]'"
        )
        conn.commit()

    vpn_cols = {r[1] for r in conn.execute(
        "PRAGMA table_info(vpn_servers)").fetchall()}
    if vpn_cols and "profiles_cache" not in vpn_cols:
        conn.execute("ALTER TABLE vpn_servers ADD COLUMN profiles_cache TEXT")
        conn.execute("ALTER TABLE vpn_servers ADD COLUMN profiles_cached_at INTEGER")
        conn.commit()

    cols = {row[1] for row in conn.execute("PRAGMA table_info(servers)").fetchall()}
    if "ssh_port" not in cols:
        conn.execute("ALTER TABLE servers ADD COLUMN ssh_port INTEGER NOT NULL DEFAULT 22")
        conn.commit()
    if "vless_uuid" not in cols:
        conn.execute("ALTER TABLE servers ADD COLUMN vless_uuid TEXT")
        conn.execute("ALTER TABLE servers ADD COLUMN vless_public_key TEXT")
        conn.execute("ALTER TABLE servers ADD COLUMN vless_short_id TEXT")
        conn.execute("ALTER TABLE servers ADD COLUMN vless_port INTEGER DEFAULT 8443")
        conn.commit()

    if "public_ip" not in cols:
        conn.execute("ALTER TABLE servers ADD COLUMN public_ip TEXT")
        conn.commit()

    # Auto-generate ssconf_token for servers that lack one
    rows = conn.execute(
        "SELECT id FROM servers WHERE ssconf_token_enc IS NULL"
    ).fetchall()
    if rows:
        from core.auth import encrypt_value
        from core.credential_gen import gen_ssconf_token
        for row in rows:
            token = gen_ssconf_token()
            conn.execute(
                "UPDATE servers SET ssconf_token_enc = ? WHERE id = ?",
                (encrypt_value(token), row[0]),
            )
        conn.commit()
        import logging
        logging.getLogger("adm.db").info(
            f"Generated ssconf_token for {len(rows)} server(s): "
            + ", ".join(str(r[0]) for r in rows)
        )

    # server_metrics migrations
    metric_cols = {row[1] for row in conn.execute("PRAGMA table_info(server_metrics)").fetchall()}
    if "cpu_pct" not in metric_cols:
        conn.execute("ALTER TABLE server_metrics ADD COLUMN cpu_pct REAL")
        conn.commit()

    # Cumulative byte counters from the billed interface, stored as read.
    # Rates are derived at query time: the counters reset on reboot and only
    # something comparing consecutive samples can tell a reset from a quiet
    # interval.
    if "rx_bytes" not in metric_cols:
        conn.execute("ALTER TABLE server_metrics ADD COLUMN rx_bytes INTEGER")
        conn.execute("ALTER TABLE server_metrics ADD COLUMN tx_bytes INTEGER")
        conn.commit()

    # Exit nodes join the management network too. Their agent is reachable on
    # a public port today, which dies whenever the path to that IP does — and
    # then ADM reports the node offline while the node itself is healthy.
    # Riding the tunnel instead makes "agent unreachable" mean something.
    server_cols = {row[1] for row in conn.execute("PRAGMA table_info(servers)").fetchall()}
    # What the plan allows and when it resets. NULL means unmetered — most
    # nodes — so an alert only exists where a limit does.
    if "traffic_limit_gb" not in server_cols:
        conn.execute("ALTER TABLE servers ADD COLUMN traffic_limit_gb REAL")
        conn.execute("ALTER TABLE servers ADD COLUMN traffic_period_day INTEGER NOT NULL DEFAULT 1")
        conn.commit()

    if "callhome_ip" not in server_cols:
        for stmt in (
            "ALTER TABLE servers ADD COLUMN callhome_ip TEXT",
            "ALTER TABLE servers ADD COLUMN callhome_pubkey TEXT",
            "ALTER TABLE servers ADD COLUMN callhome_privkey_enc TEXT",
            "ALTER TABLE servers ADD COLUMN callhome_psk_enc TEXT",
        ):
            conn.execute(stmt)
        conn.commit()

    # alert_config migrations
    alert_cols = {row[1] for row in conn.execute("PRAGMA table_info(alert_config)").fetchall()}
    if "cpu_threshold" not in alert_cols:
        conn.execute("ALTER TABLE alert_config ADD COLUMN cpu_threshold REAL DEFAULT 80.0")
        conn.commit()

    # vpn_servers migrations
    vpn_cols = {row[1] for row in conn.execute("PRAGMA table_info(vpn_servers)").fetchall()}
    if "public_url" not in vpn_cols:
        conn.execute("ALTER TABLE vpn_servers ADD COLUMN public_url TEXT DEFAULT ''")
        conn.commit()
    if "ssh_host" not in vpn_cols:
        for stmt in (
            "ALTER TABLE vpn_servers ADD COLUMN ssh_host TEXT",
            "ALTER TABLE vpn_servers ADD COLUMN ssh_port INTEGER NOT NULL DEFAULT 22",
            "ALTER TABLE vpn_servers ADD COLUMN ssh_user TEXT NOT NULL DEFAULT 'root'",
            "ALTER TABLE vpn_servers ADD COLUMN ssh_password_enc TEXT",
            "ALTER TABLE vpn_servers ADD COLUMN server_code TEXT",
            "ALTER TABLE vpn_servers ADD COLUMN callhome_ip TEXT",
        ):
            conn.execute(stmt)
        conn.commit()
    if "vpn_subnet" not in vpn_cols:
        conn.execute("ALTER TABLE vpn_servers ADD COLUMN vpn_subnet TEXT")
        conn.execute("ALTER TABLE vpn_servers ADD COLUMN lan_subnet TEXT")
        conn.commit()
    if "vpn_endpoint" not in vpn_cols:
        conn.execute("ALTER TABLE vpn_servers ADD COLUMN vpn_endpoint TEXT")
        conn.commit()
    # The management tunnel's keys move here from wg-easy's store. Keeping
    # them means a site can be re-provisioned without losing its tunnel
    # identity, and it makes ADM the only writer — which wg-easy's file could
    # never be, since its UI rewrites that file wholesale.
    if "callhome_pubkey" not in vpn_cols:
        for stmt in (
            "ALTER TABLE vpn_servers ADD COLUMN callhome_pubkey TEXT",
            "ALTER TABLE vpn_servers ADD COLUMN callhome_privkey_enc TEXT",
            "ALTER TABLE vpn_servers ADD COLUMN callhome_psk_enc TEXT",
        ):
            conn.execute(stmt)
        conn.commit()


# ── Server CRUD ──────────────────────────────────────────────────────────

def create_server(data: dict) -> int:
    conn = get_conn()
    ts = int(time.time())
    cur = conn.execute(
        "INSERT INTO servers (name, display_name, ip, server_type, location, provider, "
        "status, root_password_enc, ss_password_enc, agent_api_key_enc, ssconf_token_enc, "
        "speedtest_api_key_enc, ss_port, ss_cipher, agent_port, node_id, install_adguard, "
        "created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            data["name"], data["display_name"], data["ip"], data["server_type"],
            data.get("location", ""), data.get("provider", ""),
            data.get("status", "new"),
            data.get("root_password_enc"), data.get("ss_password_enc"),
            data.get("agent_api_key_enc"), data.get("ssconf_token_enc"),
            data.get("speedtest_api_key_enc"),
            data.get("ss_port", 8388), data.get("ss_cipher", "chacha20-ietf-poly1305"),
            data.get("agent_port", 5051), data.get("node_id"),
            1 if data.get("install_adguard") else 0,
            ts, ts,
        ),
    )
    conn.commit()
    return cur.lastrowid


def get_server(server_id: int) -> dict | None:
    conn = get_conn()
    row = conn.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
    return dict(row) if row else None


def get_server_by_name(name: str) -> dict | None:
    conn = get_conn()
    row = conn.execute("SELECT * FROM servers WHERE name = ?", (name,)).fetchone()
    return dict(row) if row else None


def get_all_servers() -> list[dict]:
    conn = get_conn()
    rows = conn.execute("SELECT * FROM servers ORDER BY id").fetchall()
    return [dict(r) for r in rows]


def update_server(server_id: int, updates: dict) -> bool:
    conn = get_conn()
    allowed = {
        "name", "display_name", "ip", "public_ip", "server_type", "location",
        "provider", "status", "root_password_enc", "ss_password_enc",
        "agent_api_key_enc", "ssconf_token_enc", "speedtest_api_key_enc",
        "ss_port", "ss_cipher", "agent_port", "ssh_port", "node_id",
        "install_adguard",
        "vless_uuid", "vless_public_key", "vless_short_id", "vless_port",
        "callhome_ip", "callhome_pubkey", "callhome_privkey_enc",
        "callhome_psk_enc",
        "traffic_limit_gb", "traffic_period_day",
    }
    sets, vals = [], []
    for key, val in updates.items():
        if key in allowed:
            sets.append(f"{key} = ?")
            vals.append(val)
    if not sets:
        return False
    sets.append("updated_at = ?")
    vals.append(int(time.time()))
    vals.append(server_id)
    conn.execute(f"UPDATE servers SET {', '.join(sets)} WHERE id = ?", vals)
    conn.commit()
    return True


def delete_server(server_id: int) -> bool:
    conn = get_conn()
    cur = conn.execute("DELETE FROM servers WHERE id = ?", (server_id,))
    conn.commit()
    return cur.rowcount > 0


def server_count() -> int:
    conn = get_conn()
    row = conn.execute("SELECT COUNT(*) as cnt FROM servers").fetchone()
    return row["cnt"] if row else 0


# ── Operations CRUD ──────────────────────────────────────────────────────

def create_operation(server_id: int | None, op_type: str, playbook: str | None = None) -> int:
    conn = get_conn()
    ts = int(time.time())
    cur = conn.execute(
        "INSERT INTO operations (server_id, op_type, status, playbook, output, started_at) "
        "VALUES (?, ?, 'running', ?, '', ?)",
        (server_id, op_type, playbook, ts),
    )
    conn.commit()
    return cur.lastrowid


def get_operation(op_id: int) -> dict | None:
    conn = get_conn()
    row = conn.execute("SELECT * FROM operations WHERE id = ?", (op_id,)).fetchone()
    return dict(row) if row else None


def get_operations(limit: int = 50) -> list[dict]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, server_id, op_type, status, playbook, error, started_at, completed_at "
        "FROM operations ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_operations_by_server(server_id: int, limit: int = 20) -> list[dict]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, server_id, op_type, status, playbook, error, started_at, completed_at "
        "FROM operations WHERE server_id = ? ORDER BY id DESC LIMIT ?",
        (server_id, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def append_operation_output(op_id: int, text: str) -> None:
    conn = get_conn()
    conn.execute(
        "UPDATE operations SET output = output || ? WHERE id = ?",
        (text, op_id),
    )
    conn.commit()


def complete_operation(op_id: int, status: str, error: str | None = None) -> None:
    conn = get_conn()
    conn.execute(
        "UPDATE operations SET status = ?, error = ?, completed_at = ? WHERE id = ?",
        (status, error, int(time.time()), op_id),
    )
    conn.commit()


# ── Admin CRUD ───────────────────────────────────────────────────────────

def create_admin(username: str, password_hash: str,
                 role: str = "superadmin") -> int:
    conn = get_conn()
    ts = int(time.time())
    cur = conn.execute(
        "INSERT INTO admins (username, password_hash, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        (username, password_hash, role, ts),
    )
    conn.commit()
    return cur.lastrowid


def get_admin_by_username(username: str) -> dict | None:
    conn = get_conn()
    row = conn.execute(
        "SELECT id, username, password_hash, role, enabled, created_at "
        "FROM admins WHERE username = ?",
        (username,),
    ).fetchone()
    return dict(row) if row else None


def get_admin(admin_id: int) -> dict | None:
    conn = get_conn()
    row = conn.execute(
        "SELECT id, username, password_hash, role, enabled, created_at "
        "FROM admins WHERE id = ?",
        (admin_id,),
    ).fetchone()
    return dict(row) if row else None


def get_all_admins() -> list[dict]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, username, role, enabled, created_at FROM admins ORDER BY username"
    ).fetchall()
    return [dict(r) for r in rows]


def update_admin(admin_id: int, updates: dict) -> bool:
    conn = get_conn()
    allowed = {"username", "password_hash", "role", "enabled"}
    sets, vals = [], []
    for key, val in updates.items():
        if key in allowed:
            sets.append(f"{key} = ?")
            vals.append(val)
    if not sets:
        return False
    vals.append(admin_id)
    conn.execute(f"UPDATE admins SET {', '.join(sets)} WHERE id = ?", vals)
    conn.commit()
    return True


def delete_admin(admin_id: int) -> bool:
    conn = get_conn()
    cur = conn.execute("DELETE FROM admins WHERE id = ?", (admin_id,))
    conn.commit()
    return cur.rowcount > 0


def superadmin_count(exclude_id: int | None = None) -> int:
    """How many enabled superadmins remain — used to refuse the last one."""
    conn = get_conn()
    sql = "SELECT COUNT(*) AS c FROM admins WHERE role = 'superadmin' AND enabled = 1"
    params: tuple = ()
    if exclude_id is not None:
        sql += " AND id != ?"
        params = (exclude_id,)
    return conn.execute(sql, params).fetchone()["c"]


# ── Admin server scope ───────────────────────────────────────────────────

def get_admin_scope(admin_id: int) -> list[int]:
    """VPN server ids this admin may manage users on."""
    conn = get_conn()
    rows = conn.execute(
        "SELECT vpn_server_id FROM admin_server_scope WHERE admin_id = ? "
        "ORDER BY vpn_server_id",
        (admin_id,),
    ).fetchall()
    return [r["vpn_server_id"] for r in rows]


def set_admin_scope(admin_id: int, vpn_server_ids: list[int]) -> None:
    conn = get_conn()
    conn.execute("DELETE FROM admin_server_scope WHERE admin_id = ?", (admin_id,))
    conn.executemany(
        "INSERT OR IGNORE INTO admin_server_scope (admin_id, vpn_server_id) "
        "VALUES (?, ?)",
        [(admin_id, sid) for sid in vpn_server_ids],
    )
    conn.commit()


def admin_count() -> int:
    conn = get_conn()
    row = conn.execute("SELECT COUNT(*) as cnt FROM admins").fetchone()
    return row["cnt"] if row else 0


def update_admin_password(admin_id: int, password_hash: str) -> bool:
    """Set an operator's password and queue it for every site they administer.

    One credential is the point: the same password signs them into ADM and
    into each panel they hold an account on. Marking their access rows here
    means a change made in one place does not quietly leave the sites behind.
    """
    conn = get_conn()
    now = int(time.time())
    cur = conn.execute(
        "UPDATE admins SET password_hash = ?, password_changed_at = ? WHERE id = ?",
        (password_hash, now, admin_id),
    )
    if cur.rowcount:
        conn.execute(
            "UPDATE admin_server_access SET sync_status = 'pending', updated_at = ? "
            "WHERE admin_id = ? AND sync_status != 'pending_delete'",
            (now, admin_id),
        )
    conn.commit()
    return cur.rowcount > 0


# ── Panel access: which sites an operator can sign into ──────────────────

def get_admin_access(admin_id: int) -> list[dict]:
    conn = get_conn()
    return [dict(r) for r in conn.execute(
        "SELECT a.*, s.name AS server_name, s.display_name AS server_display_name "
        "FROM admin_server_access a "
        "JOIN vpn_servers s ON a.vpn_server_id = s.id "
        "WHERE a.admin_id = ? ORDER BY s.name", (admin_id,)).fetchall()]


def get_all_admin_access() -> list[dict]:
    conn = get_conn()
    return [dict(r) for r in conn.execute(
        "SELECT * FROM admin_server_access ORDER BY admin_id, vpn_server_id"
    ).fetchall()]


def grant_admin_access(admin_id: int, vpn_server_id: int) -> None:
    """Give an operator a panel account on a site. Idempotent."""
    conn = get_conn()
    now = int(time.time())
    conn.execute(
        "INSERT INTO admin_server_access "
        "(admin_id, vpn_server_id, sync_status, created_at, updated_at) "
        "VALUES (?, ?, 'pending', ?, ?) "
        "ON CONFLICT(admin_id, vpn_server_id) DO UPDATE SET "
        "  sync_status = 'pending', sync_error = NULL, updated_at = excluded.updated_at",
        (admin_id, vpn_server_id, now, now))
    conn.commit()


def mark_admin_access_pending_delete(admin_id: int, vpn_server_id: int) -> None:
    """Queue removal. The row survives until the site confirms it.

    Dropping it here instead would lose the instruction: the account would
    stay on a box nobody is watching, still able to log in.
    """
    conn = get_conn()
    conn.execute(
        "UPDATE admin_server_access SET sync_status = 'pending_delete', "
        "sync_error = NULL, updated_at = ? WHERE admin_id = ? AND vpn_server_id = ?",
        (int(time.time()), admin_id, vpn_server_id))
    conn.commit()


def delete_admin_access(admin_id: int, vpn_server_id: int) -> None:
    conn = get_conn()
    conn.execute(
        "DELETE FROM admin_server_access WHERE admin_id = ? AND vpn_server_id = ?",
        (admin_id, vpn_server_id))
    conn.commit()


def get_pending_admin_access(vpn_server_id: int | None = None) -> list[dict]:
    conn = get_conn()
    sql = (
        "SELECT a.*, m.username, m.password_hash, m.enabled AS admin_enabled, "
        "m.password_changed_at, s.name AS server_name "
        "FROM admin_server_access a "
        "JOIN admins m ON a.admin_id = m.id "
        "JOIN vpn_servers s ON a.vpn_server_id = s.id "
        "WHERE a.sync_status IN ('pending', 'pending_delete')"
    )
    params: tuple = ()
    if vpn_server_id is not None:
        sql += " AND a.vpn_server_id = ?"
        params = (vpn_server_id,)
    return [dict(r) for r in conn.execute(sql + " ORDER BY a.id", params).fetchall()]


def mark_admin_access_synced(access_id: int, password_pushed: bool = False) -> None:
    conn = get_conn()
    now = int(time.time())
    if password_pushed:
        conn.execute(
            "UPDATE admin_server_access SET sync_status = 'synced', sync_error = NULL, "
            "synced_at = ?, password_synced_at = ?, updated_at = ? WHERE id = ?",
            (now, now, now, access_id))
    else:
        conn.execute(
            "UPDATE admin_server_access SET sync_status = 'synced', sync_error = NULL, "
            "synced_at = ?, updated_at = ? WHERE id = ?", (now, now, access_id))
    conn.commit()


def mark_admin_access_error(access_id: int, error: str) -> None:
    """Record a failure without discarding the instruction.

    The row stays pending, so the next run retries it. Clearing the status
    instead would strand a grant — or worse, a revocation, leaving an account
    alive on a site ADM believes it removed.
    """
    conn = get_conn()
    conn.execute(
        "UPDATE admin_server_access SET sync_error = ?, updated_at = ? WHERE id = ?",
        (error[:500], int(time.time()), access_id))
    conn.commit()


# ── VPN Server CRUD ─────────────────────────────────────────────────────

def create_vpn_server(data: dict) -> int:
    conn = get_conn()
    ts = int(time.time())
    cur = conn.execute(
        "INSERT INTO vpn_servers (name, display_name, url, public_url, api_token_enc, "
        "ssh_host, ssh_port, ssh_user, ssh_password_enc, server_code, callhome_ip, "
        "vpn_subnet, lan_subnet, vpn_endpoint, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            data["name"], data["display_name"], data["url"],
            data.get("public_url", ""), data.get("api_token_enc"),
            data.get("ssh_host"), data.get("ssh_port", 22),
            data.get("ssh_user", "root"), data.get("ssh_password_enc"),
            data.get("server_code"), data.get("callhome_ip"),
            data.get("vpn_subnet"), data.get("lan_subnet"),
            data.get("vpn_endpoint"),
            ts, ts,
        ),
    )
    conn.commit()
    return cur.lastrowid


def get_vpn_server(vpn_server_id: int) -> dict | None:
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM vpn_servers WHERE id = ?", (vpn_server_id,)
    ).fetchone()
    return dict(row) if row else None


def get_all_vpn_servers() -> list[dict]:
    conn = get_conn()
    rows = conn.execute("SELECT * FROM vpn_servers ORDER BY id").fetchall()
    return [dict(r) for r in rows]


def update_vpn_server(vpn_server_id: int, updates: dict) -> bool:
    conn = get_conn()
    allowed = {"name", "display_name", "url", "public_url", "api_token_enc",
               "ssh_host", "ssh_port", "ssh_user", "ssh_password_enc",
               "server_code", "callhome_ip", "vpn_subnet", "lan_subnet", "vpn_endpoint",
               "callhome_pubkey", "callhome_privkey_enc", "callhome_psk_enc"}
    sets, vals = [], []
    for key, val in updates.items():
        if key in allowed:
            sets.append(f"{key} = ?")
            vals.append(val)
    if not sets:
        return False
    sets.append("updated_at = ?")
    vals.append(int(time.time()))
    vals.append(vpn_server_id)
    conn.execute(f"UPDATE vpn_servers SET {', '.join(sets)} WHERE id = ?", vals)
    conn.commit()
    return True


def set_server_profiles(vpn_server_id: int, profiles: list[dict]) -> None:
    """Store the Direct profiles a site currently publishes.

    Deliberately does not touch updated_at: this is polled state, not an
    administrative edit, and drift indicators key off updated_at.
    """
    conn = get_conn()
    conn.execute(
        "UPDATE vpn_servers SET profiles_cache = ?, profiles_cached_at = ? WHERE id = ?",
        (json.dumps(profiles), int(time.time()), vpn_server_id),
    )
    conn.commit()


def parse_server_profiles(row: dict | None) -> list[dict]:
    """Read the cached profiles off a vpn_servers row already in hand."""
    try:
        value = json.loads((row or {}).get("profiles_cache") or "[]")
    except (ValueError, TypeError):
        return []
    return value if isinstance(value, list) else []


def get_server_profiles(vpn_server_id: int) -> list[dict]:
    """Profiles last seen on a site. Empty when never polled or unparseable."""
    return parse_server_profiles(get_vpn_server(vpn_server_id))


def delete_vpn_server(vpn_server_id: int) -> bool:
    conn = get_conn()
    with conn:
        cur = conn.execute("DELETE FROM vpn_servers WHERE id = ?", (vpn_server_id,))
    return cur.rowcount > 0


def next_callhome_ip(base: str = "10.13.13", first: int = 10) -> str | None:
    """Next unused address in the management network.

    Admin devices live below `first`; site servers are allocated from it
    upwards, so the two never collide as either side grows.
    """
    conn = get_conn()
    taken = {
        r["callhome_ip"] for r in
        conn.execute("SELECT callhome_ip FROM vpn_servers "
                     "WHERE callhome_ip IS NOT NULL").fetchall()
    }
    for host in range(first, 255):
        candidate = f"{base}.{host}"
        if candidate not in taken:
            return candidate
    return None


# ── Monitoring CRUD ────────────────────────────────────────────────────

def insert_metric(server_id: int, data: dict) -> None:
    conn = get_conn()
    conn.execute(
        "INSERT INTO server_metrics "
        "(server_id, timestamp, online, uptime, disk_pct, memory_pct, cpu_pct, services_ok, docker_ok, "
        "rx_bytes, tx_bytes) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            server_id, int(time.time()),
            1 if data.get("online") else 0,
            data.get("uptime"),
            data.get("disk_pct"),
            data.get("memory_pct"),
            data.get("cpu_pct"),
            data.get("services_ok"),
            data.get("docker_ok"),
            data.get("rx_bytes"),
            data.get("tx_bytes"),
        ),
    )
    conn.commit()


_METRIC_COLS = ("disk_pct", "memory_pct", "cpu_pct")


def _fetch_metrics(
    table: str,
    id_col: str,
    entity_id: int | None,
    hours: int,
    bucket: int,
    extra_cols: tuple[str, ...] = (),
) -> list[dict]:
    """Read a metric table, optionally averaged into `bucket`-second slots.

    A month of five-minute samples is ~8600 points per server, which the chart
    cannot draw legibly and the browser cannot draw quickly. Averaging into
    buckets fixes both. The peak of each bucket comes along as `<metric>_max`
    so an averaged-away CPU spike is still visible in the tooltip.
    """
    conn = get_conn()
    since = int(time.time()) - hours * 3600
    where = f"{id_col} = ? AND timestamp >= ?" if entity_id else "timestamp >= ?"
    id_params = [entity_id] if entity_id else []

    if bucket > 1:
        select = [id_col, "(timestamp / ?) * ? AS bucket_ts", "MIN(online) AS online"]
        select += [f"MAX({c}) AS {c}" for c in extra_cols]
        for col in _METRIC_COLS:
            select.append(f"ROUND(AVG({col}), 1) AS {col}")
            select.append(f"ROUND(MAX({col}), 1) AS {col[:-4]}_max")
        rows = conn.execute(
            f"SELECT {', '.join(select)} FROM {table} WHERE {where} "
            f"GROUP BY {id_col}, timestamp / ? ORDER BY bucket_ts",
            [bucket, bucket, *id_params, since, bucket],
        ).fetchall()
        out = []
        for r in rows:
            point = dict(r)
            point["timestamp"] = point.pop("bucket_ts")
            out.append(point)
        return out

    cols = ", ".join([id_col, "timestamp", "online", *extra_cols, *_METRIC_COLS])
    rows = conn.execute(
        f"SELECT {cols} FROM {table} WHERE {where} ORDER BY timestamp",
        [*id_params, since],
    ).fetchall()
    return [dict(r) for r in rows]


def get_metrics(
    server_id: int | None = None, hours: int = 24, bucket: int = 0
) -> list[dict]:
    return _fetch_metrics(
        "server_metrics", "server_id", server_id, hours, bucket, ("uptime",)
    )


def cleanup_old_metrics(days: int = 30) -> int:
    conn = get_conn()
    cutoff = int(time.time()) - days * 86400
    cur = conn.execute("DELETE FROM server_metrics WHERE timestamp < ?", (cutoff,))
    cur2 = conn.execute("DELETE FROM vpn_server_metrics WHERE timestamp < ?", (cutoff,))
    conn.commit()
    return cur.rowcount + cur2.rowcount


# ── VPN Server Metrics CRUD ──────────────────────────────────────────

def insert_vpn_metric(vpn_server_id: int, data: dict) -> None:
    conn = get_conn()
    conn.execute(
        "INSERT INTO vpn_server_metrics "
        "(vpn_server_id, timestamp, online, disk_pct, memory_pct, cpu_pct) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            vpn_server_id, int(time.time()),
            1 if data.get("online") else 0,
            data.get("disk_pct"),
            data.get("memory_pct"),
            data.get("cpu_pct"),
        ),
    )
    conn.commit()


def get_vpn_metrics(
    vpn_server_id: int | None = None, hours: int = 24, bucket: int = 0
) -> list[dict]:
    return _fetch_metrics(
        "vpn_server_metrics", "vpn_server_id", vpn_server_id, hours, bucket
    )


def get_vpn_servers_last_online() -> dict[int, bool]:
    """Last-known online flag per VPN server, from its newest metric row.

    Servers with no metrics yet are simply absent — callers treat missing
    as unknown, not offline.
    """
    conn = get_conn()
    rows = conn.execute(
        "SELECT vpn_server_id, online FROM vpn_server_metrics WHERE id IN "
        "(SELECT MAX(id) FROM vpn_server_metrics GROUP BY vpn_server_id)"
    ).fetchall()
    return {r["vpn_server_id"]: bool(r["online"]) for r in rows}


def get_alert_config() -> dict:
    conn = get_conn()
    row = conn.execute("SELECT * FROM alert_config WHERE id = 1").fetchone()
    return dict(row) if row else {
        "enabled": 0, "telegram_bot_token": "", "telegram_chat_id": "",
        "disk_threshold": 90.0, "memory_threshold": 90.0, "offline_minutes": 5,
    }


def update_alert_config(updates: dict) -> bool:
    conn = get_conn()
    allowed = {
        "enabled", "telegram_bot_token", "telegram_chat_id",
        "disk_threshold", "memory_threshold", "cpu_threshold", "offline_minutes",
    }
    sets, vals = [], []
    for key, val in updates.items():
        if key in allowed:
            sets.append(f"{key} = ?")
            vals.append(val)
    if not sets:
        return False
    conn.execute(f"UPDATE alert_config SET {', '.join(sets)} WHERE id = 1", vals)
    conn.commit()
    return True


def insert_alert(server_id: int | None, alert_type: str, message: str) -> int:
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO alert_history (server_id, alert_type, message, sent_at) "
        "VALUES (?, ?, ?, ?)",
        (server_id, alert_type, message, int(time.time())),
    )
    conn.commit()
    return cur.lastrowid


def get_recent_alerts(limit: int = 100) -> list[dict]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT ah.id, ah.server_id, ah.alert_type, ah.message, ah.sent_at, "
        "s.display_name as server_name "
        "FROM alert_history ah LEFT JOIN servers s ON ah.server_id = s.id "
        "ORDER BY ah.id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


# ── Central VPN user CRUD ────────────────────────────────────────────────

def create_vpn_user(data: dict) -> int:
    conn = get_conn()
    ts = int(time.time())
    cur = conn.execute(
        "INSERT INTO vpn_users (username, full_name, password_hash, enabled, note, "
        "password_changed_at, created_at, updated_at, update_channel, account_id, allow_pools) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            data["username"], data.get("full_name", ""), data["password_hash"],
            1 if data.get("enabled", True) else 0, data.get("note", ""), ts, ts, ts,
            data.get("update_channel", "stable"),
            str(uuid.uuid4()), int(data.get("allow_pools", False)),
        ),
    )
    conn.commit()
    return cur.lastrowid


def get_vpn_user(user_id: int) -> dict | None:
    conn = get_conn()
    row = conn.execute("SELECT * FROM vpn_users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


def get_vpn_user_by_username(username: str) -> dict | None:
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM vpn_users WHERE username = ?", (username,)
    ).fetchone()
    return dict(row) if row else None


def get_all_vpn_users() -> list[dict]:
    conn = get_conn()
    rows = conn.execute("SELECT * FROM vpn_users ORDER BY username").fetchall()
    return [dict(r) for r in rows]


def update_vpn_user(user_id: int, updates: dict) -> bool:
    conn = get_conn()
    allowed = {"username", "full_name", "password_hash", "enabled", "note", "update_channel", "allow_pools"}
    sets, vals = [], []
    for key, val in updates.items():
        if key in allowed:
            sets.append(f"{key} = ?")
            vals.append(val)
    if not sets:
        return False
    now = int(time.time())
    if "password_hash" in updates:
        sets.append("password_changed_at = ?")
        vals.append(now)
    sets.append("updated_at = ?")
    vals.append(now)
    vals.append(user_id)
    cur = conn.execute(
        f"UPDATE vpn_users SET {', '.join(sets)} WHERE id = ? AND deletion_pending = 0", vals
    )
    conn.commit()
    return cur.rowcount > 0


def request_vpn_user_deletion(user_id: int) -> None:
    """Disable centrally and durably queue every replica before removing identity."""
    conn = get_conn()
    ts = int(time.time())
    with conn:
        conn.execute(
            "UPDATE vpn_users SET deletion_pending = 1, enabled = 0, updated_at = ? WHERE id = ?",
            (ts, user_id),
        )
        conn.execute(
            "UPDATE vpn_user_access SET sync_status = 'pending_delete', updated_at = ? WHERE user_id = ?",
            (ts, user_id),
        )
        conn.execute(
            "DELETE FROM vpn_users WHERE id = ? AND deletion_pending = 1 "
            "AND NOT EXISTS (SELECT 1 FROM vpn_user_access WHERE user_id = vpn_users.id)",
            (user_id,),
        )


def delete_vpn_user(user_id: int) -> bool:
    conn = get_conn()
    cur = conn.execute("DELETE FROM vpn_users WHERE id = ?", (user_id,))
    conn.commit()
    return cur.rowcount > 0


# ── VPN user ↔ server access CRUD ────────────────────────────────────────

ACCESS_FIELDS = {
    "enabled", "max_peers", "bandwidth_quota",
    "speed_download", "speed_upload", "assigned_groups", "lan_access",
    "allowed_profiles", "allow_smart_test",
}


def get_user_access(user_id: int) -> list[dict]:
    """All server-access rows for one user, with server display info."""
    conn = get_conn()
    rows = conn.execute(
        "SELECT a.*, s.name AS server_name, s.display_name AS server_display_name "
        "FROM vpn_user_access a "
        "JOIN vpn_servers s ON a.vpn_server_id = s.id "
        "WHERE a.user_id = ? ORDER BY s.id",
        (user_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_all_user_access() -> list[dict]:
    """Every access row — used to build the aggregated user list in one query."""
    conn = get_conn()
    rows = conn.execute(
        "SELECT a.*, s.name AS server_name, s.display_name AS server_display_name "
        "FROM vpn_user_access a "
        "JOIN vpn_servers s ON a.vpn_server_id = s.id ORDER BY a.user_id, s.id"
    ).fetchall()
    return [dict(r) for r in rows]


def count_access_for_server(vpn_server_id: int) -> int:
    """How many users are still authorized on a server."""
    conn = get_conn()
    row = conn.execute(
        "SELECT COUNT(*) AS cnt FROM vpn_user_access WHERE vpn_server_id = ?",
        (vpn_server_id,),
    ).fetchone()
    return row["cnt"] if row else 0


def get_access(user_id: int, vpn_server_id: int) -> dict | None:
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM vpn_user_access WHERE user_id = ? AND vpn_server_id = ?",
        (user_id, vpn_server_id),
    ).fetchone()
    return dict(row) if row else None


def upsert_user_access(user_id: int, vpn_server_id: int, data: dict) -> int | None:
    """Create or update an access row. Any change marks it pending re-sync."""
    conn = get_conn()
    ts = int(time.time())
    existing = get_access(user_id, vpn_server_id)

    if existing:
        sets, vals = [], []
        for key, val in data.items():
            if key in ACCESS_FIELDS or key == "remote_user_id":
                sets.append(f"{key} = ?")
                vals.append(val)
        sets += ["sync_status = 'pending'", "updated_at = ?"]
        vals += [ts, existing["id"], user_id]
        cur = conn.execute(
            f"UPDATE vpn_user_access SET {', '.join(sets)} WHERE id = ? "
            "AND EXISTS (SELECT 1 FROM vpn_users WHERE id = ? AND deletion_pending = 0)", vals
        )
        conn.commit()
        return existing["id"] if cur.rowcount else None

    cur = conn.execute(
        "INSERT INTO vpn_user_access (user_id, vpn_server_id, remote_user_id, enabled, "
        "max_peers, bandwidth_quota, speed_download, speed_upload, assigned_groups, "
        "allowed_profiles, lan_access, allow_smart_test, sync_status, created_at, updated_at) "
        "SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ? "
        "WHERE EXISTS (SELECT 1 FROM vpn_users WHERE id = ? AND deletion_pending = 0)",
        (
            user_id, vpn_server_id, data.get("remote_user_id"),
            1 if data.get("enabled", True) else 0,
            data.get("max_peers"), data.get("bandwidth_quota"),
            data.get("speed_download"), data.get("speed_upload"),
            data.get("assigned_groups", "[]"),
            data.get("allowed_profiles", "[]"),
            1 if data.get("lan_access", True) else 0,
            int(type(data.get("allow_smart_test")) in (bool, int)
                and data["allow_smart_test"] == 1), ts, ts, user_id,
        ),
    )
    conn.commit()
    return cur.lastrowid if cur.rowcount else None


def mark_access_pending_delete(user_id: int, vpn_server_id: int) -> bool:
    """Flag an access row for removal.

    The row is kept until the remote user has actually been deleted on the
    Proxima instance — dropping it here would orphan the remote account.
    """
    conn = get_conn()
    cur = conn.execute(
        "UPDATE vpn_user_access SET sync_status = 'pending_delete', updated_at = ? "
        "WHERE user_id = ? AND vpn_server_id = ?",
        (int(time.time()), user_id, vpn_server_id),
    )
    conn.commit()
    return cur.rowcount > 0


def delete_user_access(user_id: int, vpn_server_id: int) -> bool:
    """Drop the row outright. Only safe once the remote side is gone."""
    conn = get_conn()
    cur = conn.execute(
        "DELETE FROM vpn_user_access WHERE user_id = ? AND vpn_server_id = ?",
        (user_id, vpn_server_id),
    )
    conn.execute(
        "DELETE FROM vpn_users WHERE id = ? AND deletion_pending = 1 "
        "AND NOT EXISTS (SELECT 1 FROM vpn_user_access WHERE user_id = vpn_users.id)",
        (user_id,),
    )
    conn.commit()
    return cur.rowcount > 0


def get_pending_access(vpn_server_id: int | None = None) -> list[dict]:
    """Access rows awaiting a push ('pending' or 'pending_delete')."""
    conn = get_conn()
    sql = (
        "SELECT a.*, u.username, u.password_hash, u.enabled AS user_enabled, "
        "u.password_changed_at, u.update_channel AS user_update_channel, s.name AS server_name "
        "FROM vpn_user_access a "
        "JOIN vpn_users u ON a.user_id = u.id "
        "JOIN vpn_servers s ON a.vpn_server_id = s.id "
        "WHERE a.sync_status IN ('pending', 'pending_delete')"
    )
    params: tuple = ()
    if vpn_server_id is not None:
        sql += " AND a.vpn_server_id = ?"
        params = (vpn_server_id,)
    return [dict(r) for r in conn.execute(sql + " ORDER BY a.id", params).fetchall()]


def mark_access_synced(access_id: int, remote_user_id: int | None = None,
                       password_pushed: bool = False) -> None:
    """Record a successful push.

    password_pushed records that this push carried the password, which is
    what lets a later push skip it — and so leave a password the user changed
    on the instance alone.
    """
    conn = get_conn()
    ts = int(time.time())
    # An in-flight push must not erase a deletion requested while it ran.
    sets = ["sync_status = CASE WHEN sync_status = 'pending_delete' THEN sync_status ELSE 'synced' END",
            "sync_error = NULL", "synced_at = ?"]
    vals: list = [ts]
    if remote_user_id is not None:
        sets.append("remote_user_id = ?")
        vals.append(remote_user_id)
    if password_pushed:
        sets.append("password_synced_at = ?")
        vals.append(ts)
    vals.append(access_id)
    conn.execute(f"UPDATE vpn_user_access SET {', '.join(sets)} WHERE id = ?", vals)
    conn.commit()


def mark_access_error(access_id: int, error: str) -> None:
    """Record a failed push without losing what still has to be done.

    sync_status stays the *intent* ('pending' or 'pending_delete') so the row
    is picked up again on the next attempt — an error is a pending row that
    has not succeeded yet, not a state of its own. Overwriting the status
    would both strand the row forever and, for a revocation, forget that a
    remote account was supposed to be deleted.
    """
    conn = get_conn()
    conn.execute(
        "UPDATE vpn_user_access SET sync_error = ? WHERE id = ?",
        (error[:500], access_id),
    )
    conn.commit()


def get_sync_summary() -> dict:
    """Keep queued unreachable sites separate from actual rejected changes."""
    from core.proxima_client import waiting_note
    conn = get_conn()
    counts = {
        r["sync_status"]: r["cnt"]
        for r in conn.execute(
            "SELECT sync_status, COUNT(*) AS cnt FROM vpn_user_access "
            "GROUP BY sync_status"
        ).fetchall()
    }
    issues = [dict(r) for r in conn.execute(
        "SELECT u.username, s.name AS server_name, a.sync_error "
        "FROM vpn_user_access a "
        "JOIN vpn_users u ON a.user_id = u.id "
        "JOIN vpn_servers s ON a.vpn_server_id = s.id "
        "WHERE a.sync_error IS NOT NULL AND a.sync_status != 'synced' "
        "ORDER BY u.username"
    ).fetchall()]
    deferred = [r for r in issues if r["sync_error"].startswith(waiting_note(""))]
    errors = [r for r in issues if not r["sync_error"].startswith(waiting_note(""))]
    return {
        "synced": counts.get("synced", 0),
        "pending": counts.get("pending", 0),
        "pending_delete": counts.get("pending_delete", 0),
        "error": len(errors),
        "errors": errors,
        "deferred": deferred,
    }


def mark_all_access_pending(user_id: int) -> None:
    """Re-push identity changes without resurrecting queued revocations."""
    conn = get_conn()
    conn.execute(
        "UPDATE vpn_user_access SET sync_status = 'pending', updated_at = ? "
        "WHERE user_id = ? AND sync_status != 'pending_delete'",
        (int(time.time()), user_id),
    )
    conn.commit()


# ── Traffic accounting ───────────────────────────────────────────────────

def period_start(period_day: int, now: float | None = None) -> int:
    """Start of the current billing period, as a unix timestamp.

    Providers count from a day of the month, not from the 1st — HOSTKEY's
    ERG-TR turns over on the 18th. A month boundary would report the wrong
    figure for three weeks of every four.
    """
    import datetime as _dt
    ts = _dt.datetime.fromtimestamp(now or time.time())
    day = max(1, min(28, int(period_day or 1)))
    start = ts.replace(day=day, hour=0, minute=0, second=0, microsecond=0)
    if ts.day < day:
        # Before this month's turnover, so the period began last month.
        start = (start.replace(day=1) - _dt.timedelta(days=1)).replace(
            day=day, hour=0, minute=0, second=0, microsecond=0)
    return int(start.timestamp())


def traffic_since(server_id: int, since_ts: int) -> dict:
    """Bytes moved since *since_ts*, summed from consecutive samples.

    The stored counters are cumulative and reset whenever the box reboots, so
    a plain last-minus-first would report a negative number after any reboot
    and silently under-count after every one. Summing only the positive steps
    treats a reset as an unknown gap rather than as traffic that never
    happened — an undercount at worst, which is the honest direction for a
    figure someone will use to decide whether they are near a cap.
    """
    conn = get_conn()
    rows = conn.execute(
        "SELECT rx_bytes, tx_bytes FROM server_metrics "
        "WHERE server_id = ? AND timestamp >= ? AND tx_bytes IS NOT NULL "
        "ORDER BY timestamp",
        (server_id, since_ts),
    ).fetchall()

    rx = tx = 0
    resets = 0
    prev = None
    for row in rows:
        cur = (row["rx_bytes"], row["tx_bytes"])
        if prev is not None:
            if cur[0] >= prev[0] and cur[1] >= prev[1]:
                rx += cur[0] - prev[0]
                tx += cur[1] - prev[1]
            else:
                resets += 1
        prev = cur

    return {
        "rx_bytes": rx,
        "tx_bytes": tx,
        "rx_gb": round(rx / (1024**3), 2),
        "tx_gb": round(tx / (1024**3), 2),
        "samples": len(rows),
        "counter_resets": resets,
    }
