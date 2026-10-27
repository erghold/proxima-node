"""Proxima ADM — centralized infrastructure management."""

import logging
import os

from flask import Flask, g, jsonify, request

from core.auth import verify_token
from core.config import PORT
from core.db import init_db


def create_app() -> Flask:
    app = Flask(
        __name__,
        static_folder="static",
        static_url_path="",
    )

    # Logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    log = logging.getLogger("adm")

    # Init database
    init_db()
    log.info("Database initialized")

    # First-boot: import existing servers from inventory
    from core.first_boot import import_existing_servers
    import_existing_servers()

    # hosts.yml is generated from the DB and is no longer tracked in git, so a
    # fresh checkout arrives without one. Write it here rather than waiting for
    # the next server edit, or a deploy followed straight by a playbook run
    # would find no inventory at all. After the import above, never before it:
    # that reads the file to seed an empty DB, and generating first would
    # overwrite what it was about to read.
    from core.config import REPO_ROOT
    import os as _os
    if not _os.path.exists(_os.path.join(REPO_ROOT, "inventory", "hosts.yml")):
        from core.inventory_writer import regenerate_inventory
        regenerate_inventory()
        log.info("Inventory regenerated (no hosts.yml present)")

    # SSH key management (Linux only)
    from core.ssh_keys import ensure_ssh_key, ensure_group_vars_ssh_key
    pubkey = ensure_ssh_key()
    if pubkey:
        ensure_group_vars_ssh_key(pubkey)

    # Register blueprints
    from api.auth import bp as auth_bp
    from api.servers import bp as servers_bp
    from api.provision import bp as provision_bp
    from api.operations import bp as operations_bp
    from api.vpn_servers import bp as vpn_servers_bp
    from api.vpn_users import bp as vpn_users_bp
    from api.vpn_discover import bp as vpn_discover_bp
    from api.vpn_sync import bp as vpn_sync_bp
    from api.admins import bp as admins_bp
    from api.monitoring import bp as monitoring_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(servers_bp)
    app.register_blueprint(provision_bp)
    app.register_blueprint(operations_bp)
    app.register_blueprint(vpn_servers_bp)
    app.register_blueprint(vpn_users_bp)
    app.register_blueprint(vpn_discover_bp)
    app.register_blueprint(vpn_sync_bp)
    app.register_blueprint(admins_bp)
    app.register_blueprint(monitoring_bp)
    from api.pool_client import bp as pool_client_bp
    from api.pool_catalog import bp as pool_catalog_bp
    from api.pool_attachments import bp as pool_attachments_bp
    app.register_blueprint(pool_client_bp)
    app.register_blueprint(pool_catalog_bp)
    app.register_blueprint(pool_attachments_bp)

    # Auth middleware
    # /api/vpn/discover IS a login (the single-login client's) and
    # /api/vpn/sync authenticates with an instance-issued user token, so
    # neither can sit behind the admin token gate; both carry their own
    # rate limiting and delegate verification to the instance.
    NO_AUTH_PATHS = {"/api/auth/login", "/api/auth/setup", "/api/auth/me",
                     "/api/vpn/discover", "/api/vpn/sync"}

    def _scoped_admin_may(path: str, method: str) -> bool:
        """What a non-superadmin may reach.

        An allowlist rather than a blocklist: anything added later is
        superadmin-only until somebody decides otherwise, which is the safer
        way round for a panel that can provision servers.
        """
        if path in ("/api/auth/me", "/api/auth/password"):
            return True
        # Per-server and per-user checks happen inside these endpoints.
        if path.startswith("/api/vpn-users"):
            return True
        # Needed to render their own servers; mutations stay superadmin-only.
        if path == "/api/vpn-servers" and method == "GET":
            return True
        return False

    @app.before_request
    def check_auth():
        path = request.path

        if not path.startswith("/api/"):
            return None

        # These routes authenticate opaque client sessions themselves. Never
        # interpret an admin JWT here, even when usernames happen to coincide.
        if request.endpoint and request.endpoint.split(".")[0] == "pool_client":
            return None

        # ssconf proxy — authenticated via URL token, not JWT
        if "/ssconf/" in path and path.startswith("/api/servers/"):
            return None

        requires_auth = path not in NO_AUTH_PATHS

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            user_info = verify_token(token)
            if user_info:
                # The token only carries a username; role and scope are read
                # from the database on every request, so revoking an admin
                # takes effect immediately instead of when their token
                # eventually expires.
                from core.db import get_admin_by_username
                admin = get_admin_by_username(user_info["username"])
                if not admin or not admin.get("enabled", 1):
                    return jsonify({"ok": False, "error": "Unauthorized"}), 401
                g.user = user_info["username"]
                g.user_info = user_info
                g.admin = admin
                if admin["role"] != "superadmin" and not _scoped_admin_may(path, request.method):
                    return jsonify({"ok": False, "error": "Superadmin only"}), 403
                return None

        if requires_auth:
            return jsonify({"ok": False, "error": "Unauthorized"}), 401

        return None

    # Cache headers
    @app.after_request
    def set_response_headers(response):
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
        path = request.path
        if path.startswith("/assets/"):
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        elif not path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    # Start background scheduler
    from core.scheduler import start_scheduler
    start_scheduler()
    log.info("Monitoring scheduler started")

    # Serve React SPA
    @app.get("/")
    def index():
        return app.send_static_file("index.html")

    @app.errorhandler(404)
    def not_found(e):
        # SPA fallback: serve index.html for non-API, non-static routes
        if not request.path.startswith("/api/"):
            index_path = os.path.join(app.static_folder or "", "index.html")
            if os.path.exists(index_path):
                return app.send_static_file("index.html")
        return jsonify({"ok": False, "error": "Not found"}), 404

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=PORT, threaded=True)
