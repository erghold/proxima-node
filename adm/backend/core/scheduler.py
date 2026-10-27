"""Background scheduler — collects server metrics and checks alert thresholds."""

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests as http_requests

from core.alerts import send_telegram
from core.auth import decrypt_value
from core.db import (
    cleanup_old_metrics,
    get_alert_config,
    get_all_servers,
    get_all_vpn_servers,
    get_metrics,
    insert_alert,
    insert_metric,
    insert_vpn_metric,
    period_start,
    set_server_profiles,
    traffic_since,
)

log = logging.getLogger("adm.scheduler")

_stop = threading.Event()
_cooldowns: dict[tuple[int, str], float] = {}  # (server_id, alert_type) -> last_sent_ts
_active_alerts: set[tuple[int, str]] = set()  # alerts currently firing
_last_cleanup: float = 0.0
_last_source_refresh: float = 0.0
_last_token_refresh: float = 0.0

POLL_INTERVAL = 300  # 5 minutes
# How far back an offline alert may look when working out how long a server
# has been down. An outage older than this is reported as "over 24h" rather
# than pretending the oldest row on hand is when it started.
OFFLINE_LOOKBACK_HOURS = 24
COOLDOWN_SECONDS = 3600  # 1 hour between same alerts
CLEANUP_INTERVAL = 86400  # daily cleanup
SOURCE_REFRESH_INTERVAL = 3600  # hourly: keep the drift comparison honest
TOKEN_REFRESH_INTERVAL = 3600   # hourly: renew site tokens before they expire

# A metric must fall this far below its threshold before we call it recovered,
# otherwise a value hovering on the threshold alternates alert/recovery forever.
RECOVERY_MARGIN = 5.0


def start_scheduler() -> None:
    """Start the background scheduler thread."""
    thread = threading.Thread(target=_loop, daemon=True, name="adm-scheduler")
    thread.start()
    threading.Thread(target=_pool_delivery_loop, daemon=True, name="adm-pool-delivery").start()
    log.info(f"Scheduler started, interval: {POLL_INTERVAL}s")


def stop_scheduler() -> None:
    """Signal the scheduler to stop."""
    _stop.set()


def _pool_delivery_loop() -> None:
    # Independent of metrics/password/legacy-user sync, which may wait on offline sites.
    from core.pool_attachment_sync import reconcile
    while not _stop.wait(timeout=60):
        try:
            reconcile(limit=10)
        except Exception:
            log.exception("Pool authorization delivery error")


def _loop() -> None:
    # Wait a bit on startup to let app initialize
    _stop.wait(timeout=30)
    while not _stop.is_set():
        try:
            _collect_metrics()
            _collect_vpn_metrics()
            _check_alerts()
            _maybe_cleanup()
            _reconcile_vpn_passwords()
            _retry_vpn_user_access()
            _retry_panel_access()
            _maybe_refresh_source()
            _maybe_refresh_site_tokens()
        except Exception:
            log.exception("Scheduler error")
        _stop.wait(timeout=POLL_INTERVAL)


def _maybe_refresh_source() -> None:
    """Keep the checkout ADM compares sites against up to date.

    Every site's "up to date / update available" badge is decided by comparing
    its reported revision with this checkout. Nothing else advanced it: the
    refresh endpoint existed but had no caller anywhere — not the UI, not here
    — so the checkout stayed wherever it was last left and the badge could only
    ever read "up to date". Sites then froze silently, which is exactly what a
    drift indicator is supposed to prevent. Found 2026-08-03 with SVR eight
    commits behind and ADM reporting it current.

    Failure is logged and otherwise ignored: a missed fetch means the badge is
    briefly stale, which is the state this whole function exists to shorten,
    and it must never take the metrics loop down with it.
    """
    global _last_source_refresh
    now = time.time()
    if now - _last_source_refresh < SOURCE_REFRESH_INTERVAL:
        return
    _last_source_refresh = now

    from core.vpn_provision import update_source

    revision, error = update_source()
    if error:
        log.warning(f"Source refresh failed: {error}")
    elif revision:
        log.info(f"Source refreshed to {revision['short']}")


def _maybe_refresh_site_tokens() -> None:
    """Renew each site's admin token before it expires.

    The token ADM holds per site is a 90-day Proxima JWT. Nothing renewed
    them: ERG's and SHV's, issued 2026-06-20, expired on 2026-09-18 and from
    then on every user sync to both sites failed with Unauthorized — logged
    per user as a WARNING, shown nowhere. Found two days later by reading the
    journal for an unrelated reason.

    A token within TOKEN_REFRESH_AHEAD of expiry is traded for a fresh one at
    the site's /api/auth/refresh. An already expired one cannot be — by
    design, on the site — so it is reported at ERROR every hour until someone
    re-claims the site, and a Telegram alert goes out — loud is the point,
    and a log line alone has already proven not to be loud enough.
    """
    global _last_token_refresh
    now = time.time()
    if now - _last_token_refresh < TOKEN_REFRESH_INTERVAL:
        return
    _last_token_refresh = now

    from core.auth import encrypt_value
    from core.db import update_vpn_server
    from core.proxima_client import refresh_token, token_expiry, token_state

    # Telegram, not just the log. The failure this guards against went unseen
    # for two days precisely because it was only ever a log line, and the
    # ERROR below would have been read exactly as often.
    alert_config = get_alert_config()
    bot_token = alert_config.get("telegram_bot_token", "")
    chat_id = alert_config.get("telegram_chat_id", "")
    alerting = bool(alert_config.get("enabled")) and bool(bot_token) and bool(chat_id)

    for server in get_all_vpn_servers():
        name = server["name"]
        state = token_state(server)
        if state in ("none", "ok"):
            continue

        exp = token_expiry(server) or 0
        when = time.strftime("%Y-%m-%d", time.localtime(exp))
        # Site-scoped keys; see _maybe_send_alert on why server_id is None.
        expired_alert = f"site_token_expired:{name}"
        failed_alert = f"site_token_refresh_failed:{name}"

        if state == "expired":
            log.error(f"[TOKEN] {name}: site token expired on {when} — "
                      f"every call to this site fails until it is re-claimed")
            if alerting:
                _maybe_send_alert(
                    None, expired_alert, bot_token, chat_id,
                    f"*Site Token Expired*\nSite: {name}\nExpired: {when}\n"
                    f"Every ADM call to this site fails until it is re-claimed.",
                    now)
            continue

        token, error = refresh_token(server)
        if error:
            log.warning(f"[TOKEN] {name}: refresh failed ({error}); "
                        f"token expires {when}")
            if alerting:
                _maybe_send_alert(
                    None, failed_alert, bot_token, chat_id,
                    f"*Site Token Refresh Failed*\nSite: {name}\n"
                    f"Expires: {when}\nError: {error}",
                    now)
            continue

        update_vpn_server(server["id"], {"api_token_enc": encrypt_value(token)})
        log.info(f"[TOKEN] {name}: token refreshed (was expiring {when})")
        if alerting:
            for alert_type in (failed_alert, expired_alert):
                _maybe_send_recovery(
                    None, alert_type, bot_token, chat_id,
                    f"*Site Token Renewed*\nSite: {name}\n"
                    f"Was expiring {when}; a fresh token is stored.")


def _agent_urls(server: dict) -> list[str]:
    """Where to reach this server's agent, best path first.

    The management tunnel comes first when the server is enrolled on it. That
    path is obfuscated, outbound-initiated and carries no public port, so it
    survives the two things that have actually taken agents offline: a stalled
    scanner on the public port, and a route to the public address going dark
    while the box itself is healthy.

    The public address stays as a fallback rather than being dropped. A server
    whose tunnel has not come up yet, or whose tunnel is the thing that broke,
    must not become unmanageable because ADM stopped trying the old way.
    """
    port = server.get("agent_port", 5051)
    urls = []
    if server.get("callhome_ip"):
        urls.append(f"https://{server['callhome_ip']}:{port}")
    if server.get("ip"):
        urls.append(f"https://{server['ip']}:{port}")
    return urls


def _agent_url(server: dict) -> str:
    """The preferred URL. Kept for callers that only need one."""
    urls = _agent_urls(server)
    return urls[0] if urls else f"https://{server.get('ip')}:{server.get('agent_port', 5051)}"


def _agent_headers(server: dict) -> dict:
    headers = {}
    enc_key = server.get("agent_api_key_enc")
    if enc_key:
        api_key = decrypt_value(enc_key)
        if api_key:
            headers["X-API-Key"] = api_key
    return headers


def _poll_server(server: dict) -> dict:
    """Poll a single server's agent for status metrics.

    Tries the management tunnel first and the public address second, so a node
    is only reported offline when *no* path to it works.
    """
    result = {"online": False}
    for url_base in _agent_urls(server):
        if _poll_agent_at(url_base, server, result):
            result["agent_path"] = (
                "tunnel" if url_base.startswith(f"https://{server.get('callhome_ip')}:")
                else "public"
            )
            break
    return result


def _poll_agent_at(url_base: str, server: dict, result: dict) -> bool:
    """Fill *result* from one candidate URL. Returns True when it answered."""
    try:
        url = url_base + "/api/status"
        resp = http_requests.get(
            url, headers=_agent_headers(server), timeout=10, verify=False
        )
        data = resp.json()
        if data.get("ok"):
            status_data = data.get("data", {})
            result["online"] = True
            result["uptime"] = status_data.get("uptime")
            # Agent returns nested objects: disk.used_pct, memory.used_pct
            disk = status_data.get("disk", {})
            if isinstance(disk, dict):
                result["disk_pct"] = disk.get("used_pct")
            memory = status_data.get("memory", {})
            if isinstance(memory, dict):
                result["memory_pct"] = memory.get("used_pct")
            cpu = status_data.get("cpu", {})
            if isinstance(cpu, dict):
                result["cpu_pct"] = cpu.get("used_pct")
            # Cumulative, stored as read — see traffic_since() for why.
            net = status_data.get("network", {})
            if isinstance(net, dict):
                result["rx_bytes"] = net.get("rx_bytes")
                result["tx_bytes"] = net.get("tx_bytes")
            # Count services
            services = status_data.get("services", {})
            if services:
                result["services_ok"] = sum(
                    1 for v in services.values() if v is True or v == "active"
                )
            # Count running docker containers
            containers = status_data.get("docker_containers", [])
            if isinstance(containers, list):
                result["docker_ok"] = sum(
                    1 for c in containers
                    if isinstance(c, dict) and "up" in c.get("status", "").lower()
                )
            return True
    except http_requests.exceptions.RequestException:
        pass
    except Exception:
        log.debug(f"Error polling {server['name']} at {url_base}", exc_info=True)
    return False


def _collect_metrics() -> None:
    """Poll all active servers and store metrics."""
    servers = [s for s in get_all_servers() if s["status"] == "active"]
    if not servers:
        return

    results = {}
    with ThreadPoolExecutor(max_workers=min(len(servers), 5)) as pool:
        futures = {pool.submit(_poll_server, s): s for s in servers}
        for future in as_completed(futures):
            server = futures[future]
            try:
                results[server["id"]] = future.result()
            except Exception:
                results[server["id"]] = {"online": False}

    for server in servers:
        metric = results.get(server["id"], {"online": False})
        insert_metric(server["id"], metric)

    log.info(
        f"Collected metrics for {len(servers)} server(s): "
        + ", ".join(
            f"{s['name']}={'up' if results.get(s['id'], {}).get('online') else 'down'}"
            for s in servers
        )
    )


def _published_profiles(status_data: dict) -> list[dict]:
    """Direct profiles a site advertises, from its /api/status payload.

    The label is taken as-is: Proxima reports the slot's own label, never the
    active key, because that string is what a user sees and it must not change
    when failover rotates the pool.
    """
    slots = status_data.get("slots")
    if not isinstance(slots, dict):
        return []
    profiles = []
    for slot_id, slot in slots.items():
        if not isinstance(slot, dict):
            continue
        profile = slot.get("client_profile") or {}
        if not profile.get("enabled"):
            continue
        health = slot.get("health") or {}
        profiles.append({
            "slot_id": slot_id,
            "label": slot.get("label") or slot_id,
            "description": profile.get("description") or "",
            "enabled": bool(slot.get("enabled", True)),
            "last_ip_ok": health.get("last_ip_ok"),
        })
    return sorted(profiles, key=lambda p: p["slot_id"])


def _poll_vpn_server(server: dict) -> dict:
    """Poll a VPN server (Proxima instance) for system metrics."""
    result = {"online": False}
    enc_token = server.get("api_token_enc")
    if not enc_token:
        return result
    try:
        token = decrypt_value(enc_token)
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        url = server["url"].rstrip("/") + "/api/status"
        resp = http_requests.get(url, headers=headers, timeout=10, verify=False)
        data = resp.json()
        if data.get("ok"):
            result["online"] = True
            system = data.get("data", {}).get("system", {})
            disk = system.get("disk", {})
            if isinstance(disk, dict) and "used_pct" in disk:
                result["disk_pct"] = disk["used_pct"]
            memory = system.get("memory", {})
            if isinstance(memory, dict) and "used_pct" in memory:
                result["memory_pct"] = memory["used_pct"]
            cpu = system.get("cpu", {})
            if isinstance(cpu, dict) and "used_pct" in cpu:
                result["cpu_pct"] = cpu["used_pct"]
            result["profiles"] = _published_profiles(data.get("data", {}))
    except http_requests.exceptions.RequestException:
        pass
    except Exception:
        log.debug(f"Error polling VPN server {server['name']}", exc_info=True)
    return result


def _collect_vpn_metrics() -> None:
    """Poll all VPN servers and store system metrics."""
    servers = get_all_vpn_servers()
    if not servers:
        return

    # Only poll servers that have an API token
    active = [s for s in servers if s.get("api_token_enc")]
    if not active:
        return

    results = {}
    with ThreadPoolExecutor(max_workers=min(len(active), 5)) as pool:
        futures = {pool.submit(_poll_vpn_server, s): s for s in active}
        for future in as_completed(futures):
            server = futures[future]
            try:
                results[server["id"]] = future.result()
            except Exception:
                results[server["id"]] = {"online": False}

    for server in active:
        metric = results.get(server["id"], {"online": False})
        insert_vpn_metric(server["id"], metric)
        # Only refresh from a site that actually answered; a failed poll must
        # not erase profiles an admin is in the middle of granting.
        if metric.get("online") and "profiles" in metric:
            set_server_profiles(server["id"], metric["profiles"])

    log.info(
        f"Collected VPN metrics for {len(active)} server(s): "
        + ", ".join(
            f"{s['name']}={'up' if results.get(s['id'], {}).get('online') else 'down'}"
            for s in active
        )
    )


def _check_alerts() -> None:
    """Check thresholds and send Telegram alerts if needed."""
    config = get_alert_config()
    if not config.get("enabled"):
        return

    bot_token = config.get("telegram_bot_token", "")
    chat_id = config.get("telegram_chat_id", "")
    if not bot_token or not chat_id:
        return

    disk_threshold = config.get("disk_threshold", 90.0)
    memory_threshold = config.get("memory_threshold", 90.0)
    cpu_threshold = config.get("cpu_threshold", 80.0)
    offline_minutes = config.get("offline_minutes", 5)

    servers = [s for s in get_all_servers() if s["status"] == "active"]
    now = time.time()

    for server in servers:
        sid = server["id"]
        name = server["display_name"]

        # A day's worth, not an hour's. The window used to be an hour and the
        # duration was counted in readings, so it could never exceed the number
        # of polls an hour holds: every alert for a server down since yesterday
        # said "~65 minutes", hour after hour, and the number carried no
        # information at all.
        recent = get_metrics(server_id=sid, hours=OFFLINE_LOOKBACK_HOURS)
        if not recent:
            continue

        latest = recent[-1]

        # Check offline
        if not latest.get("online"):
            # Walk back to the last reading that was online. The one after it
            # is when this outage started, so the duration comes from its
            # timestamp rather than from how many rows happen to be in view.
            first_offline = None
            saw_online = False
            for m in reversed(recent):
                if m.get("online"):
                    saw_online = True
                    break
                first_offline = m

            started = (first_offline or {}).get("timestamp")
            offline_duration = (now - started) / 60 if started else 0.0

            if offline_duration >= offline_minutes:
                # Without an online reading in the window the outage predates
                # everything we can see, so say so instead of implying the
                # oldest row is when it began.
                how_long = (f"~{int(offline_duration)} minutes" if saw_online
                            else f"over {OFFLINE_LOOKBACK_HOURS}h")
                _maybe_send_alert(
                    sid, "offline", bot_token, chat_id,
                    f"*Server Offline*\nServer: {name}\n"
                    f"Down for: {how_long}",
                    now,
                )
            continue

        _maybe_send_recovery(
            sid, "offline", bot_token, chat_id,
            f"*Server Recovered*\nServer: {name}\nAgent is responding again",
        )

        _check_metric(sid, name, "disk", "Disk", latest.get("disk_pct"),
                      disk_threshold, bot_token, chat_id, now)
        _check_metric(sid, name, "memory", "Memory", latest.get("memory_pct"),
                      memory_threshold, bot_token, chat_id, now)
        _check_metric(sid, name, "cpu", "CPU", latest.get("cpu_pct"),
                      cpu_threshold, bot_token, chat_id, now)
        _check_traffic(server, bot_token, chat_id, now)


def _check_traffic(server: dict, bot_token: str, chat_id: str, now: float) -> None:
    """Warn before a metered node reaches its allowance.

    Only outbound is counted. On an exit node the billed direction is the one
    carrying the payload — internet to server is inbound and free, server to
    client is outbound and metered — so downloads and video land squarely on
    the cap while inbound stays near zero.

    This exists because nothing counted it. ERG-TR allows 0.5 TB and its
    provider does not bill overage, it cuts the connection: the first symptom
    was going to be an exit node that silently stopped working, with no
    number anywhere to explain it.
    """
    limit_gb = server.get("traffic_limit_gb")
    if not limit_gb or limit_gb <= 0:
        return  # unmetered, nothing to warn about

    start = period_start(server.get("traffic_period_day") or 1, now)
    used = traffic_since(server["id"], start)
    if not used["samples"]:
        return

    pct = used["tx_gb"] / limit_gb * 100
    for level in (90, 70):
        if pct >= level:
            days_left = max(0, int((period_start(
                server.get("traffic_period_day") or 1,
                now + 31 * 86400) - now) / 86400))
            lines = [
                f"*Traffic {level}%*",
                f"Server: {server['display_name']}",
                f"Outbound: {used['tx_gb']:.1f} GB of {limit_gb:.0f} GB ({pct:.0f}%)",
                f"Period resets in ~{days_left} days",
            ]
            if used["counter_resets"]:
                # A reboot lost whatever moved between the last sample before
                # it and the first one after. Say so rather than present an
                # undercount as the figure.
                lines.append("_Counter reset seen — the real figure may be higher._")
            _maybe_send_alert(
                server["id"], f"traffic{level}", bot_token, chat_id,
                "\n".join(lines), now,
            )
            break


def _check_metric(
    server_id: int, name: str, alert_type: str, label: str,
    value: float | None, threshold: float,
    bot_token: str, chat_id: str, now: float,
) -> None:
    """Alert above the threshold, notify recovery once it drops back below it."""
    if value is None:
        return

    if value >= threshold:
        _maybe_send_alert(
            server_id, alert_type, bot_token, chat_id,
            f"*{label} Warning*\nServer: {name}\n"
            f"{label} Usage: {value:.1f}%",
            now,
        )
    elif value < threshold - RECOVERY_MARGIN:
        _maybe_send_recovery(
            server_id, alert_type, bot_token, chat_id,
            f"*{label} Recovered*\nServer: {name}\n"
            f"{label} Usage: {value:.1f}%",
        )


def _maybe_send_alert(
    server_id: int | None, alert_type: str,
    bot_token: str, chat_id: str,
    message: str, now: float,
) -> None:
    """Send alert if cooldown has expired.

    `server_id` is a `servers` row — an exit node. Alerts about a VPN *site*
    pass None and carry the site in `alert_type` instead, because
    `alert_history.server_id` is a foreign key into `servers` and a
    `vpn_servers` id would silently point at an unrelated exit node.
    """
    key = (server_id, alert_type)
    last_sent = _cooldowns.get(key, 0)
    if now - last_sent < COOLDOWN_SECONDS:
        return

    ok, error = send_telegram(bot_token, chat_id, message)
    if ok:
        _cooldowns[key] = now
        _active_alerts.add(key)
        insert_alert(server_id, alert_type, message)
        log.info(f"Alert sent: {alert_type} for server {server_id}")
    else:
        log.error(f"Alert failed: {alert_type} for server {server_id}: {error}")


def _maybe_send_recovery(
    server_id: int | None, alert_type: str,
    bot_token: str, chat_id: str, message: str,
) -> None:
    """Send a one-off recovery notice if this alert was firing.

    Without this an unresolved condition produces one Telegram message per
    cooldown window forever, with no way to tell from Telegram that it ended.
    """
    key = (server_id, alert_type)
    if key not in _active_alerts:
        return

    ok, error = send_telegram(bot_token, chat_id, message)
    if not ok:
        log.error(f"Recovery failed: {alert_type} for server {server_id}: {error}")
        return

    _active_alerts.discard(key)
    _cooldowns.pop(key, None)  # next occurrence alerts immediately
    insert_alert(server_id, f"{alert_type}_recovered", message)
    log.info(f"Recovery sent: {alert_type} for server {server_id}")


def _reconcile_vpn_passwords() -> None:
    """Converge a user's password across the sites they belong to.

    Someone changing their password from the client only changes it on the
    instance their client is talking to. Left alone the sites drift apart,
    which the planned single-login client cannot tolerate. Cheap when there
    is nothing to do — it only writes when two sites disagree.
    """
    try:
        from core.vpn_user_sync import reconcile_passwords
        result = reconcile_passwords()
        if result["propagated"]:
            log.info(f"Propagated {len(result['propagated'])} password change(s)")
    except Exception:
        log.exception("Password reconcile error")


def _retry_vpn_user_access() -> None:
    """Push any VPN user change still waiting on a site.

    Every edit tries to reach its sites at once, so a row is only left
    pending when that push did not get through — most often because the site
    was switched off. Nothing came back to those rows until somebody pressed
    Sync, and for a revocation that means devices that keep carrying traffic
    on a site that has since come back. Does nothing when the queue is empty.
    """
    try:
        from core.db import get_pending_access
        if not get_pending_access():
            return
        from core.vpn_user_sync import sync_pending
        result = sync_pending()
        delivered = sum(len(result[k]) for k in
                        ("created", "adopted", "updated", "recreated", "removed"))
        if delivered or result["failed"]:
            log.info(f"VPN user retry: delivered={delivered} "
                     f"failed={len(result['failed'])} "
                     f"waiting={len(result['deferred'])}")
    except Exception:
        log.exception("VPN user retry error")


def _retry_panel_access() -> None:
    """Push any panel grant or revocation still waiting on a site.

    A site that was down when the change was made would otherwise keep the
    old state until somebody noticed and pressed sync — and for a revocation
    that means a login staying alive. Does nothing when the queue is empty.
    """
    try:
        from core.db import get_pending_admin_access
        if not get_pending_admin_access():
            return
        from core.admin_sync import sync_pending
        result = sync_pending()
        if result["granted"] or result["removed"]:
            log.info(f"Panel access retry: granted={len(result['granted'])} "
                     f"removed={len(result['removed'])} failed={len(result['failed'])}")
    except Exception:
        log.exception("Panel access retry error")


def _maybe_cleanup() -> None:
    """Delete old metrics once per day."""
    global _last_cleanup
    now = time.time()
    if now - _last_cleanup < CLEANUP_INTERVAL:
        return
    _last_cleanup = now
    deleted = cleanup_old_metrics(days=30)
    if deleted > 0:
        log.info(f"Cleaned up {deleted} old metric(s)")
