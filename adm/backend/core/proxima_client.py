"""HTTP transport to Proxima instances.

Shared by the VPN-server proxy, the central user import and the user sync.
Every call is authenticated with the per-server admin token stored encrypted
in `vpn_servers.api_token_enc`.
"""

import base64
import ipaddress
import json
import logging
import threading
import time
import uuid
from urllib.parse import urlsplit, urlunsplit

import requests

from core.auth import decrypt_value

log = logging.getLogger("adm.proxima_client")

DEFAULT_TIMEOUT = 15

# For probes a human is waiting on, split the budget: a short connect timeout
# and a longer read one. A powered-off site does not refuse the connection, it
# simply never answers, so a single scalar timeout is spent in full on the
# connect — and because the dashboard cannot render until every instance has
# answered, its load time became the worst site's timeout. Two seconds is two
# orders of magnitude above the real RTT to any of our sites (Moscow-to-Moscow
# is ~5 ms, the interconnect ~6 ms), so this cannot cost a reachable server its
# place in the list. The read half stays generous: an instance that is slow to
# answer is still worth waiting for.
PROBE_TIMEOUT: tuple[int, int] = (2, 8)

# The same split for writes. A push may legitimately take a while on the site
# (creating a user rewrites its WireGuard config), so the read half is long;
# the connect half is what a dead site costs, and it is paid once per run —
# see SiteGate. Wider than the probe's: SHV is reached over its public name
# and took 1.1 s to connect when measured (2026-09-29), and five seconds
# leaves room for two SYN retransmissions on a lossy line. A false "down"
# here delays a change by a scheduler round; a probe's only greys out a card.
PUSH_TIMEOUT: tuple[int, int] = (5, 30)

# What call() reports when the site itself did not answer, as opposed to
# answering with an error. Only these two say anything about the site.
UNREACHABLE = "Cannot reach Proxima instance"
TIMED_OUT = "Request timed out"

# How long a site that did not answer is left alone. Editing one user issues
# several requests in a row, each with its own push; without a memory every
# one of them would wait out the connect timeout on the same dead site.
DOWN_MEMORY = 60

# TLS is verified. Every Proxima instance is reached either over loopback
# (plain http, where this is a no-op) or over a public HTTPS endpoint with a
# real certificate. A site with a self-signed certificate would fail loudly
# here — which is the intent; carrying admin tokens and password hashes over
# an unverified channel is not an acceptable default.
VERIFY_TLS = True


# Proxima admin tokens are JWTs that expire (TOKEN_EXPIRY_DAYS on the site,
# 90 days). ADM stores one per site and replays it; until 2026-09-20 nothing
# renewed them, so ERG's and SHV's died on 2026-09-18 and every user sync
# failed with 401 — visible only in the journal. The scheduler now refreshes a
# token this far ahead of its expiry, and the UI names an expired one.
TOKEN_REFRESH_AHEAD = 30 * 86400


def token_expiry(server: dict) -> int | None:
    """Unix expiry of the stored site token, read from the JWT payload.

    Not verified — ADM does not hold the site's secret and does not need to:
    this decides *when to refresh*, and the site still judges validity.
    """
    enc_token = server.get("api_token_enc")
    if not enc_token:
        return None
    token = decrypt_value(enc_token)
    if not token:
        return None
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        exp = json.loads(base64.urlsafe_b64decode(payload)).get("exp")
        return int(exp) if exp else None
    except Exception:  # noqa: BLE001 — an unreadable token is simply "unknown"
        return None


def token_state(server: dict) -> str:
    """'none', 'expired', 'expiring' (within TOKEN_REFRESH_AHEAD) or 'ok'."""
    if not server.get("api_token_enc"):
        return "none"
    exp = token_expiry(server)
    if exp is None:
        return "ok"  # a token we cannot read is left to the site to judge
    now = time.time()
    if exp <= now:
        return "expired"
    if exp - now < TOKEN_REFRESH_AHEAD:
        return "expiring"
    return "ok"


def refresh_token(server: dict) -> tuple[str | None, str | None]:
    """Trade the stored (still valid) token for a fresh one. Returns (token, error)."""
    data, error = call(server, "POST", "/api/auth/refresh")
    if error:
        return None, error
    token = (data or {}).get("token") if isinstance(data, dict) else None
    if not token:
        return None, "No token in refresh response"
    return token, None


def auth_headers(server: dict) -> dict:
    """Bearer header for a Proxima instance, empty if no token is stored."""
    enc_token = server.get("api_token_enc")
    if not enc_token:
        return {}
    token = decrypt_value(enc_token)
    return {"Authorization": f"Bearer {token}"} if token else {}


def _pool_management_url(server: dict) -> str:
    """Select once from this registered site's configuration, never after a failure."""
    def parse(value):
        if (not isinstance(value, str) or not value or any(ord(c) <= 32 for c in value)
                or any(c in value for c in ("\\", "?", "#"))):
            raise ValueError("Untrusted credential transport")
        parsed = urlsplit(value)
        if (not parsed.hostname or parsed.username is not None or parsed.password is not None
                or parsed.scheme not in ("http", "https")):
            raise ValueError("Untrusted credential transport")
        _ = parsed.port  # Reject malformed/out-of-range ports before sending credentials.
        return parsed

    parsed = parse(server.get("url"))
    try:
        loopback = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        loopback = parsed.hostname == "localhost"
    if parsed.scheme == "http" and not loopback:
        parsed = parse(server.get("public_url"))
        if parsed.scheme != "https":
            raise ValueError("Untrusted credential transport")
    if parsed.hostname == "localhost":
        port = f":{parsed.port}" if parsed.port is not None else ""
        parsed = parsed._replace(netloc=f"127.0.0.1{port}")
    return urlunsplit(parsed).rstrip("/")


def request(server: dict, method: str, path: str, body: dict | None = None,
            timeout: int | tuple[int, int] = DEFAULT_TIMEOUT, *,
            credential_bootstrap: bool = False, management_write: bool = False) -> requests.Response:
    """Forward a request to a Proxima instance. Returns the raw response."""
    if credential_bootstrap or management_write:
        # Only the new pool flows select this stricter registered transport.
        attachment_id = path.removeprefix("/api/vpn/pool-attachments/")
        valid_operation = (credential_bootstrap and not management_write and method == "POST" and path == "/api/vpn/auth/login") or (
            management_write and not credential_bootstrap and method == "PUT" and path.startswith("/api/vpn/pool-attachments/")
            and str(uuid.UUID(attachment_id)) == attachment_id)
        if not valid_operation:
            raise ValueError("Untrusted credential transport")
        url = f"{_pool_management_url(server)}{path}"
        # Loopback includes already-established management tunnels; never create one.
        # Login needs no admin token, and a redirect must never replay the password.
        if credential_bootstrap:
            return requests.post(url, json=body, headers={}, timeout=timeout,
                                 verify=True, allow_redirects=False)
        headers = auth_headers(server)
        if not headers:
            raise ValueError("Missing management credential")
        return requests.put(url, json=body, headers=headers, timeout=timeout,
                            verify=True, allow_redirects=False)

    url = f"{server['url'].rstrip('/')}{path}"
    headers = auth_headers(server)

    if method == "GET":
        return requests.get(url, headers=headers, timeout=timeout, verify=VERIFY_TLS)
    if method == "POST":
        return requests.post(url, json=body, headers=headers, timeout=timeout, verify=VERIFY_TLS)
    if method == "PUT":
        return requests.put(url, json=body, headers=headers, timeout=timeout, verify=VERIFY_TLS)
    if method == "DELETE":
        return requests.delete(url, headers=headers, timeout=timeout, verify=VERIFY_TLS)
    raise ValueError(f"Unsupported method: {method}")


def call(server: dict, method: str, path: str, body: dict | None = None,
         timeout: int | tuple[int, int] = DEFAULT_TIMEOUT) -> tuple[object | None, str | None]:
    """Call a Proxima endpoint and unwrap its {ok, data} envelope.

    Returns (data, None) on success or (None, error_message) on any failure —
    transport, HTTP status or application-level error.
    """
    if not server.get("api_token_enc"):
        return None, "No API token configured"

    try:
        resp = request(server, method, path, body=body, timeout=timeout)
    except requests.exceptions.ConnectionError:
        return None, UNREACHABLE
    except requests.exceptions.Timeout:
        return None, TIMED_OUT
    except Exception as e:  # noqa: BLE001 — surfaced to the operator as text
        return None, str(e)

    try:
        payload = resp.json()
    except ValueError:
        return None, f"HTTP {resp.status_code}: non-JSON response"

    if not payload.get("ok"):
        return None, payload.get("error") or f"HTTP {resp.status_code}"

    return payload.get("data"), None


class SiteUnreachable(Exception):
    """The site did not answer, now or a moment ago."""


_down_lock = threading.Lock()
_recently_down: dict[int, tuple[float, str]] = {}


class SiteGate:
    """Remembers which sites did not answer, so nobody waits on them twice.

    A sync run walks its rows one by one, and every edit starts a run. While
    KLM was powered down (2026-09-29) each request of an edit spent 30 s
    failing to connect to it and came back marked failed — five requests,
    two and a half minutes, a red message each time — although the other
    sites had been updated within a second. With more than a couple of rows
    queued for the dead site the request would also have outlived the
    reverse proxy (90 s).

    The first call that gets no answer closes the gate for that site; the
    rest of its rows are set aside without touching the network. The memory
    outlives the run for DOWN_MEMORY seconds. `fresh=True` ignores what was
    remembered earlier — for a sync the operator asked for by hand, which
    should find out for itself whether the site is back.
    """

    def __init__(self, fresh: bool = False):
        self._fresh = fresh
        self._down: dict[int, str] = {}

    def down_reason(self, server: dict) -> str | None:
        """Why this site is being skipped, or None if it is not."""
        sid = server["id"]
        if sid in self._down:
            return self._down[sid]
        if self._fresh:
            return None
        with _down_lock:
            seen = _recently_down.get(sid)
            if not seen:
                return None
            if time.time() - seen[0] > DOWN_MEMORY:
                del _recently_down[sid]
                return None
        self._down[sid] = seen[1]
        return seen[1]

    def is_down(self, server: dict) -> bool:
        return self.down_reason(server) is not None

    def down_ids(self) -> list[int]:
        return list(self._down)

    def _mark_down(self, server: dict, reason: str) -> None:
        self._down[server["id"]] = reason
        with _down_lock:
            _recently_down[server["id"]] = (time.time(), reason)
        log.warning(f"[GATE] {server.get('name', server['id'])} did not answer "
                    f"({reason}) — its remaining changes wait for the next run")

    def _mark_up(self, server: dict) -> None:
        with _down_lock:
            _recently_down.pop(server["id"], None)

    def call(self, server: dict, method: str, path: str, body: dict | None = None,
             timeout: int | tuple[int, int] = PUSH_TIMEOUT) -> tuple[object | None, str | None]:
        """call(), except that a site already known to be down costs nothing."""
        reason = self.down_reason(server)
        if reason:
            return None, reason
        data, error = call(server, method, path, body=body, timeout=timeout)
        if error in (UNREACHABLE, TIMED_OUT):
            self._mark_down(server, error)
        elif server.get("api_token_enc"):
            self._mark_up(server)
        return data, error

    def request(self, server: dict, method: str, path: str, body: dict | None = None,
                timeout: int | tuple[int, int] = PUSH_TIMEOUT) -> requests.Response:
        """request(), raising SiteUnreachable instead of waiting on a dead site."""
        reason = self.down_reason(server)
        if reason:
            raise SiteUnreachable(reason)
        try:
            resp = request(server, method, path, body=body, timeout=timeout)
        except requests.exceptions.ConnectionError:
            self._mark_down(server, UNREACHABLE)
            raise SiteUnreachable(UNREACHABLE) from None
        except requests.exceptions.Timeout:
            self._mark_down(server, TIMED_OUT)
            raise SiteUnreachable(TIMED_OUT) from None
        self._mark_up(server)
        return resp


def waiting_note(reason: str) -> str:
    """What a row is told when its site is down: not an error, a wait."""
    return f"Site unreachable, change is waiting: {reason}"
