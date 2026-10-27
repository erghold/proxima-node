"""Authentication: password hashing, JWT, Fernet encryption, rate limiting."""

import base64
import hashlib
import os
import secrets
import threading
import time

import jwt
from cryptography.fernet import Fernet, InvalidToken
from werkzeug.security import check_password_hash, generate_password_hash

from core.config import JWT_SECRET_PATH

TOKEN_EXPIRY_DAYS = 90

# ── JWT secret management ────────────────────────────────────────────────

_jwt_secret: str | None = None
_jwt_lock = threading.Lock()


def get_jwt_secret() -> str:
    """Return JWT secret, creating one if it doesn't exist."""
    global _jwt_secret
    if _jwt_secret is not None:
        return _jwt_secret
    with _jwt_lock:
        if _jwt_secret is not None:
            return _jwt_secret
        if os.path.exists(JWT_SECRET_PATH):
            with open(JWT_SECRET_PATH, "r") as f:
                _jwt_secret = f.read().strip()
        else:
            _jwt_secret = secrets.token_hex(32)
            with open(JWT_SECRET_PATH, "w") as f:
                f.write(_jwt_secret)
            os.chmod(JWT_SECRET_PATH, 0o600)
        return _jwt_secret


# ── Password hashing ────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return generate_password_hash(password, method="pbkdf2:sha256")


def verify_password(password: str, password_hash: str) -> bool:
    return check_password_hash(password_hash, password)


# ── JWT tokens ───────────────────────────────────────────────────────────

def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + TOKEN_EXPIRY_DAYS * 86400,
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm="HS256")


def verify_token(token: str) -> dict | None:
    """Return {"username": ...} if valid, else None."""
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=["HS256"])
        username = payload.get("sub")
        if not username:
            return None
        return {"username": username}
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


# ── Fernet encryption (for server credentials) ──────────────────────────

def _get_fernet() -> Fernet:
    """Derive a Fernet key from the JWT secret."""
    key = hashlib.sha256(get_jwt_secret().encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_value(plaintext: str) -> str:
    """Encrypt a string using Fernet."""
    return _get_fernet().encrypt(plaintext.encode()).decode("ascii")


def decrypt_value(ciphertext: str) -> str | None:
    """Decrypt a string. Returns None if decryption fails."""
    try:
        return _get_fernet().decrypt(ciphertext.encode()).decode("utf-8")
    except (InvalidToken, Exception):
        return None


# ── Login rate limiting ──────────────────────────────────────────────────

_rate_lock = threading.Lock()
_fail_tracker: dict[str, list[float]] = {}
RATE_WINDOW = 300          # 5-minute sliding window
MAX_ATTEMPTS = 10          # max failures per window for a single identity
MAX_ATTEMPTS_PER_IP = 100  # coarse backstop for one source address
LOCKOUT_SECONDS = 300


def check_rate_limit(key: str, max_attempts: int = MAX_ATTEMPTS) -> int | None:
    """Check if a key is rate-limited. Returns seconds remaining if locked out.

    The key is whatever identity failures were recorded under — a bare
    address, or "ip|username" for the per-identity tier. Counting only by
    address is wrong for endpoints a whole site reaches through one NAT:
    one person's typo would lock out every colleague behind it.
    """
    now = time.time()
    with _rate_lock:
        timestamps = _fail_tracker.get(key, [])
        timestamps = [t for t in timestamps if now - t < RATE_WINDOW + LOCKOUT_SECONDS]
        if timestamps:
            _fail_tracker[key] = timestamps
        else:
            _fail_tracker.pop(key, None)
        recent = [t for t in timestamps if now - t < RATE_WINDOW]
        if len(recent) >= max_attempts:
            last_fail = max(recent)
            remaining = int(LOCKOUT_SECONDS - (now - last_fail))
            return max(remaining, 1)
    return None


def record_login_failure(*keys: str) -> None:
    now = time.time()
    with _rate_lock:
        for key in keys:
            _fail_tracker.setdefault(key, []).append(now)


def clear_login_failures(*keys: str) -> None:
    with _rate_lock:
        for key in keys:
            _fail_tracker.pop(key, None)
