"""Authentication and authorisation.

- Passwords: scrypt.
- Roles: 'admin' sees and manages everything; 'user' (team user) only sees the
  sites assigned to them and can't create/delete sites or touch server settings.
- API tokens: random 40-byte secrets, stored as SHA-256 hashes; a token acts as
  the user who created it.
"""
import base64
import hashlib
import hmac
import secrets
import subprocess
import time
from collections import defaultdict

from . import config, db


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt_b64, digest_b64 = stored.split("$")
        salt, expected = base64.b64decode(salt_b64), base64.b64decode(digest_b64)
    except ValueError:
        return False
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return hmac.compare_digest(digest, expected)


def sha512_crypt(password: str) -> str:
    """$6$ crypt hash, understood by nginx basic auth and Dovecot.
    Computed with `openssl passwd` (read-only, safe to run even in dry-run)."""
    out = subprocess.run(["openssl", "passwd", "-6", "-stdin"], input=password, capture_output=True,
                         text=True, check=True)
    return out.stdout.strip()


def secret_key() -> str:
    f = config.SECRET_FILE
    if not f.exists():
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(secrets.token_urlsafe(48))
        f.chmod(0o600)
    return f.read_text().strip()


# ---------- users ----------

def create_user(username: str, password: str, role: str = "admin") -> int:
    h = hash_password(password)
    row = db.one("SELECT id FROM users WHERE username = ?", username)
    if row:
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?", h, row["id"])
        return row["id"]
    return db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", username, h, role)


create_admin = create_user  # backwards-compatible name used by the CLI


def authenticate(username: str, password: str):
    row = db.one("SELECT * FROM users WHERE username = ?", username)
    if not row:
        hash_password(password)  # equalise timing
        return None
    return row if verify_password(password, row["password_hash"]) else None


def site_ids_for(user_id: int) -> set[int]:
    return {r["site_id"] for r in db.all("SELECT site_id FROM user_sites WHERE user_id = ?", user_id)}


def can_access_site(principal: dict, site_id: int) -> bool:
    if principal.get("role") == "admin":
        return True
    return site_id in site_ids_for(principal["uid"])


# ---------- API tokens ----------

def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_token(user_id: int, name: str) -> str:
    token = "hbr_" + secrets.token_urlsafe(40)
    db.execute("INSERT INTO api_tokens (user_id, name, prefix, token_hash) VALUES (?, ?, ?, ?)",
               user_id, name, token[:10], _token_hash(token))
    return token


def principal_from_token(token: str):
    row = db.one("""SELECT t.id tid, u.id uid, u.username, u.role FROM api_tokens t
                    JOIN users u ON u.id = t.user_id WHERE t.token_hash = ?""", _token_hash(token))
    if not row:
        return None
    db.execute("UPDATE api_tokens SET last_used = CURRENT_TIMESTAMP WHERE id = ?", row["tid"])
    return {"uid": row["uid"], "user": row["username"], "role": row["role"]}


# ---------- CSRF + throttling ----------

def csrf_token(session: dict) -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def check_csrf(session: dict, token: str | None) -> bool:
    expected = session.get("csrf")
    return bool(expected and token and hmac.compare_digest(expected, token))


_attempts: dict[str, list[float]] = defaultdict(list)
WINDOW, MAX_ATTEMPTS = 900, 8


def throttled(key: str) -> bool:
    now = time.time()
    _attempts[key] = [t for t in _attempts[key] if now - t < WINDOW]
    return len(_attempts[key]) >= MAX_ATTEMPTS


def record_failure(key: str) -> None:
    _attempts[key].append(time.time())


def clear_failures(key: str) -> None:
    _attempts.pop(key, None)


# ---------- two-factor (TOTP, RFC 6238) ----------

import struct  # noqa: E402

TOTP_STEP, TOTP_DIGITS = 30, 6


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 10 ** TOTP_DIGITS
    return str(code).zfill(TOTP_DIGITS)


def totp_now(secret: str, at: float | None = None) -> str:
    return _hotp(secret, int((at or time.time()) // TOTP_STEP))


def totp_match(secret: str, code: str, last_counter: int = 0, at: float | None = None) -> int | None:
    """Return the matching time step (±1 for clock drift), or None. Steps at or
    before `last_counter` are refused so a code can't be replayed."""
    code = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(code) != TOTP_DIGITS:
        return None
    now = int((at or time.time()) // TOTP_STEP)
    for c in (now - 1, now, now + 1):
        if c > last_counter and hmac.compare_digest(_hotp(secret, c), code):
            return c
    return None


def totp_uri(secret: str, username: str, issuer: str) -> str:
    from urllib.parse import quote
    label = quote(f"{issuer}:{username}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"


def qr_svg_data_uri(text: str) -> str:
    import segno
    return segno.make(text, error="m").svg_data_uri(scale=5, dark="#16242c", light="#ffffff", border=2)


def new_recovery_codes(user_id: int, n: int = 8) -> list[str]:
    codes = ["-".join(secrets.token_hex(2) for _ in range(3)) for _ in range(n)]
    with db.tx() as c:
        c.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
        c.executemany("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)",
                      [(user_id, hashlib.sha256(code.encode()).hexdigest()) for code in codes])
    return codes


def use_recovery_code(user_id: int, code: str) -> bool:
    code = (code or "").strip().lower()
    h = hashlib.sha256(code.encode()).hexdigest()
    row = db.one("SELECT id FROM recovery_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL", user_id, h)
    if not row:
        return False
    db.execute("UPDATE recovery_codes SET used_at = CURRENT_TIMESTAMP WHERE id = ?", row["id"])
    return True


def verify_second_factor(user, code: str) -> bool:
    """TOTP code or a one-time recovery code."""
    step = totp_match(user["totp_secret"], code, user["totp_last"])
    if step is not None:
        db.execute("UPDATE users SET totp_last = ? WHERE id = ?", step, user["id"])
        return True
    return use_recovery_code(user["id"], code)


def disable_2fa(user_id: int) -> None:
    db.execute("UPDATE users SET totp_enabled = 0, totp_secret = NULL, totp_last = 0 WHERE id = ?", user_id)
    db.execute("DELETE FROM recovery_codes WHERE user_id = ?", user_id)


# ---------- failed-login log (read by fail2ban) ----------

def log_auth_failure(what: str, username: str, ip: str) -> None:
    import re as _re
    safe_user = _re.sub(r"[^A-Za-z0-9_.@\-]", "?", username or "")[:64]
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} harbor: failed {what} for user '{safe_user}' from {ip}\n"
    try:
        config.AUTH_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(config.AUTH_LOG, "a") as f:
            f.write(line)
    except OSError:
        pass
