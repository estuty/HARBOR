"""Database editor: opens Adminer signed in to one database.

"Open" creates a temporary MySQL user that can only use that database, writes
its credentials to a one-time token file readable by the editor's own Linux
user, and sends the browser to /dbadmin/?harbor=TOKEN. The editor's wrapper
(harbor/dbadmin/index.php) exchanges the token for a login and deletes it, so
the password never reaches the browser. Temporary users are dropped when they
expire. nginx only lets signed-in panel users reach /dbadmin/ at all."""
import json
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone

from .. import config, db
from ..system import mysql
from ..system.runner import chown
from . import OpError, get_site

log = logging.getLogger("harbor")
ADMINER = config.p("/opt/harbor/adminer/adminer.php")
TOKEN_DIR = config.p("/var/lib/harbor-dbadmin/tokens")
EDITOR_USER = "harbor-dbadmin"
LIFETIME = timedelta(hours=2)
TOKEN_TTL = 120  # seconds the browser has to use the link
USER_PREFIX = "hbr_ed_"


def available() -> bool:
    return config.DRY_RUN or ADMINER.exists()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _fmt(t: datetime) -> str:
    return t.strftime("%Y-%m-%d %H:%M:%S")


def open_editor(site_id: int, db_id: int, actor: str) -> str:
    """Returns the one-time token for /dbadmin/?harbor=TOKEN."""
    site = get_site(site_id)
    row = db.one("SELECT name FROM databases WHERE id = ? AND site_id = ?", db_id, site_id)
    if not row:
        raise OpError("Database not found")
    if not available():
        raise OpError("The database editor isn't installed on this server yet. "
                      "Run: sudo bash /opt/harbor/source/install.sh")
    cleanup_expired()
    user = USER_PREFIX + secrets.token_hex(6)
    password = mysql.generate_password(32)
    mysql.create_user(user, password)
    try:
        mysql.grant(user, row["name"])
        token = secrets.token_urlsafe(32)
        _write_token(token, {"username": user, "password": password, "db": row["name"],
                             "expires": int(_now().timestamp()) + TOKEN_TTL})
    except Exception:
        mysql.drop_user(user)
        raise
    db.execute("INSERT INTO db_editor_sessions (mysql_user, db_name, site_id, actor, expires_at) VALUES (?, ?, ?, ?, ?)",
               user, row["name"], site_id, actor, _fmt(_now() + LIFETIME))
    db.log(f"{site['domain']}: opened database {row['name']} in the editor", actor)
    return token


def _write_token(token: str, data: dict) -> None:
    TOKEN_DIR.mkdir(parents=True, exist_ok=True)
    path = TOKEN_DIR / f"{token}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    chown(path, "root", EDITOR_USER)


def cleanup_expired() -> int:
    """Drop temporary users whose time is up, and stale token files."""
    removed = 0
    for row in db.all("SELECT id, mysql_user FROM db_editor_sessions WHERE expires_at <= ?", _fmt(_now())):
        try:
            mysql.drop_user(row["mysql_user"])
            db.execute("DELETE FROM db_editor_sessions WHERE id = ?", row["id"])
            removed += 1
        except Exception:
            log.exception("could not drop editor user %s", row["mysql_user"])
    if TOKEN_DIR.exists():
        cutoff = _now().timestamp() - TOKEN_TTL * 2
        for f in TOKEN_DIR.glob("*.json"):
            try:
                if f.stat().st_mtime < cutoff:
                    f.unlink()
            except OSError:
                pass
    return removed


def close_for_database(db_name: str) -> None:
    """When a database is deleted, its editor users go too."""
    for row in db.all("SELECT id, mysql_user FROM db_editor_sessions WHERE db_name = ?", db_name):
        try:
            mysql.drop_user(row["mysql_user"])
        finally:
            db.execute("DELETE FROM db_editor_sessions WHERE id = ?", row["id"])
