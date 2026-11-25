"""Remote MySQL: let named hosts reach a database from outside localhost
(cPanel's "Remote MySQL"). Each allowed host gets a user@host account sharing
the database user's password; MariaDB is switched to listen externally while
any remote host exists."""
from .. import db, validators
from ..system import mysql
from ..system.runner import CommandError
from . import OpError, get_site, log


def hosts(db_id: int):
    return db.all("SELECT * FROM db_remote_hosts WHERE db_id = ? ORDER BY host", db_id)


def _database(site_id: int, db_id: int):
    row = db.one("SELECT * FROM databases WHERE id = ? AND site_id = ?", db_id, site_id)
    if not row:
        raise OpError("Database not found")
    return row


def _remote_count() -> int:
    return db.one("SELECT COUNT(*) AS n FROM db_remote_hosts")["n"]


def _sync_listening(actor: str) -> None:
    """Keep MariaDB's external-listening drop-in in step with whether any remote host exists."""
    want = "1" if _remote_count() else "0"
    if db.get_setting("mysql_remote", "0") == want:
        return
    mysql.set_remote_listening(want == "1")
    db.set_setting("mysql_remote", want)
    db.log(f"Remote database access {'enabled' if want == '1' else 'disabled'} "
           f"(MariaDB now listens {'on all interfaces' if want == '1' else 'on localhost only'})", actor)


def add_host(site_id: int, db_id: int, host: str, actor: str) -> None:
    site = get_site(site_id)
    row = _database(site_id, db_id)
    host = validators.mysql_host(host)
    if db.one("SELECT 1 FROM db_remote_hosts WHERE db_id = ? AND host = ?", db_id, host):
        raise OpError(f"{host} is already allowed for this database")
    try:
        mysql.add_host(row["name"], row["username"], host, mysql.native_hash(row["username"]))
    except (CommandError, ValueError) as e:
        raise OpError(f"Could not grant remote access: {e}")
    db.execute("INSERT INTO db_remote_hosts (db_id, host) VALUES (?, ?)", db_id, host)
    _sync_listening(actor)
    db.log(f"{site['domain']}: database {row['name']} now reachable from {host}", actor)


def remove_host(site_id: int, db_id: int, host_id: int, actor: str) -> None:
    site = get_site(site_id)
    row = _database(site_id, db_id)
    h = db.one("SELECT * FROM db_remote_hosts WHERE id = ? AND db_id = ?", host_id, db_id)
    if not h:
        raise OpError("Host not found")
    # The same user@host may serve another of this user's databases; only drop the account
    # when no other allowed host row keeps it.
    others = db.one("""SELECT 1 FROM db_remote_hosts rh JOIN databases d ON d.id = rh.db_id
                       WHERE rh.host = ? AND d.username = ? AND rh.id != ?""",
                    h["host"], row["username"], host_id)
    try:
        mysql.revoke_host(row["name"], row["username"], h["host"], drop_user=not others)
    except CommandError as e:
        raise OpError(f"Could not revoke remote access: {e}")
    db.execute("DELETE FROM db_remote_hosts WHERE id = ?", host_id)
    _sync_listening(actor)
    db.log(f"{site['domain']}: database {row['name']} no longer reachable from {h['host']}", actor)


def cleanup_database(db_row, actor: str = "system") -> None:
    """Drop a database's remote-host accounts before the database itself is removed.
    Called from delete_database / delete_site; rows then cascade with the database."""
    rows = db.all("SELECT * FROM db_remote_hosts WHERE db_id = ?", db_row["id"])
    for h in rows:
        others = db.one("""SELECT 1 FROM db_remote_hosts rh JOIN databases d ON d.id = rh.db_id
                           WHERE rh.host = ? AND d.username = ? AND rh.id != ?""",
                        h["host"], db_row["username"], h["id"])
        try:
            mysql.revoke_host(db_row["name"], db_row["username"], h["host"], drop_user=not others)
        except CommandError:
            log.exception("revoking remote host during cleanup failed")
    if rows:
        db.execute("DELETE FROM db_remote_hosts WHERE db_id = ?", db_row["id"])
        _sync_listening(actor)
