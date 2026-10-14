"""MySQL / MariaDB management through the `mysql` client running as root
(unix-socket authentication, so no root password is stored anywhere).

Database and user names are validated against a strict pattern and passwords
are either generated or validated to exclude quotes, so values interpolated
into SQL cannot break out of their literals."""
import re
import secrets
import string

from .runner import run

NAME_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")       # database names (cPanel imports keep theirs)
USER_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,80}$")       # MariaDB allows up to 80 characters
NATIVE_HASH_RE = re.compile(r"^\*[0-9A-F]{40}$")


def _check(name: str) -> str:
    if not NAME_RE.match(name or ""):
        raise ValueError(f"Unsafe identifier: {name!r}")
    return name


def _check_user(name: str) -> str:
    if not USER_RE.match(name or ""):
        raise ValueError(f"Unsafe user name: {name!r}")
    return name


def generate_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _sql(statements: str) -> str:
    return run(["mysql", "--batch", "--skip-column-names"], input=statements)


def create(db: str, user: str, password: str) -> None:
    db, user = _check(db), _check_user(user)
    _sql(
        f"CREATE DATABASE `{db}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n"
        f"CREATE USER '{user}'@'localhost' IDENTIFIED BY '{password}';\n"
        f"GRANT ALL PRIVILEGES ON `{db}`.* TO '{user}'@'localhost';\n"
        "FLUSH PRIVILEGES;\n"
    )


def set_password(user: str, password: str) -> None:
    _sql(f"ALTER USER '{_check_user(user)}'@'localhost' IDENTIFIED BY '{password}';\nFLUSH PRIVILEGES;\n")


def drop(db: str, user: str | None) -> None:
    """Drop a database, and its user when given (pass None if other databases still use it)."""
    sql = f"DROP DATABASE IF EXISTS `{_check(db)}`;\n"
    if user:
        sql += f"DROP USER IF EXISTS '{_check_user(user)}'@'localhost';\n"
    _sql(sql + "FLUSH PRIVILEGES;\n")


# ---------- used by the cPanel importer ----------

def exists(db: str) -> bool:
    return bool(_sql(f"SHOW DATABASES LIKE '{_check(db).replace('_', chr(92) + '_')}';\n").strip())


def user_exists(user: str) -> bool:
    return bool(_sql(f"SELECT 1 FROM mysql.user WHERE User = '{_check_user(user)}' AND Host = 'localhost';\n").strip())


def create_db(db: str) -> None:
    _sql(f"CREATE DATABASE `{_check(db)}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n")


def create_user_with_hash(user: str, native_hash: str) -> None:
    """Recreate a user with its existing mysql_native_password hash, so the
    application's saved password keeps working."""
    if not NATIVE_HASH_RE.match(native_hash or ""):
        raise ValueError("Unsupported password hash")
    _sql(f"CREATE USER '{_check_user(user)}'@'localhost' IDENTIFIED BY PASSWORD '{native_hash}';\n")


def create_user(user: str, password: str) -> None:
    _sql(f"CREATE USER '{_check_user(user)}'@'localhost' IDENTIFIED BY '{password}';\n")


def grant(user: str, db: str) -> None:
    _sql(f"GRANT ALL PRIVILEGES ON `{_check(db)}`.* TO '{_check_user(user)}'@'localhost';\nFLUSH PRIVILEGES;\n")


def import_dump(db: str, path) -> None:
    from .runner import run_from_file
    run_from_file(["mysql", "--default-character-set=utf8mb4", _check(db)], path)


def sizes(names: list[str]) -> dict[str, int]:
    names = [_check(n) for n in names]
    if not names:
        return {}
    in_list = ",".join(f"'{n}'" for n in names)
    out = _sql(
        "SELECT table_schema, COALESCE(SUM(data_length + index_length), 0) "
        f"FROM information_schema.tables WHERE table_schema IN ({in_list}) GROUP BY table_schema;\n"
    )
    result = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and parts[1].isdigit():
            result[parts[0]] = int(parts[1])
    return result


def dump_cmd(db: str) -> list[str]:
    return ["mysqldump", "--single-transaction", "--routines", "--triggers", _check(db)]
