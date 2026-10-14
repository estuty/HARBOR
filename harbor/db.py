"""Panel state in SQLite. Schema changes are applied by numbered migrations,
so upgrading an existing install keeps all data."""
import json
import sqlite3
from contextlib import contextmanager

from . import config

MIGRATIONS = [
    # 1: original schema
    """
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS sites (
        id INTEGER PRIMARY KEY, domain TEXT UNIQUE NOT NULL, sysuser TEXT UNIQUE,
        php_version TEXT NOT NULL, include_www INTEGER NOT NULL DEFAULT 1,
        ssl INTEGER NOT NULL DEFAULT 0, sftp_enabled INTEGER NOT NULL DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS databases (
        id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        name TEXT UNIQUE NOT NULL, username TEXT UNIQUE NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS cron_jobs (
        id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        schedule TEXT NOT NULL, command TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS backups (
        id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        filename TEXT, size INTEGER DEFAULT 0, status TEXT NOT NULL DEFAULT 'running', error TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS activity (
        id INTEGER PRIMARY KEY, ts TEXT DEFAULT CURRENT_TIMESTAMP, actor TEXT, message TEXT NOT NULL,
        level TEXT NOT NULL DEFAULT 'info');
    """,
    # 2: users with roles, per-site settings, server settings, quick-group tables
    """
    CREATE TABLE users (
        id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'admin', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    INSERT INTO users (username, password_hash, role, created_at)
        SELECT username, password_hash, 'admin', created_at FROM admins;
    DROP TABLE admins;
    CREATE TABLE user_sites (
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        PRIMARY KEY (user_id, site_id));
    CREATE TABLE api_tokens (
        id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL, prefix TEXT NOT NULL, token_hash TEXT UNIQUE NOT NULL,
        last_used TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    ALTER TABLE sites ADD COLUMN settings TEXT NOT NULL DEFAULT '{}';
    ALTER TABLE backups ADD COLUMN kind TEXT NOT NULL DEFAULT 'manual';
    CREATE TABLE protected_dirs (
        id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        path TEXT NOT NULL, realm TEXT NOT NULL, UNIQUE (site_id, path));
    CREATE TABLE protected_users (
        id INTEGER PRIMARY KEY, dir_id INTEGER NOT NULL REFERENCES protected_dirs(id) ON DELETE CASCADE,
        username TEXT NOT NULL, password_hash TEXT NOT NULL, UNIQUE (dir_id, username));
    CREATE TABLE server_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    """,
    # 3: DNS
    """
    CREATE TABLE dns_zones (
        id INTEGER PRIMARY KEY, domain TEXT UNIQUE NOT NULL,
        site_id INTEGER REFERENCES sites(id) ON DELETE SET NULL,
        serial INTEGER NOT NULL DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE dns_records (
        id INTEGER PRIMARY KEY, zone_id INTEGER NOT NULL REFERENCES dns_zones(id) ON DELETE CASCADE,
        name TEXT NOT NULL, type TEXT NOT NULL, content TEXT NOT NULL, ttl INTEGER NOT NULL DEFAULT 3600,
        priority INTEGER, managed TEXT);
    CREATE TABLE ddns_hosts (
        id INTEGER PRIMARY KEY, zone_id INTEGER NOT NULL REFERENCES dns_zones(id) ON DELETE CASCADE,
        name TEXT NOT NULL, token_hash TEXT UNIQUE NOT NULL, description TEXT,
        last_ip TEXT, last_update TEXT, UNIQUE (zone_id, name));
    """,
    # 4: email
    """
    CREATE TABLE mail_domains (
        id INTEGER PRIMARY KEY, site_id INTEGER UNIQUE NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        domain TEXT UNIQUE NOT NULL, dkim_selector TEXT, dkim_record TEXT,
        catch_all TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE mailboxes (
        id INTEGER PRIMARY KEY, domain_id INTEGER NOT NULL REFERENCES mail_domains(id) ON DELETE CASCADE,
        local TEXT NOT NULL, password_hash TEXT NOT NULL, quota_mb INTEGER NOT NULL DEFAULT 1024,
        enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (domain_id, local));
    CREATE TABLE forwarders (
        id INTEGER PRIMARY KEY, domain_id INTEGER NOT NULL REFERENCES mail_domains(id) ON DELETE CASCADE,
        local TEXT NOT NULL, destinations TEXT NOT NULL, UNIQUE (domain_id, local));
    CREATE TABLE autoresponders (
        mailbox_id INTEGER PRIMARY KEY REFERENCES mailboxes(id) ON DELETE CASCADE,
        enabled INTEGER NOT NULL DEFAULT 0, subject TEXT NOT NULL DEFAULT '', body TEXT NOT NULL DEFAULT '',
        days INTEGER NOT NULL DEFAULT 1, start_date TEXT, end_date TEXT);
    """,
    # 5: applications
    """
    CREATE TABLE app_installs (
        id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        app TEXT NOT NULL, path TEXT NOT NULL, version TEXT, admin_user TEXT, db_id INTEGER,
        status TEXT NOT NULL DEFAULT 'installing', error TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE (site_id, path));
    """,
    # 6: stage 1 - two-factor, offsite backups, alerts, updates
    """
    ALTER TABLE users ADD COLUMN totp_secret TEXT;
    ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE users ADD COLUMN totp_last INTEGER NOT NULL DEFAULT 0;
    CREATE TABLE recovery_codes (
        id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        code_hash TEXT NOT NULL, used_at TEXT);
    ALTER TABLE backups ADD COLUMN remote_status TEXT;
    ALTER TABLE backups ADD COLUMN remote_key TEXT;
    ALTER TABLE backups ADD COLUMN remote_error TEXT;
    CREATE TABLE alerts (
        key TEXT PRIMARY KEY, title TEXT NOT NULL, detail TEXT, severity TEXT NOT NULL DEFAULT 'warning',
        first_seen TEXT DEFAULT CURRENT_TIMESTAMP, last_notified TEXT, resolved_at TEXT);
    CREATE TABLE updates (
        id INTEGER PRIMARY KEY, from_version TEXT, to_version TEXT, status TEXT NOT NULL,
        log TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, finished_at TEXT);
    """,
    # 7: stage 2 - cPanel imports; a database user may own several databases
    """
    CREATE TABLE databases_new (
        id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        name TEXT UNIQUE NOT NULL, username TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    INSERT INTO databases_new (id, site_id, name, username, created_at)
        SELECT id, site_id, name, username, created_at FROM databases;
    DROP TABLE databases;
    ALTER TABLE databases_new RENAME TO databases;
    CREATE TABLE imports (
        id INTEGER PRIMARY KEY, source TEXT NOT NULL, size INTEGER DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'scanning', plan TEXT, choices TEXT, result TEXT, log TEXT,
        actor TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, finished_at TEXT);
    """,
    # 8: Git deploy
    """
    CREATE TABLE git_deploy (
        site_id INTEGER PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
        repo_url TEXT NOT NULL, branch TEXT NOT NULL DEFAULT 'main', subdir TEXT NOT NULL DEFAULT '',
        build_cmd TEXT NOT NULL DEFAULT '', after_cmd TEXT NOT NULL DEFAULT '', keep_paths TEXT NOT NULL DEFAULT '[]',
        delete_extra INTEGER NOT NULL DEFAULT 1, auto_deploy INTEGER NOT NULL DEFAULT 1,
        hook_secret TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE deployments (
        id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        status TEXT NOT NULL DEFAULT 'queued', trigger TEXT NOT NULL DEFAULT 'manual', actor TEXT,
        branch TEXT, target_sha TEXT, commit_sha TEXT, commit_msg TEXT, commit_author TEXT,
        backup_id INTEGER, log TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP, started_at TEXT, finished_at TEXT);
    CREATE INDEX deployments_site ON deployments(site_id, id);
    """,
]


def connect() -> sqlite3.Connection:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextmanager
def tx():
    conn = connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init() -> None:
    conn = connect()
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version == 0 and conn.execute(
                "SELECT 1 FROM sqlite_master WHERE name = 'sites'").fetchone():
            version = 1  # database created by v0.1 before migrations existed
        for i, script in enumerate(MIGRATIONS[version:], start=version + 1):
            conn.execute("PRAGMA foreign_keys = OFF")
            conn.executescript("BEGIN;\n" + script + f"\nPRAGMA user_version = {i};\nCOMMIT;")
            conn.execute("PRAGMA foreign_keys = ON")
    finally:
        conn.close()


def one(sql: str, *args):
    with tx() as c:
        return c.execute(sql, args).fetchone()


def all(sql: str, *args):
    with tx() as c:
        return c.execute(sql, args).fetchall()


def execute(sql: str, *args) -> int:
    with tx() as c:
        return c.execute(sql, args).lastrowid


def log(message: str, actor: str = "system", level: str = "info") -> None:
    execute("INSERT INTO activity (actor, message, level) VALUES (?, ?, ?)", actor, message, level)


# ---- per-site JSON settings ----

def site_settings(site) -> dict:
    try:
        return json.loads(site["settings"] or "{}")
    except (ValueError, KeyError, IndexError):
        return {}


def save_site_settings(site_id: int, settings: dict) -> None:
    execute("UPDATE sites SET settings = ? WHERE id = ?", json.dumps(settings, sort_keys=True), site_id)


# ---- server-wide settings ----

def get_setting(key: str, default: str = "") -> str:
    row = one("SELECT value FROM server_settings WHERE key = ?", key)
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    execute("INSERT INTO server_settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, value)
