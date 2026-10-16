"""Sites, databases and cron jobs."""
from .. import config, db, validators
from ..system import cron, mysql, nginx, phpfpm, ssl, users
from ..system.runner import CommandError
from . import OpError, apply_pool, apply_vhost, get_site, log, site_root, vhost_spec


# ---------- sites ----------

def create_site(domain: str, php_version: str, include_www: bool, actor: str, create_zone: bool = True) -> int:
    domain = validators.domain(domain)
    if db.one("SELECT id FROM sites WHERE domain = ?", domain):
        raise OpError(f"{domain} already exists")
    if php_version not in phpfpm.available_versions():
        raise OpError("That PHP version is not installed")

    site_id = db.execute("INSERT INTO sites (domain, php_version, include_www) VALUES (?, ?, ?)",
                         domain, php_version, int(include_www))
    sysuser = f"site{site_id}"
    db.execute("UPDATE sites SET sysuser = ? WHERE id = ?", sysuser, site_id)
    done = []
    try:
        users.create(sysuser, domain); done.append("user")
        apply_pool(site_id); done.append("pool")
        apply_vhost(site_id)
    except Exception as e:
        if "pool" in done:
            try: phpfpm.remove_pool(sysuser)
            except Exception: pass
        if "user" in done:
            users.delete(sysuser, domain, remove_files=True)
        db.execute("DELETE FROM sites WHERE id = ?", site_id)
        raise OpError(f"Could not create site: {e}")
    db.log(f"Created site {domain} (PHP {php_version})", actor)
    from ..system import firewall
    firewall.reload_site_logs()

    if create_zone and config.features()["dns"] and db.get_setting("dns_auto_zone", "1") == "1":
        from . import dns
        try:
            dns.create_zone(domain, actor, site_id=site_id)
        except Exception as e:
            db.log(f"{domain}: could not create DNS zone automatically: {e}", actor, "warn")
    return site_id


def change_php(site_id: int, version: str, actor: str) -> None:
    site = get_site(site_id)
    if version not in phpfpm.available_versions():
        raise OpError("That PHP version is not installed")
    old = site["php_version"]
    if version == old:
        return
    db.execute("UPDATE sites SET php_version = ? WHERE id = ?", version, site_id)
    try:
        apply_pool(site_id)
    except CommandError as e:
        db.execute("UPDATE sites SET php_version = ? WHERE id = ?", old, site_id)
        raise OpError(str(e))
    db.log(f"{site['domain']}: PHP {old} → {version}", actor)


def set_www(site_id: int, include_www: bool, actor: str) -> None:
    site = get_site(site_id)
    db.execute("UPDATE sites SET include_www = ? WHERE id = ?", int(include_www), site_id)
    try:
        if site["ssl"]:
            ssl.issue(site["domain"], include_www, str(site_root(site) / "public"))
        apply_vhost(site_id)
    except CommandError as e:
        db.execute("UPDATE sites SET include_www = ? WHERE id = ?", site["include_www"], site_id)
        raise OpError(str(e))
    db.log(f"{site['domain']}: www alias {'on' if include_www else 'off'}", actor)


def enable_ssl(site_id: int, actor: str) -> None:
    site = get_site(site_id)
    try:
        ssl.issue(site["domain"], bool(site["include_www"]), str(site_root(site) / "public"))
    except CommandError as e:
        msg = str(e)
        if "invalid email" in msg or "Unable to register an account" in msg:
            raise OpError("Let's Encrypt rejected the account email set at install time. Put a real address in "
                          "HARBOR_ACME_EMAIL in /etc/harbor/harbor.env (or leave it empty), then run: "
                          "systemctl restart harbor")
        if "too many" in msg.lower() or "rateLimited" in msg:
            raise OpError(f"Let's Encrypt rate limit reached for {site['domain']}; try again later. {msg}")
        raise OpError(f"Certificate request failed. Check that DNS for {site['domain']} points to this server. {msg}")
    db.execute("UPDATE sites SET ssl = 1 WHERE id = ?", site_id)
    try:
        apply_vhost(site_id)
    except CommandError as e:
        db.execute("UPDATE sites SET ssl = 0 WHERE id = ?", site_id)
        raise OpError(str(e))
    db.log(f"{site['domain']}: HTTPS enabled", actor)


def disable_ssl(site_id: int, actor: str) -> None:
    site = get_site(site_id)
    db.execute("UPDATE sites SET ssl = 0 WHERE id = ?", site_id)
    apply_vhost(site_id)
    db.log(f"{site['domain']}: HTTPS disabled", actor)


def set_sftp(site_id: int, password: str | None, actor: str) -> None:
    site = get_site(site_id)
    if password is None:
        users.disable_sftp(site["sysuser"])
        db.execute("UPDATE sites SET sftp_enabled = 0 WHERE id = ?", site_id)
        db.log(f"{site['domain']}: SFTP disabled", actor)
        return
    users.set_sftp_password(site["sysuser"], validators.password(password))
    db.execute("UPDATE sites SET sftp_enabled = 1 WHERE id = ?", site_id)
    db.log(f"{site['domain']}: SFTP password set", actor)


def delete_site(site_id: int, remove_files: bool, drop_dbs: bool, actor: str) -> None:
    from . import dns, mail, security
    site = get_site(site_id)
    errors = []

    def attempt(fn):
        try:
            fn()
        except Exception as e:
            errors.append(str(e))

    attempt(lambda: nginx.remove(site["domain"]))
    attempt(lambda: phpfpm.remove_pool(site["sysuser"]))
    attempt(lambda: cron.sync(site["sysuser"], []))
    if site["ssl"]:
        attempt(lambda: ssl.delete(site["domain"]))
    attempt(lambda: security.cleanup_site(site))
    attempt(lambda: mail.disable_domain(site_id, actor, remove_mail=remove_files))
    if drop_dbs:
        from . import dbeditor
        for d in db.all("SELECT * FROM databases WHERE site_id = ?", site_id):
            attempt(lambda d=d: dbeditor.close_for_database(d["name"]))
            attempt(lambda d=d: mysql.drop(d["name"], _user_if_unshared(d)))
    from . import malware
    attempt(lambda: malware.forget_site(site_id))
    users.delete(site["sysuser"], site["domain"], remove_files)
    zone = db.one("SELECT id FROM dns_zones WHERE site_id = ?", site_id)
    db.execute("DELETE FROM sites WHERE id = ?", site_id)
    if zone and remove_files:
        attempt(lambda: dns.delete_zone(zone["id"], actor))
    db.log(f"Deleted site {site['domain']}" + (f" (warnings: {'; '.join(errors)})" if errors else ""),
           actor, "warn" if errors else "info")


# ---------- databases ----------

def _user_if_unshared(row) -> str | None:
    """The database user, unless another database still uses it (possible after a cPanel import)."""
    other = db.one("SELECT 1 FROM databases WHERE username = ? AND id != ?", row["username"], row["id"])
    return None if other else row["username"]


def create_database(site_id: int, suffix: str, actor: str) -> tuple[int, str, str, str]:
    site = get_site(site_id)
    name = f"{site['sysuser']}_{validators.db_suffix(suffix)}"
    if db.one("SELECT id FROM databases WHERE name = ?", name):
        raise OpError(f"Database {name} already exists")
    password = mysql.generate_password()
    try:
        mysql.create(name, name, password)
    except CommandError as e:
        raise OpError(str(e))
    db_id = db.execute("INSERT INTO databases (site_id, name, username) VALUES (?, ?, ?)", site_id, name, name)
    db.log(f"{site['domain']}: created database {name}", actor)
    return db_id, name, name, password


def reset_db_password(site_id: int, db_id: int, actor: str) -> tuple[str, str]:
    row = db.one("SELECT * FROM databases WHERE id = ? AND site_id = ?", db_id, site_id)
    if not row:
        raise OpError("Database not found")
    password = mysql.generate_password()
    mysql.set_password(row["username"], password)
    db.log(f"Reset password for database user {row['username']}", actor)
    return row["username"], password


def delete_database(site_id: int, db_id: int, actor: str) -> None:
    row = db.one("SELECT * FROM databases WHERE id = ? AND site_id = ?", db_id, site_id)
    if not row:
        raise OpError("Database not found")
    from . import dbeditor
    dbeditor.close_for_database(row["name"])
    mysql.drop(row["name"], _user_if_unshared(row))
    db.execute("DELETE FROM databases WHERE id = ?", db_id)
    db.log(f"Dropped database {row['name']}", actor)


# ---------- cron ----------

def _sync_cron(site):
    cron.sync(site["sysuser"], db.all("SELECT * FROM cron_jobs WHERE site_id = ? ORDER BY id", site["id"]))


def add_cron(site_id: int, schedule: str, command: str, actor: str) -> None:
    site = get_site(site_id)
    schedule, command = validators.cron_schedule(schedule), validators.cron_command(command)
    job_id = db.execute("INSERT INTO cron_jobs (site_id, schedule, command) VALUES (?, ?, ?)", site_id, schedule, command)
    try:
        _sync_cron(site)
    except CommandError as e:
        db.execute("DELETE FROM cron_jobs WHERE id = ?", job_id)
        raise OpError(str(e))
    db.log(f"{site['domain']}: added cron job '{schedule} {command}'", actor)


def toggle_cron(site_id: int, job_id: int, actor: str) -> None:
    site = get_site(site_id)
    db.execute("UPDATE cron_jobs SET enabled = 1 - enabled WHERE id = ? AND site_id = ?", job_id, site_id)
    _sync_cron(site)


def delete_cron(site_id: int, job_id: int, actor: str) -> None:
    site = get_site(site_id)
    db.execute("DELETE FROM cron_jobs WHERE id = ? AND site_id = ?", job_id, site_id)
    _sync_cron(site)
    db.log(f"{site['domain']}: removed cron job #{job_id}", actor)


# ---------- resource limits ----------

def set_limits(site_id: int, form: dict, actor: str) -> None:
    from . import update_settings, site_limits
    site = get_site(site_id)

    def num(key, lo, hi, label):
        raw = str(form.get(key, "")).strip() or "0"
        if not raw.isdigit() or not (int(raw) == 0 or lo <= int(raw) <= hi):
            raise OpError(f"{label}: enter 0 for no limit, or {lo}-{hi}")
        return int(raw)
    limits = {
        "cpu_pct": num("cpu_pct", 10, 6400, "CPU"),
        "memory_mb": num("memory_mb", 128, 262144, "Memory"),
        "processes": max(num("processes", 1, 500, "PHP processes"), 1),
        "disk_mb": num("disk_mb", 100, 10_000_000, "Disk allowance"),
    }
    ini_mem = phpfpm.size_mb(phpfpm.effective_ini(db.site_settings(site).get("php_ini", {}))["memory_limit"])
    if limits["memory_mb"] and ini_mem and ini_mem > limits["memory_mb"]:
        raise OpError(f"The memory limit must be at least PHP's memory_limit ({ini_mem} MB, PHP tab)")
    update_settings(site_id, lambda st: st.__setitem__("limits", limits), apply=("pool",))
    db.log(f"{site['domain']}: limits CPU {limits['cpu_pct'] or '∞'}%, memory {limits['memory_mb'] or '∞'} MB, "
           f"{limits['processes']} PHP processes, disk {limits['disk_mb'] or '∞'} MB", actor)


def over_disk_allowance(site) -> bool:
    st = db.site_settings(site)
    allowance = int((st.get("limits") or {}).get("disk_mb", 0) or 0)
    return bool(allowance and st.get("disk_used_mb", 0) > allowance)
