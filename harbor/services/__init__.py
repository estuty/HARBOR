"""High-level operations combining the panel database with system changes.

The database is the source of truth: `apply_vhost` / `apply_pool` regenerate a
site's nginx and PHP-FPM config from it. Every operation updates the database,
applies, and restores the previous database state if applying fails."""
import logging

from .. import config, db
from ..system import nginx, phpfpm, users
from ..system.runner import CommandError

log = logging.getLogger("harbor")


class OpError(Exception):
    pass


def get_site(site_id: int):
    s = db.one("SELECT * FROM sites WHERE id = ?", site_id)
    if not s:
        raise OpError("Site not found")
    return s


def site_root(site):
    return users.site_root(site["domain"])


def htpasswd_file(dir_id: int) -> str:
    return str(config.NGINX_HARBOR / "htpasswd" / f"dir-{dir_id}")


def modsec_file(site) -> str:
    return str(config.MODSEC_DIR / f"{site['sysuser']}.conf")


def vhost_spec(site) -> nginx.VhostSpec:
    st = db.site_settings(site)
    root = site_root(site)
    rules: dict = {}
    for path in st.get("indexes", []):
        rules.setdefault(path, {})["autoindex"] = True
    for d in db.all("SELECT * FROM protected_dirs WHERE site_id = ?", site["id"]):
        if db.one("SELECT 1 FROM protected_users WHERE dir_id = ?", d["id"]):
            rules.setdefault(d["path"], {})["auth"] = (d["realm"], htpasswd_file(d["id"]))
    hot = st.get("hotlink") or {}
    modsec = st.get("modsec") or {}
    ini = phpfpm.effective_ini(st.get("php_ini", {}))
    body_mb = max(phpfpm.size_mb(ini["post_max_size"]), phpfpm.size_mb(ini["upload_max_filesize"]), 8)
    return nginx.VhostSpec(
        domain=site["domain"], include_www=bool(site["include_www"]), ssl=bool(site["ssl"]),
        root=root, sock=phpfpm.socket_path(site["sysuser"]),
        canonical=st.get("canonical", "none"),
        redirects=st.get("redirects", []),
        ip_deny=st.get("ip_deny", []),
        error_codes=sorted(st.get("error_pages", [])),
        path_rules=rules,
        hotlink={"exts": hot["exts"], "allowed": hot.get("allowed", [])} if hot.get("enabled") else None,
        modsec_file=modsec_file(site) if config.features()["modsec"] and modsec.get("mode", "off") != "off" else None,
        max_body_mb=body_mb + 1,
    )


def apply_vhost(site_id: int) -> None:
    nginx.write(vhost_spec(get_site(site_id)))


def site_limits(site) -> dict:
    from .. import db as _db
    return {**phpfpm.DEFAULT_LIMITS, **default_limits(), **(_db.site_settings(site).get("limits") or {})}


def default_limits() -> dict:
    import json
    try:
        return json.loads(db.get_setting("default_limits", "{}"))
    except ValueError:
        return {}


def apply_pool(site_id: int) -> None:
    site = get_site(site_id)
    phpfpm.write_pool(site["sysuser"], site["domain"], site["php_version"], site_root(site),
                      db.site_settings(site).get("php_ini", {}), site_limits(site))


def update_settings(site_id: int, mutate, apply=("vhost",)) -> None:
    """Change a site's settings JSON with `mutate(settings)`, then apply.
    On failure the previous settings are restored and re-applied."""
    site = get_site(site_id)
    before = db.site_settings(site)
    after = db.site_settings(site)
    mutate(after)
    db.save_site_settings(site_id, after)
    try:
        if "pool" in apply:
            apply_pool(site_id)
        if "vhost" in apply:
            apply_vhost(site_id)
    except CommandError as e:
        db.save_site_settings(site_id, before)
        try:
            if "pool" in apply:
                apply_pool(site_id)
            if "vhost" in apply:
                apply_vhost(site_id)
        except Exception:
            log.exception("re-applying previous settings failed")
        raise OpError(f"The server rejected that change, nothing was modified. ({e})")
