"""Directory privacy (HTTP basic auth) and ModSecurity settings."""
import os
from pathlib import Path

from .. import auth, config, db, validators
from ..system import modsec
from ..system.runner import chown
from . import OpError, get_site, htpasswd_file, modsec_file, update_settings, apply_vhost


# ---------- directory privacy ----------

def _write_htpasswd(dir_id: int) -> None:
    f = Path(htpasswd_file(dir_id))
    f.parent.mkdir(parents=True, exist_ok=True)
    rows = db.all("SELECT username, password_hash FROM protected_users WHERE dir_id = ? ORDER BY username", dir_id)
    tmp = f.with_suffix(".tmp")
    tmp.write_text("".join(f"{r['username']}:{r['password_hash']}\n" for r in rows))
    os.chmod(tmp, 0o640)
    chown(tmp, "root", config.WEB_USER)
    tmp.replace(f)


def protect_dir(site_id: int, path: str, realm: str, actor: str) -> int:
    site = get_site(site_id)
    path = validators.url_path(path, directory=True)
    realm = validators.realm(realm)
    existing = db.one("SELECT id FROM protected_dirs WHERE site_id = ? AND path = ?", site_id, path)
    if existing:
        db.execute("UPDATE protected_dirs SET realm = ? WHERE id = ?", realm, existing["id"])
        dir_id = existing["id"]
    else:
        dir_id = db.execute("INSERT INTO protected_dirs (site_id, path, realm) VALUES (?, ?, ?)", site_id, path, realm)
    apply_vhost(site_id)
    db.log(f"{site['domain']}: password protection set up for {path}", actor)
    return dir_id


def add_protected_user(site_id: int, dir_id: int, username: str, password: str, actor: str) -> None:
    d = db.one("SELECT * FROM protected_dirs WHERE id = ? AND site_id = ?", dir_id, site_id)
    if not d:
        raise OpError("Protected folder not found")
    username = validators.htuser(username)
    hashed = auth.sha512_crypt(validators.password(password, min_len=8))
    db.execute("INSERT INTO protected_users (dir_id, username, password_hash) VALUES (?, ?, ?) "
               "ON CONFLICT(dir_id, username) DO UPDATE SET password_hash = excluded.password_hash",
               dir_id, username, hashed)
    _write_htpasswd(dir_id)
    apply_vhost(site_id)  # first user switches protection on
    db.log(f"{get_site(site_id)['domain']}: set login '{username}' for {d['path']}", actor)


def remove_protected_user(site_id: int, dir_id: int, user_id: int, actor: str) -> None:
    d = db.one("SELECT * FROM protected_dirs WHERE id = ? AND site_id = ?", dir_id, site_id)
    if not d:
        raise OpError("Protected folder not found")
    db.execute("DELETE FROM protected_users WHERE id = ? AND dir_id = ?", user_id, dir_id)
    _write_htpasswd(dir_id)
    apply_vhost(site_id)


def unprotect_dir(site_id: int, dir_id: int, actor: str) -> None:
    d = db.one("SELECT * FROM protected_dirs WHERE id = ? AND site_id = ?", dir_id, site_id)
    if not d:
        raise OpError("Protected folder not found")
    db.execute("DELETE FROM protected_dirs WHERE id = ?", dir_id)
    apply_vhost(site_id)
    Path(htpasswd_file(dir_id)).unlink(missing_ok=True)
    db.log(f"{get_site(site_id)['domain']}: removed password protection from {d['path']}", actor)


# ---------- ModSecurity ----------

def set_modsec(site_id: int, mode: str, disabled_rules: str, actor: str) -> None:
    if mode not in ("off", "detect", "on"):
        raise OpError("Unknown mode")
    if mode != "off" and not config.features()["modsec"]:
        raise OpError("ModSecurity isn't installed on this server")
    ids = validators.rule_ids(disabled_rules)
    site = get_site(site_id)
    modsec.write_site_rules(modsec_file(site), mode, ids)
    update_settings(site_id, lambda st: st.__setitem__("modsec", {"mode": mode, "disabled_rules": ids}))
    db.log(f"{site['domain']}: ModSecurity {dict(off='off', detect='detection only', on='blocking')[mode]}"
           + (f", {len(ids)} rule(s) disabled" if ids else ""), actor)


def cleanup_site(site) -> None:
    for d in db.all("SELECT id FROM protected_dirs WHERE site_id = ?", site["id"]):
        Path(htpasswd_file(d["id"])).unlink(missing_ok=True)
    Path(modsec_file(site)).unlink(missing_ok=True)
