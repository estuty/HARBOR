"""Application Manager (one-click WordPress) and Site Publisher (templates)."""
import re
import time
from datetime import date
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import config, db, validators
from ..system import apps, files, mysql, phpfpm
from ..system.runner import chown
from . import OpError, get_site, log, site_root
from . import sites as site_svc

APPS = {
    "wordpress": {"name": "WordPress", "desc": "The world's most popular CMS for blogs, business sites and shops."},
}

TEMPLATES = {
    "business": {"name": "Business", "desc": "A bold landing page with services and contact details."},
    "personal": {"name": "Personal", "desc": "A calm, readable about-me page with your links."},
    "coming_soon": {"name": "Coming soon", "desc": "A dark holding page while you build the real site."},
}
_env = Environment(loader=FileSystemLoader(str(Path(__file__).parent.parent / "publisher")),
                   autoescape=select_autoescape(["html"]))
HEX_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
URL_RE = re.compile(r"^https?://[^\s\"'<>]{3,300}$")
SUBDIR_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,40}$")


# ---------- WordPress ----------

def _install_dir(site, subdir: str) -> tuple[Path, str]:
    subdir = (subdir or "").strip().strip("/").lower()
    if subdir and not SUBDIR_RE.match(subdir):
        raise OpError("Folder: letters, digits, - and _ only (e.g. blog), or leave blank for the site root")
    public = site_root(site) / "public"
    return (public / subdir if subdir else public), ("/" + subdir if subdir else "/")


def start_wordpress(site_id: int, subdir: str, title: str, admin_user: str, admin_email: str,
                    admin_pass: str, actor: str):
    site = get_site(site_id)
    if not config.features()["apps"]:
        raise OpError("WP-CLI isn't installed on this server (re-run the installer)")
    title = validators.single_line(title, "Site title", 100) or site["domain"]
    admin_user = validators.htuser(admin_user)
    admin_email = validators.email(admin_email)
    admin_pass = validators.password(admin_pass, min_len=12)
    path, rel = _install_dir(site, subdir)
    if db.one("SELECT id FROM app_installs WHERE site_id = ? AND path = ?", site_id, rel):
        raise OpError(f"Something is already installed at {rel}")
    if path.exists():
        leftovers = [p.name for p in path.iterdir() if p.name not in ("index.html",) and not
                     (rel == "/" and p.is_dir() and p.name in _other_install_dirs(site_id))]
        if leftovers:
            raise OpError(f"{rel} isn't empty ({', '.join(sorted(leftovers)[:5])}…). Use an empty folder or delete those files first.")
    suffix = "wp" if not subdir else ("wp_" + re.sub(r"[^a-z0-9]", "", subdir))[:24]
    base, n = suffix, 2
    while db.one("SELECT id FROM databases WHERE name = ?", f"{site['sysuser']}_{suffix}"):
        suffix = f"{base[:21]}{n}"; n += 1
    db_id, db_name, db_user, db_pass = site_svc.create_database(site_id, suffix, actor)
    install_id = db.execute("INSERT INTO app_installs (site_id, app, path, admin_user, db_id) VALUES (?, 'wordpress', ?, ?, ?)",
                            site_id, rel, admin_user, db_id)
    url = f"{'https' if site['ssl'] else 'http'}://{site['domain']}{rel.rstrip('/')}"
    db.log(f"{site['domain']}: installing WordPress at {rel}", actor)

    def job():
        try:
            (path / "index.html").unlink(missing_ok=True)
            version = apps.install_wordpress(site["sysuser"], site_root(site), path, phpfpm.php_binary(site["php_version"]),
                                             url, title, admin_user, admin_pass, admin_email, db_name, db_user, db_pass)
            db.execute("UPDATE app_installs SET status = 'installed', version = ? WHERE id = ?", version, install_id)
            db.log(f"{site['domain']}: WordPress {version} installed at {rel}")
        except Exception as e:
            log.exception("wordpress install failed")
            db.execute("UPDATE app_installs SET status = 'failed', error = ? WHERE id = ?", str(e)[:500], install_id)
            db.log(f"{site['domain']}: WordPress install failed: {e}", level="error")
    return job


def _other_install_dirs(site_id: int) -> set[str]:
    return {r["path"].strip("/") for r in db.all("SELECT path FROM app_installs WHERE site_id = ?", site_id)}


def update_app(site_id: int, install_id: int, actor: str):
    site = get_site(site_id)
    row = db.one("SELECT * FROM app_installs WHERE id = ? AND site_id = ?", install_id, site_id)
    if not row or row["status"] not in ("installed", "failed"):
        raise OpError("Nothing to update")
    path, _ = _install_dir(site, row["path"].strip("/"))
    db.execute("UPDATE app_installs SET status = 'updating', error = NULL WHERE id = ?", install_id)

    def job():
        try:
            v = apps.update_wordpress(site["sysuser"], site_root(site), path, phpfpm.php_binary(site["php_version"]))
            db.execute("UPDATE app_installs SET status = 'installed', version = ? WHERE id = ?", v, install_id)
            db.log(f"{site['domain']}: WordPress at {row['path']} updated to {v}")
        except Exception as e:
            db.execute("UPDATE app_installs SET status = 'installed', error = ? WHERE id = ?", f"Update failed: {e}"[:500], install_id)
            db.log(f"{site['domain']}: WordPress update failed: {e}", level="error")
    db.log(f"{site['domain']}: updating WordPress at {row['path']}", actor)
    return job


def remove_app(site_id: int, install_id: int, delete_files: bool, drop_db: bool, actor: str) -> None:
    site = get_site(site_id)
    row = db.one("SELECT * FROM app_installs WHERE id = ? AND site_id = ?", install_id, site_id)
    if not row:
        raise OpError("Not found")
    if row["status"] in ("installing", "updating"):
        raise OpError("Wait for the current operation to finish")
    if delete_files:
        path, rel = _install_dir(site, row["path"].strip("/"))
        if rel == "/":
            for p in list(path.iterdir()):
                if p.name in _other_install_dirs(site_id) - {""}:
                    continue
                files.delete(site_root(site), str(p.relative_to(site_root(site))))
        else:
            files.delete(site_root(site), str(path.relative_to(site_root(site))))
    if drop_db and row["db_id"]:
        try:
            site_svc.delete_database(site_id, row["db_id"], actor)
        except OpError:
            pass
    db.execute("DELETE FROM app_installs WHERE id = ?", install_id)
    db.log(f"{site['domain']}: removed {APPS.get(row['app'], {}).get('name', row['app'])} from {row['path']}", actor)


# ---------- Site Publisher ----------

def render_template(template: str, form: dict) -> str:
    if template not in TEMPLATES:
        raise OpError("Unknown template")
    title = validators.single_line(form.get("title", ""), "Title", 80)
    if not title:
        raise OpError("Give your site a title")
    accent = form.get("accent", "#0d7a6b")
    if not HEX_RE.match(accent):
        accent = "#0d7a6b"
    email = form.get("email", "").strip()
    if email:
        email = validators.email(email)
    links = []
    for line in (form.get("links", "") or "").splitlines():
        if not line.strip():
            continue
        name, _, url = line.partition("|") if "|" in line else (line.strip(), "", line.strip())
        url = url.strip()
        if not URL_RE.match(url):
            raise OpError(f"Links must start with http:// or https:// ({url[:40]})")
        links.append(((name.strip() or url)[:40], url))
    if len(form.get("description", "")) > 3000:
        raise OpError("Description is too long (max 3,000 characters)")
    services = [s.strip()[:60] for s in (form.get("services", "") or "").splitlines() if s.strip()][:9]
    return _env.get_template(f"{template}.html").render(
        title=title, accent=accent, email=email, links=links[:10], services=services,
        tagline=validators.single_line(form.get("tagline", ""), "Tagline", 160),
        description=form.get("description", "").strip(),
        phone=validators.single_line(form.get("phone", ""), "Phone", 40),
        address=validators.single_line(form.get("address", ""), "Address", 160),
        year=date.today().year)


def publish_template(site_id: int, template: str, form: dict, actor: str) -> None:
    site = get_site(site_id)
    html = render_template(template, form)
    public = site_root(site) / "public"
    index = public / "index.html"
    if index.exists():
        backup = public / f"index.html.bak-{time.strftime('%Y%m%d%H%M%S')}"
        index.rename(backup)
        chown(backup, site["sysuser"])
    index.write_text(html)
    chown(index, site["sysuser"])
    if (public / "index.php").exists():
        db.log(f"{site['domain']}: note: index.php takes priority over the published index.html", actor, "warn")
    st = db.site_settings(site)
    st["publisher"] = {"template": template, **{k: form.get(k, "") for k in
                       ("title", "tagline", "description", "email", "phone", "address", "links", "services", "accent")}}
    db.save_site_settings(site_id, st)
    db.log(f"{site['domain']}: published the {TEMPLATES[template]['name']} template", actor)
