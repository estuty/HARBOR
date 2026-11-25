"""Subdomains: blog.example.com served from its own document root under the
parent site, sharing the parent's PHP-FPM pool and system user (like a cPanel
subdomain, which lives inside the account)."""
from pathlib import Path

from .. import config, db, validators
from ..system import files, nginx, phpfpm, ssl, users
from ..system.runner import CommandError, chmod, chown
from . import OpError, get_site, log, site_root

WELCOME = """<!doctype html>
<html><head><meta charset="utf-8"><title>{fqdn}</title>
<style>body{{font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#f5f3ee;color:#1d2a33}}
main{{text-align:center}}h1{{font-weight:600}}p{{color:#5b6670}}</style></head>
<body><main><h1>{fqdn}</h1><p>This subdomain is hosted with Harbor. Upload its files to <code>{docroot}/</code>.</p></main></body></html>
"""


def listing(site_id: int):
    return db.all("SELECT * FROM subdomains WHERE site_id = ? ORDER BY fqdn", site_id)


def _spec(site, sub) -> nginx.SubdomainSpec:
    root = site_root(site)
    ini = phpfpm.effective_ini(db.site_settings(site).get("php_ini", {}))
    body_mb = max(phpfpm.size_mb(ini["post_max_size"]), phpfpm.size_mb(ini["upload_max_filesize"]), 8)
    return nginx.SubdomainSpec(
        fqdn=sub["fqdn"], ssl=bool(sub["ssl"]),
        root=files.safe_path(root, sub["docroot"]),
        sock=phpfpm.socket_path(site["sysuser"]),
        logs=root / "logs", max_body_mb=body_mb + 1)


def apply(site, sub) -> None:
    nginx.write_subdomain(_spec(site, sub))


def _make_docroot(site, docroot: str, fqdn: str) -> Path:
    """Create the document root under the site (owned by the site user) if missing."""
    target = files.safe_path(site_root(site), docroot)
    created = not target.exists()
    target.mkdir(parents=True, exist_ok=True)
    chown(target, site["sysuser"])
    chmod(target, 0o755)
    if created:
        index = target / "index.html"
        if not index.exists():
            index.write_text(WELCOME.format(fqdn=fqdn, docroot=docroot))
            chown(index, site["sysuser"])
    return target


def create_subdomain(site_id: int, label: str, docroot: str, actor: str) -> int:
    site = get_site(site_id)
    label = validators.subdomain_label(label)
    fqdn = f"{label}.{site['domain']}"
    docroot = validators.rel_path(docroot, "Document root") or f"public/{label}"
    if db.one("SELECT id FROM sites WHERE domain = ?", fqdn):
        raise OpError(f"{fqdn} is already a site of its own")
    if db.one("SELECT id FROM subdomains WHERE fqdn = ?", fqdn):
        raise OpError(f"{fqdn} already exists")

    _make_docroot(site, docroot, fqdn)
    sub_id = db.execute("INSERT INTO subdomains (site_id, label, fqdn, docroot) VALUES (?, ?, ?, ?)",
                        site_id, label, fqdn, docroot)
    sub = db.one("SELECT * FROM subdomains WHERE id = ?", sub_id)
    try:
        apply(site, sub)
    except CommandError as e:
        db.execute("DELETE FROM subdomains WHERE id = ?", sub_id)
        raise OpError(f"The server rejected that change, nothing was added. ({e})")
    _dns_record(site["domain"], label, add=True, actor=actor)
    db.log(f"{site['domain']}: added subdomain {fqdn} → {docroot}", actor)
    return sub_id


def enable_ssl(site_id: int, sub_id: int, actor: str) -> None:
    site = get_site(site_id)
    sub = _get(site_id, sub_id)
    try:
        ssl.issue(sub["fqdn"], False, str(files.safe_path(site_root(site), sub["docroot"])))
    except CommandError as e:
        raise OpError(f"Certificate request failed. Check that DNS for {sub['fqdn']} points to this server. {e}")
    db.execute("UPDATE subdomains SET ssl = 1 WHERE id = ?", sub_id)
    try:
        apply(site, _get(site_id, sub_id))
    except CommandError as e:
        db.execute("UPDATE subdomains SET ssl = 0 WHERE id = ?", sub_id)
        raise OpError(str(e))
    db.log(f"{sub['fqdn']}: HTTPS enabled", actor)


def disable_ssl(site_id: int, sub_id: int, actor: str) -> None:
    site = get_site(site_id)
    sub = _get(site_id, sub_id)
    db.execute("UPDATE subdomains SET ssl = 0 WHERE id = ?", sub_id)
    apply(site, _get(site_id, sub_id))
    db.log(f"{sub['fqdn']}: HTTPS disabled", actor)


def delete_subdomain(site_id: int, sub_id: int, remove_files: bool, actor: str) -> None:
    site = get_site(site_id)
    sub = _get(site_id, sub_id)
    errors = []

    def attempt(fn):
        try:
            fn()
        except Exception as e:
            errors.append(str(e))

    attempt(lambda: nginx.remove_subdomain(sub["fqdn"]))
    if sub["ssl"]:
        attempt(lambda: ssl.delete(sub["fqdn"]))
    attempt(lambda: _dns_record(site["domain"], sub["label"], add=False, actor=actor))
    if remove_files:
        attempt(lambda: _remove_docroot(site, sub["docroot"]))
    db.execute("DELETE FROM subdomains WHERE id = ?", sub_id)
    db.log(f"{site['domain']}: removed subdomain {sub['fqdn']}"
           + (f" (warnings: {'; '.join(errors)})" if errors else ""), actor,
           "warn" if errors else "info")


def cleanup_site(site) -> None:
    """Remove every subdomain's nginx config and certificate when the parent site is deleted."""
    for sub in db.all("SELECT * FROM subdomains WHERE site_id = ?", site["id"]):
        try:
            nginx.remove_subdomain(sub["fqdn"])
        except Exception:
            log.exception("removing subdomain vhost failed")
        if sub["ssl"]:
            ssl.delete(sub["fqdn"])


# ---------- helpers ----------

def _get(site_id: int, sub_id: int):
    sub = db.one("SELECT * FROM subdomains WHERE id = ? AND site_id = ?", sub_id, site_id)
    if not sub:
        raise OpError("Subdomain not found")
    return sub


def _remove_docroot(site, docroot: str) -> None:
    target = files.safe_path(site_root(site), docroot)
    if target == site_root(site) or docroot in ("public", "logs", "tmp", ""):
        return  # never delete the site's own folders
    files.delete(site_root(site), docroot)


def _dns_record(domain: str, label: str, add: bool, actor: str) -> None:
    """Add or remove the subdomain's A record in the parent zone, if Harbor manages it."""
    if not config.features()["dns"]:
        return
    zone = db.one("SELECT * FROM dns_zones WHERE domain = ?", domain)
    if not zone:
        return
    from . import dns
    existing = db.one("SELECT id FROM dns_records WHERE zone_id = ? AND name = ? AND type = 'A' AND managed = 'sub'",
                      zone["id"], label)
    if add:
        if existing:
            return
        db.execute("INSERT INTO dns_records (zone_id, name, type, content, managed) VALUES (?, ?, 'A', ?, 'sub')",
                   zone["id"], label, dns.server_ip())
    elif existing:
        db.execute("DELETE FROM dns_records WHERE id = ?", existing["id"])
    try:
        dns.publish(zone["id"])
    except Exception:
        log.exception("publishing zone after subdomain DNS change failed")
