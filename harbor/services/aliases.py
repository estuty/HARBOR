"""Domain aliases: a second domain that serves the same site (like a cPanel
parked domain) or redirects to it. Alias names live on the site's own nginx
vhost and certificate."""
from .. import config, db, validators
from ..system import ssl
from ..system.runner import CommandError
from . import OpError, apply_vhost, cert_extra_domains, get_site, log, site_root


def listing(site_id: int):
    return db.all("SELECT * FROM site_aliases WHERE site_id = ? ORDER BY domain", site_id)


def _in_use(domain: str) -> bool:
    return bool(db.one("SELECT 1 FROM sites WHERE domain = ?", domain)
               or db.one("SELECT 1 FROM site_aliases WHERE domain = ?", domain)
               or db.one("SELECT 1 FROM subdomains WHERE fqdn = ?", domain))


def create_alias(site_id: int, domain: str, redirect: bool, actor: str) -> int:
    site = get_site(site_id)
    domain = validators.domain(domain)
    if domain == site["domain"]:
        raise OpError("That's already this site's domain")
    if _in_use(domain):
        raise OpError(f"{domain} is already used by another site, alias or subdomain")

    zid = _make_zone(domain, site_id, actor)
    alias_id = db.execute("INSERT INTO site_aliases (site_id, domain, redirect) VALUES (?, ?, ?)",
                          site_id, domain, int(redirect))
    try:
        apply_vhost(site_id)
        if site["ssl"]:
            ssl.issue(site["domain"], bool(site["include_www"]), str(site_root(site) / "public"),
                      extra=cert_extra_domains(site))
            apply_vhost(site_id)
    except CommandError as e:
        db.execute("DELETE FROM site_aliases WHERE id = ?", alias_id)
        try:
            apply_vhost(site_id)
        except Exception:
            log.exception("restoring vhost after failed alias add")
        if zid:
            _drop_zone(zid, actor)
        raise OpError(f"Could not add the alias. Check that {domain} points to this server. ({e})")
    db.log(f"{site['domain']}: added alias {domain} ({'redirect' if redirect else 'same content'})", actor)
    return alias_id


def set_redirect(site_id: int, alias_id: int, redirect: bool, actor: str) -> None:
    alias = _get(site_id, alias_id)
    db.execute("UPDATE site_aliases SET redirect = ? WHERE id = ?", int(redirect), alias_id)
    try:
        apply_vhost(site_id)
    except CommandError as e:
        db.execute("UPDATE site_aliases SET redirect = ? WHERE id = ?", alias["redirect"], alias_id)
        raise OpError(str(e))
    db.log(f"{get_site(site_id)['domain']}: alias {alias['domain']} now "
           f"{'redirects' if redirect else 'serves the site'}", actor)


def delete_alias(site_id: int, alias_id: int, remove_zone: bool, actor: str) -> None:
    site = get_site(site_id)
    alias = _get(site_id, alias_id)
    db.execute("DELETE FROM site_aliases WHERE id = ?", alias_id)
    apply_vhost(site_id)
    if remove_zone:
        zone = db.one("SELECT id FROM dns_zones WHERE domain = ?", alias["domain"])
        if zone:
            _drop_zone(zone["id"], actor)
    db.log(f"{site['domain']}: removed alias {alias['domain']}", actor)


# ---------- helpers ----------

def _get(site_id: int, alias_id: int):
    a = db.one("SELECT * FROM site_aliases WHERE id = ? AND site_id = ?", alias_id, site_id)
    if not a:
        raise OpError("Alias not found")
    return a


def _make_zone(domain: str, site_id: int, actor: str):
    """Give the alias domain a DNS zone pointing at this server, if Harbor manages DNS and none exists."""
    if not config.features()["dns"] or db.get_setting("dns_auto_zone", "1") != "1":
        return None
    if db.one("SELECT 1 FROM dns_zones WHERE domain = ?", domain):
        return None
    from . import dns
    try:
        return dns.create_zone(domain, actor, site_id=site_id)
    except Exception as e:
        db.log(f"{domain}: could not create DNS zone automatically: {e}", actor, "warn")
        return None


def _drop_zone(zone_id: int, actor: str) -> None:
    from . import dns
    try:
        dns.delete_zone(zone_id, actor)
    except Exception:
        log.exception("removing alias DNS zone failed")
