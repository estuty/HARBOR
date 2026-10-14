"""Server-wide settings: host name, name servers, IPs, panel/mail certificate."""
import os

from .. import config, db, validators
from ..system import ssl
from ..system.runner import run, CommandError
from . import OpError


def save(form: dict, actor: str) -> list[str]:
    changed = []
    for key, fn in (("hostname", validators.hostname), ("ns1", validators.hostname), ("ns2", validators.hostname)):
        raw = (form.get(key) or "").strip()
        val = fn(raw) if raw else ""
        if val != db.get_setting(key):
            db.set_setting(key, val); changed.append(key)
    for key, version in (("server_ipv4", 4), ("server_ipv6", 6)):
        raw = (form.get(key) or "").strip()
        if raw:
            import ipaddress
            try:
                ip = ipaddress.ip_address(raw)
                if ip.version != version:
                    raise ValueError
            except ValueError:
                raise OpError(f"{key.replace('_', ' ')}: not a valid IPv{version} address")
            raw = str(ip)
        if raw != db.get_setting(key):
            db.set_setting(key, raw); changed.append(key)
    hm = (form.get("hostmaster") or "").strip()
    if hm:
        hm = validators.email(hm)
    if hm != db.get_setting("hostmaster"):
        db.set_setting("hostmaster", hm); changed.append("hostmaster")
    auto = "1" if form.get("dns_auto_zone") == "1" else "0"
    if auto != db.get_setting("dns_auto_zone", "1"):
        db.set_setting("dns_auto_zone", auto); changed.append("dns_auto_zone")

    if changed and config.features()["dns"] and set(changed) & {"ns1", "ns2", "hostmaster"}:
        from . import dns
        dns.refresh_all()
    if "hostname" in changed and config.features()["mail"]:
        try:
            run(["postconf", "-e", f"myhostname={db.get_setting('hostname')}"])
            run(["postfix", "reload"], check=False)
        except CommandError as e:
            raise OpError(f"Saved, but Postfix rejected the host name: {e}")
    if changed:
        db.log(f"Server settings updated: {', '.join(changed)}", actor)
    return changed


def secure_hostname(actor: str) -> str:
    """Get a Let's Encrypt certificate for the server host name and use it for
    the panel (port 8443), webmail (2096) and mail (SMTP/IMAP/POP3)."""
    host = db.get_setting("hostname")
    if not host:
        raise OpError("Set the server host name first")
    try:
        # If the host name is also a hosted site, port 80 for it is served from that site's folder.
        site = db.one("SELECT domain FROM sites WHERE domain = ? OR 'www.' || domain = ?", host, host)
        webroot = str(config.SITES_DIR / site["domain"] / "public") if site else "/var/www/html"
        ssl.issue(host, False, webroot, deploy_hook="systemctl reload nginx postfix dovecot")
    except CommandError as e:
        raise OpError(f"Certificate request failed. Make sure {host} points to this server. {e}")
    tls = config.ETC / "tls"
    tls.mkdir(parents=True, exist_ok=True)
    for name, src in (("cert.pem", "fullchain.pem"), ("key.pem", "privkey.pem")):
        link = tls / name
        if link.exists() and not link.is_symlink():
            link.rename(tls / f"{name}.selfsigned")
        if link.is_symlink():
            link.unlink()
        os.symlink(f"{config.LE_LIVE}/{host}/{src}", link)
    for svc in ("nginx", "postfix", "dovecot"):
        run(["systemctl", "reload", svc], check=False)
    db.set_setting("hostname_ssl", "1")
    db.log(f"Panel and mail now use a Let's Encrypt certificate for {host}", actor)
    return host
