"""DNS zones, records and Dynamic DNS."""
import hashlib
import ipaddress
import secrets
import socket
from datetime import date, datetime, timezone

from .. import config, db, validators
from ..system import bind
from ..system.runner import CommandError
from . import OpError


def _check_enabled():
    if not config.features()["dns"]:
        raise OpError("DNS hosting (BIND) isn't installed on this server")


def server_ip() -> str:
    ip = db.get_setting("server_ipv4")
    if ip:
        return ip
    if config.DRY_RUN:
        return "203.0.113.10"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 53))  # no packets sent; just picks the outbound interface
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def nameservers() -> list[str]:
    ns = [n for n in (db.get_setting("ns1"), db.get_setting("ns2")) if n]
    return ns or [f"ns1.{socket.getfqdn()}" if "." in socket.getfqdn() else "ns1.localhost"]


def get_zone(zone_id: int):
    z = db.one("SELECT * FROM dns_zones WHERE id = ?", zone_id)
    if not z:
        raise OpError("Zone not found")
    return z


def _next_serial(old: int) -> int:
    base = int(date.today().strftime("%Y%m%d") + "00")
    return max(old + 1, base)


def publish(zone_id: int) -> None:
    """Regenerate the zone file; bumps the serial. Raises OpError if BIND rejects it."""
    z = get_zone(zone_id)
    serial = _next_serial(z["serial"])
    records = db.all("SELECT * FROM dns_records WHERE zone_id = ?", zone_id)
    hostmaster = db.get_setting("hostmaster") or f"hostmaster@{z['domain']}"
    content = bind.render(z["domain"], serial, nameservers(), hostmaster, records,
                          glue_ipv4=server_ip(), glue_ipv6=db.get_setting("server_ipv6"))
    try:
        bind.write_zone(z["domain"], content)
    except CommandError as e:
        raise OpError(f"BIND rejected the zone: {e}")
    db.execute("UPDATE dns_zones SET serial = ? WHERE id = ?", serial, zone_id)


def _publish_list() -> None:
    bind.write_zone_list([z["domain"] for z in db.all("SELECT domain FROM dns_zones")])


def mail_host(domain: str) -> str:
    """The server's own host name when set (one name, one certificate, matching
    reverse DNS); otherwise mail.<domain>."""
    return db.get_setting("hostname") or f"mail.{domain}"


def default_records(domain: str) -> list[tuple]:
    ip = server_ip()
    recs = [
        ("@", "A", ip, None, "default"),
        ("www", "CNAME", "@", None, "default"),
        ("mail", "A", ip, None, "mail"),
        ("@", "MX", f"{mail_host(domain)}.", 10, "mail"),
        ("@", "TXT", "v=spf1 a mx ~all", None, "mail"),
        ("_dmarc", "TXT", f"v=DMARC1; p=quarantine; rua=mailto:postmaster@{domain}", None, "mail"),
        ("@", "CAA", '0 issue "letsencrypt.org"', None, "default"),
    ]
    ipv6 = db.get_setting("server_ipv6")
    if ipv6:
        recs.insert(1, ("@", "AAAA", ipv6, None, "default"))
    return recs


def create_zone(domain: str, actor: str, site_id: int | None = None, with_defaults: bool = True) -> int:
    _check_enabled()
    domain = validators.hostname(domain)
    if db.one("SELECT id FROM dns_zones WHERE domain = ?", domain):
        raise OpError(f"A zone for {domain} already exists")
    if site_id is None:
        s = db.one("SELECT id FROM sites WHERE domain = ?", domain)
        site_id = s["id"] if s else None
    zid = db.execute("INSERT INTO dns_zones (domain, site_id) VALUES (?, ?)", domain, site_id)
    if with_defaults:
        with db.tx() as c:
            c.executemany("INSERT INTO dns_records (zone_id, name, type, content, priority, managed) VALUES (?,?,?,?,?,?)",
                          [(zid, *r) for r in default_records(domain)])
        md = db.one("SELECT dkim_selector, dkim_record FROM mail_domains WHERE domain = ?", domain)
        if md and md["dkim_record"]:
            set_dkim(domain, md["dkim_selector"], md["dkim_record"])
    try:
        publish(zid)
        _publish_list()
    except Exception:
        bind.remove_zone_file(domain)
        db.execute("DELETE FROM dns_zones WHERE id = ?", zid)
        raise
    db.log(f"Created DNS zone {domain}", actor)
    return zid


def delete_zone(zone_id: int, actor: str) -> None:
    z = get_zone(zone_id)
    db.execute("DELETE FROM dns_zones WHERE id = ?", zone_id)
    _publish_list()
    bind.remove_zone_file(z["domain"])
    db.log(f"Deleted DNS zone {z['domain']}", actor)


def add_record(zone_id: int, name: str, rtype: str, content: str, ttl, priority, actor: str) -> int:
    z = get_zone(zone_id)
    rtype = (rtype or "").upper()
    name = validators.dns_name(name)
    content, prio = validators.dns_content(rtype, content, priority)
    if rtype == "CNAME" and name == "@":
        raise OpError("The domain itself (@) can't be a CNAME; use an A record")
    rid = db.execute("INSERT INTO dns_records (zone_id, name, type, content, ttl, priority) VALUES (?,?,?,?,?,?)",
                     zone_id, name, rtype, content, validators.dns_ttl(ttl), prio)
    try:
        publish(zone_id)
    except OpError:
        db.execute("DELETE FROM dns_records WHERE id = ?", rid)
        raise
    db.log(f"{z['domain']}: added {rtype} record {name}", actor)
    return rid


def update_record(zone_id: int, record_id: int, name: str, content: str, ttl, priority, actor: str) -> None:
    z = get_zone(zone_id)
    old = db.one("SELECT * FROM dns_records WHERE id = ? AND zone_id = ?", record_id, zone_id)
    if not old:
        raise OpError("Record not found")
    name = validators.dns_name(name)
    content, prio = validators.dns_content(old["type"], content, priority)
    db.execute("UPDATE dns_records SET name = ?, content = ?, ttl = ?, priority = ? WHERE id = ?",
               name, content, validators.dns_ttl(ttl), prio, record_id)
    try:
        publish(zone_id)
    except OpError:
        db.execute("UPDATE dns_records SET name = ?, content = ?, ttl = ?, priority = ? WHERE id = ?",
                   old["name"], old["content"], old["ttl"], old["priority"], record_id)
        raise
    db.log(f"{z['domain']}: updated {old['type']} record {name}", actor)


def delete_record(zone_id: int, record_id: int, actor: str) -> None:
    z = get_zone(zone_id)
    old = db.one("SELECT * FROM dns_records WHERE id = ? AND zone_id = ?", record_id, zone_id)
    if not old:
        raise OpError("Record not found")
    db.execute("DELETE FROM dns_records WHERE id = ?", record_id)
    try:
        publish(zone_id)
    except OpError:
        db.execute("INSERT INTO dns_records (id, zone_id, name, type, content, ttl, priority, managed) "
                   "VALUES (?,?,?,?,?,?,?,?)", *[old[k] for k in
                   ("id", "zone_id", "name", "type", "content", "ttl", "priority", "managed")])
        raise
    db.log(f"{z['domain']}: deleted {old['type']} record {old['name']}", actor)


def set_dkim(domain: str, selector: str, txt: str) -> None:
    """Called by the mail service when a DKIM key is created (no-op without a zone)."""
    z = db.one("SELECT id FROM dns_zones WHERE domain = ?", domain)
    if not z:
        return
    db.execute("DELETE FROM dns_records WHERE zone_id = ? AND managed = 'dkim'", z["id"])
    if txt:
        db.execute("INSERT INTO dns_records (zone_id, name, type, content, managed) VALUES (?, ?, 'TXT', ?, 'dkim')",
                   z["id"], f"{selector}._domainkey", txt)
    publish(z["id"])


def refresh_all() -> int:
    """Re-publish every zone (after nameserver or IP settings change)."""
    n = 0
    for z in db.all("SELECT id FROM dns_zones"):
        publish(z["id"])
        n += 1
    return n


# ---------- Dynamic DNS ----------

def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_ddns(zone_id: int, name: str, description: str, actor: str) -> str:
    z = get_zone(zone_id)
    name = validators.dns_name(name)
    if name in ("@", "*") or name.startswith("*"):
        raise OpError("Choose a sub-name such as home or office")
    if db.one("SELECT id FROM ddns_hosts WHERE zone_id = ? AND name = ?", zone_id, name):
        raise OpError(f"{name}.{z['domain']} already has a Dynamic DNS key")
    token = secrets.token_urlsafe(24)
    db.execute("INSERT INTO ddns_hosts (zone_id, name, token_hash, description) VALUES (?, ?, ?, ?)",
               zone_id, name, _hash(token), validators.single_line(description, "Description", 100))
    db.log(f"{z['domain']}: created Dynamic DNS for {name}", actor)
    return token


def delete_ddns(zone_id: int, ddns_id: int, actor: str) -> None:
    z = get_zone(zone_id)
    h = db.one("SELECT * FROM ddns_hosts WHERE id = ? AND zone_id = ?", ddns_id, zone_id)
    if not h:
        raise OpError("Not found")
    db.execute("DELETE FROM ddns_hosts WHERE id = ?", ddns_id)
    db.execute("DELETE FROM dns_records WHERE zone_id = ? AND managed = ?", zone_id, f"ddns:{ddns_id}")
    publish(zone_id)
    db.log(f"{z['domain']}: removed Dynamic DNS for {h['name']}", actor)


def ddns_update(token: str, ip: str) -> tuple[str, str]:
    """Returns (status, ip) using the classic dyndns answers: good / nochg / badauth / notfqdn."""
    h = db.one("SELECT * FROM ddns_hosts WHERE token_hash = ?", _hash(token or ""))
    if not h:
        return "badauth", ""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "notfqdn", ""
    rtype = "A" if addr.version == 4 else "AAAA"
    tag = f"ddns:{h['id']}"
    rec = db.one("SELECT * FROM dns_records WHERE zone_id = ? AND managed = ? AND type = ?", h["zone_id"], tag, rtype)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    if rec and rec["content"] == str(addr):
        db.execute("UPDATE ddns_hosts SET last_update = ? WHERE id = ?", now, h["id"])
        return "nochg", str(addr)
    if rec:
        db.execute("UPDATE dns_records SET content = ? WHERE id = ?", str(addr), rec["id"])
    else:
        db.execute("INSERT INTO dns_records (zone_id, name, type, content, ttl, managed) VALUES (?,?,?,?,?,?)",
                   h["zone_id"], h["name"], rtype, str(addr), 300, tag)
    publish(h["zone_id"])
    db.execute("UPDATE ddns_hosts SET last_ip = ?, last_update = ? WHERE id = ?", str(addr), now, h["id"])
    z = get_zone(h["zone_id"])
    db.log(f"{z['domain']}: Dynamic DNS {h['name']} → {addr}", "ddns")
    return "good", str(addr)
