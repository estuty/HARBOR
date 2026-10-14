"""Email accounts, forwarders, catch-all and autoresponders."""
from .. import auth, config, db, validators
from ..system import mail
from ..system.runner import CommandError
from . import OpError, get_site, log


def _check_enabled():
    if not config.features()["mail"]:
        raise OpError("Email hosting (Postfix + Dovecot) isn't installed on this server")


def get_domain(site_id: int):
    return db.one("SELECT * FROM mail_domains WHERE site_id = ?", site_id)


def _require_domain(site_id: int):
    d = get_domain(site_id)
    if not d:
        raise OpError("Email isn't enabled for this site")
    return d


def sync() -> None:
    """Regenerate every Postfix map and the Dovecot user file from the database."""
    domains = db.all("SELECT * FROM mail_domains")
    boxes = db.all("""SELECT m.*, d.domain FROM mailboxes m JOIN mail_domains d ON d.id = m.domain_id
                      ORDER BY d.domain, m.local""")
    mb = [{"address": f"{b['local']}@{b['domain']}", "domain": b["domain"], "local": b["local"],
           "password_hash": b["password_hash"], "quota_mb": b["quota_mb"], "enabled": b["enabled"]} for b in boxes]
    mailbox_addrs = {m["address"] for m in mb}
    aliases = {}
    for f in db.all("SELECT f.*, d.domain FROM forwarders f JOIN mail_domains d ON d.id = f.domain_id"):
        src = f"{f['local']}@{f['domain']}"
        dests = f["destinations"].split(",")
        if src in mailbox_addrs and src not in dests:
            dests = [src] + dests  # forwarding from a real mailbox keeps a copy
        aliases[src] = dests
    catch = {d["domain"]: d["catch_all"] for d in domains if d["catch_all"]}
    try:
        mail.write_maps([d["domain"] for d in domains], mb, aliases, catch)
        mail.write_users(mb)
    except CommandError as e:
        raise OpError(f"Mail server rejected the change: {e}")


# ---------- domains ----------

def enable_domain(site_id: int, actor: str) -> None:
    _check_enabled()
    site = get_site(site_id)
    if get_domain(site_id):
        return
    record = mail.generate_dkim(site["domain"])
    db.execute("INSERT INTO mail_domains (site_id, domain, dkim_selector, dkim_record) VALUES (?, ?, ?, ?)",
               site_id, site["domain"], mail.DKIM_SELECTOR, record)
    try:
        sync()
    except OpError:
        db.execute("DELETE FROM mail_domains WHERE site_id = ?", site_id)
        raise
    from . import dns
    try:
        dns.set_dkim(site["domain"], mail.DKIM_SELECTOR, record)
    except Exception as e:
        db.log(f"{site['domain']}: couldn't publish DKIM record: {e}", actor, "warn")
    db.log(f"{site['domain']}: email enabled", actor)


def disable_domain(site_id: int, actor: str, remove_mail: bool = True) -> None:
    d = get_domain(site_id)
    if not d:
        return
    db.execute("DELETE FROM mail_domains WHERE id = ?", d["id"])
    sync()
    mail.remove_dkim(d["domain"])
    if remove_mail:
        mail.remove_home(d["domain"])
    from . import dns
    try:
        dns.set_dkim(d["domain"], d["dkim_selector"], "")
    except Exception:
        pass
    db.log(f"{d['domain']}: email disabled", actor)


def set_catch_all(site_id: int, target: str, actor: str) -> None:
    d = _require_domain(site_id)
    target = validators.email(target) if target.strip() else None
    db.execute("UPDATE mail_domains SET catch_all = ? WHERE id = ?", target, d["id"])
    try:
        sync()
    except OpError:
        db.execute("UPDATE mail_domains SET catch_all = ? WHERE id = ?", d["catch_all"], d["id"])
        raise
    db.log(f"{d['domain']}: catch-all {'→ ' + target if target else 'off (unknown addresses bounce)'}", actor)


# ---------- mailboxes ----------

def get_mailbox(site_id: int, box_id: int):
    d = _require_domain(site_id)
    b = db.one("SELECT * FROM mailboxes WHERE id = ? AND domain_id = ?", box_id, d["id"])
    if not b:
        raise OpError("Mailbox not found")
    return d, b


def create_mailbox(site_id: int, local: str, password: str, quota_mb: int, actor: str) -> str:
    d = _require_domain(site_id)
    local = validators.mail_local(local)
    if db.one("SELECT id FROM mailboxes WHERE domain_id = ? AND local = ?", d["id"], local):
        raise OpError(f"{local}@{d['domain']} already exists")
    if quota_mb != 0 and not 50 <= quota_mb <= 1_000_000:
        raise OpError("Quota must be between 50 MB and 1000 GB (or unlimited)")
    hashed = auth.sha512_crypt(validators.password(password, min_len=10))
    bid = db.execute("INSERT INTO mailboxes (domain_id, local, password_hash, quota_mb) VALUES (?, ?, ?, ?)",
                     d["id"], local, hashed, quota_mb)
    try:
        mail.ensure_home(d["domain"], local)
        sync()
    except Exception:
        db.execute("DELETE FROM mailboxes WHERE id = ?", bid)
        raise
    address = f"{local}@{d['domain']}"
    db.log(f"Created mailbox {address}", actor)
    return address


def update_mailbox(site_id: int, box_id: int, password: str | None, quota_mb: int | None,
                   enabled: bool | None, actor: str) -> None:
    d, b = get_mailbox(site_id, box_id)
    changes = []
    if password:
        db.execute("UPDATE mailboxes SET password_hash = ? WHERE id = ?",
                   auth.sha512_crypt(validators.password(password, min_len=10)), box_id)
        changes.append("password")
    if quota_mb is not None:
        if quota_mb != 0 and not 50 <= quota_mb <= 1_000_000:
            raise OpError("Quota must be between 50 MB and 1000 GB (or unlimited)")
        db.execute("UPDATE mailboxes SET quota_mb = ? WHERE id = ?", quota_mb, box_id)
        changes.append(f"quota {quota_mb} MB")
    if enabled is not None:
        db.execute("UPDATE mailboxes SET enabled = ? WHERE id = ?", int(enabled), box_id)
        changes.append("login enabled" if enabled else "login suspended")
    sync()
    if enabled is False or password:
        # Dovecot re-reads its user file at most once a second; wait for that, then
        # disconnect sessions that were opened with the old password / before suspension.
        if not config.DRY_RUN:
            import time
            time.sleep(1.2)
        from ..system.runner import run
        run(["doveadm", "kick", f"{b['local']}@{d['domain']}"], check=False)
    db.log(f"{b['local']}@{d['domain']}: {', '.join(changes) or 'no changes'}", actor)


def delete_mailbox(site_id: int, box_id: int, actor: str) -> None:
    d, b = get_mailbox(site_id, box_id)
    db.execute("DELETE FROM mailboxes WHERE id = ?", box_id)
    sync()
    mail.remove_home(d["domain"], b["local"])
    db.log(f"Deleted mailbox {b['local']}@{d['domain']}", actor)


def mailbox_usage(address: str):
    return mail.usage(address)


# ---------- forwarders ----------

def add_forwarder(site_id: int, local: str, destinations: str, actor: str) -> None:
    d = _require_domain(site_id)
    local = validators.mail_local(local)
    dests = [validators.email(x) for x in destinations.replace(";", ",").replace(" ", ",").split(",") if x.strip()]
    if not dests:
        raise OpError("Enter at least one destination address")
    if len(dests) > 50:
        raise OpError("At most 50 destinations")
    existing = db.one("SELECT * FROM forwarders WHERE domain_id = ? AND local = ?", d["id"], local)
    if existing:
        merged = list(dict.fromkeys(existing["destinations"].split(",") + dests))
        db.execute("UPDATE forwarders SET destinations = ? WHERE id = ?", ",".join(merged), existing["id"])
    else:
        db.execute("INSERT INTO forwarders (domain_id, local, destinations) VALUES (?, ?, ?)",
                   d["id"], local, ",".join(dests))
    try:
        sync()
    except OpError:
        if existing:
            db.execute("UPDATE forwarders SET destinations = ? WHERE id = ?", existing["destinations"], existing["id"])
        else:
            db.execute("DELETE FROM forwarders WHERE domain_id = ? AND local = ?", d["id"], local)
        raise
    db.log(f"Forwarding {local}@{d['domain']} → {', '.join(dests)}", actor)


def delete_forwarder(site_id: int, fwd_id: int, actor: str) -> None:
    d = _require_domain(site_id)
    f = db.one("SELECT * FROM forwarders WHERE id = ? AND domain_id = ?", fwd_id, d["id"])
    if not f:
        raise OpError("Forwarder not found")
    db.execute("DELETE FROM forwarders WHERE id = ?", fwd_id)
    sync()
    db.log(f"Removed forwarder {f['local']}@{d['domain']}", actor)


# ---------- autoresponders ----------

def set_autoresponder(site_id: int, box_id: int, enabled: bool, subject: str, body: str, days: int,
                      start: str, end: str, actor: str) -> None:
    import datetime as dt
    d, b = get_mailbox(site_id, box_id)
    subject = validators.single_line(subject, "Subject", 200) or "Out of office"
    if len(body) > 10000:
        raise OpError("Message is too long (max 10,000 characters)")
    if not 1 <= days <= 30:
        raise OpError("Reply interval must be 1-30 days")
    for v in (start, end):
        if v:
            try:
                dt.date.fromisoformat(v)
            except ValueError:
                raise OpError("Dates must be YYYY-MM-DD")
    if enabled and not body.strip():
        raise OpError("Write a message for the autoresponder")
    db.execute("""INSERT INTO autoresponders (mailbox_id, enabled, subject, body, days, start_date, end_date)
                  VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(mailbox_id) DO UPDATE SET enabled = excluded.enabled,
                  subject = excluded.subject, body = excluded.body, days = excluded.days,
                  start_date = excluded.start_date, end_date = excluded.end_date""",
               box_id, int(enabled), subject, body, days, start or None, end or None)
    mail.write_autoresponder(d["domain"], b["local"], enabled, subject, body, days, start or None, end or None)
    db.log(f"{b['local']}@{d['domain']}: autoresponder {'on' if enabled else 'off'}", actor)
