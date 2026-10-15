"""Plain-English health checks.

Each check returns {area, status, title, detail, fix}: status is one of
ok / warn / bad / info / unknown. DNS is looked up through public resolvers,
so results match what the rest of the internet sees (not this server's own
DNS)."""
import re
import socket
import subprocess
import time
from datetime import datetime

import httpx

from .. import config, db
from ..system import firewall, notify, offsite, phpfpm
from . import site_root

PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
_cache: dict[str, tuple[float, object]] = {}
_down_until = 0.0  # after a timeout, don't wait on every other lookup too


class Unknown(Exception):
    pass


def _resolver():
    import dns.resolver
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = PUBLIC_RESOLVERS
    r.lifetime, r.timeout = 6, 3
    return r


def lookup(name: str, rtype: str) -> list[str]:
    """Answers as text; [] if the name/type doesn't exist; Unknown if DNS can't be reached."""
    key = f"{name}/{rtype}"
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < 60:
        if isinstance(hit[1], Unknown):
            raise hit[1]
        return hit[1]
    global _down_until
    if time.time() < _down_until:
        raise Unknown("Public DNS isn't reachable from this server")
    import dns.exception
    import dns.resolver
    try:
        ans = _resolver().resolve(name, rtype)
        if rtype == "MX":
            out = [f"{r.preference} {r.exchange.to_text().rstrip('.').lower()}" for r in ans]
        elif rtype == "TXT":
            out = [b"".join(r.strings).decode("utf-8", "replace") for r in ans]
        else:
            out = [r.to_text().rstrip(".").lower() for r in ans]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        out = []
    except (dns.exception.DNSException, OSError) as e:
        if isinstance(e, (dns.exception.Timeout, dns.resolver.NoNameservers, OSError)):
            _down_until = time.time() + 30
        err = Unknown(f"DNS lookup failed ({e.__class__.__name__})")
        _cache[key] = (time.time(), err)
        raise err
    _cache[key] = (time.time(), out)
    return out


def _r(area, status, title, detail="", fix=""):
    return {"area": area, "status": status, "title": title, "detail": detail, "fix": fix}


def _ips() -> tuple[str, str]:
    from .dns import server_ip
    return server_ip(), db.get_setting("server_ipv6")


def _resolves_to_us(name: str, ip: str) -> tuple[bool | None, list[str]]:
    try:
        a = lookup(name, "A")
    except Unknown:
        return None, []
    if not a:
        try:
            cname = lookup(name, "CNAME")
        except Unknown:
            cname = []
        return False, [f"CNAME {c}" for c in cname]
    return ip in a, a


# ---------------------------------------------------------------- site checks

def site_checks(site) -> list[dict]:
    from . import mail as mail_svc
    ip, ip6 = _ips()
    out = []
    d = site["domain"]

    # --- web: DNS
    ok, found = _resolves_to_us(d, ip)
    if ok is None:
        out.append(_r("Website", "unknown", f"Couldn't look up {d}", "Public DNS didn't answer from this server.",
                      "Try again in a minute."))
    elif ok:
        out.append(_r("Website", "ok", f"{d} points to this server", f"A record: {ip}"))
    elif not found:
        out.append(_r("Website", "bad", f"{d} doesn't point anywhere",
                      "There's no A record, so visitors can't reach the site.",
                      f"At your DNS provider, add an A record for {d} with the value {ip}."))
    else:
        out.append(_r("Website", "bad", f"{d} points somewhere else",
                      f"Visitors go to {', '.join(found)}, not this server ({ip}). If you just moved the site, "
                      "they still see the old host.",
                      f"At your DNS provider, change the A record for {d} to {ip}. Changes take up to a few hours."))
    if site["include_www"]:
        ok, found = _resolves_to_us(f"www.{d}", ip)
        if ok is False and any(f == f"CNAME {d}" for f in found):
            ok = True
        if ok is False:
            out.append(_r("Website", "warn", f"www.{d} doesn't reach this site",
                          f"It points to {', '.join(found) or 'nothing'}.",
                          f"Add a CNAME record www → {d} (or an A record → {ip})."))
        elif ok:
            out.append(_r("Website", "ok", f"www.{d} works too"))
    try:
        aaaa = lookup(d, "AAAA")
        if aaaa and ip6 not in aaaa:
            out.append(_r("Website", "warn", "IPv6 address points somewhere else",
                          f"{d} has an AAAA record ({', '.join(aaaa)}) that isn't this server. Visitors with IPv6 "
                          "(many phones) go there instead.",
                          "Delete the AAAA record, or set it to this server's IPv6 address (Settings)."))
    except Unknown:
        pass

    # --- HTTPS
    if site["ssl"]:
        days = _cert_days(d)
        if days is None:
            out.append(_r("Website", "unknown", "Couldn't read the certificate"))
        elif days < 0:
            out.append(_r("Website", "bad", "The HTTPS certificate has expired",
                          "Browsers show a security warning.", "Click 'Get free certificate' on the Overview tab to see why renewal fails."))
        elif days < 14:
            out.append(_r("Website", "warn", f"Certificate expires in {days} days", "Automatic renewal hasn't worked yet.",
                          "Make sure the domain still points here, then click 'Get free certificate'."))
        else:
            out.append(_r("Website", "ok", "HTTPS is on", f"Certificate valid for {days} more days, renews automatically."))
    else:
        out.append(_r("Website", "warn", "HTTPS is off", "Browsers mark the site 'Not secure' and search engines rank it lower.",
                      "Once the domain points here, click 'Get free certificate' on the Overview tab."))

    # --- does it answer?
    if not config.DRY_RUN:
        try:
            t0 = time.time()
            r = httpx.get("http://127.0.0.1/", headers={"Host": d, "User-Agent": "Harbor-health"}, timeout=20,
                          follow_redirects=False)
            ms = (time.time() - t0) * 1000
            if r.status_code >= 500:
                out.append(_r("Website", "bad", f"The home page shows an error (HTTP {r.status_code})",
                              "Usually a PHP error or the database can't be reached.", "Open the Logs tab → PHP errors."))
            elif ms > 3000:
                out.append(_r("Website", "warn", f"The home page is slow ({ms / 1000:.1f} s)",
                              "Visitors leave when pages take more than 2–3 seconds.",
                              "Check PHP errors, and the site's limits on the Overview tab."))
            else:
                out.append(_r("Website", "ok", f"The home page answers ({ms:.0f} ms)"))
        except httpx.HTTPError as e:
            out.append(_r("Website", "bad", "The home page doesn't answer", str(e)[:200], "Check that nginx is running (Dashboard)."))
        errs = _php_errors_today(site_root(site) / "logs" / "php-error.log")
        if errs:
            out.append(_r("Website", "warn", f"{errs} PHP error(s) logged today",
                          "Errors can break pages or forms even if the home page loads.", "Open the Logs tab → PHP errors."))

    # --- email
    md = mail_svc.get_domain(site["id"])
    mx = spf = None
    try:
        mx = lookup(d, "MX")
        spf = next((t for t in lookup(d, "TXT") if t.lower().startswith("v=spf1")), None)
    except Unknown:
        out.append(_r("Email", "unknown", "Couldn't look up the email records"))
    host = db.get_setting("hostname")
    if mx is not None:
        mx_hosts = [m.split()[1] for m in mx]
        ours = False
        for h in mx_hosts:
            try:
                if ip in lookup(h, "A"):
                    ours = True
            except Unknown:
                pass
        if md:
            if not mx_hosts:
                out.append(_r("Email", "bad", "No MX record: nobody can email this domain",
                              "", f"Add an MX record for {d} → {host or 'this server'} (priority 10)."))
            elif ours:
                out.append(_r("Email", "ok", "Incoming mail comes to this server", f"MX: {', '.join(mx_hosts)}"))
            else:
                out.append(_r("Email", "bad", "Email is on here, but mail goes elsewhere",
                              f"The MX record points to {', '.join(mx_hosts)}, so mail from outside arrives there, "
                              "not in the mailboxes on this server. Mail sent from this server to "
                              f"@{d} addresses also stays here.",
                              f"Either change the MX record to {host or 'this server'} to move email here, or turn "
                              "email off for this site (Email tab) to keep using your current provider."))
        else:
            out.append(_r("Email", "info", "Email for this domain is handled elsewhere" if mx_hosts else "This domain receives no email",
                          f"MX: {', '.join(mx_hosts)}" if mx_hosts else "No MX record."))
        # SPF: can this server send as the domain (contact forms, WordPress emails, mailboxes)?
        if spf is None:
            out.append(_r("Email", "bad" if md else "warn", "No SPF record",
                          "Without it, mail from this domain often lands in spam or is rejected.",
                          f"Add a TXT record for {d}: v=spf1 a mx ip4:{ip} ~all" if md else
                          f"Add a TXT record that includes your mail provider and ip4:{ip}."))
        else:
            terms = spf.lower().split()
            allowed = (f"ip4:{ip}" in spf or (any(t in ("a", "+a") for t in terms) and _resolves_to_us(d, ip)[0])
                       or (any(t in ("mx", "+mx") for t in terms) and ours))
            if allowed:
                out.append(_r("Email", "ok", "SPF allows this server to send", spf))
            elif "include:" in spf:
                out.append(_r("Email", "warn" if md else "info", "SPF may not cover this server",
                              f"{spf}. Mail that this server sends (website forms{', mailboxes' if md else ''}) can be marked as spam.",
                              f"Add ip4:{ip} to the record, before ~all or -all."))
            else:
                out.append(_r("Email", "bad" if md else "warn", "SPF doesn't allow this server", spf,
                              f"Add ip4:{ip} to the record, before ~all or -all."))
        if md:
            try:
                dkim = lookup(f"{md['dkim_selector']}._domainkey.{d}", "TXT")
                want = re.sub(r"\s", "", md["dkim_record"] or "")
                if any(re.sub(r"\s", "", t) == want for t in dkim):
                    out.append(_r("Email", "ok", "DKIM signature is published"))
                else:
                    out.append(_r("Email", "bad", "DKIM record missing or different",
                                  "Mail is signed but receivers can't check the signature, so more goes to spam.",
                                  f"Add the TXT record {md['dkim_selector']}._domainkey shown on the Email tab."))
            except Unknown:
                pass
            try:
                dmarc = lookup(f"_dmarc.{d}", "TXT")
                if any(t.lower().startswith("v=dmarc1") for t in dmarc):
                    out.append(_r("Email", "ok", "DMARC is set up"))
                else:
                    out.append(_r("Email", "warn", "No DMARC record", "Gmail and Yahoo expect one from senders.",
                                  f"Add a TXT record _dmarc: v=DMARC1; p=quarantine; rua=mailto:postmaster@{d}"))
            except Unknown:
                pass
    return out


def _cert_days(name: str) -> int | None:
    if config.DRY_RUN:
        return 60
    try:
        out = subprocess.run(["openssl", "x509", "-noout", "-enddate", "-in", f"{config.LE_LIVE}/{name}/cert.pem"],
                             capture_output=True, text=True, timeout=10).stdout
        m = re.search(r"notAfter=(.+)", out)
        return (datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z") - datetime.utcnow()).days if m else None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def _php_errors_today(path) -> int:
    if not path.exists():
        return 0
    today = datetime.utcnow().strftime("%d-%b-%Y")
    from ..system.stats import tail
    return sum(1 for line in tail(path, 2000).splitlines() if line.startswith(f"[{today}"))


# ---------------------------------------------------------------- server checks

def server_checks() -> list[dict]:
    ip, _ = _ips()
    host = db.get_setting("hostname")
    out = []
    # identity
    from .. import validators
    if host and not validators.is_full_hostname(host):
        out.append(_r("Server", "bad", f"The server host name '{host}' isn't a full domain name",
                      "Mail servers and Let's Encrypt need a name like server1.example.com.",
                      f"Settings → General → Server host name: enter a full name, and add a DNS A record for it → {ip}."))
    elif host:
        ok, found = _resolves_to_us(host, ip)
        if ok:
            out.append(_r("Server", "ok", f"{host} points to this server"))
        elif ok is False:
            out.append(_r("Server", "bad", f"The server name {host} doesn't point here",
                          f"It resolves to {', '.join(found) or 'nothing'}. Mail apps and the panel certificate use this name.",
                          f"Add an A record for {host} → {ip}."))
    else:
        out.append(_r("Server", "warn", "No server host name set", "", "Set one in Settings → General."))
    try:
        rev = socket.gethostbyaddr(ip)[0].lower() if not config.DRY_RUN else host
        if host and rev == host:
            out.append(_r("Server", "ok", "Reverse DNS matches the host name", f"{ip} → {rev}"))
        else:
            out.append(_r("Server", "warn", "Reverse DNS doesn't match the host name",
                          f"{ip} → {rev}. Many mail servers reject mail from servers without matching reverse DNS.",
                          "Your hosting provider sets this. On DigitalOcean: rename the Droplet to exactly "
                          f"{host or 'your host name'} (Droplet → name), and reverse DNS follows."))
    except (socket.herror, socket.gaierror, OSError):
        out.append(_r("Server", "warn", "No reverse DNS for this server's IP",
                      "Many mail servers reject mail from servers without it.",
                      f"Ask your provider to set reverse DNS for {ip} to {host or 'your host name'} "
                      "(DigitalOcean: name the Droplet with the host name)."))
    if host and db.get_setting("hostname_ssl") == "1":
        out.append(_r("Server", "ok", "Panel, webmail and mail use a trusted certificate"))
    else:
        out.append(_r("Server", "warn", "The panel uses a self-signed certificate",
                      "Browsers and mail apps show warnings.", "Settings → General → Get certificate."))

    # email delivery from this server
    if config.features()["mail"] and not config.DRY_RUN:
        try:
            with socket.create_connection(("gmail-smtp-in.l.google.com", 25), timeout=6) as s:
                banner = s.recv(200)
            out.append(_r("Email", "ok", "Outgoing email can leave this server", "Port 25 to Gmail is open."))
        except OSError:
            out.append(_r("Email", "bad", "Your hosting provider blocks outgoing email",
                          "This server can't reach other mail servers on port 25, so mail to Gmail, Outlook etc. "
                          "waits in the queue and eventually bounces. Receiving still works.",
                          "Ask your provider's support to open outbound port 25 (DigitalOcean blocks it on new accounts)."))
        listed = _blacklists(ip)
        if listed is None:
            out.append(_r("Email", "unknown", "Couldn't check spam blocklists"))
        elif listed:
            out.append(_r("Email", "bad", f"This server is on a spam blocklist: {', '.join(listed)}",
                          "Many receivers will reject its mail.", "Look up the IP on the list's website to request removal."))
        else:
            out.append(_r("Email", "ok", "Not on the main spam blocklists"))
        q = _queue()
        if q >= 20:
            out.append(_r("Email", "warn", f"{q} emails waiting to be sent", "Usually means outgoing mail is blocked or rejected.",
                          "See the check about port 25 above."))

    # safety
    admins = db.all("SELECT username, totp_enabled FROM users WHERE role = 'admin'")
    no2fa = [a["username"] for a in admins if not a["totp_enabled"]]
    out.append(_r("Safety", "ok" if not no2fa else "warn",
                  "All admins use two-factor sign-in" if not no2fa else f"Admins without two-factor sign-in: {', '.join(no2fa)}",
                  "" if not no2fa else "A stolen password is enough to take over the server.",
                  "" if not no2fa else "My account → Two-factor sign-in, then Security → Require for all admins."))
    if config.features()["fail2ban"]:
        running = firewall.fail2ban_running()
        out.append(_r("Safety", "ok" if running else "bad", "Password-guessing protection is on" if running
                      else "Password-guessing protection (fail2ban) isn't running",
                      "", "" if running else "Run: sudo systemctl restart fail2ban"))
    out.append(_r("Safety", "ok" if offsite.configured() else "warn",
                  "Backups are copied offsite" if offsite.configured() else "Backups only exist on this server",
                  "" if offsite.configured() else "If the server is lost, so are the backups.",
                  "" if offsite.configured() else "Settings → Offsite backups."))
    scheduled = sum(1 for s in db.all("SELECT settings FROM sites") if '"freq": "daily"' in (s["settings"] or "")
                    or '"freq": "weekly"' in (s["settings"] or ""))
    total = db.one("SELECT COUNT(*) c FROM sites")["c"]
    if total:
        out.append(_r("Safety", "ok" if scheduled == total else "warn",
                      "Every site has automatic backups" if scheduled == total else f"{total - scheduled} of {total} site(s) have no automatic backups",
                      "", "" if scheduled == total else "Each site → Backups → Automatic backups → Daily."))
    out.append(_r("Safety", "ok" if notify.channels_configured() else "warn",
                  "Alerts are set up" if notify.channels_configured() else "Nobody gets told when something breaks",
                  "", "" if notify.channels_configured() else "Settings → Alerts."))
    return out


def _blacklists(ip: str) -> list[str] | None:
    rev = ".".join(reversed(ip.split(".")))
    listed, answered = [], 0
    for zone in ("zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org"):
        try:
            a = lookup(f"{rev}.{zone}", "A")
        except Unknown:
            continue
        answered += 1
        # 127.255.255.x means "query refused" (public resolver), not listed
        if any(x.startswith("127.") and not x.startswith("127.255.255.") for x in a):
            listed.append(zone)
    return listed if answered else None


def _queue() -> int:
    try:
        out = subprocess.run(["postqueue", "-j"], capture_output=True, text=True, timeout=20).stdout
        return sum(1 for line in out.splitlines() if line.strip())
    except (OSError, subprocess.TimeoutExpired):
        return 0


def summarize(checks: list[dict]) -> dict:
    counts = {k: sum(1 for c in checks if c["status"] == k) for k in ("ok", "warn", "bad", "info", "unknown")}
    counts["worst"] = "bad" if counts["bad"] else ("warn" if counts["warn"] else "ok")
    return counts
