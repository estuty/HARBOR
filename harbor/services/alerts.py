"""Health checks and alerting.

Each problem has a stable key (e.g. "disk:/", "svc:nginx"). An alert is sent
when a problem first appears, repeated once a day while it lasts, and a
"resolved" message is sent when it clears."""
import logging
import re
import subprocess
import threading
import time
from datetime import datetime, timezone

import httpx
import psutil

from .. import config, db
from ..system import notify, stats

log = logging.getLogger("harbor")
REMIND_SECONDS = 24 * 3600
_site_failures: dict[int, int] = {}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _subject(title: str, resolved: bool = False) -> str:
    host = db.get_setting("hostname") or "Harbor"
    return f"[{host}] {'Resolved: ' if resolved else ''}{title}"


def fire(key: str, title: str, detail: str = "", severity: str = "warning") -> None:
    row = db.one("SELECT * FROM alerts WHERE key = ?", key)
    if row and row["resolved_at"] is None:
        db.execute("UPDATE alerts SET title = ?, detail = ?, severity = ? WHERE key = ?", title, detail, severity, key)
        last = row["last_notified"]
        due = not last or (datetime.now(timezone.utc).replace(tzinfo=None) -
                           datetime.fromisoformat(last)).total_seconds() > REMIND_SECONDS
        if not due:
            return
        prefix = "Still happening: "
    else:
        db.execute("INSERT INTO alerts (key, title, detail, severity, first_seen, resolved_at) VALUES (?, ?, ?, ?, ?, NULL) "
                   "ON CONFLICT(key) DO UPDATE SET title = excluded.title, detail = excluded.detail, "
                   "severity = excluded.severity, first_seen = excluded.first_seen, resolved_at = NULL, last_notified = NULL",
                   key, title, detail, severity, _now())
        db.log(f"Alert: {title}", "monitor", "error" if severity == "critical" else "warn")
        prefix = ""
    errors = notify.send(_subject(prefix + title), f"{detail}\n\nFirst seen: {(row and row['first_seen']) or _now()} UTC")
    if errors:
        log.warning("alert delivery failed: %s", errors)
    db.execute("UPDATE alerts SET last_notified = ? WHERE key = ?", _now(), key)


def resolve(key: str) -> None:
    row = db.one("SELECT * FROM alerts WHERE key = ? AND resolved_at IS NULL", key)
    if not row:
        return
    db.execute("UPDATE alerts SET resolved_at = ? WHERE key = ?", _now(), key)
    db.log(f"Resolved: {row['title']}", "monitor")
    notify.send(_subject(row["title"], resolved=True), f"This is back to normal.\nStarted: {row['first_seen']} UTC")


def active() -> list:
    return db.all("SELECT * FROM alerts WHERE resolved_at IS NULL ORDER BY severity = 'critical' DESC, first_seen")


# ---------- checks ----------

def check_disk() -> None:
    limit = int(db.get_setting("alert_disk_pct", "85") or 85)
    for mount in ("/",):
        u = psutil.disk_usage(mount)
        key = f"disk:{mount}"
        if u.percent >= limit:
            fire(key, f"Disk {u.percent:.0f}% full", f"{mount}: {u.free / 1e9:.1f} GB free of {u.total / 1e9:.1f} GB.",
                 "critical" if u.percent >= 95 else "warning")
        else:
            resolve(key)


def check_services() -> None:
    from ..system import phpfpm
    names = stats.service_names()
    if config.features().get("fail2ban", True):
        names.append("fail2ban")
    names += [phpfpm.unit_name(s["sysuser"]) for s in db.all("SELECT sysuser FROM sites") if phpfpm.uses_unit(s["sysuser"])]
    for name, state in stats.service_status(names).items():
        key = f"svc:{name}"
        if state not in ("active", "reloading", "activating"):
            fire(key, f"Service {name} is {state}", f"Harbor checked `{name}` and it isn't running.", "critical")
        else:
            resolve(key)


def _cert_expiry(name: str) -> datetime | None:
    path = f"{config.LE_LIVE}/{name}/cert.pem"
    try:
        out = subprocess.run(["openssl", "x509", "-noout", "-enddate", "-in", path], capture_output=True,
                             text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"notAfter=(.+)", out)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None


def check_certificates() -> None:
    if config.DRY_RUN:
        return
    names = [s["domain"] for s in db.all("SELECT domain FROM sites WHERE ssl = 1")]
    if db.get_setting("hostname_ssl") == "1" and db.get_setting("hostname"):
        names.append(db.get_setting("hostname"))
    for name in names:
        exp = _cert_expiry(name)
        key = f"cert:{name}"
        if exp is None:
            continue
        days = (exp - datetime.utcnow()).days
        if days < 14:
            fire(key, f"Certificate for {name} expires in {days} day(s)",
                 f"Automatic renewal hasn't succeeded. Check that {name} still points to this server, then use "
                 f"'Get free certificate' (or Settings → Renew now) to see the error.",
                 "critical" if days < 3 else "warning")
        else:
            resolve(key)


def check_sites() -> None:
    if config.DRY_RUN:
        return
    for s in db.all("SELECT id, domain FROM sites"):
        key = f"site:{s['id']}"
        try:
            r = httpx.get("http://127.0.0.1/", headers={"Host": s["domain"], "User-Agent": "Harbor-monitor"},
                          timeout=15, follow_redirects=False)
            ok = r.status_code < 500
            detail = f"The home page answered HTTP {r.status_code}."
        except httpx.HTTPError as e:
            ok, detail = False, f"No answer: {e}"
        if ok:
            _site_failures[s["id"]] = 0
            resolve(key)
        else:
            _site_failures[s["id"]] = _site_failures.get(s["id"], 0) + 1
            if _site_failures[s["id"]] >= 2:  # two checks in a row, to ignore a blip
                fire(key, f"{s['domain']} is down", detail + " Check the site's Logs tab (PHP errors).", "critical")


def check_mail_queue() -> None:
    if config.DRY_RUN or not config.features()["mail"]:
        return
    try:
        out = subprocess.run(["postqueue", "-j"], capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.TimeoutExpired):
        return
    stuck = sum(1 for line in out.splitlines() if '"queue_name": "deferred"' in line)
    limit = int(db.get_setting("alert_queue", "50") or 50)
    if stuck >= limit:
        fire("mailqueue", f"{stuck} emails are stuck in the outgoing queue",
             "Outgoing mail isn't being delivered. On DigitalOcean and many other providers outbound port 25 is "
             "blocked until you ask support to open it.")
    else:
        resolve("mailqueue")


def check_disk_allowances() -> None:
    from . import site_root
    for s in db.all("SELECT * FROM sites"):
        allowance = int((db.site_settings(s).get("limits") or {}).get("disk_mb", 0) or 0)
        key = f"quota:{s['id']}"
        if not allowance:
            resolve(key)
            continue
        used = stats.dir_size(site_root(s)) / 1048576
        st = db.site_settings(s)
        st["disk_used_mb"] = round(used)
        db.save_site_settings(s["id"], st)
        if used > allowance:
            fire(key, f"{s['domain']} is over its disk allowance",
                 f"Using {used:.0f} MB of {allowance} MB. Uploads in the file manager are paused until it's below.")
        else:
            resolve(key)


CHECKS = [check_disk, check_services, check_certificates, check_sites, check_mail_queue]


def run_checks(include_slow: bool = False) -> None:
    for fn in CHECKS + ([check_disk_allowances] if include_slow else []):
        try:
            fn()
        except Exception:
            log.exception("check %s failed", fn.__name__)


def start_monitor(interval: int = 300) -> None:
    def loop():
        time.sleep(60)
        n = 0
        while True:
            run_checks(include_slow=(n % 12 == 0))  # disk allowances hourly
            n += 1
            time.sleep(interval)
    threading.Thread(target=loop, name="harbor-monitor", daemon=True).start()
