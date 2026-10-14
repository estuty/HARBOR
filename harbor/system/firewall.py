"""Server-level protection: who may open the panel (nginx allow/deny) and
automatic banning of repeat offenders (fail2ban)."""
import re
from pathlib import Path

from .. import config
from .runner import run, CommandError

PANEL_ACCESS = config.NGINX_HARBOR / "panel-access.conf"
WEBMAIL_ACCESS = config.NGINX_HARBOR / "webmail-access.conf"
F2B_IGNORE = config.p("/etc/fail2ban/jail.d/harbor-ignore.local")
MANUAL_JAIL = "harbor-manual"
JAIL_LABELS = {
    "sshd": "SSH logins",
    "harbor-panel": "Harbor panel sign-ins",
    "postfix-sasl": "Email sending (SMTP logins)",
    "dovecot": "Email reading (IMAP/POP3 logins)",
    "roundcube-auth": "Webmail sign-ins",
    "nginx-http-auth": "Password-protected folders",
    MANUAL_JAIL: "Blocked by hand",
}


def _write_access(path: Path, ips: list[str]) -> str | None:
    previous = path.read_text() if path.exists() else None
    path.parent.mkdir(parents=True, exist_ok=True)
    if ips:
        body = "".join(f"allow {ip};\n" for ip in ["127.0.0.1", "::1"] + ips) + "deny all;\n"
    else:
        body = ""
    path.write_text("# Managed by Harbor - edit in Server security\n" + body)
    return previous


def set_panel_access(ips: list[str], include_webmail: bool) -> None:
    prev_panel = _write_access(PANEL_ACCESS, ips)
    prev_webmail = _write_access(WEBMAIL_ACCESS, ips if include_webmail else [])
    try:
        run(["nginx", "-t"])
        run(["systemctl", "reload", "nginx"])
    except CommandError:
        for path, prev in ((PANEL_ACCESS, prev_panel), (WEBMAIL_ACCESS, prev_webmail)):
            if prev is None:
                path.unlink(missing_ok=True)
            else:
                path.write_text(prev)
        raise


def set_ignore_ips(ips: list[str]) -> None:
    """Never ban the server itself or the admin's allowed addresses."""
    F2B_IGNORE.parent.mkdir(parents=True, exist_ok=True)
    F2B_IGNORE.write_text("# Managed by Harbor\n[DEFAULT]\nignoreip = 127.0.0.1/8 ::1 " + " ".join(ips) + "\n")
    run(["fail2ban-client", "reload"], check=False)


def fail2ban_running() -> bool:
    if config.DRY_RUN:
        return True
    try:
        return "pong" in run(["fail2ban-client", "ping"]).lower()
    except CommandError:
        return False


def jail_status() -> list[dict]:
    """[{name, label, failed, total_failed, banned: [ip...], total_banned}]"""
    if config.DRY_RUN:
        return [{"name": j, "label": l, "failed": 0, "total_failed": 0, "banned": [], "total_banned": 0}
                for j, l in JAIL_LABELS.items()]
    try:
        out = run(["fail2ban-client", "status"])
    except CommandError:
        return []
    m = re.search(r"Jail list:\s*(.*)", out)
    jails = [j.strip() for j in (m.group(1) if m else "").split(",") if j.strip()]
    result = []
    for j in jails:
        try:
            s = run(["fail2ban-client", "status", j])
        except CommandError:
            continue

        def num(label):
            mm = re.search(label + r":\s*(\d+)", s)
            return int(mm.group(1)) if mm else 0
        bm = re.search(r"Banned IP list:\s*(.*)", s)
        result.append({"name": j, "label": JAIL_LABELS.get(j, j),
                       "failed": num("Currently failed"), "total_failed": num("Total failed"),
                       "banned": (bm.group(1).split() if bm else []), "total_banned": num("Total banned")})
    order = list(JAIL_LABELS)
    return sorted(result, key=lambda r: order.index(r["name"]) if r["name"] in order else 99)


def unban(ip: str, jail: str | None = None) -> None:
    if jail:
        run(["fail2ban-client", "set", jail, "unbanip", ip])
    else:
        run(["fail2ban-client", "unban", ip])


def ban(ip: str) -> None:
    run(["fail2ban-client", "set", MANUAL_JAIL, "banip", ip])


def reload_site_logs() -> None:
    """New sites add error logs that the nginx-http-auth jail must pick up."""
    run(["fail2ban-client", "reload", "nginx-http-auth"], check=False)


def recent_failures(limit: int = 30) -> list[dict]:
    log = config.AUTH_LOG
    if not log.exists():
        return []
    rx = re.compile(r"^(\S+ \S+) harbor: failed (\S+) for user '([^']*)' from (\S+)$")
    out = []
    for line in reversed(log.read_text(errors="replace").splitlines()[-2000:]):
        m = rx.match(line)
        if m:
            out.append({"time": m.group(1), "what": m.group(2), "user": m.group(3), "ip": m.group(4)})
        if len(out) >= limit:
            break
    return out
