"""Email hosting: Postfix (SMTP) + Dovecot (IMAP/POP3/LMTP/Sieve) + Rspamd
(spam filtering and DKIM signing). Postfix lookup tables and the Dovecot user
file are regenerated from panel state on every change."""
import os
import re
import shutil
from pathlib import Path

from .. import config
from .runner import run, chown, CommandError

VMAIL = "vmail"
RSPAMD_USER = "_rspamd"
DKIM_SELECTOR = "harbor"


def _atomic_write(path: Path, content: str, mode: int = 0o640, owner: tuple[str, str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(content)
    os.chmod(tmp, mode)
    if owner:
        chown(tmp, *owner)
    tmp.replace(path)


def valias_lines(mailboxes: list[dict], aliases: dict[str, list[str]], catch_alls: dict[str, str]) -> list[str]:
    """Each mailbox without a forwarder maps to itself, so a catch-all never
    swallows real addresses. A forwarder on a real mailbox keeps a copy."""
    lines = [f"{m['address']} {m['address']}" for m in mailboxes if m["address"] not in aliases]
    lines += [f"{src} {', '.join(dst)}" for src, dst in sorted(aliases.items())]
    lines += [f"@{dom} {target}" for dom, target in sorted(catch_alls.items())]
    return lines


def write_maps(domains: list[str], mailboxes: list[dict], aliases: dict[str, list[str]], catch_alls: dict[str, str]) -> None:
    """domains: ["example.com"]; mailboxes: [{"address", "domain", "local"}];
    aliases: {"sales@example.com": ["a@x.com", ...]}; catch_alls: {"example.com": "info@example.com"}."""
    d = config.POSTFIX_MAPS
    _atomic_write(d / "vdomains", "".join(f"{x} OK\n" for x in sorted(domains)), 0o644)
    _atomic_write(d / "vmailbox", "".join(f"{m['address']} {m['domain']}/{m['local']}/\n" for m in mailboxes), 0o644)
    _atomic_write(d / "valias", "\n".join(valias_lines(mailboxes, aliases, catch_alls)) + "\n", 0o644)
    _atomic_write(d / "senders", "".join(f"{m['address']} {m['address']}\n" for m in mailboxes), 0o644)
    for name in ("vdomains", "vmailbox", "valias", "senders"):
        run(["postmap", str(d / name)])
    run(["postfix", "reload"], check=False)


def write_users(mailboxes: list[dict]) -> None:
    """Dovecot passwd-file. Suspended mailboxes still receive mail but can't log in."""
    lines = []
    for m in mailboxes:
        extra = f"userdb_quota_rule=*:storage={m['quota_mb']}M" if m["quota_mb"] else ""  # 0 = unlimited
        # A '!' prefix makes the hash unmatchable: login fails, but the userdb
        # entry stays, so a suspended mailbox keeps receiving mail.
        pw = m["password_hash"] if m["enabled"] else "!" + m["password_hash"]
        lines.append(f"{m['address']}:{{CRYPT}}{pw}::::::{extra}")  # CRYPT: $6$, and $1$/$5$/$y$ hashes imported from cPanel
    _atomic_write(config.DOVECOT_USERS, "\n".join(lines) + "\n", 0o640, ("root", "dovecot"))


def mailbox_home(domain: str, local: str) -> Path:
    return config.MAIL_ROOT / domain / local


def ensure_home(domain: str, local: str) -> Path:
    home = mailbox_home(domain, local)
    for p in (config.MAIL_ROOT / domain, home):
        if not p.exists():
            p.mkdir(parents=True)
            os.chmod(p, 0o700)
            chown(p, VMAIL)
    return home


def remove_home(domain: str, local: str | None = None) -> None:
    target = mailbox_home(domain, local) if local else config.MAIL_ROOT / domain
    if target.resolve().parent.is_relative_to(config.MAIL_ROOT.resolve()):
        shutil.rmtree(target, ignore_errors=True)


def usage(address: str) -> int | None:
    """Bytes used, via doveadm (None if unknown)."""
    if config.DRY_RUN:
        return 0
    try:
        out = run(["doveadm", "-f", "flow", "quota", "get", "-u", address])
    except CommandError:
        return None
    m = re.search(r"Type=STORAGE Value=(\d+)", out)
    return int(m.group(1)) * 1024 if m else None


# ---------- Sieve autoresponder ----------

def _sieve_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _sieve_text(s: str) -> str:
    lines = s.replace("\r\n", "\n").split("\n")
    body = "\n".join("." + l if l.startswith(".") else l for l in lines)  # dot-stuffing
    return f"text:\n{body}\n.\n"


def write_autoresponder(domain: str, local: str, enabled: bool, subject: str, body: str, days: int,
                        start: str | None, end: str | None) -> None:
    home = ensure_home(domain, local)
    sieve_dir = home / "sieve"
    active = home / ".dovecot.sieve"
    script = sieve_dir / "harbor.sieve"
    if not enabled:
        if active.is_symlink() or active.exists():
            active.unlink()
        script.unlink(missing_ok=True)
        return
    if not sieve_dir.exists():
        sieve_dir.mkdir()
        os.chmod(sieve_dir, 0o700)
        chown(sieve_dir, VMAIL)
    conds = []
    if start:
        conds.append(f'currentdate :value "ge" "date" {_sieve_str(start)}')
    if end:
        conds.append(f'currentdate :value "le" "date" {_sieve_str(end)}')
    action = f"vacation :days {days} :subject {_sieve_str(subject)} {_sieve_text(body)};"
    src = ['require ["vacation", "date", "relational"];', "# Managed by Harbor"]
    if conds:
        src += [f"if allof({', '.join(conds)}) {{", "    " + action.replace("\n", "\n"), "}"]
    else:
        src.append(action)
    script.write_text("\n".join(src) + "\n")
    chown(script, VMAIL)
    if active.is_symlink() or active.exists():
        active.unlink()
    active.symlink_to("sieve/harbor.sieve")
    if not config.DRY_RUN:
        os.lchown(active, *_ids(VMAIL))
        run(["sievec", str(script)], check=False)
        for f in sieve_dir.glob("*.svbin"):
            chown(f, VMAIL)


def _ids(user: str):
    import pwd
    pw = pwd.getpwnam(user)
    return pw.pw_uid, pw.pw_gid


# ---------- DKIM (signed by Rspamd) ----------

def dkim_key_path(domain: str) -> Path:
    return config.DKIM_DIR / f"{domain}.{DKIM_SELECTOR}.key"


def generate_dkim(domain: str) -> str:
    """Create a 2048-bit key (if missing) and return the TXT record value."""
    config.DKIM_DIR.mkdir(parents=True, exist_ok=True)
    key = dkim_key_path(domain)
    if config.DRY_RUN:
        key.write_text("dry-run key\n")
        return "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAdryrun"
    pub = key.with_suffix(".txt")
    if key.exists() and pub.exists():
        return parse_dkim_record(pub.read_text())
    out = run(["rspamadm", "dkim_keygen", "-s", DKIM_SELECTOR, "-d", domain, "-b", "2048", "-k", str(key)])
    os.chmod(key, 0o640)
    chown(key, "root", RSPAMD_USER)
    pub.write_text(out)
    return parse_dkim_record(out)


def parse_dkim_record(text: str) -> str:
    parts = re.findall(r'"([^"]*)"', text)
    return "".join(parts).strip()


def remove_dkim(domain: str) -> None:
    dkim_key_path(domain).unlink(missing_ok=True)
    dkim_key_path(domain).with_suffix(".txt").unlink(missing_ok=True)
