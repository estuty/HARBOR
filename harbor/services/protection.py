"""Server security: panel IP allowlist, required 2FA, fail2ban bans."""
import ipaddress
import json

from .. import db, validators
from ..system import firewall
from ..system.runner import CommandError
from . import OpError


def allowlist() -> list[str]:
    try:
        return json.loads(db.get_setting("panel_allow_ips", "[]"))
    except ValueError:
        return []


def _covers(networks: list[str], ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(n, strict=False) for n in networks)


def save_access(raw: str, include_webmail: bool, client_ip: str, actor: str) -> list[str]:
    ips = []
    for part in raw.replace(",", " ").split():
        n = validators.ip_or_network(part)
        if n not in ips:
            ips.append(n)
    if ips and not _covers(ips + ["127.0.0.0/8", "::1/128"], client_ip):
        raise OpError(f"Your current address ({client_ip}) isn't in the list, so saving would lock you out. "
                      "Add it first.")
    try:
        firewall.set_panel_access(ips, include_webmail)
    except CommandError as e:
        raise OpError(f"nginx rejected the change, nothing was modified. ({e})")
    db.set_setting("panel_allow_ips", json.dumps(ips))
    db.set_setting("panel_allow_webmail", "1" if include_webmail else "0")
    sync_ignore()
    db.log("Panel access: " + (f"only {', '.join(ips)}" if ips else "open to any address"), actor)
    return ips


def sync_ignore() -> None:
    from .dns import server_ip
    try:
        firewall.set_ignore_ips([server_ip()] + allowlist())
    except (CommandError, OSError):
        pass


def set_require_2fa(on: bool, actor_uid: int, actor: str) -> None:
    if on:
        me = db.one("SELECT totp_enabled FROM users WHERE id = ?", actor_uid)
        if not me or not me["totp_enabled"]:
            raise OpError("Turn on two-factor sign-in for your own account first (My account).")
    db.set_setting("require_2fa", "1" if on else "0")
    db.log(f"Two-factor sign-in {'required' if on else 'optional'} for admins", actor)


def ban(ip: str, actor: str) -> str:
    ip = str(ipaddress.ip_address((ip or "").strip())) if ip else ""
    if not ip:
        raise OpError("Enter an IP address")
    if _covers(allowlist() + ["127.0.0.0/8", "::1/128"], ip):
        raise OpError("That address is in your panel allowlist")
    from .dns import server_ip
    if ip == server_ip():
        raise OpError("That's this server's own address")
    try:
        firewall.ban(ip)
    except CommandError as e:
        raise OpError(f"fail2ban couldn't ban it: {e}")
    db.log(f"Banned {ip} on all ports", actor)
    return ip


def unban(ip: str, jail: str, actor: str) -> None:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise OpError("Invalid address")
    if jail and jail not in firewall.JAIL_LABELS and not jail.replace("-", "").isalnum():
        raise OpError("Unknown jail")
    try:
        firewall.unban(ip, jail or None)
    except CommandError as e:
        raise OpError(str(e))
    db.log(f"Unbanned {ip}" + (f" ({jail})" if jail else ""), actor)
