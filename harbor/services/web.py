"""Per-site web rules: redirects, canonical host, custom error pages,
directory indexes, IP blocking, hotlink protection and php.ini overrides."""
import secrets

from .. import db, validators
from ..system import phpfpm
from ..system.runner import chown
from . import OpError, get_site, site_root, update_settings

ERROR_CODES = {400: "Bad request", 401: "Unauthorized", 403: "Forbidden", 404: "Not found",
               500: "Server error", 502: "Bad gateway", 503: "Service unavailable"}

ERROR_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{code} {title}</title>
<style>body{{font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#f5f3ee;color:#1d2a33}}
main{{text-align:center;padding:24px}}h1{{font-size:64px;margin:0}}p{{color:#5b6670}}a{{color:#0d7a6b}}</style></head>
<body><main><h1>{code}</h1><p>{message}</p><p><a href="/">Go to the home page</a></p></main></body></html>
"""
MESSAGES = {404: "Sorry, we couldn't find that page.", 403: "You don't have permission to view this page.",
            500: "Something went wrong on our side. Please try again shortly.",
            503: "We're doing some maintenance. Please check back soon."}


# ---------- redirects ----------

def add_redirect(site_id: int, source: str, target: str, code: int, match: str, actor: str) -> None:
    source = validators.url_path(source, directory=(match == "prefix" and source.strip() != "/"))
    target = validators.redirect_target(target)
    if code not in (301, 302):
        raise OpError("Redirect type must be 301 (permanent) or 302 (temporary)")
    if match not in ("exact", "prefix"):
        raise OpError("Unknown match type")
    if match == "exact" and source == "/":
        raise OpError("To redirect the whole site, use 'This path and everything below it' with path /")

    def m(st):
        reds = st.setdefault("redirects", [])
        if any(r["source"] == source and r["match"] == match for r in reds):
            raise OpError(f"A redirect for {source} already exists")
        reds.append({"id": secrets.token_hex(4), "source": source, "target": target, "code": code, "match": match})
    update_settings(site_id, m)
    db.log(f"{get_site(site_id)['domain']}: redirect {source} → {target} ({code})", actor)


def delete_redirect(site_id: int, rid: str, actor: str) -> None:
    update_settings(site_id, lambda st: st.__setitem__(
        "redirects", [r for r in st.get("redirects", []) if r["id"] != rid]))
    db.log(f"{get_site(site_id)['domain']}: removed a redirect", actor)


def set_canonical(site_id: int, value: str, actor: str) -> None:
    if value not in ("none", "www", "bare"):
        raise OpError("Unknown option")
    site = get_site(site_id)
    if value != "none" and not site["include_www"]:
        raise OpError("Turn on the www alias first (Overview tab)")
    update_settings(site_id, lambda st: st.__setitem__("canonical", value))
    db.log(f"{site['domain']}: preferred host set to {value}", actor)


# ---------- error pages ----------

def error_page_path(site, code: int):
    return site_root(site) / "errors" / f"{code}.html"


def read_error_page(site_id: int, code: int) -> str:
    site = get_site(site_id)
    f = error_page_path(site, code)
    if f.exists():
        return f.read_text(errors="replace")
    return ERROR_TEMPLATE.format(code=code, title=ERROR_CODES.get(code, ""),
                                 message=MESSAGES.get(code, ERROR_CODES.get(code, "")))


def save_error_page(site_id: int, code: int, content: str, enabled: bool, actor: str) -> None:
    if code not in ERROR_CODES:
        raise OpError("Unsupported status code")
    site = get_site(site_id)
    d = site_root(site) / "errors"
    if not d.exists():
        d.mkdir()
        chown(d, site["sysuser"])
        d.chmod(0o755)
    f = error_page_path(site, code)
    f.write_text(content.replace("\r\n", "\n"))
    chown(f, site["sysuser"])

    def m(st):
        codes = set(st.get("error_pages", []))
        codes.add(code) if enabled else codes.discard(code)
        st["error_pages"] = sorted(codes)
    update_settings(site_id, m)
    db.log(f"{site['domain']}: {'enabled' if enabled else 'saved'} custom {code} page", actor)


# ---------- indexes ----------

def set_index(site_id: int, path: str, enabled: bool, actor: str) -> None:
    path = validators.url_path(path, directory=True)
    if path == "/":
        raise OpError("Listing the whole site root isn't allowed; choose a folder such as /downloads/")

    def m(st):
        paths = set(st.get("indexes", []))
        paths.add(path) if enabled else paths.discard(path)
        st["indexes"] = sorted(paths)
    update_settings(site_id, m)
    db.log(f"{get_site(site_id)['domain']}: directory listing {'on' if enabled else 'off'} for {path}", actor)


# ---------- IP blocker ----------

def block_ips(site_id: int, raw: str, actor: str) -> int:
    ips = [validators.ip_or_network(x) for x in raw.replace(",", " ").split() if x.strip()]
    if not ips:
        raise OpError("Enter at least one IP address or range")

    def m(st):
        cur = st.get("ip_deny", [])
        st["ip_deny"] = cur + [i for i in ips if i not in cur]
    update_settings(site_id, m)
    db.log(f"{get_site(site_id)['domain']}: blocked {', '.join(ips)}", actor)
    return len(ips)


def unblock_ip(site_id: int, ip: str, actor: str) -> None:
    update_settings(site_id, lambda st: st.__setitem__("ip_deny", [i for i in st.get("ip_deny", []) if i != ip]))
    db.log(f"{get_site(site_id)['domain']}: unblocked {ip}", actor)


# ---------- hotlink protection ----------

def set_hotlink(site_id: int, enabled: bool, exts: str, allowed: str, actor: str) -> None:
    ext_list = validators.extensions(exts)
    allowed_list = validators.referer_domains(allowed)
    update_settings(site_id, lambda st: st.__setitem__(
        "hotlink", {"enabled": enabled, "exts": ext_list, "allowed": allowed_list}))
    db.log(f"{get_site(site_id)['domain']}: hotlink protection {'on' if enabled else 'off'}", actor)


# ---------- php.ini ----------

def set_php_ini(site_id: int, form: dict, actor: str) -> None:
    values = {}
    for key, (default, kind) in phpfpm.INI_KEYS.items():
        raw = form.get(key, default)
        values[key] = validators.ini_value(key, raw, kind)
    if phpfpm.size_mb(values["post_max_size"]) < phpfpm.size_mb(values["upload_max_filesize"]):
        raise OpError("post_max_size must be at least as large as upload_max_filesize")
    overrides = {k: v for k, v in values.items() if v != phpfpm.INI_KEYS[k][0]}
    update_settings(site_id, lambda st: st.__setitem__("php_ini", overrides), apply=("pool", "vhost"))
    db.log(f"{get_site(site_id)['domain']}: PHP settings updated", actor)
