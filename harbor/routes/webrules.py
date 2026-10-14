"""Redirects, security (IP blocker, hotlink, directory privacy, ModSecurity),
PHP settings and advanced options (error pages, directory indexes)."""
from fastapi import APIRouter, Request

from .. import config, db
from ..services import get_site, security, web as svc
from ..system import modsec, phpfpm
from ..web import actor, back, flash, form_of, guard, render

router = APIRouter()


# ---------- redirects ----------

@router.get("/sites/{site_id}/redirects")
async def redirects_page(request: Request, site_id: int):
    site = get_site(site_id)
    st = db.site_settings(site)
    return render(request, "site_redirects.html", site=site, tab="redirects",
                  redirects=st.get("redirects", []), canonical=st.get("canonical", "none"))


@router.post("/sites/{site_id}/redirects")
async def add_redirect(request: Request, site_id: int):
    async with guard(request):
        form = await form_of(request)
        svc.add_redirect(site_id, form.get("source", ""), form.get("target", ""), int(form.get("code") or 301),
                         form.get("match", "exact"), actor(request))
        flash(request, "Redirect added.")
    return back(f"/sites/{site_id}/redirects")


@router.post("/sites/{site_id}/redirects/{rid}/delete")
async def delete_redirect(request: Request, site_id: int, rid: str):
    async with guard(request):
        await form_of(request)
        svc.delete_redirect(site_id, rid, actor(request))
        flash(request, "Redirect removed.")
    return back(f"/sites/{site_id}/redirects")


@router.post("/sites/{site_id}/canonical")
async def canonical(request: Request, site_id: int):
    async with guard(request):
        form = await form_of(request)
        svc.set_canonical(site_id, form.get("canonical", "none"), actor(request))
        flash(request, "Preferred address saved.")
    return back(f"/sites/{site_id}/redirects")


# ---------- security ----------

@router.get("/sites/{site_id}/security")
async def security_page(request: Request, site_id: int):
    site = get_site(site_id)
    st = db.site_settings(site)
    dirs = db.all("SELECT * FROM protected_dirs WHERE site_id = ? ORDER BY path", site_id)
    dir_users = {d["id"]: db.all("SELECT id, username FROM protected_users WHERE dir_id = ? ORDER BY username", d["id"])
                 for d in dirs}
    hot = st.get("hotlink") or {"enabled": False, "exts": ["jpg", "jpeg", "png", "gif", "webp", "svg", "mp4"], "allowed": []}
    ms = st.get("modsec") or {"mode": "off", "disabled_rules": []}
    hits = modsec.recent_hits(site["domain"], 50) if ms["mode"] != "off" else []
    return render(request, "site_security.html", site=site, tab="security", ip_deny=st.get("ip_deny", []),
                  hot=hot, dirs=dirs, dir_users=dir_users, ms=ms, hits=hits)


@router.post("/sites/{site_id}/security/ip")
async def block_ip(request: Request, site_id: int):
    async with guard(request):
        form = await form_of(request)
        n = svc.block_ips(site_id, form.get("ips", ""), actor(request))
        flash(request, f"Blocked {n} address(es).")
    return back(request.headers.get("referer") or f"/sites/{site_id}/security")


@router.post("/sites/{site_id}/security/ip/unblock")
async def unblock_ip(request: Request, site_id: int):
    async with guard(request):
        form = await form_of(request)
        svc.unblock_ip(site_id, form.get("ip", ""), actor(request))
        flash(request, "Address unblocked.")
    return back(f"/sites/{site_id}/security")


@router.post("/sites/{site_id}/security/hotlink")
async def hotlink(request: Request, site_id: int):
    async with guard(request):
        form = await form_of(request)
        svc.set_hotlink(site_id, form.get("enabled") == "1", form.get("exts", ""), form.get("allowed", ""), actor(request))
        flash(request, "Hotlink protection saved.")
    return back(f"/sites/{site_id}/security#hotlink")


@router.post("/sites/{site_id}/security/dirs")
async def protect_dir(request: Request, site_id: int):
    async with guard(request):
        form = await form_of(request)
        dir_id = security.protect_dir(site_id, form.get("path", ""), form.get("realm", ""), actor(request))
        if form.get("username"):
            security.add_protected_user(site_id, dir_id, form.get("username", ""), form.get("password", ""), actor(request))
            flash(request, "Folder is now password protected.")
        else:
            flash(request, "Folder added. Add a login to switch protection on.")
    return back(f"/sites/{site_id}/security#privacy")


@router.post("/sites/{site_id}/security/dirs/{dir_id}/users")
async def add_dir_user(request: Request, site_id: int, dir_id: int):
    async with guard(request):
        form = await form_of(request)
        security.add_protected_user(site_id, dir_id, form.get("username", ""), form.get("password", ""), actor(request))
        flash(request, "Login saved.")
    return back(f"/sites/{site_id}/security#privacy")


@router.post("/sites/{site_id}/security/dirs/{dir_id}/users/{user_id}/delete")
async def del_dir_user(request: Request, site_id: int, dir_id: int, user_id: int):
    async with guard(request):
        await form_of(request)
        security.remove_protected_user(site_id, dir_id, user_id, actor(request))
        flash(request, "Login removed.")
    return back(f"/sites/{site_id}/security#privacy")


@router.post("/sites/{site_id}/security/dirs/{dir_id}/delete")
async def unprotect_dir(request: Request, site_id: int, dir_id: int):
    async with guard(request):
        await form_of(request)
        security.unprotect_dir(site_id, dir_id, actor(request))
        flash(request, "Protection removed.")
    return back(f"/sites/{site_id}/security#privacy")


@router.post("/sites/{site_id}/security/modsec")
async def set_modsec(request: Request, site_id: int):
    async with guard(request):
        form = await form_of(request)
        security.set_modsec(site_id, form.get("mode", "off"), form.get("disabled_rules", ""), actor(request))
        flash(request, "ModSecurity settings saved.")
    return back(f"/sites/{site_id}/security#modsec")


@router.post("/sites/{site_id}/security/modsec/disable-rule")
async def modsec_disable_rule(request: Request, site_id: int):
    async with guard(request):
        form = await form_of(request)
        site = get_site(site_id)
        ms = db.site_settings(site).get("modsec") or {"mode": "off", "disabled_rules": []}
        rules = sorted(set(ms.get("disabled_rules", [])) | {int(form.get("rule", "0"))})
        security.set_modsec(site_id, ms["mode"], " ".join(map(str, rules)), actor(request))
        flash(request, f"Rule {form.get('rule')} disabled for this site.")
    return back(f"/sites/{site_id}/security#modsec")


# ---------- PHP ----------

@router.get("/sites/{site_id}/php")
async def php_page(request: Request, site_id: int):
    site = get_site(site_id)
    overrides = db.site_settings(site).get("php_ini", {})
    return render(request, "site_php.html", site=site, tab="php", php_versions=phpfpm.available_versions(),
                  ini=phpfpm.effective_ini(overrides), overrides=overrides, keys=phpfpm.INI_KEYS)


@router.post("/sites/{site_id}/php/ini")
async def php_ini(request: Request, site_id: int):
    async with guard(request):
        form = await form_of(request)
        svc.set_php_ini(site_id, dict(form), actor(request))
        flash(request, "PHP settings applied.")
    return back(f"/sites/{site_id}/php")


@router.post("/sites/{site_id}/php/ini/reset")
async def php_ini_reset(request: Request, site_id: int):
    async with guard(request):
        await form_of(request)
        svc.set_php_ini(site_id, {k: d for k, (d, _) in phpfpm.INI_KEYS.items()}, actor(request))
        flash(request, "PHP settings reset to defaults.")
    return back(f"/sites/{site_id}/php")


# ---------- advanced: error pages, indexes ----------

@router.get("/sites/{site_id}/advanced")
async def advanced_page(request: Request, site_id: int, code: int = 404):
    site = get_site(site_id)
    st = db.site_settings(site)
    code = code if code in svc.ERROR_CODES else 404
    return render(request, "site_advanced.html", site=site, tab="advanced", codes=svc.ERROR_CODES, code=code,
                  enabled=set(st.get("error_pages", [])), content=svc.read_error_page(site_id, code),
                  indexes=st.get("indexes", []))


@router.post("/sites/{site_id}/advanced/errors")
async def save_error(request: Request, site_id: int):
    code = 404
    async with guard(request):
        form = await form_of(request)
        code = int(form.get("code", 404))
        svc.save_error_page(site_id, code, form.get("content", ""), form.get("enabled") == "1", actor(request))
        flash(request, f"{code} page saved.")
    return back(f"/sites/{site_id}/advanced?code={code}")


@router.post("/sites/{site_id}/advanced/indexes")
async def set_index(request: Request, site_id: int):
    async with guard(request):
        form = await form_of(request)
        enabled = form.get("enabled", "1") == "1"
        svc.set_index(site_id, form.get("path", ""), enabled, actor(request))
        flash(request, "Directory listing " + ("turned on." if enabled else "turned off."))
    return back(f"/sites/{site_id}/advanced#indexes")
