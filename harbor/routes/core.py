"""Login, dashboard, activity, account & API tokens, team users, server settings, Dynamic DNS endpoint."""
import time
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse

from .. import auth, config, db
from ..services import accounts, server
from ..services import dns as dns_svc
from ..system import phpfpm, stats
from ..web import back, flash, form_of, guard, int_list, is_admin, principal, render, reveal, actor, visible_sites

router = APIRouter()


# ---------- auth ----------

@router.get("/login")
async def login_page(request: Request):
    if request.session.get("uid"):
        return back("/")
    return render(request, "login.html")


def _finish_login(request: Request, user, ip: str):
    auth.clear_failures(ip)
    request.session.clear()
    request.session["uid"] = user["id"]
    db.log(f"Signed in from {ip}" + (" (2FA)" if user["totp_enabled"] else ""), user["username"])
    if user["role"] == "admin" and not user["totp_enabled"] and db.get_setting("require_2fa") == "1":
        flash(request, "Two-factor sign-in is required on this server. Set it up to continue.", "error")
        return back("/account#twofactor")
    return back("/" if user["role"] == "admin" else "/sites")


@router.post("/login")
async def login(request: Request):
    ip = request.client.host if request.client else "?"
    try:
        form = await form_of(request)
    except PermissionError as e:
        flash(request, str(e), "error")
        return back("/login")
    if auth.throttled(ip):
        flash(request, "Too many failed attempts. Try again in 15 minutes.", "error")
        return back("/login")
    username = (form.get("username") or "").strip().lower()
    user = auth.authenticate(username, form.get("password") or "")
    if user:
        if user["totp_enabled"]:
            request.session.clear()
            request.session["pending_uid"] = user["id"]
            request.session["pending_at"] = int(time.time())
            return back("/login/2fa")
        return _finish_login(request, user, ip)
    auth.record_failure(ip)
    auth.log_auth_failure("sign-in", username, ip)
    db.log(f"Failed sign-in for '{username[:64]}' from {ip}", "anonymous", "warn")
    flash(request, "Incorrect username or password.", "error")
    return back("/login")


def _pending_user(request: Request):
    uid, at = request.session.get("pending_uid"), request.session.get("pending_at", 0)
    if not uid or time.time() - at > 300:
        return None
    return db.one("SELECT * FROM users WHERE id = ?", uid)


@router.get("/login/2fa")
async def login_2fa_page(request: Request):
    if not _pending_user(request):
        request.session.clear()
        return back("/login")
    return render(request, "login_2fa.html")


@router.post("/login/2fa")
async def login_2fa(request: Request):
    ip = request.client.host if request.client else "?"
    user = _pending_user(request)
    if not user:
        request.session.clear()
        flash(request, "That took too long. Please sign in again.", "error")
        return back("/login")
    try:
        form = await form_of(request)
    except PermissionError as e:
        flash(request, str(e), "error")
        return back("/login/2fa")
    if auth.throttled(ip):
        request.session.clear()
        flash(request, "Too many failed attempts. Try again in 15 minutes.", "error")
        return back("/login")
    if auth.verify_second_factor(user, form.get("code", "")):
        return _finish_login(request, user, ip)
    auth.record_failure(ip)
    auth.log_auth_failure("2fa", user["username"], ip)
    db.log(f"Wrong two-factor code for '{user['username']}' from {ip}", "anonymous", "warn")
    flash(request, "That code didn't work. Check your authenticator app's time, or use a recovery code.", "error")
    return back("/login/2fa")


@router.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return back("/login")


# ---------- dashboard ----------

@router.get("/")
async def dashboard(request: Request):
    if not is_admin(request):
        return back("/sites")
    sites = db.all("SELECT * FROM sites ORDER BY domain")
    counts = {
        "sites": len(sites),
        "ssl": sum(1 for s in sites if s["ssl"]),
        "databases": db.one("SELECT COUNT(*) c FROM databases")["c"],
        "mailboxes": db.one("SELECT COUNT(*) c FROM mailboxes")["c"],
        "zones": db.one("SELECT COUNT(*) c FROM dns_zones")["c"],
        "apps": db.one("SELECT COUNT(*) c FROM app_installs WHERE status = 'installed'")["c"],
    }
    from ..services import alerts
    me = db.one("SELECT totp_enabled FROM users WHERE id = ?", principal(request)["uid"])
    return render(request, "dashboard.html", alerts=alerts.active(), no_2fa=not me["totp_enabled"], stats=stats.server(), services=stats.service_status(stats.service_names()),
                  counts=counts, sites=sites[:8], setup_needed=not db.get_setting("hostname"),
                  activity=db.all("SELECT * FROM activity ORDER BY id DESC LIMIT 8"))


@router.get("/api/stats")
async def api_stats():
    return stats.server()


@router.get("/activity")
async def activity(request: Request):
    return render(request, "activity.html", rows=db.all("SELECT * FROM activity ORDER BY id DESC LIMIT 500"))


# ---------- my account & API tokens ----------

@router.get("/account")
async def account_page(request: Request):
    p = principal(request)
    me = db.one("SELECT * FROM users WHERE id = ?", p["uid"])
    setup = None
    secret = request.session.get("totp_setup")
    if not me["totp_enabled"] and secret:
        uri = auth.totp_uri(secret, me["username"], f"Harbor ({db.get_setting('hostname') or request.url.hostname})")
        setup = {"secret": secret, "qr": auth.qr_svg_data_uri(uri),
                 "spaced": " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))}
    left = db.one("SELECT COUNT(*) c FROM recovery_codes WHERE user_id = ? AND used_at IS NULL", p["uid"])["c"]
    return render(request, "account.html", me=me, setup=setup, codes_left=left,
                  require_2fa=db.get_setting("require_2fa") == "1",
                  tokens=db.all("SELECT * FROM api_tokens WHERE user_id = ? ORDER BY id DESC", p["uid"]),
                  base_url=str(request.base_url).rstrip("/"))


@router.post("/account/2fa/start")
async def start_2fa(request: Request):
    async with guard(request):
        await form_of(request)
        request.session["totp_setup"] = auth.new_totp_secret()
    return back("/account#twofactor")


@router.post("/account/2fa/confirm")
async def confirm_2fa(request: Request):
    async with guard(request):
        form = await form_of(request)
        secret = request.session.get("totp_setup")
        if not secret:
            raise ValueError("Start the setup again")
        step = auth.totp_match(secret, form.get("code", ""))
        if step is None:
            raise ValueError("That code didn't match. Make sure your phone's clock is set automatically, then try the newest code.")
        uid = principal(request)["uid"]
        db.execute("UPDATE users SET totp_secret = ?, totp_enabled = 1, totp_last = ? WHERE id = ?", secret, step, uid)
        request.session.pop("totp_setup", None)
        codes = auth.new_recovery_codes(uid)
        db.log("Turned on two-factor sign-in", actor(request))
        reveal(request, {"title": "Two-factor sign-in is on — save these recovery codes",
                         "note": "Each code works once, if you lose your phone. Store them somewhere safe (a password manager).",
                         "pairs": [(f"Code {i + 1}", c) for i, c in enumerate(codes)]})
    return back("/account#twofactor")


@router.post("/account/2fa/codes")
async def regenerate_codes(request: Request):
    async with guard(request):
        form = await form_of(request)
        uid = principal(request)["uid"]
        me = db.one("SELECT * FROM users WHERE id = ?", uid)
        if not me["totp_enabled"] or not auth.verify_second_factor(me, form.get("code", "")):
            raise PermissionError("Enter a current code from your authenticator app")
        codes = auth.new_recovery_codes(uid)
        db.log("Generated new recovery codes", actor(request))
        reveal(request, {"title": "New recovery codes — the old ones no longer work",
                         "pairs": [(f"Code {i + 1}", c) for i, c in enumerate(codes)]})
    return back("/account#twofactor")


@router.post("/account/2fa/disable")
async def disable_own_2fa(request: Request):
    async with guard(request):
        form = await form_of(request)
        uid = principal(request)["uid"]
        me = db.one("SELECT * FROM users WHERE id = ?", uid)
        if not auth.verify_password(form.get("password", ""), me["password_hash"]):
            raise PermissionError("Your password is incorrect")
        if me["role"] == "admin" and db.get_setting("require_2fa") == "1":
            raise PermissionError("Two-factor sign-in is required for admins on this server")
        auth.disable_2fa(uid)
        db.log("Turned off two-factor sign-in", actor(request))
        flash(request, "Two-factor sign-in turned off.")
    return back("/account#twofactor")


@router.post("/account/password")
async def change_own_password(request: Request):
    async with guard(request):
        form = await form_of(request)
        p = principal(request)
        row = db.one("SELECT * FROM users WHERE id = ?", p["uid"])
        if not auth.verify_password(form.get("current", ""), row["password_hash"]):
            raise PermissionError("Your current password is incorrect")
        if form.get("new") != form.get("confirm"):
            raise ValueError("The new passwords don't match")
        accounts.set_password(p["uid"], form.get("new", ""), actor(request))
        flash(request, "Password changed.")
    return back("/account")


@router.post("/account/tokens")
async def create_token(request: Request):
    async with guard(request):
        form = await form_of(request)
        token = accounts.create_token(principal(request)["uid"], form.get("name", ""), actor(request))
        reveal(request, {"title": "API token created — copy it now", "pairs": [("Token", token)]})
    return back("/account")


@router.post("/account/tokens/{token_id}/delete")
async def revoke_token(request: Request, token_id: int):
    async with guard(request):
        await form_of(request)
        accounts.revoke_token(principal(request)["uid"], token_id, is_admin(request), actor(request))
        flash(request, "Token revoked.")
    return back(request.headers.get("referer", "/account") if "/users" in request.headers.get("referer", "") else "/account")


# ---------- team users (admin) ----------

@router.get("/users")
async def users_page(request: Request):
    users = db.all("SELECT * FROM users ORDER BY role, username")
    access = {}
    for r in db.all("SELECT us.user_id, s.domain FROM user_sites us JOIN sites s ON s.id = us.site_id"):
        access.setdefault(r["user_id"], []).append(r["domain"])
    assigned = {}
    for r in db.all("SELECT user_id, site_id FROM user_sites"):
        assigned.setdefault(r["user_id"], set()).add(r["site_id"])
    return render(request, "users.html", users=users, access=access, assigned=assigned,
                  sites=db.all("SELECT id, domain FROM sites ORDER BY domain"),
                  tokens=db.all("""SELECT t.*, u.username FROM api_tokens t JOIN users u ON u.id = t.user_id
                                   ORDER BY t.id DESC"""))


@router.post("/users")
async def create_user(request: Request):
    async with guard(request):
        form = await form_of(request)
        accounts.create_user(form.get("username", ""), form.get("password", ""), form.get("role", "user"),
                             int_list(form.getlist("sites")), actor(request))
        flash(request, "User created. Share the username and password with them securely.")
    return back("/users")


@router.post("/users/{user_id}/access")
async def update_user(request: Request, user_id: int):
    async with guard(request):
        form = await form_of(request)
        accounts.update_user(user_id, form.get("role", "user"), int_list(form.getlist("sites")),
                             principal(request)["uid"], actor(request))
        flash(request, "Access updated.")
    return back("/users")


@router.post("/users/{user_id}/password")
async def reset_user_password(request: Request, user_id: int):
    async with guard(request):
        form = await form_of(request)
        accounts.set_password(user_id, form.get("password", ""), actor(request))
        flash(request, "Password changed.")
    return back("/users")


@router.post("/users/{user_id}/2fa/reset")
async def reset_user_2fa(request: Request, user_id: int):
    async with guard(request):
        await form_of(request)
        u = db.one("SELECT username FROM users WHERE id = ?", user_id)
        if not u:
            raise ValueError("User not found")
        auth.disable_2fa(user_id)
        db.log(f"Reset two-factor sign-in for {u['username']}", actor(request))
        flash(request, f"Two-factor sign-in removed for {u['username']}. They can set it up again from their account.")
    return back("/users")


@router.post("/users/{user_id}/delete")
async def delete_user(request: Request, user_id: int):
    async with guard(request):
        await form_of(request)
        accounts.delete_user(user_id, principal(request)["uid"], actor(request))
        flash(request, "User deleted.")
    return back("/users")


# ---------- server settings (admin) ----------

@router.get("/settings")
async def settings_page(request: Request):
    keys = ("hostname", "ns1", "ns2", "server_ipv4", "server_ipv6", "hostmaster", "hostname_ssl")
    from ..services import default_limits
    return render(request, "settings.html", s={k: db.get_setting(k) for k in keys},
                  limits={**phpfpm.DEFAULT_LIMITS, **default_limits()},
                  dns_auto=db.get_setting("dns_auto_zone", "1") == "1", detected_ip=dns_svc.server_ip(),
                  php_versions=phpfpm.available_versions())


@router.post("/settings")
async def save_settings(request: Request):
    async with guard(request):
        form = await form_of(request)
        changed = server.save(form, actor(request))
        flash(request, "Settings saved." if changed else "Nothing changed.")
    return back("/settings")


@router.post("/settings/secure")
async def secure_hostname(request: Request):
    async with guard(request):
        await form_of(request)
        host = server.secure_hostname(actor(request))
        flash(request, f"The panel, webmail and mail server now use a trusted certificate for {host}.")
    return back("/settings")


# ---------- Dynamic DNS (public endpoint, token authenticated) ----------

@router.api_route("/ddns/update", methods=["GET", "POST"])
async def ddns_update(request: Request, token: str = "", ip: str = ""):
    if request.method == "POST" and not token:
        form = await request.form()
        token, ip = form.get("token", ""), form.get("ip", "")
    client_ip = ip or (request.client.host if request.client else "")
    key = f"ddns:{request.client.host if request.client else '?'}"
    if auth.throttled(key):
        return PlainTextResponse("abuse", status_code=429)
    status, addr = dns_svc.ddns_update(token, client_ip)
    if status == "badauth":
        auth.record_failure(key)
    return PlainTextResponse(f"{status} {addr}".strip(), status_code=200 if status in ("good", "nochg") else 400)
