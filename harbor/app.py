import logging
import os
import re

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from . import auth, config, db
from .services import backups
from .web import HERE

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

db.init()
backups.recover_interrupted()
from .services import importer as _importer  # noqa: E402
_importer.recover_interrupted()
from .services import deploy as _deploy  # noqa: E402
_deploy.recover_interrupted()

app = FastAPI(title="Harbor", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")

PUBLIC = ("/login", "/static/", "/ddns/", "/hooks/")
ADMIN_ONLY = ("/users", "/settings", "/activity", "/mail", "/api/stats", "/security", "/import", "/health")
SITE_RE = re.compile(r"^/(?:api/v1/)?sites/(\d+)")
ZONE_RE = re.compile(r"^/(?:api/v1/)?dns/(\d+)")


def _allowed(principal: dict, request: Request) -> bool:
    path, method = request.url.path, request.method
    if principal["role"] == "admin":
        return True
    if path.startswith(ADMIN_ONLY):
        return False
    if path in ("/sites", "/api/v1/sites") and method == "POST":
        return False
    m = SITE_RE.match(path)
    if m:
        if path.endswith("/delete") and path.count("/") == 3:
            return False  # deleting a whole site is admin-only
        if path.endswith("/limits"):
            return False  # team users can't change their own resource limits
        return auth.can_access_site(principal, int(m.group(1)))
    m = ZONE_RE.match(path)
    if m:
        z = db.one("SELECT site_id FROM dns_zones WHERE id = ?", int(m.group(1)))
        return bool(z and z["site_id"] and auth.can_access_site(principal, z["site_id"]))
    if path == "/dns" and method == "POST":
        return False
    return True


@app.middleware("http")
async def access_control(request: Request, call_next):
    path = request.url.path
    principal = None
    if path.startswith("/api/v1/"):
        header = request.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            principal = auth.principal_from_token(header[7:].strip())
        if not principal:
            return JSONResponse({"error": "invalid or missing API token"}, status_code=401)
    elif not path.startswith(PUBLIC):
        uid = request.session.get("uid")
        row = db.one("SELECT id, username, role, totp_enabled FROM users WHERE id = ?", uid) if uid else None
        if not row:
            if uid:
                request.session.clear()  # user was deleted; a pending 2FA sign-in is left alone
            if path.startswith("/api/"):
                return JSONResponse({"error": "unauthorized"}, status_code=401)
            return RedirectResponse("/login", status_code=303)
        principal = {"uid": row["id"], "user": row["username"], "role": row["role"]}
        if (row["role"] == "admin" and not row["totp_enabled"] and db.get_setting("require_2fa") == "1"
                and not path.startswith(("/account", "/logout"))):
            return RedirectResponse("/account#twofactor", status_code=303)
    if principal:
        request.state.principal = principal
        if not _allowed(principal, request):
            if path.startswith("/api/"):
                return JSONResponse({"error": "forbidden"}, status_code=403)
            return PlainTextResponse("You don't have access to this page.", status_code=403)
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers.setdefault("Content-Security-Policy",
        "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
    return response


# Session middleware must wrap access control, so it is added last.
app.add_middleware(SessionMiddleware, secret_key=auth.secret_key(), session_cookie="harbor_session",
                   max_age=60 * 60 * 12, same_site="strict",
                   https_only=os.environ.get("HARBOR_COOKIE_SECURE", "0" if config.DRY_RUN else "1") == "1")

from .routes import core, sites, webrules, mail, dns, apps, api, admin, imports, health, deploy  # noqa: E402

for r in (core, sites, webrules, mail, dns, apps, api, admin, imports, health, deploy):
    app.include_router(r.router)


@app.on_event("startup")
async def _start_scheduler():
    if os.environ.get("HARBOR_SCHEDULER", "1") == "1":
        backups.start_scheduler()
        from .services import alerts
        alerts.start_monitor()
