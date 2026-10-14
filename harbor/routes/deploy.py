"""Deploy tab: publish a site from a Git repository, plus the push webhook and API."""
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from .. import db
from ..services import OpError, deploy as svc, get_site
from ..web import ERRORS, actor, back, flash, form_of, guard, principal, render

router = APIRouter()


def _hook_url(request: Request, site_id: int, secret: str) -> tuple[str, bool]:
    """Webhook address, and whether it uses a trusted certificate."""
    host = request.headers.get("host", "")
    port = host.rsplit(":", 1)[1] if ":" in host and not host.endswith("]") else "8443"
    name, trusted = db.get_setting("hostname"), db.get_setting("hostname_ssl") == "1"
    base = f"https://{name}:{port}" if name and trusted else f"https://{host}"
    return f"{base}/hooks/deploy/{site_id}/{secret}", trusted


@router.get("/sites/{site_id}/deploy")
async def deploy_page(request: Request, site_id: int):
    try:
        site = get_site(site_id)
    except OpError:
        return back("/sites")
    cfg = svc.get_config(site_id)
    rows = svc.history(site_id) if cfg else []
    active = next((d for d in rows if d["status"] in ("queued", "running")), None)
    hook, trusted = _hook_url(request, site_id, cfg["hook_secret"]) if cfg else ("", False)
    return render(request, "site_deploy.html", site=site, tab="deploy", cfg=cfg, rows=rows, active=active,
                  live=svc.live(site_id) if cfg else None, key=svc.public_key(site) if cfg else "",
                  keep="\n".join(svc.keep_list(cfg)), hook=hook, trusted=trusted)


@router.post("/sites/{site_id}/deploy/connect")
async def connect(request: Request, site_id: int):
    async with guard(request):
        svc.connect(site_id, await form_of(request), actor(request))
        flash(request, "Connected. If the repository is private, add the deploy key below, then click Deploy now.")
    return back(f"/sites/{site_id}/deploy")


@router.post("/sites/{site_id}/deploy/settings")
async def settings(request: Request, site_id: int):
    async with guard(request):
        svc.update(site_id, await form_of(request), actor(request))
        flash(request, "Deploy settings saved.")
    return back(f"/sites/{site_id}/deploy")


@router.post("/sites/{site_id}/deploy/check")
async def check(request: Request, site_id: int):
    async with guard(request):
        await form_of(request)
        branches = svc.check_connection(site_id)
        cfg = svc.get_config(site_id)
        if not branches:
            raise OpError("Connected, but the repository has no branches yet. Push a commit first.")
        if cfg["branch"] not in branches:
            raise OpError(f"Connected, but there's no branch '{cfg['branch']}'. Branches: {', '.join(branches[:15])}")
        flash(request, f"Connection works. Branch '{cfg['branch']}' found"
                       + (f" (also: {', '.join(b for b in branches if b != cfg['branch'])[:200]})" if len(branches) > 1 else "")
                       + ".")
    return back(f"/sites/{site_id}/deploy")


@router.post("/sites/{site_id}/deploy/run")
async def run_deploy(request: Request, site_id: int):
    async with guard(request):
        await form_of(request)
        svc.start(site_id, "manual", actor(request))
        flash(request, "Deploy started.")
    return back(f"/sites/{site_id}/deploy")


@router.post("/sites/{site_id}/deploy/{dep_id}/redeploy")
async def redeploy(request: Request, site_id: int, dep_id: int):
    async with guard(request):
        await form_of(request)
        row = db.one("SELECT commit_sha FROM deployments WHERE id = ? AND site_id = ?", dep_id, site_id)
        if not row or not row["commit_sha"]:
            raise OpError("Unknown deploy")
        svc.start(site_id, "rollback", actor(request), sha=row["commit_sha"])
        flash(request, f"Redeploying version {row['commit_sha'][:7]}.")
    return back(f"/sites/{site_id}/deploy")


@router.post("/sites/{site_id}/deploy/{what}/rotate")
async def rotate(request: Request, site_id: int, what: str):
    async with guard(request):
        await form_of(request)
        if what == "key":
            svc.rotate_key(site_id, actor(request))
            flash(request, "New deploy key created. Replace the old one in your repository's settings.")
        elif what == "hook":
            svc.rotate_secret(site_id, actor(request))
            flash(request, "New webhook address created. Update it in your repository's webhook settings.")
        else:
            raise OpError("Unknown action")
    return back(f"/sites/{site_id}/deploy")


@router.post("/sites/{site_id}/deploy/disconnect")
async def disconnect(request: Request, site_id: int):
    async with guard(request):
        await form_of(request)
        svc.disconnect(site_id, actor(request))
        flash(request, "Disconnected. The live site's files were kept.")
    return back(f"/sites/{site_id}/deploy")


@router.get("/sites/{site_id}/deploy/{dep_id}/status")
async def status(site_id: int, dep_id: int):
    row = db.one("SELECT status, log, commit_sha FROM deployments WHERE id = ? AND site_id = ?", dep_id, site_id)
    if not row:
        return JSONResponse({"status": "missing"}, status_code=404)
    return {"status": row["status"], "log": (row["log"] or "")[-20000:], "commit": row["commit_sha"]}


# ---------------------------------------------------------------- webhook (public, secret in the address)

@router.post("/hooks/deploy/{site_id}/{token}")
async def webhook(request: Request, site_id: int, token: str):
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > 5 * 1024 * 1024:
            return PlainTextResponse("payload too large", status_code=413)
    try:
        code, msg = svc.handle_webhook(site_id, token, body, request.headers)
    except ERRORS as e:
        code, msg = 409, str(e)
    return PlainTextResponse(msg + "\n", status_code=code)


# ---------------------------------------------------------------- API (Bearer token, site access as usual)

@router.post("/api/v1/sites/{site_id}/deploy")
async def api_deploy(request: Request, site_id: int):
    try:
        dep_id = svc.start(site_id, "api", principal(request)["user"] + " (api)")
    except ERRORS as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    return JSONResponse({"deployment": dep_id, "status": "queued"}, status_code=202)


@router.get("/api/v1/sites/{site_id}/deployments")
async def api_history(site_id: int):
    rows = svc.history(site_id)
    return {"deployments": [{k: r[k] for k in ("id", "status", "trigger", "actor", "branch", "commit_sha",
                                                  "commit_msg", "created_at", "finished_at")} for r in rows]}
