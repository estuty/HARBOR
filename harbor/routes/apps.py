"""Application Manager and Site Publisher."""
from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import RedirectResponse

from .. import db
from ..services import apps as svc, get_site
from ..web import actor, back, flash, form_of, guard, principal, render

router = APIRouter()


@router.get("/sites/{site_id}/apps")
async def apps_page(request: Request, site_id: int):
    site = get_site(site_id)
    installs = db.all("SELECT * FROM app_installs WHERE site_id = ? ORDER BY path", site_id)
    pub = db.site_settings(site).get("publisher") or {}
    return render(request, "site_apps.html", site=site, tab="apps", apps=svc.APPS, templates_=svc.TEMPLATES,
                  installs=installs, pub=pub, busy=any(i["status"] in ("installing", "updating") for i in installs),
                  default_email=f"admin@{site['domain']}")


@router.post("/sites/{site_id}/apps/wordpress")
async def install_wp(request: Request, site_id: int, tasks: BackgroundTasks):
    async with guard(request):
        form = await form_of(request)
        job = svc.start_wordpress(site_id, form.get("subdir", ""), form.get("title", ""), form.get("admin_user", ""),
                                  form.get("admin_email", ""), form.get("admin_pass", ""), actor(request))
        tasks.add_task(job)
        flash(request, "Installing WordPress. This takes about a minute.")
    return RedirectResponse(f"/sites/{site_id}/apps", status_code=303, background=tasks)


@router.post("/sites/{site_id}/apps/{install_id}/update")
async def update_app(request: Request, site_id: int, install_id: int, tasks: BackgroundTasks):
    async with guard(request):
        await form_of(request)
        tasks.add_task(svc.update_app(site_id, install_id, actor(request)))
        flash(request, "Updating WordPress core, plugins and themes.")
    return RedirectResponse(f"/sites/{site_id}/apps", status_code=303, background=tasks)


@router.post("/sites/{site_id}/apps/{install_id}/remove")
async def remove_app(request: Request, site_id: int, install_id: int):
    async with guard(request):
        form = await form_of(request)
        svc.remove_app(site_id, install_id, form.get("files") == "1", form.get("db") == "1", actor(request))
        flash(request, "Application removed.")
    return back(f"/sites/{site_id}/apps")


@router.post("/sites/{site_id}/publisher")
async def publish(request: Request, site_id: int):
    async with guard(request):
        form = await form_of(request)
        svc.publish_template(site_id, form.get("template", ""), dict(form), actor(request))
        flash(request, "Published. Your previous index.html was kept as a .bak file.")
    return back(f"/sites/{site_id}/apps#publisher")
