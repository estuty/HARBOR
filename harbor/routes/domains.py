"""Subdomains and domain aliases for a site."""
from fastapi import APIRouter, Request

from .. import config, db
from ..services import get_site, subdomains as subs
from ..web import actor, back, flash, form_of, guard, render

router = APIRouter()


@router.get("/sites/{site_id}/subdomains")
async def subdomains_page(request: Request, site_id: int):
    site = get_site(site_id)
    return render(request, "site_subdomains.html", site=site, tab="subdomains",
                  subdomains=subs.listing(site_id), dns_on=config.features()["dns"])


@router.post("/sites/{site_id}/subdomains")
async def add_subdomain(request: Request, site_id: int):
    async with guard(request):
        form = await form_of(request)
        subs.create_subdomain(site_id, form.get("label", ""), form.get("docroot", ""), actor(request))
        flash(request, "Subdomain added.")
    return back(f"/sites/{site_id}/subdomains")


@router.post("/sites/{site_id}/subdomains/{sub_id}/ssl")
async def subdomain_ssl(request: Request, site_id: int, sub_id: int):
    async with guard(request):
        form = await form_of(request)
        if form.get("enable") == "1":
            subs.enable_ssl(site_id, sub_id, actor(request))
            flash(request, "HTTPS enabled for the subdomain.")
        else:
            subs.disable_ssl(site_id, sub_id, actor(request))
            flash(request, "HTTPS disabled for the subdomain.")
    return back(f"/sites/{site_id}/subdomains")


@router.post("/sites/{site_id}/subdomains/{sub_id}/delete")
async def delete_subdomain(request: Request, site_id: int, sub_id: int):
    async with guard(request):
        form = await form_of(request)
        subs.delete_subdomain(site_id, sub_id, form.get("remove_files") == "1", actor(request))
        flash(request, "Subdomain removed.")
    return back(f"/sites/{site_id}/subdomains")
