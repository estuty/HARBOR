"""Health pages: whole server (admins) and per site."""
import asyncio

from fastapi import APIRouter, Request

from .. import db
from ..services import get_site, health
from ..web import render, visible_sites

router = APIRouter()


@router.get("/health")
async def server_health(request: Request):
    sites = visible_sites(request)
    server, *site_results = await asyncio.gather(asyncio.to_thread(health.server_checks),
                                                 *[asyncio.to_thread(health.site_checks, s) for s in sites])
    per_site = [{"site": s, "checks": c, "sum": health.summarize(c)} for s, c in zip(sites, site_results)]
    return render(request, "health.html", server=server, server_sum=health.summarize(server), per_site=per_site)


@router.get("/sites/{site_id}/health")
async def site_health(request: Request, site_id: int):
    site = get_site(site_id)
    checks = await asyncio.to_thread(health.site_checks, site)
    return render(request, "site_health.html", site=site, tab="health", checks=checks, summary=health.summarize(checks))
