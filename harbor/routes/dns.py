"""DNS zone editor and Dynamic DNS."""
from fastapi import APIRouter, Request

from .. import db, validators
from ..services import OpError, dns as svc
from ..web import actor, back, flash, form_of, guard, is_admin, principal, render, reveal

router = APIRouter()


@router.get("/dns")
async def zones_page(request: Request):
    if is_admin(request):
        zones = db.all("""SELECT z.*, (SELECT COUNT(*) FROM dns_records r WHERE r.zone_id = z.id) AS n
                          FROM dns_zones z ORDER BY domain""")
    else:
        zones = db.all("""SELECT z.*, (SELECT COUNT(*) FROM dns_records r WHERE r.zone_id = z.id) AS n
                          FROM dns_zones z JOIN user_sites us ON us.site_id = z.site_id
                          WHERE us.user_id = ? ORDER BY domain""", principal(request)["uid"])
    return render(request, "dns.html", zones=zones, ns=svc.nameservers(), ip=svc.server_ip(),
                  ns_set=bool(db.get_setting("ns1")))


@router.post("/dns")
async def create_zone(request: Request):
    async with guard(request):
        form = await form_of(request)
        zid = svc.create_zone(form.get("domain", ""), actor(request), with_defaults=form.get("defaults") == "1")
        flash(request, "Zone created.")
        return back(f"/dns/{zid}")
    return back("/dns")


@router.get("/dns/{zone_id}")
async def zone_page(request: Request, zone_id: int, edit: int = 0):
    try:
        z = svc.get_zone(zone_id)
    except OpError:
        return back("/dns")
    records = db.all("""SELECT * FROM dns_records WHERE zone_id = ?
                        ORDER BY CASE WHEN name = '@' THEN 0 ELSE 1 END, name, type""", zone_id)
    return render(request, "dns_zone.html", z=z, records=records, edit=edit, types=validators.RECORD_TYPES,
                  ddns=db.all("SELECT * FROM ddns_hosts WHERE zone_id = ? ORDER BY name", zone_id),
                  ns=svc.nameservers(), base_url=str(request.base_url).rstrip("/"))


@router.post("/dns/{zone_id}/records")
async def add_record(request: Request, zone_id: int):
    async with guard(request):
        form = await form_of(request)
        svc.add_record(zone_id, form.get("name", ""), form.get("type", ""), form.get("content", ""),
                       form.get("ttl"), form.get("priority"), actor(request))
        flash(request, "Record added. Changes reach the internet within the record's TTL.")
    return back(f"/dns/{zone_id}")


@router.post("/dns/{zone_id}/records/{record_id}")
async def update_record(request: Request, zone_id: int, record_id: int):
    async with guard(request):
        form = await form_of(request)
        svc.update_record(zone_id, record_id, form.get("name", ""), form.get("content", ""),
                          form.get("ttl"), form.get("priority"), actor(request))
        flash(request, "Record updated.")
        return back(f"/dns/{zone_id}")
    return back(f"/dns/{zone_id}?edit={record_id}")


@router.post("/dns/{zone_id}/records/{record_id}/delete")
async def delete_record(request: Request, zone_id: int, record_id: int):
    async with guard(request):
        await form_of(request)
        svc.delete_record(zone_id, record_id, actor(request))
        flash(request, "Record deleted.")
    return back(f"/dns/{zone_id}")


@router.post("/dns/{zone_id}/delete")
async def delete_zone(request: Request, zone_id: int):
    async with guard(request):
        form = await form_of(request)
        if not is_admin(request):
            raise PermissionError("Only admins can delete zones")
        z = svc.get_zone(zone_id)
        if form.get("confirm", "").strip().lower() != z["domain"]:
            raise ValueError("Type the domain name to confirm")
        svc.delete_zone(zone_id, actor(request))
        flash(request, f"Zone {z['domain']} deleted.")
        return back("/dns")
    return back(f"/dns/{zone_id}")


@router.post("/dns/{zone_id}/ddns")
async def create_ddns(request: Request, zone_id: int):
    async with guard(request):
        form = await form_of(request)
        z = svc.get_zone(zone_id)
        name = validators.dns_name(form.get("name", ""))
        token = svc.create_ddns(zone_id, name, form.get("description", ""), actor(request))
        url = f"{str(request.base_url).rstrip('/')}/ddns/update?token={token}"
        reveal(request, {"title": f"Dynamic DNS key for {name}.{z['domain']} — copy it now",
                         "pairs": [("Update URL", url), ("Token", token)]})
    return back(f"/dns/{zone_id}#ddns")


@router.post("/dns/{zone_id}/ddns/{ddns_id}/delete")
async def delete_ddns(request: Request, zone_id: int, ddns_id: int):
    async with guard(request):
        await form_of(request)
        svc.delete_ddns(zone_id, ddns_id, actor(request))
        flash(request, "Dynamic DNS host removed.")
    return back(f"/dns/{zone_id}#ddns")
