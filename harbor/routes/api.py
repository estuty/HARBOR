"""JSON API (Bearer token). A token acts with its owner's permissions.

    curl -H "Authorization: Bearer hbr_..." https://server:8443/api/v1/sites
"""
from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import JSONResponse

from .. import db
from ..services import backups as bk, dns as dns_svc, mail as mail_svc, sites as svc, get_site
from ..system import phpfpm
from ..web import ERRORS, principal, visible_sites

router = APIRouter(prefix="/api/v1")


def _err(e: Exception, status: int = 400):
    return JSONResponse({"error": str(e)}, status_code=status)


async def _body(request: Request) -> dict:
    try:
        data = await request.json()
        return data if isinstance(data, dict) else {}
    except ValueError:
        return {}


def _site(s) -> dict:
    return {"id": s["id"], "domain": s["domain"], "php_version": s["php_version"], "https": bool(s["ssl"]),
            "www_alias": bool(s["include_www"]), "system_user": s["sysuser"], "created_at": s["created_at"]}


def _who(request: Request) -> str:
    return principal(request)["user"] + " (api)"


@router.get("/sites")
async def list_sites(request: Request):
    return {"sites": [_site(s) for s in visible_sites(request)]}


@router.post("/sites")
async def create_site(request: Request):
    b = await _body(request)
    try:
        sid = svc.create_site(b.get("domain", ""), b.get("php_version") or phpfpm.default_version(),
                              bool(b.get("www_alias", True)), _who(request))
    except ERRORS as e:
        return _err(e)
    return JSONResponse(_site(get_site(sid)), status_code=201)


@router.get("/sites/{site_id}")
async def show_site(site_id: int):
    try:
        return _site(get_site(site_id))
    except ERRORS as e:
        return _err(e, 404)


@router.post("/sites/{site_id}/https")
async def https(request: Request, site_id: int):
    try:
        svc.enable_ssl(site_id, _who(request))
    except ERRORS as e:
        return _err(e)
    return {"ok": True}


@router.get("/sites/{site_id}/databases")
async def list_dbs(site_id: int):
    return {"databases": [{"id": r["id"], "name": r["name"], "user": r["username"]}
                          for r in db.all("SELECT * FROM databases WHERE site_id = ?", site_id)]}


@router.post("/sites/{site_id}/databases")
async def create_db(request: Request, site_id: int):
    b = await _body(request)
    try:
        db_id, name, user, pw = svc.create_database(site_id, b.get("name", ""), _who(request))
    except ERRORS as e:
        return _err(e)
    return JSONResponse({"id": db_id, "name": name, "user": user, "password": pw, "host": "localhost"}, status_code=201)


@router.get("/sites/{site_id}/backups")
async def list_backups(site_id: int):
    return {"backups": [{"id": r["id"], "file": r["filename"], "size": r["size"], "status": r["status"],
                         "kind": r["kind"], "created_at": r["created_at"]}
                        for r in db.all("SELECT * FROM backups WHERE site_id = ? ORDER BY id DESC", site_id)]}


@router.post("/sites/{site_id}/backups")
async def create_backup(request: Request, site_id: int, tasks: BackgroundTasks):
    try:
        bid = bk.start_backup(site_id, _who(request))
    except ERRORS as e:
        return _err(e)
    tasks.add_task(bk.run_backup, bid)
    return JSONResponse({"id": bid, "status": "running"}, status_code=202, background=tasks)


@router.get("/sites/{site_id}/mailboxes")
async def list_boxes(site_id: int):
    d = mail_svc.get_domain(site_id)
    if not d:
        return {"mailboxes": []}
    return {"mailboxes": [{"id": b["id"], "address": f"{b['local']}@{d['domain']}", "quota_mb": b["quota_mb"],
                           "enabled": bool(b["enabled"])}
                          for b in db.all("SELECT * FROM mailboxes WHERE domain_id = ?", d["id"])]}


@router.post("/sites/{site_id}/mailboxes")
async def create_box(request: Request, site_id: int):
    b = await _body(request)
    try:
        address = mail_svc.create_mailbox(site_id, b.get("local", ""), b.get("password", ""),
                                          int(b.get("quota_mb", 1024)), _who(request))
    except ERRORS as e:
        return _err(e)
    return JSONResponse({"address": address}, status_code=201)


@router.get("/dns/{zone_id}/records")
async def list_records(zone_id: int):
    return {"records": [dict(r) for r in db.all("SELECT id, name, type, content, ttl, priority FROM dns_records "
                                                "WHERE zone_id = ?", zone_id)]}


@router.post("/dns/{zone_id}/records")
async def add_record(request: Request, zone_id: int):
    b = await _body(request)
    try:
        rid = dns_svc.add_record(zone_id, b.get("name", ""), b.get("type", ""), b.get("content", ""),
                                 b.get("ttl"), b.get("priority"), _who(request))
    except ERRORS as e:
        return _err(e)
    return JSONResponse({"id": rid}, status_code=201)
