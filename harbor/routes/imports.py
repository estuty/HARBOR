"""Move sites from cPanel: upload / pick / download a backup, review the plan, import."""
import json

from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import JSONResponse, RedirectResponse

from .. import auth, db
from ..services import importer, OpError
from ..system import phpfpm
from ..web import actor, back, flash, form_of, guard, render

router = APIRouter()


@router.get("/import")
async def import_page(request: Request):
    rows = db.all("SELECT id, source, size, status, created_at, finished_at, plan FROM imports ORDER BY id DESC LIMIT 20")
    items = []
    for r in rows:
        plan = json.loads(r["plan"] or "{}")
        items.append({**dict(r), "main": plan.get("main_domain"), "name": r["source"].rsplit("/", 1)[-1]})
    return render(request, "import.html", items=items, server_files=importer.list_server_files(),
                  import_dir=str(importer.IMPORT_DIR))


@router.put("/import/upload")
async def upload(request: Request, tasks: BackgroundTasks, name: str = "backup.tar.gz"):
    """Streamed upload (no size limit, no temporary copy). CSRF token in a header."""
    if not auth.check_csrf(request.session, request.headers.get("x-csrf-token")):
        return JSONResponse({"error": "Security token expired. Reload the page."}, status_code=403)
    try:
        target = importer.new_upload_path(name)
    except OpError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    size = 0
    try:
        with open(target, "wb") as out:
            async for chunk in request.stream():
                out.write(chunk)
                size += len(chunk)
    except Exception as e:
        target.unlink(missing_ok=True)
        return JSONResponse({"error": f"Upload interrupted: {e}"}, status_code=400)
    if size < 1024:
        target.unlink(missing_ok=True)
        return JSONResponse({"error": "That file is empty or too small to be a backup"}, status_code=400)
    iid, job = importer.start_scan(target, actor(request))
    tasks.add_task(job)
    return JSONResponse({"id": iid, "url": f"/import/{iid}"}, background=tasks)


@router.post("/import/server")
async def from_server(request: Request, tasks: BackgroundTasks):
    async with guard(request):
        form = await form_of(request)
        iid, job = importer.start_scan(importer.server_file(form.get("file", "")), actor(request))
        tasks.add_task(job)
        return RedirectResponse(f"/import/{iid}", status_code=303, background=tasks)
    return back("/import")


@router.post("/import/url")
async def from_url(request: Request, tasks: BackgroundTasks):
    async with guard(request):
        form = await form_of(request)
        iid, job = importer.start_download(form.get("url", "").strip(), actor(request))
        tasks.add_task(job)
        return RedirectResponse(f"/import/{iid}", status_code=303, background=tasks)
    return back("/import")


@router.get("/import/{import_id}")
async def import_detail(request: Request, import_id: int):
    try:
        row = importer.get(import_id)
    except OpError:
        return back("/import")
    plan = importer.plan_of(row)
    result = json.loads(row["result"] or "{}")
    from ..services.dns import server_ip
    return render(request, "import_detail.html", row=row, plan=plan, result=result, server_ip=server_ip(),
                  php_versions=phpfpm.available_versions(), log=(row["log"] or ""),
                  choices=json.loads(row["choices"] or "{}"))


@router.get("/import/{import_id}/status")
async def import_status(import_id: int):
    row = db.one("SELECT status, log FROM imports WHERE id = ?", import_id)
    if not row:
        return JSONResponse({"status": "missing"}, status_code=404)
    return {"status": row["status"], "log": (row["log"] or "")[-6000:]}


@router.post("/import/{import_id}/run")
async def run_import(request: Request, import_id: int, tasks: BackgroundTasks):
    async with guard(request):
        form = await form_of(request)
        choices = {"domains": form.getlist("domains"), "databases": form.get("databases") == "1",
                   "mail": form.get("mail") == "1", "dns": form.get("dns") == "1",
                   "repoint": form.get("repoint") == "1", "cron": form.get("cron") == "1"}
        if not choices["domains"]:
            raise OpError("Choose at least one domain to import")
        tasks.add_task(importer.start_run(import_id, choices, actor(request)))
        return RedirectResponse(f"/import/{import_id}", status_code=303, background=tasks)
    return back(f"/import/{import_id}")


@router.post("/import/{import_id}/delete")
async def delete_import(request: Request, import_id: int):
    async with guard(request):
        form = await form_of(request)
        importer.delete(import_id, form.get("file") == "1", actor(request))
        flash(request, "Removed.")
    return back("/import")
