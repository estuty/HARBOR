"""Sites, databases, files, cron, backups, logs and statistics."""
import secrets
from urllib.parse import quote

from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import FileResponse, RedirectResponse

from .. import config, db
from ..services import OpError, backups as bk, get_site, site_root, sites as svc
from ..services import mail as mail_svc
from ..system import backup, files as fm, mysql, phpfpm, stats, weblogs
from ..web import ERRORS, actor, back, flash, form_of, guard, is_admin, render, reveal, visible_sites

router = APIRouter()


def site_ctx(site_id: int):
    site = get_site(site_id)
    return site, site_root(site)


@router.get("/sites")
async def sites_page(request: Request):
    ids = [s["id"] for s in visible_sites(request)]
    rows = db.all(f"""SELECT s.*, (SELECT COUNT(*) FROM databases d WHERE d.site_id = s.id) AS dbs,
                      (SELECT COUNT(*) FROM mailboxes m JOIN mail_domains md ON md.id = m.domain_id
                       WHERE md.site_id = s.id) AS boxes
                      FROM sites s WHERE s.id IN ({','.join('?' * len(ids)) or 'NULL'}) ORDER BY domain""", *ids)
    return render(request, "sites.html", sites=rows, php_versions=phpfpm.available_versions(),
                  default_php=phpfpm.default_version())


@router.post("/sites")
async def create_site(request: Request):
    async with guard(request):
        form = await form_of(request)
        site_id = svc.create_site(form.get("domain", ""), form.get("php_version", ""),
                                  form.get("include_www") == "1", actor(request))
        flash(request, "Site created. Point your domain at this server, then turn on HTTPS.")
        return back(f"/sites/{site_id}")
    return back("/sites")


@router.get("/sites/{site_id}")
async def site_overview(request: Request, site_id: int):
    try:
        site, root = site_ctx(site_id)
    except OpError:
        return back("/sites")
    usage = stats.dir_size(root) if root.exists() else 0
    zone = db.one("SELECT id FROM dns_zones WHERE domain = ?", site["domain"])
    from ..services import site_limits
    limits = site_limits(site)
    live = phpfpm.usage(site["sysuser"])
    return render(request, "site_overview.html", site=site, tab="overview", root=root, usage=usage,
                  limits=limits, live=live,
                  php_versions=phpfpm.available_versions(), zone=zone,
                  mail=mail_svc.get_domain(site_id),
                  db_count=db.one("SELECT COUNT(*) c FROM databases WHERE site_id = ?", site_id)["c"],
                  cron_count=db.one("SELECT COUNT(*) c FROM cron_jobs WHERE site_id = ?", site_id)["c"],
                  apps=db.all("SELECT * FROM app_installs WHERE site_id = ?", site_id),
                  host=request.url.hostname)


def _simple(path: str, fn, ok: str, to: str = ""):
    async def handler(request: Request, site_id: int):
        async with guard(request):
            form = await form_of(request)
            fn(site_id, form, actor(request))
            flash(request, ok)
        return back(to.format(id=site_id) if to else f"/sites/{site_id}")
    router.post(f"/sites/{{site_id}}/{path}")(handler)


_simple("php", lambda i, f, a: svc.change_php(i, f.get("php_version", ""), a), "PHP version updated.", "/sites/{id}/php")
_simple("www", lambda i, f, a: svc.set_www(i, f.get("include_www") == "1", a), "Domain aliases updated.")
_simple("ssl/enable", lambda i, f, a: svc.enable_ssl(i, a), "HTTPS is on. Certificates renew automatically.")
_simple("ssl/disable", lambda i, f, a: svc.disable_ssl(i, a), "HTTPS turned off.")
_simple("sftp/disable", lambda i, f, a: svc.set_sftp(i, None, a), "SFTP access disabled.")
_simple("limits", lambda i, f, a: svc.set_limits(i, f, a), "Limits applied. PHP for this site restarted with them.")
_simple("cron", lambda i, f, a: svc.add_cron(i, f.get("schedule", ""), f.get("command", ""), a),
        "Cron job added.", "/sites/{id}/cron")


@router.post("/sites/{site_id}/sftp")
async def set_sftp(request: Request, site_id: int):
    async with guard(request):
        form = await form_of(request)
        pw = form.get("password") or ""
        generated = not pw
        if generated:
            pw = mysql.generate_password(20)
        svc.set_sftp(site_id, pw, actor(request))
        site = get_site(site_id)
        if generated:
            reveal(request, {"title": "SFTP password", "pairs": [("Username", site["sysuser"]), ("Password", pw)]})
        flash(request, "SFTP access enabled.")
    return back(f"/sites/{site_id}")


@router.post("/sites/{site_id}/delete")
async def delete_site(request: Request, site_id: int):
    async with guard(request):
        form = await form_of(request)
        site = get_site(site_id)
        if form.get("confirm", "").strip().lower() != site["domain"]:
            raise OpError("Type the domain name exactly to confirm deletion.")
        svc.delete_site(site_id, form.get("remove_files") == "1", form.get("drop_dbs") == "1", actor(request))
        flash(request, f"{site['domain']} was deleted.")
        return back("/sites")
    return back(f"/sites/{site_id}")


# ---------- databases ----------

@router.get("/sites/{site_id}/databases")
async def databases_page(request: Request, site_id: int):
    site, _ = site_ctx(site_id)
    rows = db.all("SELECT * FROM databases WHERE site_id = ? ORDER BY name", site_id)
    try:
        sizes = mysql.sizes([r["name"] for r in rows])
    except Exception:
        sizes = {}
    return render(request, "site_databases.html", site=site, tab="databases", rows=rows, sizes=sizes)


@router.post("/sites/{site_id}/databases")
async def create_db(request: Request, site_id: int):
    async with guard(request):
        form = await form_of(request)
        _, name, user, pw = svc.create_database(site_id, form.get("name", ""), actor(request))
        reveal(request, {"title": "Database created — save this password now",
                         "pairs": [("Host", "localhost"), ("Database", name), ("Username", user), ("Password", pw)]})
    return back(f"/sites/{site_id}/databases")


@router.post("/sites/{site_id}/databases/{db_id}/{op}")
async def db_op(request: Request, site_id: int, db_id: int, op: str):
    async with guard(request):
        await form_of(request)
        if op == "reset":
            user, pw = svc.reset_db_password(site_id, db_id, actor(request))
            reveal(request, {"title": "New database password", "pairs": [("Username", user), ("Password", pw)]})
        elif op == "delete":
            svc.delete_database(site_id, db_id, actor(request))
            flash(request, "Database deleted.")
    return back(f"/sites/{site_id}/databases")


# ---------- files ----------

def files_url(site_id: int, rel: str) -> str:
    return f"/sites/{site_id}/files?path={quote(rel or '', safe='/')}"


@router.get("/sites/{site_id}/files")
async def files_page(request: Request, site_id: int, path: str = "public"):
    site, root = site_ctx(site_id)
    try:
        d, entries = fm.listing(root, path)
    except ERRORS as e:
        flash(request, str(e), "error")
        return back(files_url(site_id, "public")) if path != "public" else back(f"/sites/{site_id}")
    rel = fm.relpath(root, d)
    parent = "/".join(rel.split("/")[:-1]) if rel else None
    return render(request, "site_files.html", site=site, tab="files", entries=entries, rel=rel, parent=parent,
                  crumbs=fm.breadcrumbs(rel))


@router.get("/sites/{site_id}/files/edit")
async def edit_file(request: Request, site_id: int, path: str):
    site, root = site_ctx(site_id)
    try:
        content = fm.read_text(root, path)
    except ERRORS as e:
        flash(request, str(e), "error")
        return back(files_url(site_id, "/".join(path.split("/")[:-1])))
    return render(request, "site_file_edit.html", site=site, tab="files", rel=path, content=content,
                  crumbs=fm.breadcrumbs(path))


@router.get("/sites/{site_id}/files/download")
async def download_file(request: Request, site_id: int, path: str):
    site, root = site_ctx(site_id)
    try:
        f = fm.safe_path(root, path)
    except fm.FileError:
        return back(files_url(site_id, "public"))
    if not f.is_file():
        return back(files_url(site_id, "public"))
    return FileResponse(f, filename=f.name)


@router.post("/sites/{site_id}/files/save")
async def save_file(request: Request, site_id: int):
    site, root = site_ctx(site_id)
    rel = ""
    async with guard(request):
        form = await form_of(request)
        rel = form.get("path", "")
        fm.write_text(root, rel, form.get("content", ""), site["sysuser"])
        flash(request, f"Saved {rel.split('/')[-1]}.")
    return back(f"/sites/{site_id}/files/edit?path={quote(rel, safe='/')}")


@router.post("/sites/{site_id}/files/upload")
async def upload_files(request: Request, site_id: int):
    site, root = site_ctx(site_id)
    rel = "public"
    async with guard(request):
        form = await form_of(request)
        rel = form.get("dir", "public")
        if svc.over_disk_allowance(site):
            raise OpError("This site is over its disk allowance. Delete some files or ask an admin to raise it.")
        names = [fm.save_upload(root, rel, up.filename, up.file, site["sysuser"])
                 for up in form.getlist("files") if getattr(up, "filename", "")]
        flash(request, f"Uploaded {len(names)} file(s)." if names else "No files selected.", "ok" if names else "error")
    return back(files_url(site_id, rel))


@router.post("/sites/{site_id}/files/op")
async def file_op(request: Request, site_id: int):
    site, root = site_ctx(site_id)
    rel = "public"
    async with guard(request):
        form = await form_of(request)
        rel, op = form.get("dir", "public"), form.get("op")
        if op == "mkdir":
            fm.mkdir(root, rel, form.get("name", ""), site["sysuser"])
            flash(request, "Folder created.")
        elif op == "newfile":
            new_rel = fm.new_file(root, rel, form.get("name", ""), site["sysuser"])
            return back(f"/sites/{site_id}/files/edit?path={quote(new_rel, safe='/')}")
        elif op == "rename":
            fm.rename(root, form.get("target", ""), form.get("name", ""))
            flash(request, "Renamed.")
        elif op == "delete":
            fm.delete(root, form.get("target", ""))
            flash(request, "Deleted.")
        else:
            raise ValueError("Unknown action")
    return back(files_url(site_id, rel))


# ---------- cron ----------

@router.get("/sites/{site_id}/cron")
async def cron_page(request: Request, site_id: int):
    site, root = site_ctx(site_id)
    return render(request, "site_cron.html", site=site, tab="cron", root=root,
                  php_bin=phpfpm.php_binary(site["php_version"]),
                  jobs=db.all("SELECT * FROM cron_jobs WHERE site_id = ? ORDER BY id", site_id))


@router.post("/sites/{site_id}/cron/{job_id}/{op}")
async def cron_op(request: Request, site_id: int, job_id: int, op: str):
    async with guard(request):
        await form_of(request)
        if op == "toggle":
            svc.toggle_cron(site_id, job_id, actor(request))
            flash(request, "Cron job updated.")
        elif op == "delete":
            svc.delete_cron(site_id, job_id, actor(request))
            flash(request, "Cron job removed.")
    return back(f"/sites/{site_id}/cron")


# ---------- backups ----------

@router.get("/sites/{site_id}/backups")
async def backups_page(request: Request, site_id: int):
    site, _ = site_ctx(site_id)
    rows = db.all("SELECT * FROM backups WHERE site_id = ? ORDER BY id DESC", site_id)
    contents = {}
    for r in rows:
        if r["status"] == "done" and r["filename"]:
            try:
                contents[r["id"]] = backup.archive_dbs(backup.safe_file(site["domain"], r["filename"]))
            except ValueError:
                contents[r["id"]] = []
    owned = [d["name"] for d in db.all("SELECT name FROM databases WHERE site_id = ? ORDER BY name", site_id)]
    sched = db.site_settings(site).get("backup_schedule") or {"freq": "off", "keep": 7}
    from ..system import offsite
    remote, offsite_error = [], None
    if offsite.configured():
        try:
            remote = offsite.list_for(site["domain"])
        except offsite.OffsiteError as e:
            offsite_error = str(e)
    return render(request, "site_backups.html", site=site, tab="backups", rows=rows, contents=contents,
                  owned=owned, sched=sched, running=any(r["status"] in ("running", "restoring") for r in rows),
                  uploading=any(r["remote_status"] == "uploading" for r in rows),
                  offsite_on=offsite.configured(), remote=remote, offsite_error=offsite_error,
                  local_names={r["filename"] for r in rows if r["filename"] and r["status"] == "done"
                               and (backup.backup_dir(site["domain"]) / r["filename"]).exists()})


@router.post("/sites/{site_id}/backups")
async def create_backup(request: Request, site_id: int, tasks: BackgroundTasks):
    async with guard(request):
        await form_of(request)
        bid = bk.start_backup(site_id, actor(request))
        tasks.add_task(bk.run_backup, bid)
        flash(request, "Backup started. This page refreshes until it finishes.")
    return RedirectResponse(f"/sites/{site_id}/backups", status_code=303, background=tasks)


@router.post("/sites/{site_id}/backups/schedule")
async def backup_schedule(request: Request, site_id: int):
    async with guard(request):
        form = await form_of(request)
        bk.set_schedule(site_id, form.get("freq", "off"), int(form.get("keep") or 7), actor(request))
        flash(request, "Backup schedule saved.")
    return back(f"/sites/{site_id}/backups")


@router.post("/sites/{site_id}/backups/upload")
async def upload_backup(request: Request, site_id: int):
    site, _ = site_ctx(site_id)
    async with guard(request):
        form = await form_of(request)
        up = form.get("archive")
        if not getattr(up, "filename", "") or not up.filename.endswith(".tar.gz"):
            raise ValueError("Choose a Harbor backup (.tar.gz) to upload")
        name = f"{site['domain']}-uploaded-{secrets.token_hex(3)}.tar.gz"
        target = backup.backup_dir(site["domain"]) / name
        size = 0
        with open(target, "wb") as out:
            while chunk := up.file.read(1024 * 1024):
                size += len(chunk)
                out.write(chunk)
        target.chmod(0o600)
        if not backup.archive_dbs(target) and not _looks_like_backup(target, site["domain"]):
            target.unlink()
            raise ValueError("That file isn't a Harbor backup for this site")
        bk.register_upload(site_id, name, size, actor(request))
        flash(request, "Backup uploaded. You can restore from it below.")
    return back(f"/sites/{site_id}/backups")


def _looks_like_backup(path, domain: str) -> bool:
    import tarfile
    try:
        with tarfile.open(path, "r:gz") as t:
            return any(m.name.startswith(f"files/{domain}/") for m in t.getmembers()[:2000])
    except (tarfile.TarError, OSError):
        return False


@router.post("/sites/{site_id}/backups/{backup_id}/restore")
async def restore_backup(request: Request, site_id: int, backup_id: int, tasks: BackgroundTasks):
    async with guard(request):
        form = await form_of(request)
        job = bk.start_restore(site_id, backup_id, form.get("files") == "1", form.getlist("dbs"), actor(request))
        tasks.add_task(job)
        flash(request, "Restore started. This page refreshes until it finishes.")
    return RedirectResponse(f"/sites/{site_id}/backups", status_code=303, background=tasks)


@router.get("/sites/{site_id}/backups/{backup_id}/download")
async def download_backup(request: Request, site_id: int, backup_id: int):
    site, _ = site_ctx(site_id)
    row = db.one("SELECT * FROM backups WHERE id = ? AND site_id = ? AND status = 'done'", backup_id, site_id)
    if not row:
        return back(f"/sites/{site_id}/backups")
    f = backup.safe_file(site["domain"], row["filename"])
    return FileResponse(f, filename=f.name, media_type="application/gzip")


@router.post("/sites/{site_id}/backups/{backup_id}/delete")
async def delete_backup(request: Request, site_id: int, backup_id: int):
    async with guard(request):
        await form_of(request)
        bk.delete_backup(site_id, backup_id, actor(request))
        flash(request, "Backup deleted.")
    return back(f"/sites/{site_id}/backups")


# ---------- logs & statistics ----------

LOGS = {"access": "access.log", "error": "error.log", "php": "php-error.log"}


@router.get("/sites/{site_id}/logs")
async def logs_page(request: Request, site_id: int, log: str = "error", lines: int = 200):
    site, root = site_ctx(site_id)
    log = log if log in LOGS else "error"
    lines = max(50, min(lines, 2000))
    return render(request, "site_logs.html", site=site, tab="logs", log=log, logs=LOGS, lines=lines,
                  content=stats.tail(root / "logs" / LOGS[log], lines))


@router.get("/sites/{site_id}/stats")
async def stats_page(request: Request, site_id: int, days: int = 30):
    site, root = site_ctx(site_id)
    days = days if days in (7, 30, 90) else 30
    data = weblogs.analyse(root / "logs", site["domain"], days)
    peak = max([s["visitors"] for s in data["series"]] + [1])
    peak_bytes = max([s["bytes"] for s in data["series"]] + [1])
    return render(request, "site_stats.html", site=site, tab="stats", d=data, days=days, peak=peak,
                  peak_bytes=peak_bytes, blocked=set(db.site_settings(site).get("ip_deny", [])))
