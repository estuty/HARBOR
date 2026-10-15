"""Server-wide admin pages: security, offsite backups, alerts, updates, default limits."""
import json

from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import JSONResponse, RedirectResponse

from .. import __version__, config, db, validators
from ..services import OpError, alerts, protection, updates
from ..services import backups as bk
from ..system import firewall, notify, offsite, phpfpm
from ..web import actor, back, flash, form_of, guard, principal, render

router = APIRouter()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


# ---------- security ----------

@router.get("/security")
async def security_page(request: Request):
    me = db.one("SELECT totp_enabled FROM users WHERE id = ?", principal(request)["uid"])
    return render(request, "security.html", allow=protection.allowlist(),
                  allow_webmail=db.get_setting("panel_allow_webmail") == "1", my_ip=client_ip(request),
                  require_2fa=db.get_setting("require_2fa") == "1", my_2fa=bool(me and me["totp_enabled"]),
                  jails=firewall.jail_status() if config.features()["fail2ban"] else [],
                  f2b=config.features()["fail2ban"] and firewall.fail2ban_running(),
                  failures=firewall.recent_failures(15),
                  no2fa=db.all("SELECT username FROM users WHERE role = 'admin' AND totp_enabled = 0"))


@router.post("/security/access")
async def save_access(request: Request):
    async with guard(request):
        form = await form_of(request)
        ips = protection.save_access(form.get("ips", ""), form.get("webmail") == "1", client_ip(request), actor(request))
        flash(request, f"Only {len(ips)} address(es) can open the panel now." if ips
              else "The panel can be opened from any address.")
    return back("/security")


@router.post("/security/require-2fa")
async def require_2fa(request: Request):
    async with guard(request):
        form = await form_of(request)
        protection.set_require_2fa(form.get("on") == "1", principal(request)["uid"], actor(request))
        flash(request, "Saved.")
    return back("/security")


@router.post("/security/ban")
async def ban(request: Request):
    async with guard(request):
        form = await form_of(request)
        ip = protection.ban(form.get("ip", ""), actor(request))
        flash(request, f"{ip} is blocked from every service on this server.")
    return back("/security#bans")


@router.post("/security/unban")
async def unban(request: Request):
    async with guard(request):
        form = await form_of(request)
        protection.unban(form.get("ip", ""), form.get("jail", ""), actor(request))
        flash(request, f"{form.get('ip')} unblocked.")
    return back("/security#bans")


# ---------- offsite backups ----------

@router.get("/settings/backups")
async def offsite_page(request: Request):
    s = offsite.settings()
    recent = db.all("""SELECT b.*, s.domain FROM backups b JOIN sites s ON s.id = b.site_id
                       WHERE b.remote_status IS NOT NULL ORDER BY b.id DESC LIMIT 15""")
    return render(request, "settings_backups.html", tab="backups", s=s, configured=offsite.configured(), recent=recent)


def _offsite_form(form) -> dict:
    s = offsite.settings()
    endpoint = (form.get("endpoint") or "").strip().rstrip("/")
    if endpoint and not endpoint.startswith("https://") and not endpoint.startswith("http://"):
        endpoint = "https://" + endpoint
    bucket = (form.get("bucket") or "").strip()
    if bucket and not validators.re.fullmatch(r"[a-z0-9][a-z0-9.\-]{1,62}", bucket):
        raise OpError("Bucket names use lowercase letters, digits, dots and dashes")
    prefix = (form.get("prefix") or "harbor").strip().strip("/")
    if not validators.re.fullmatch(r"[A-Za-z0-9._\-/]{1,100}", prefix):
        raise OpError("Folder prefix: letters, digits and . _ - / only")
    keep = (form.get("keep_days") or "30").strip()
    if not keep.isdigit():
        raise OpError("Keep days must be a number (0 = keep forever)")
    return {
        "offsite_endpoint": endpoint, "offsite_region": (form.get("region") or "").strip(),
        "offsite_bucket": bucket, "offsite_prefix": prefix, "offsite_key": (form.get("key") or "").strip(),
        # leaving the secret blank keeps the saved one
        "offsite_secret": ((form.get("secret") or "").strip() or s["offsite_secret"]) if bucket else "",
        "offsite_auto": form.get("auto") == "1", "offsite_keep_days": int(keep),
    }


@router.post("/settings/backups")
async def save_offsite(request: Request):
    async with guard(request):
        form = await form_of(request)
        s = _offsite_form(form)
        if s["offsite_bucket"]:
            offsite.test(s)  # refuse to save settings that don't work
        for k, v in s.items():
            db.set_setting(k, ("1" if v else "0") if isinstance(v, bool) else str(v))
        db.log("Offsite backup settings " + (f"saved (bucket {s['offsite_bucket']})" if s["offsite_bucket"] else "cleared"),
               actor(request))
        flash(request, "Connected and saved. New backups will be copied offsite." if s["offsite_bucket"]
              else "Offsite backups turned off.")
    return back("/settings/backups")


@router.post("/settings/backups/test")
async def test_offsite(request: Request):
    async with guard(request):
        form = await form_of(request)
        bucket = offsite.test(_offsite_form(form))
        flash(request, f"Connection works: wrote, read and deleted a test file in '{bucket}'. Click Save to keep these settings.")
    return back("/settings/backups")


@router.post("/sites/{site_id}/backups/{backup_id}/offsite")
async def copy_offsite(request: Request, site_id: int, backup_id: int, tasks: BackgroundTasks):
    async with guard(request):
        await form_of(request)
        if not offsite.configured():
            raise OpError("Set up offsite storage first (Settings → Backups)")
        if not db.one("SELECT id FROM backups WHERE id = ? AND site_id = ? AND status = 'done'", backup_id, site_id):
            raise OpError("Backup not found")
        db.execute("UPDATE backups SET remote_status = 'uploading' WHERE id = ?", backup_id)
        tasks.add_task(bk.upload_offsite, backup_id)
        flash(request, "Copying offsite…")
    return RedirectResponse(f"/sites/{site_id}/backups", status_code=303, background=tasks)


@router.post("/sites/{site_id}/backups/offsite/fetch")
async def fetch_offsite(request: Request, site_id: int):
    async with guard(request):
        form = await form_of(request)
        bk.fetch_offsite(site_id, form.get("key", ""), actor(request))
        flash(request, "Downloaded to this server. Use Restore on it below.")
    return back(f"/sites/{site_id}/backups")


# ---------- alerts ----------

ALERT_KEYS = ("alert_email", "alert_webhook", "smtp_host", "smtp_port", "smtp_security", "smtp_user", "smtp_from",
              "alert_disk_pct")


@router.get("/settings/alerts")
async def alerts_page(request: Request):
    s = {k: db.get_setting(k) for k in ALERT_KEYS}
    s["smtp_port"] = s["smtp_port"] or "587"
    s["smtp_security"] = s["smtp_security"] or "starttls"
    s["alert_disk_pct"] = s["alert_disk_pct"] or "85"
    s["has_password"] = bool(db.get_setting("smtp_password"))
    history = db.all("SELECT * FROM alerts ORDER BY COALESCE(resolved_at, '9999') DESC, first_seen DESC LIMIT 30")
    return render(request, "settings_alerts.html", tab="alerts", s=s, active=alerts.active(), history=history)


@router.post("/settings/alerts")
async def save_alerts(request: Request):
    async with guard(request):
        form = await form_of(request)
        emails = [e.strip() for e in (form.get("alert_email") or "").replace(";", ",").split(",") if e.strip()]
        for e in emails:
            validators.email(e)
        hook = (form.get("alert_webhook") or "").strip()
        if hook and not validators.re.match(r"^https://\S+$", hook):
            raise OpError("Webhook must be an https:// address")
        host = (form.get("smtp_host") or "").strip()
        if host:
            validators.hostname(host)
        port = (form.get("smtp_port") or "587").strip()
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise OpError("SMTP port must be a number")
        sec = form.get("smtp_security", "starttls")
        if sec not in ("starttls", "ssl", "none"):
            raise OpError("Unknown security option")
        sender = (form.get("smtp_from") or "").strip()
        if sender:
            validators.email(sender)
        disk = (form.get("alert_disk_pct") or "85").strip()
        if not disk.isdigit() or not 50 <= int(disk) <= 99:
            raise OpError("Disk warning level must be 50-99%")
        values = {"alert_email": ", ".join(emails), "alert_webhook": hook, "smtp_host": host, "smtp_port": port,
                  "smtp_security": sec, "smtp_user": validators.single_line(form.get("smtp_user", ""), "SMTP user", 200),
                  "smtp_from": sender, "alert_disk_pct": disk}
        for k, v in values.items():
            db.set_setting(k, v)
        if form.get("smtp_password"):
            db.set_setting("smtp_password", form.get("smtp_password"))
        if form.get("clear_password") == "1":
            db.set_setting("smtp_password", "")
        db.log("Alert settings saved", actor(request))
        flash(request, "Alert settings saved. Send a test to check delivery.")
    return back("/settings/alerts")


@router.post("/settings/alerts/test")
async def test_alert(request: Request):
    async with guard(request):
        await form_of(request)
        if not notify.channels_configured():
            raise OpError("Add an email address or a webhook first")
        host = db.get_setting("hostname") or "Harbor"
        errors = notify.send(f"[{host}] Test alert", "If you can read this, Harbor alerts reach you. Nothing is wrong.")
        if errors:
            raise OpError(" · ".join(errors))
        flash(request, "Test alert sent. Check your inbox / channel.")
    return back("/settings/alerts")


@router.post("/settings/alerts/check")
async def check_now(request: Request, tasks: BackgroundTasks):
    async with guard(request):
        await form_of(request)
        tasks.add_task(alerts.run_checks, True)
        flash(request, "Running all checks now. Refresh in a few seconds.")
    return RedirectResponse("/settings/alerts", status_code=303, background=tasks)


# ---------- updates ----------

@router.get("/settings/updates")
async def updates_page(request: Request):
    rows = db.all("SELECT * FROM updates ORDER BY id DESC LIMIT 10")
    return render(request, "settings_updates.html", tab="updates", version=__version__, rows=rows,
                  releases=updates.releases(), busy=updates.running(), up=updates.status())


@router.post("/settings/updates/check")
async def check_updates(request: Request):
    import asyncio
    async with guard(request):
        await form_of(request)
        found = await asyncio.to_thread(updates.check)
        st = updates.status()
        if st["error"]:
            raise OpError(f"Couldn't check for updates. {st['error']}")
        if found:
            flash(request, f"Harbor {found['version']} is available.")
        elif st["latest"]:
            flash(request, f"You're running the latest version ({__version__}).")
        else:
            flash(request, f"No releases are published in {st['repo']} yet.")
    return back("/settings/updates")


@router.post("/settings/updates/latest")
async def install_latest(request: Request):
    import asyncio
    async with guard(request):
        await form_of(request)
        await asyncio.to_thread(updates.install_latest, actor(request))
        flash(request, "Update started. The panel restarts in a moment; this page follows along by itself.")
    return back("/settings/updates")


@router.post("/settings/updates/prefs")
async def update_prefs(request: Request):
    async with guard(request):
        updates.save_prefs(await form_of(request), actor(request))
        flash(request, "Update settings saved.")
    return back("/settings/updates")


@router.get("/settings/updates/status")
async def update_status():
    row = db.one("SELECT * FROM updates ORDER BY id DESC LIMIT 1")
    return JSONResponse({"version": __version__, "status": row["status"] if row else None,
                         "log": (row["log"] or "")[-4000:] if row else ""})


@router.post("/settings/updates/upload")
async def upload_update(request: Request):
    async with guard(request):
        form = await form_of(request)
        up = form.get("package")
        if not getattr(up, "filename", ""):
            raise OpError("Choose the Harbor .tar.gz package")
        path = updates.save_upload(up.file, up.filename)
        updates.start(path, actor(request))
        flash(request, "Update started. The panel restarts in a moment; this page refreshes by itself.")
    return back("/settings/updates")


@router.post("/settings/updates/url")
async def url_update(request: Request):
    async with guard(request):
        form = await form_of(request)
        path = updates.download(form.get("url", "").strip())
        updates.start(path, actor(request))
        flash(request, "Update started. The panel restarts in a moment; this page refreshes by itself.")
    return back("/settings/updates")


@router.post("/settings/updates/rollback")
async def rollback(request: Request):
    async with guard(request):
        form = await form_of(request)
        updates.rollback(form.get("release", ""), actor(request))
        flash(request, "Rolling back. The panel restarts in a moment.")
    return back("/settings/updates")


# ---------- default limits ----------

@router.post("/settings/limits")
async def default_limits(request: Request):
    async with guard(request):
        form = await form_of(request)
        out = {}
        for key, lo, hi in (("cpu_pct", 10, 6400), ("memory_mb", 128, 262144), ("processes", 1, 500), ("disk_mb", 100, 10_000_000)):
            v = (form.get(key) or "0").strip()
            if not v.isdigit() or not (int(v) == 0 or lo <= int(v) <= hi):
                raise OpError(f"{key}: 0 for no limit, or {lo}-{hi}")
            out[key] = int(v)
        out["processes"] = out["processes"] or phpfpm.DEFAULT_LIMITS["processes"]
        db.set_setting("default_limits", json.dumps(out))
        db.log("Default limits for new sites saved", actor(request))
        flash(request, "Saved. New sites get these limits; change existing sites on their Overview tab.")
    return back("/settings#limits")
