"""Email: per-site mailboxes, forwarders, catch-all, autoresponders; admin overview."""
from fastapi import APIRouter, Request

from .. import db
from ..services import get_site, mail as svc
from ..services import dns as dns_svc
from ..web import actor, back, flash, form_of, guard, render, reveal
from ..system.mysql import generate_password

router = APIRouter()


def _mail_host() -> str:
    return db.get_setting("hostname") or "mail.<your-server>"


def _dns_records(site, d):
    ip = dns_svc.server_ip()
    host = _mail_host()
    recs = [
        ("MX", "@", f"10 {host}."),
        ("TXT", "@", "v=spf1 a mx ~all"),
        ("TXT", "_dmarc", f"v=DMARC1; p=quarantine; rua=mailto:postmaster@{site['domain']}"),
    ]
    if d and d["dkim_record"]:
        recs.append(("TXT", f"{d['dkim_selector']}._domainkey", d["dkim_record"]))
    return recs, ip


@router.get("/sites/{site_id}/mail")
async def mail_page(request: Request, site_id: int):
    site = get_site(site_id)
    d = svc.get_domain(site_id)
    boxes, fwds, usage = [], [], {}
    if d:
        boxes = db.all("""SELECT m.*, a.enabled AS auto_on FROM mailboxes m
                          LEFT JOIN autoresponders a ON a.mailbox_id = m.id
                          WHERE m.domain_id = ? ORDER BY m.local""", d["id"])
        fwds = db.all("SELECT * FROM forwarders WHERE domain_id = ? ORDER BY local", d["id"])
        for b in boxes:
            usage[b["id"]] = svc.mailbox_usage(f"{b['local']}@{d['domain']}")
    recs, ip = _dns_records(site, d)
    zone = db.one("SELECT id FROM dns_zones WHERE domain = ?", site["domain"])
    return render(request, "site_mail.html", site=site, tab="mail", d=d, boxes=boxes, fwds=fwds, usage=usage,
                  recs=recs, zone=zone, mail_host=_mail_host(),
                  webmail=f"https://{db.get_setting('hostname') or request.url.hostname}:2096/")


@router.post("/sites/{site_id}/mail/enable")
async def enable(request: Request, site_id: int):
    async with guard(request):
        await form_of(request)
        svc.enable_domain(site_id, actor(request))
        flash(request, "Email is on for this domain. Add the DNS records shown below if your DNS is hosted elsewhere.")
    return back(f"/sites/{site_id}/mail")


@router.post("/sites/{site_id}/mail/disable")
async def disable(request: Request, site_id: int):
    async with guard(request):
        form = await form_of(request)
        site = get_site(site_id)
        if form.get("confirm", "").strip().lower() != site["domain"]:
            raise ValueError("Type the domain name to confirm")
        svc.disable_domain(site_id, actor(request), remove_mail=True)
        flash(request, "Email turned off and all mailboxes deleted.")
    return back(f"/sites/{site_id}/mail")


@router.post("/sites/{site_id}/mail/boxes")
async def create_box(request: Request, site_id: int):
    async with guard(request):
        form = await form_of(request)
        pw = form.get("password") or ""
        generated = not pw
        if generated:
            pw = generate_password(16)
        address = svc.create_mailbox(site_id, form.get("local", ""), pw, int(form.get("quota") or 1024), actor(request))
        if generated:
            reveal(request, {"title": "Mailbox created — save this password now",
                             "pairs": [("Email / username", address), ("Password", pw)]})
        else:
            flash(request, f"{address} created.")
    return back(f"/sites/{site_id}/mail")


@router.get("/sites/{site_id}/mail/boxes/{box_id}")
async def box_page(request: Request, site_id: int, box_id: int):
    site = get_site(site_id)
    d, b = svc.get_mailbox(site_id, box_id)
    auto = db.one("SELECT * FROM autoresponders WHERE mailbox_id = ?", box_id)
    address = f"{b['local']}@{d['domain']}"
    return render(request, "site_mailbox.html", site=site, tab="mail", d=d, b=b, auto=auto, address=address,
                  usage=svc.mailbox_usage(address), mail_host=_mail_host(),
                  webmail=f"https://{db.get_setting('hostname') or request.url.hostname}:2096/")


@router.post("/sites/{site_id}/mail/boxes/{box_id}/update")
async def update_box(request: Request, site_id: int, box_id: int):
    async with guard(request):
        form = await form_of(request)
        enabled = None if "enabled" not in form else form.get("enabled") == "1"
        quota = int(form["quota"]) if form.get("quota") else None
        svc.update_mailbox(site_id, box_id, form.get("password") or None, quota, enabled, actor(request))
        flash(request, "Mailbox updated.")
    return back(f"/sites/{site_id}/mail/boxes/{box_id}")


@router.post("/sites/{site_id}/mail/boxes/{box_id}/autoresponder")
async def autoresponder(request: Request, site_id: int, box_id: int):
    async with guard(request):
        form = await form_of(request)
        svc.set_autoresponder(site_id, box_id, form.get("enabled") == "1", form.get("subject", ""),
                              form.get("body", ""), int(form.get("days") or 1), form.get("start", ""),
                              form.get("end", ""), actor(request))
        flash(request, "Autoresponder saved.")
    return back(f"/sites/{site_id}/mail/boxes/{box_id}")


@router.post("/sites/{site_id}/mail/boxes/{box_id}/delete")
async def delete_box(request: Request, site_id: int, box_id: int):
    async with guard(request):
        await form_of(request)
        svc.delete_mailbox(site_id, box_id, actor(request))
        flash(request, "Mailbox and all its mail deleted.")
        return back(f"/sites/{site_id}/mail")
    return back(f"/sites/{site_id}/mail/boxes/{box_id}")


@router.post("/sites/{site_id}/mail/forwarders")
async def add_forwarder(request: Request, site_id: int):
    async with guard(request):
        form = await form_of(request)
        svc.add_forwarder(site_id, form.get("local", ""), form.get("destinations", ""), actor(request))
        flash(request, "Forwarder saved.")
    return back(f"/sites/{site_id}/mail#forwarders")


@router.post("/sites/{site_id}/mail/forwarders/{fwd_id}/delete")
async def delete_forwarder(request: Request, site_id: int, fwd_id: int):
    async with guard(request):
        await form_of(request)
        svc.delete_forwarder(site_id, fwd_id, actor(request))
        flash(request, "Forwarder removed.")
    return back(f"/sites/{site_id}/mail#forwarders")


@router.post("/sites/{site_id}/mail/catchall")
async def catch_all(request: Request, site_id: int):
    async with guard(request):
        form = await form_of(request)
        svc.set_catch_all(site_id, form.get("target", "") if form.get("mode") == "forward" else "", actor(request))
        flash(request, "Catch-all saved.")
    return back(f"/sites/{site_id}/mail#catchall")


@router.get("/mail")
async def mail_overview(request: Request):
    rows = db.all("""SELECT d.*, s.id AS sid,
                     (SELECT COUNT(*) FROM mailboxes m WHERE m.domain_id = d.id) AS boxes,
                     (SELECT COUNT(*) FROM forwarders f WHERE f.domain_id = d.id) AS fwds
                     FROM mail_domains d JOIN sites s ON s.id = d.site_id ORDER BY d.domain""")
    return render(request, "mail.html", rows=rows, mail_host=_mail_host(),
                  webmail=f"https://{db.get_setting('hostname') or request.url.hostname}:2096/")
