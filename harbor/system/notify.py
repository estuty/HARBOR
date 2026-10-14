"""Deliver alert messages by email (SMTP) and/or webhook (Slack, Discord,
ntfy or any JSON endpoint)."""
import json
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from urllib.parse import urlsplit

import httpx

from .. import config, db


class NotifyError(Exception):
    pass


def email_settings() -> dict:
    return {
        "to": db.get_setting("alert_email"),
        "host": db.get_setting("smtp_host"),
        "port": int(db.get_setting("smtp_port", "587") or 587),
        "security": db.get_setting("smtp_security", "starttls"),
        "user": db.get_setting("smtp_user"),
        "password": db.get_setting("smtp_password"),
        "sender": db.get_setting("smtp_from"),
    }


def send_email(subject: str, body: str, s: dict | None = None) -> None:
    s = s or email_settings()
    recipients = [r.strip() for r in (s["to"] or "").replace(";", ",").split(",") if r.strip()]
    if not recipients:
        return
    host_name = db.get_setting("hostname") or "harbor"
    msg = EmailMessage()
    msg["From"] = s["sender"] or s["user"] or f"harbor@{host_name}"
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=host_name if "." in host_name else None)
    msg.set_content(body)
    if config.DRY_RUN:
        from .runner import DRY_LOG
        DRY_LOG.append(f"email to {msg['To']}: {subject}")
        return
    ctx = ssl.create_default_context()
    try:
        if not s["host"]:  # this server's own mail system
            with smtplib.SMTP("127.0.0.1", 25, timeout=20) as c:
                c.send_message(msg)
            return
        if s["security"] == "ssl":
            c = smtplib.SMTP_SSL(s["host"], s["port"], timeout=20, context=ctx)
        else:
            c = smtplib.SMTP(s["host"], s["port"], timeout=20)
        with c:
            if s["security"] == "starttls":
                c.starttls(context=ctx)
            if s["user"]:
                c.login(s["user"], s["password"])
            c.send_message(msg)
    except (smtplib.SMTPException, OSError) as e:
        raise NotifyError(f"Email failed: {e}")


def send_webhook(title: str, body: str, url: str | None = None) -> None:
    url = url if url is not None else db.get_setting("alert_webhook")
    if not url:
        return
    host = (urlsplit(url).hostname or "").lower()
    text = f"{title}\n{body}"
    if config.DRY_RUN:
        from .runner import DRY_LOG
        DRY_LOG.append(f"webhook {host}: {title}")
        return
    try:
        if host.endswith("discord.com") or host.endswith("discordapp.com"):
            r = httpx.post(url, json={"content": text[:1900]}, timeout=15)
        elif host == "hooks.slack.com":
            r = httpx.post(url, json={"text": text}, timeout=15)
        elif host.startswith("ntfy.") or "/ntfy" in url:
            r = httpx.post(url, content=body.encode(), headers={"Title": title}, timeout=15)
        else:
            r = httpx.post(url, json={"title": title, "message": body, "text": text}, timeout=15)
        if r.status_code >= 400:
            raise NotifyError(f"Webhook answered {r.status_code}: {r.text[:200]}")
    except httpx.HTTPError as e:
        raise NotifyError(f"Webhook failed: {e}")


def send(title: str, body: str) -> list[str]:
    """Send on every configured channel. Returns errors (empty list = all good)."""
    errors = []
    for fn in (lambda: send_email(title, body), lambda: send_webhook(title, body)):
        try:
            fn()
        except NotifyError as e:
            errors.append(str(e))
    return errors


def channels_configured() -> bool:
    return bool(db.get_setting("alert_email") or db.get_setting("alert_webhook"))
