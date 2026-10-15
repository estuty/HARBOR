"""Shared web helpers: templates, flash messages, one-time secrets, CSRF and
the current principal (logged-in user or API token owner)."""
import re
import secrets
import time
from pathlib import Path
from urllib.parse import quote

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape

from . import __version__, auth, config, db, validators
from .services import OpError
from .system.files import FileError
from .system.runner import CommandError

HERE = Path(__file__).parent
templates = Jinja2Templates(directory=str(HERE / "templates"))


def filesize(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def duration(seconds) -> str:
    s = int(seconds)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    return f"{d}d {h}h" if d else f"{h}h {s // 60}m"


def release_notes(text) -> Markup:
    """Release notes (GitHub Markdown) as a small, safe subset of HTML: headings,
    bullet lists, **bold**, `code` and links. Everything else stays plain text."""
    out, in_list = [], False

    def inline(t: str) -> str:
        t = str(escape(t))
        t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
        t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
        t = re.sub(r"\[([^\]]+)\]\((https?://[^\s)\"]+)\)", r'<a href="\2" target="_blank" rel="noopener">\1</a>', t)
        return re.sub(r"(?<![\"=>])(https?://[^\s<\"]+)", r'<a href="\1" target="_blank" rel="noopener">\1</a>', t)

    for line in str(text or "").splitlines():
        line = line.rstrip()
        bullet = re.match(r"^\s*[-*+]\s+(.*)", line)
        if in_list and not bullet:
            out.append("</ul>"); in_list = False
        if bullet:
            if not in_list:
                out.append("<ul>"); in_list = True
            out.append(f"<li>{inline(bullet.group(1))}</li>")
        elif m := re.match(r"^#{1,6}\s+(.*)", line):
            out.append(f"<h4>{inline(m.group(1))}</h4>")
        elif line.strip():
            out.append(f"<p>{inline(line)}</p>")
    if in_list:
        out.append("</ul>")
    return Markup("\n".join(out))


templates.env.filters["release_notes"] = release_notes
templates.env.filters["day"] = lambda s: str(s or "")[:10]
templates.env.filters["filesize"] = filesize
templates.env.filters["duration"] = duration
templates.env.filters["urlq"] = lambda s: quote(s or "", safe="/")
templates.env.filters["num"] = lambda n: f"{int(n or 0):,}"
templates.env.globals["version"] = __version__
templates.env.globals["dry_run"] = config.DRY_RUN

from .system.notify import NotifyError  # noqa: E402
from .system.offsite import OffsiteError  # noqa: E402

ERRORS = (OpError, validators.ValidationError, CommandError, FileError, ValueError, PermissionError,
          FileExistsError, FileNotFoundError, OSError, NotifyError, OffsiteError)

_reveals: dict[str, tuple[float, dict]] = {}


def reveal(request: Request, data: dict) -> None:
    """Show a generated secret exactly once (kept server-side, never in the cookie)."""
    now = time.time()
    for k in [k for k, (t, _) in _reveals.items() if now - t > 600]:
        _reveals.pop(k, None)
    token = secrets.token_urlsafe(16)
    _reveals[token] = (now, data)
    request.session["reveal"] = token


def flash(request: Request, message: str, kind: str = "ok") -> None:
    # Reassign (not append in place) so the session notices the change.
    request.session["flash"] = request.session.get("flash", []) + [[kind, message]]


def principal(request: Request) -> dict:
    return getattr(request.state, "principal", None) or {}


def is_admin(request: Request) -> bool:
    return principal(request).get("role") == "admin"


def visible_sites(request: Request):
    p = principal(request)
    if p.get("role") == "admin":
        return db.all("SELECT * FROM sites ORDER BY domain")
    return db.all("""SELECT s.* FROM sites s JOIN user_sites us ON us.site_id = s.id
                     WHERE us.user_id = ? ORDER BY s.domain""", p.get("uid", 0))


def render(request: Request, name: str, **ctx) -> HTMLResponse:
    msgs = request.session.pop("flash", [])
    secret = None
    token = request.session.pop("reveal", None)
    if token and token in _reveals:
        secret = _reveals.pop(token)[1]
    p = principal(request)
    if p.get("role") == "admin" and "update_available" not in ctx:
        from .services import updates
        ctx["update_available"] = updates.available()
    ctx.update(request=request, user=p.get("user"), role=p.get("role"), is_admin=p.get("role") == "admin",
               flashes=msgs, secret=secret, csrf=auth.csrf_token(request.session), path=request.url.path,
               features=config.features())
    return templates.TemplateResponse(request, name, ctx)


def back(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


async def form_of(request: Request):
    form = await request.form()
    if not auth.check_csrf(request.session, form.get("csrf")):
        raise PermissionError("Security token expired. Please try again.")
    return form


def actor(request: Request) -> str:
    return principal(request).get("user", "?")


def int_list(values) -> list[int]:
    out = []
    for v in values:
        try:
            out.append(int(v))
        except (TypeError, ValueError):
            pass
    return out


class guard:
    """`async with guard(request): ...` turns expected errors into a flash message."""

    def __init__(self, request: Request):
        self.request = request

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if exc_type and issubclass(exc_type, ERRORS):
            flash(self.request, str(exc), "error")
            return True
        return False
