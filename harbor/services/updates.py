"""Panel side of self-update: receive a package, start the updater in its
own systemd unit, and show progress."""
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import httpx

from .. import __version__, config, db
from . import OpError

UPD_DIR = config.DATA_DIR / "updates"
MAX_BYTES = 200 * 1024 * 1024


def releases() -> list[dict]:
    rel = config.APP_DIR / "releases"
    if not rel.exists():
        return []
    out = []
    for d in sorted(rel.iterdir(), key=lambda d: d.stat().st_mtime, reverse=True):
        if (d / "harbor" / "__init__.py").exists():
            m = re.search(r'__version__\s*=\s*"([^"]+)"', (d / "harbor" / "__init__.py").read_text())
            out.append({"name": d.name, "version": m.group(1) if m else "?", "saved": d.stat().st_mtime})
    return out


def running() -> bool:
    return bool(db.one("SELECT id FROM updates WHERE status IN ('queued', 'running') "
                       "AND created_at > datetime('now', '-30 minutes')"))


def save_upload(fileobj, filename: str) -> Path:
    if not filename.endswith((".tar.gz", ".tgz")):
        raise OpError("Upload the Harbor package (.tar.gz)")
    UPD_DIR.mkdir(parents=True, exist_ok=True)
    target = UPD_DIR / f"harbor-{int(time.time())}.tar.gz"
    size = 0
    with open(target, "wb") as out:
        while chunk := fileobj.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_BYTES:
                out.close()
                target.unlink()
                raise OpError("That file is too large to be a Harbor package")
            out.write(chunk)
    return target


def download(url: str) -> Path:
    if not re.match(r"^https://[^\s]+$", url or "") and not re.match(r"^http://(127\.0\.0\.1|localhost)(:\d+)?/\S*$", url or ""):
        raise OpError("Enter an https:// link to a Harbor .tar.gz package")
    UPD_DIR.mkdir(parents=True, exist_ok=True)
    target = UPD_DIR / f"harbor-{int(time.time())}.tar.gz"
    try:
        with httpx.stream("GET", url, follow_redirects=True, timeout=60,
                          headers={"User-Agent": f"Harbor/{__version__}"}) as r:
            r.raise_for_status()
            size = 0
            with open(target, "wb") as out:
                for chunk in r.iter_bytes():
                    size += len(chunk)
                    if size > MAX_BYTES:
                        raise OpError("Download too large")
                    out.write(chunk)
    except httpx.HTTPError as e:
        target.unlink(missing_ok=True)
        raise OpError(f"Download failed: {e}")
    return target


def start(source: Path, actor: str) -> int:
    if running():
        raise OpError("An update is already running")
    uid = db.execute("INSERT INTO updates (from_version, status) VALUES (?, 'queued')", __version__)
    db.log(f"Update started from {source.name}", actor)
    # Run a copy of the updater, so replacing the installed code can't affect it.
    UPD_DIR.mkdir(parents=True, exist_ok=True)
    script = UPD_DIR / f"updater-{uid}.py"
    shutil.copy2(Path(__file__).parent.parent / "updater.py", script)
    if config.DRY_RUN:
        from ..system.runner import DRY_LOG
        DRY_LOG.append(f"systemd-run harbor-update-{uid} {script} {source}")
        return uid
    cmd = ["systemd-run", f"--unit=harbor-update-{uid}", "--collect", "--quiet",
           f"--setenv=HARBOR_APP_DIR={config.APP_DIR}", f"--setenv=HARBOR_DB={config.DB_PATH}",
           sys.executable, str(script), str(source), "--update-id", str(uid)]
    if not shutil.which("systemd-run"):
        cmd = [sys.executable, str(script), str(source), "--update-id", str(uid)]
        subprocess.Popen(cmd, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return uid
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        db.execute("UPDATE updates SET status = 'failed', log = ? WHERE id = ?", r.stderr[-2000:], uid)
        raise OpError(f"Couldn't start the updater: {r.stderr[-300:]}")
    return uid


def rollback(release: str, actor: str) -> int:
    src = config.APP_DIR / "releases" / release
    if not re.fullmatch(r"[\w.\-]+", release or "") or not (src / "harbor" / "__init__.py").exists():
        raise OpError("Release not found")
    db.log(f"Rolling back to saved release {release}", actor)
    return start(src, actor)


# ---------------------------------------------------------------- update checks (GitHub releases)

DEFAULT_REPO = "estuty/HARBOR"
CHECK_EVERY = 6 * 3600
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
log = __import__("logging").getLogger("harbor")


def _version_key(v: str) -> tuple:
    nums = [int(x) for x in re.findall(r"\d+", (v or "").lstrip("vV").split("-")[0].split("+")[0])[:4]]
    return tuple(nums + [0] * (4 - len(nums)))


def newer(candidate: str, current: str = __version__) -> bool:
    return _version_key(candidate) > _version_key(current)


def prefs() -> dict:
    return {"repo": db.get_setting("update_repo") or DEFAULT_REPO,
            "check": db.get_setting("update_check", "1") == "1",
            "notify": db.get_setting("update_notify", "1") == "1"}


def save_prefs(form, actor: str) -> None:
    repo = (form.get("repo") or DEFAULT_REPO).strip().removeprefix("https://github.com/").strip("/")
    if not _REPO_RE.match(repo):
        raise OpError("Repository: use owner/name, e.g. estuty/HARBOR")
    db.set_setting("update_repo", repo)
    db.set_setting("update_check", "1" if form.get("check") == "1" else "0")
    db.set_setting("update_notify", "1" if form.get("notify") == "1" else "0")
    db.log("Update settings changed", actor)


def latest() -> dict | None:
    import json
    try:
        return json.loads(db.get_setting("update_latest") or "null")
    except ValueError:
        return None


def available() -> dict | None:
    """The newest release, if it's newer than what's running."""
    info = latest()
    return info if info and newer(info.get("version", "")) else None


def status() -> dict:
    return {"latest": latest(), "available": available(), "checked_at": db.get_setting("update_checked_at"),
            "error": db.get_setting("update_error"), **prefs()}


def check() -> dict | None:
    """Ask GitHub for the latest release. Stores the result; returns it if it's newer."""
    import json
    from datetime import datetime, timezone
    repo = prefs()["repo"]
    api = (db.get_setting("update_api") or "https://api.github.com").rstrip("/")
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    db.set_setting("update_checked_at", stamp)
    try:
        r = httpx.get(f"{api}/repos/{repo}/releases/latest", timeout=20, follow_redirects=True,
                      headers={"Accept": "application/vnd.github+json", "User-Agent": f"Harbor/{__version__}"})
    except httpx.HTTPError as e:
        db.set_setting("update_error", f"Couldn't reach GitHub: {e.__class__.__name__}")
        return None
    if r.status_code == 404:
        db.set_setting("update_error", "")
        db.set_setting("update_latest", "")
        return None  # no release published yet (or the repository isn't public)
    if r.status_code != 200:
        db.set_setting("update_error", f"GitHub answered {r.status_code}"
                       + (": rate limit reached, try again later" if r.status_code == 403 else ""))
        return None
    data = r.json()
    tag = str(data.get("tag_name") or "")
    package = next((a.get("browser_download_url") for a in data.get("assets") or []
                    if str(a.get("name", "")).endswith((".tar.gz", ".tgz"))), None) or data.get("tarball_url")
    info = {"version": tag.lstrip("vV"), "tag": tag, "name": str(data.get("name") or tag)[:200],
            "notes": str(data.get("body") or "")[:20000], "published": str(data.get("published_at") or "")[:10],
            "page": str(data.get("html_url") or ""), "package": str(package or "")}
    db.set_setting("update_latest", json.dumps(info))
    db.set_setting("update_error", "")
    if newer(info["version"]):
        _notify(info)
        return info
    return None


def _notify(info: dict) -> None:
    from ..system import notify
    if db.get_setting("update_notified") == info["version"]:
        return
    db.set_setting("update_notified", info["version"])
    db.log(f"Harbor {info['version']} is available (running {__version__})")
    if not prefs()["notify"] or not notify.channels_configured():
        return
    host = db.get_setting("hostname") or "your server"
    notes = info["notes"].strip()
    body = (f"Harbor {info['version']} is available for {host} (it runs {__version__}).\n\n"
            + (notes[:1500] + ("…" if len(notes) > 1500 else "") + "\n\n" if notes else "")
            + f"Install it with one click: https://{host}:8443/settings/updates\n"
            + (f"Release notes: {info['page']}\n" if info["page"] else ""))
    errors = notify.send(f"Harbor {info['version']} is available", body)
    if errors:
        log.warning("update notification failed: %s", errors)


def install_latest(actor: str) -> int:
    info = available()
    if not info:
        raise OpError("You're already running the latest version")
    if not info.get("package"):
        raise OpError("This release has no package to download")
    db.log(f"One-click update to Harbor {info['version']}", actor)
    return start(download(info["package"]), actor)


def start_checker() -> None:
    """Check GitHub every few hours (if enabled)."""
    import threading
    from datetime import datetime, timezone

    def due() -> bool:
        last = db.get_setting("update_checked_at")
        if not last:
            return True
        try:
            then = datetime.strptime(last, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return True
        return (datetime.now(timezone.utc) - then).total_seconds() >= CHECK_EVERY

    def loop():
        time.sleep(90)
        while True:
            try:
                if prefs()["check"] and due():
                    check()
            except Exception:
                log.exception("update check failed")
            time.sleep(1800)
    threading.Thread(target=loop, name="harbor-update-check", daemon=True).start()
