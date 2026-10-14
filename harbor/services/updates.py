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
    if not re.match(r"^https://[^\s]+$", url or ""):
        raise OpError("Enter an https:// link to a Harbor .tar.gz package")
    UPD_DIR.mkdir(parents=True, exist_ok=True)
    target = UPD_DIR / f"harbor-{int(time.time())}.tar.gz"
    try:
        with httpx.stream("GET", url, follow_redirects=True, timeout=60) as r:
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
