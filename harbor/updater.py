"""Harbor self-updater, with automatic rollback.

Runs as its own process (started with systemd-run, so restarting the panel
doesn't kill it) and uses only the standard library, because it replaces the
very code it was loaded from.

    python3 updater.py SOURCE [--update-id N]

SOURCE is a Harbor .tar.gz package or an unpacked release folder (rollback).

Steps: unpack -> check -> save current code + database -> install new code
and dependencies -> import check -> restart -> health check. If anything
after "save" fails, the saved code and database are put back and the panel is
restarted on the old version.
"""
import argparse
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

APP = Path(os.environ.get("HARBOR_APP_DIR", "/opt/harbor"))
DB = Path(os.environ.get("HARBOR_DB", "/var/lib/harbor/harbor.db"))
LOG = Path(os.environ.get("HARBOR_UPDATE_LOG", "/var/log/harbor/update.log"))
HEALTH = os.environ.get("HARBOR_HEALTH_URL", "http://127.0.0.1:8090/login")
RESTART = os.environ.get("HARBOR_RESTART_CMD", "systemctl restart harbor").split()
SKIP_PIP = os.environ.get("HARBOR_UPDATE_SKIP_PIP") == "1"
SKIP_INSTALLER = os.environ.get("HARBOR_UPDATE_SKIP_INSTALLER") == "1"
KEEP_RELEASES = 5

_lines: list[str] = []


def say(msg: str) -> None:
    line = f"{datetime.now(timezone.utc).strftime('%H:%M:%S')} {msg}"
    _lines.append(line)
    print(line, flush=True)
    try:
        LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def record(update_id: int | None, status: str, to_version: str = "", from_version: str = "") -> None:
    if not update_id:
        return
    try:
        con = sqlite3.connect(DB, timeout=30)
        con.execute("INSERT OR IGNORE INTO updates (id, status) VALUES (?, ?)", (update_id, status))
        con.execute("UPDATE updates SET status = ?, log = ?, to_version = COALESCE(NULLIF(?, ''), to_version), "
                    "from_version = COALESCE(NULLIF(?, ''), from_version), "
                    "finished_at = CASE WHEN ? IN ('done', 'rolled_back', 'failed', 'attention') THEN CURRENT_TIMESTAMP END "
                    "WHERE id = ?", (status, "\n".join(_lines)[-20000:], to_version, from_version, status, update_id))
        con.commit()
        con.close()
    except sqlite3.Error as e:
        print("could not record status:", e)


def version_of(pkg: Path) -> str:
    m = re.search(r'__version__\s*=\s*"([^"]+)"', (pkg / "__init__.py").read_text())
    if not m:
        raise RuntimeError("Package has no version")
    return m.group(1)


def unpack(source: Path, work: Path) -> Path:
    """Return the folder that contains harbor/ (the package root)."""
    if source.is_dir():
        root = source
    else:
        with tarfile.open(source, "r:gz") as tar:
            tar.extractall(work, filter="data")
        candidates = [p.parent for p in work.rglob("harbor/__init__.py") if (p.parent / "app.py").exists()]
        if not candidates:
            raise RuntimeError("This file isn't a Harbor package (no harbor/app.py inside)")
        root = sorted(candidates, key=lambda p: len(p.parts))[0].parent
    if not (root / "harbor" / "app.py").exists() or not (root / "requirements.txt").exists():
        raise RuntimeError("Incomplete Harbor package (needs harbor/ and requirements.txt)")
    return root


def health_ok(timeout: int = 60) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(HEALTH, timeout=5) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(2)
    return False


def sh(cmd: list[str], timeout: int = 900) -> None:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:3])}… failed: {(r.stderr or r.stdout)[-1500:]}")


def install_code(root: Path) -> None:
    tmp = APP / "harbor.new"
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.copytree(root / "harbor", tmp, ignore=shutil.ignore_patterns("__pycache__"))
    old = APP / "harbor"
    trash = APP / "harbor.old"
    shutil.rmtree(trash, ignore_errors=True)
    if old.exists():
        old.rename(trash)
    tmp.rename(old)
    shutil.rmtree(trash, ignore_errors=True)
    shutil.copy2(root / "requirements.txt", APP / "requirements.txt")
    # keep the full package (installer included) for system-level upgrades
    if (root / "install.sh").exists():
        src = APP / "source"
        shutil.rmtree(src, ignore_errors=True)
        shutil.copytree(root, src, ignore=shutil.ignore_patterns("__pycache__", ".git"))


def pip_install() -> None:
    if SKIP_PIP:
        return
    sh([str(APP / "venv/bin/pip"), "install", "-q", "-r", str(APP / "requirements.txt")])


def import_check() -> None:
    py = str(APP / "venv/bin/python") if (APP / "venv/bin/python").exists() else sys.executable
    env = {**os.environ, "HARBOR_SCHEDULER": "0", "PYTHONDONTWRITEBYTECODE": "1"}
    r = subprocess.run([py, "-c", "import harbor.app"], cwd=str(APP), capture_output=True, text=True, env=env, timeout=120)
    if r.returncode != 0:
        raise RuntimeError("New version failed to start: " + (r.stderr or r.stdout)[-1500:])


def save_current(release_dir: Path) -> None:
    release_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(APP / "harbor", release_dir / "harbor", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy2(APP / "requirements.txt", release_dir / "requirements.txt")
    if DB.exists():
        src = sqlite3.connect(DB, timeout=30)
        dst = sqlite3.connect(release_dir / "harbor.db")
        src.backup(dst)
        dst.close()
        src.close()


def restore(release_dir: Path) -> None:
    install_code(release_dir)
    if (release_dir / "harbor.db").exists():
        src = sqlite3.connect(release_dir / "harbor.db")
        dst = sqlite3.connect(DB, timeout=30)
        src.backup(dst)
        dst.close()
        src.close()
    try:
        pip_install()
    except Exception as e:
        say(f"warning: reinstalling old dependencies failed: {e}")


def prune_releases() -> None:
    rel = APP / "releases"
    if not rel.exists():
        return
    dirs = sorted([d for d in rel.iterdir() if d.is_dir()], key=lambda d: d.stat().st_mtime, reverse=True)
    for d in dirs[KEEP_RELEASES:]:
        shutil.rmtree(d, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("source")
    ap.add_argument("--update-id", type=int)
    args = ap.parse_args()
    source = Path(args.source)
    work = Path(tempfile.mkdtemp(prefix="harbor-update-"))
    current = version_of(APP / "harbor") if (APP / "harbor/__init__.py").exists() else "?"
    say(f"Update started from {source.name} (current version {current})")
    record(args.update_id, "running", from_version=current)
    try:
        root = unpack(source, work)
        new = version_of(root / "harbor")
        say(f"Package is Harbor {new}")
        record(args.update_id, "running", to_version=new)
    except Exception as e:
        say(f"Rejected: {e}")
        record(args.update_id, "failed")
        shutil.rmtree(work, ignore_errors=True)
        return 1

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    release_dir = APP / "releases" / f"{current}-{stamp}"
    try:
        save_current(release_dir)
        say(f"Saved current code and database to {release_dir}")
    except Exception as e:
        say(f"Could not save the current version, nothing changed: {e}")
        record(args.update_id, "failed")
        return 1

    try:
        install_code(root)
        say("New code installed; installing dependencies…")
        pip_install()
        import_check()
        say("Import check passed (database migrations applied); restarting the panel…")
        subprocess.run(RESTART, timeout=120)
        if not health_ok():
            raise RuntimeError("The panel didn't come back after restarting")
    except Exception as e:
        say(f"Update failed: {e}")
        say("Rolling back to the saved version…")
        try:
            restore(release_dir)
            subprocess.run(RESTART, timeout=120)
            ok = health_ok()
            say("Rollback complete; the panel is running the previous version." if ok
                else "Rollback finished but the panel isn't answering. Check: journalctl -u harbor -n 100")
        except Exception as e2:
            say(f"Rollback error: {e2}")
        record(args.update_id, "rolled_back")
        shutil.rmtree(work, ignore_errors=True)
        return 2

    sysver_new = _system_version(root / "harbor")
    sysver_installed = _installed_system_version()
    final = "done"
    if sysver_new > sysver_installed:
        if SKIP_INSTALLER or not (APP / "source" / "install.sh").exists():
            say(f"NOTE: this version also changes server components. Run once over SSH: "
                f"sudo bash {APP}/source/install.sh")
        else:
            say("This version also updates server components; running the installer (this takes a few minutes)…")
            record(args.update_id, "running", to_version=new)
            if run_installer(args.update_id):
                say("Server components updated.")
            else:
                say(f"The new version is running, but updating server components didn't finish. "
                    f"See the lines above, fix the cause, then run once over SSH: sudo bash {APP}/source/install.sh")
                final = "attention"
    say(f"Done: Harbor {current} → {new}")
    record(args.update_id, final)
    prune_releases()
    shutil.rmtree(work, ignore_errors=True)
    return 0


def run_installer(update_id: int | None) -> bool:
    """Re-run the installer from the new package (it keeps data and settings).
    Only its step headings, warnings and errors go into the update log; the full
    output is kept next to it. Output goes to a file rather than a pipe, because
    services the installer (re)starts may hold on to a pipe and it would never close."""
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    full = LOG.parent / f"install-{update_id or 'manual'}.log"
    try:
        full.parent.mkdir(parents=True, exist_ok=True)
        out = open(full, "w")
        proc = subprocess.Popen(["bash", str(APP / "source" / "install.sh")], cwd=str(APP / "source"),
                                stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                env=env, start_new_session=True)
    except OSError as e:
        say(f"Couldn't start the installer: {e}")
        return False
    out.close()
    tail: list[str] = []
    deadline = time.time() + 3600
    with open(full, errors="replace") as f:
        buf = ""
        while True:
            done = proc.poll() is not None
            buf += f.read()
            *lines, buf = buf.split("\n")
            for line in lines:
                clean = re.sub(r"\x1b\[[0-9;]*m", "", line).rstrip()
                if not clean:
                    continue
                tail = (tail + [clean])[-15:]
                if clean.startswith("==>") or clean.startswith(("Warning", "Error")):
                    say("  " + clean.lstrip("=> ").strip())
                    record(update_id, "running")
            if done:
                break
            if time.time() > deadline:
                proc.kill()
                say(f"The installer took longer than an hour and was stopped. Full output: {full}")
                return False
            time.sleep(1)
    if proc.returncode != 0:
        say("Installer stopped with an error:")
        for t in tail[-8:]:
            say("    " + t)
        say(f"Full installer output: {full}")
        return False
    return health_ok(120)


def _system_version(pkg: Path) -> int:
    m = re.search(r"SYSTEM_VERSION\s*=\s*(\d+)", (pkg / "__init__.py").read_text())
    return int(m.group(1)) if m else 0


def _installed_system_version() -> int:
    try:
        return int(Path(os.environ.get("HARBOR_SYSTEM_VERSION_FILE", "/etc/harbor/system_version")).read_text().strip())
    except (OSError, ValueError):
        return 0


if __name__ == "__main__":
    sys.exit(main())
