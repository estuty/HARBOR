#!/usr/bin/env python3
"""Live checks for update notifications and one-click updates (run as root on a test server).

A local stand-in for the GitHub releases API serves two releases built from this
checkout: a code-only one, then one that also needs the installer. Afterwards the
panel is rolled back to the version it started with.

    python3 run_updates.py <admin-password>
"""
import http.server
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from pathlib import Path

for _v in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY", "all_proxy"):
    os.environ.pop(_v, None)

import httpx  # noqa: E402

PANEL = "https://127.0.0.1:8443"
PW = sys.argv[1]
REPO_ROOT = Path(__file__).resolve().parents[2]
DB = "/var/lib/harbor/harbor.db"
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:700]}"), flush=True)


def setting(key, value):
    con = sqlite3.connect(DB, timeout=30)
    con.execute("INSERT INTO server_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value))
    con.commit(); con.close()


def build(version, sysver=None):
    work = Path(tempfile.mkdtemp()) / "harbor"
    shutil.copytree(REPO_ROOT, work, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", "tests"))
    init = work / "harbor" / "__init__.py"
    text = re.sub(r'__version__ = "[^"]+"', f'__version__ = "{version}"', init.read_text())
    if sysver:
        text = re.sub(r"SYSTEM_VERSION = \d+", f"SYSTEM_VERSION = {sysver}", text)
    init.write_text(text)
    out = SERVE / f"harbor-{version}.tar.gz"
    with tarfile.open(out, "w:gz") as t:
        t.add(work, arcname=f"estuty-HARBOR-{version}")  # same layout as GitHub's source tarballs
    return out


SERVE = Path(tempfile.mkdtemp())
RELEASE = {}
HOOKS = []


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(SERVE), **kw)

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/repos/test/harbor/releases/latest":
            body = json.dumps(RELEASE).encode() if RELEASE else b'{"message":"Not Found"}'
            self.send_response(200 if RELEASE else 404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def do_POST(self):
        HOOKS.append(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode(errors="replace"))
        self.send_response(204)
        self.end_headers()


server = http.server.ThreadingHTTPServer(("127.0.0.1", 9911), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()


class Panel:
    def __init__(self):
        self.c = httpx.Client(base_url=PANEL, verify=False, follow_redirects=False, timeout=120)

    def csrf(self, page):
        return re.search(r'name="csrf" value="([^"]+)"', self.c.get(page).text).group(1)

    def post(self, url, data=None, page="/account"):
        return self.c.post(url, data=dict(data or {}, csrf=self.csrf(page)))

    def flash(self, page):
        import html
        return html.unescape(" ".join(re.findall(r'class="flash[^"]*"[^>]*>([^<]*)<', self.c.get(page).text)))

    def login(self):
        for _ in range(60):
            try:
                r = self.post("/login", {"username": "admin", "password": PW}, page="/login")
                if r.status_code == 303 and r.headers["location"] != "/login":
                    return True
            except Exception:
                pass
            time.sleep(2)
        return False


def version():
    try:
        return httpx.get(PANEL + "/settings/updates/status", cookies=p.c.cookies, verify=False, timeout=10).json()["version"]
    except Exception:
        return None


def wait_update(timeout=900):
    end = time.time() + timeout
    seen_running = False
    while time.time() < end:
        time.sleep(4)
        try:
            s = httpx.get(PANEL + "/settings/updates/status", cookies=p.c.cookies, verify=False, timeout=10).json()
        except Exception:
            continue
        if s["status"] in ("queued", "running"):
            seen_running = True
            continue
        if seen_running or s["status"] in ("done", "attention", "rolled_back", "failed"):
            return s
    return {}


p = Panel()
check("login", p.login())
start_version = version()
print("   panel is running", start_version)
setting("update_api", "http://127.0.0.1:9911")
setting("update_repo", "test/harbor")
setting("alert_webhook", "http://127.0.0.1:9911/hook")
setting("update_notify", "1")
setting("update_notified", "")

# ---------- no release yet ----------
p.post("/settings/updates/check", page="/settings/updates")
check("no release yet: says so", "No releases are published" in p.flash("/settings/updates"))

# ---------- a code-only release ----------
v1 = "9.0.1"
pkg = build(v1)
RELEASE.update({"tag_name": f"v{v1}", "name": f"Harbor {v1}", "body": "- One-click updates\n- Better editor",
                "published_at": "2026-11-01T09:00:00Z", "html_url": f"https://example.org/releases/v{v1}",
                "assets": [{"name": pkg.name, "browser_download_url": f"http://127.0.0.1:9911/{pkg.name}"}]})
p.post("/settings/updates/check", page="/settings/updates")
check("new release found", f"Harbor {v1} is available" in p.flash("/settings/updates"))
home = p.c.get("/").text
check("dashboard shows the update with a one-click button", f"Harbor {v1} is available." in home and "/settings/updates/latest" in home)
check("sidebar shows an update badge", 'class="nav-badge"' in home)
check("updates page shows the release notes", "One-click updates" in p.c.get("/settings/updates").text)
time.sleep(1)
check("notification sent to the webhook", any(f"Harbor {v1} is available" in h for h in HOOKS), HOOKS)
p.post("/settings/updates/check", page="/settings/updates")
check("no second notification for the same release", sum(f"Harbor {v1} is available" in h for h in HOOKS) == 1, len(HOOKS))

r = p.post("/settings/updates/latest", page="/")
check("Update now starts the update", r.status_code == 303)
s = wait_update()
p.login()
check("one-click update installed the new version", s.get("status") == "done" and version() == v1, (s.get("status"), version(), s.get("log", "")[-600:]))
check("banner gone after updating", f"is available." not in p.c.get("/").text)
check("sites still answer after the update", httpx.get("http://127.0.0.1/", headers={"Host": "acme-old.com"}, timeout=20).status_code < 500)

# ---------- a release that also needs the installer ----------
sysver_before = Path("/etc/harbor/system_version").read_text().strip()
v2 = "9.0.2"
pkg2 = build(v2, sysver=int(sysver_before) + 1)
RELEASE.update({"tag_name": f"v{v2}", "name": f"Harbor {v2}", "body": "- Needs the installer",
                "assets": [{"name": pkg2.name, "browser_download_url": f"http://127.0.0.1:9911/{pkg2.name}"}]})
p.post("/settings/updates/check", page="/settings/updates")
r = p.post("/settings/updates/latest", page="/settings/updates")
s = wait_update(1800)
p.login()
log = s.get("log", "")
check("update that needs the installer finishes by itself", s.get("status") == "done" and version() == v2
      and "Server components updated" in log, (s.get("status"), version(), log[-900:]))
check("installer recorded the new system version",
      Path("/etc/harbor/system_version").read_text().strip() == str(int(sysver_before) + 1))
check("installer steps shown in the update log", "Serving the panel on port" in log, log[-600:])

# ---------- back to where we started ----------
rel = re.findall(r'name="release" value="(' + re.escape(start_version) + r'-[^"]+)"', p.c.get("/settings/updates").text)
check("the starting version was saved", rel, start_version)
if rel:
    p.post("/settings/updates/rollback", {"release": rel[0]}, page="/settings/updates")
    s = wait_update()
    p.login()
    check("rolled back to the starting version", version() == start_version, (version(), s.get("status")))
Path("/etc/harbor/system_version").write_text(sysver_before + "\n")
for k in ("update_api", "update_repo", "alert_webhook", "update_latest", "update_notified", "update_checked_at"):
    con = sqlite3.connect(DB); con.execute("DELETE FROM server_settings WHERE key = ?", (k,)); con.commit(); con.close()
server.shutdown()

failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
