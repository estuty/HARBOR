#!/usr/bin/env python3
"""Live checks for stage 1 on a real Harbor server (run as root):
two-factor sign-in, panel allowlist, fail2ban, per-site PHP services and limits,
offsite backups (against a local S3 server), alerts, self-update with rollback.

    pip install httpx moto[server]
    python3 run_stage1.py <admin-password> <path-to-harbor.tar.gz>
"""
import base64
import hashlib
import hmac
import http.server
import json
import re
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from pathlib import Path

import os

for _v in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY", "all_proxy"):
    os.environ.pop(_v, None)  # talk to this server directly

import httpx  # noqa: E402

PANEL = "https://127.0.0.1:8443"
PW, PKG = sys.argv[1], Path(sys.argv[2])
DOMAIN = "stage1.example"
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"), flush=True)


def sh(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


def totp(secret, at=None):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    d = hmac.new(key, struct.pack(">Q", int((at or time.time()) // 30)), hashlib.sha1).digest()
    o = d[-1] & 15
    return str((struct.unpack(">I", d[o:o + 4])[0] & 0x7FFFFFFF) % 1000000).zfill(6)


class Panel:
    def __init__(self, base=PANEL):
        self.c = httpx.Client(base_url=base, verify=False, follow_redirects=False, timeout=300)

    def csrf(self, page):
        return re.search(r'name="csrf" value="([^"]+)"', self.c.get(page).text).group(1)

    def post(self, url, data=None, page="/account", files=None):
        r = self.c.post(url, data=dict(data or {}, csrf=self.csrf(page)), files=files)
        time.sleep(0.6)
        r.page = ""
        loc = r.headers.get("location", "")
        if r.status_code == 303 and loc.startswith("/"):
            r.page = self.c.get(loc).text
            for e in re.findall(r'class="flash error"[^>]*>([^<]*)<', r.page):
                print("   !", url, e[:300])
        return r

    def login(self, user, pw, code_fn=None):
        r = self.post("/login", {"username": user, "password": pw}, page="/login")
        if r.headers.get("location") == "/login/2fa" and code_fn:
            r = self.post("/login/2fa", {"code": code_fn()}, page="/login/2fa")
        return r


def web(path, host=DOMAIN, **kw):
    return httpx.get(f"http://127.0.0.1{path}", headers={"Host": host}, timeout=60, **kw)


for _ in range(30):
    try:
        if httpx.get(PANEL + "/login", verify=False).status_code == 200:
            break
    except Exception:
        pass
    time.sleep(1)

p = Panel()
check("login", p.login("admin", PW).headers.get("location") in ("/", "/account#twofactor"))

# clean slate
m = re.search(rf'href="/sites/(\d+)">{re.escape(DOMAIN)}<', p.c.get("/sites").text)
if m:
    p.post(f"/sites/{m.group(1)}/delete", {"confirm": DOMAIN, "remove_files": "1", "drop_dbs": "1"}, page="/sites")
r = p.post("/sites", {"domain": DOMAIN, "php_version": "8.3", "include_www": "1"}, page="/sites")
sid = r.headers["location"].rsplit("/", 1)[1]
SP, user = f"/sites/{sid}", f"site{sid}"

# ---------- per-site PHP service ----------
check("site PHP runs as its own service", sh(f"systemctl is-active harbor-php-{user}") == "active")
Path(f"/srv/harbor/sites/{DOMAIN}/public/who.php").write_text(
    "<?php echo posix_getpwuid(posix_geteuid())['name'], '|', getmypid(), '|', getmypid() > 0 ? posix_getppid() : 0;")
sh(f"chown {user}: /srv/harbor/sites/{DOMAIN}/public/who.php")
out = web("/who.php").text.split("|")
master = sh(f"cat /run/php/harbor-{user}.pid")
check("PHP worker belongs to the site's own master", out[0] == user and out[2] == master, (out, master))
check("old shared pool is gone", not Path(f"/etc/php/8.3/fpm/pool.d/harbor-{user}.conf").exists())

# migration from a 0.2-style shared pool
sh(f"systemctl disable --now harbor-php-{user}; rm /etc/systemd/system/harbor-php-{user}.service")
Path(f"/etc/php/8.3/fpm/pool.d/harbor-{user}.conf").write_text(
    Path(f"/etc/harbor/php/{user}.conf").read_text().split("\n[global]")[0].split("[global]")[-1].split("\n", 6)[-1]
    if False else Path(f"/etc/harbor/php/{user}.conf").read_text().split("\n\n", 1)[1].replace("request_terminate_timeout", ";x"))
sh("systemctl reload php8.3-fpm"); time.sleep(1)
check("legacy shared pool serving before migration", web("/who.php").status_code == 200, web("/who.php").status_code)
mig = sh("cd /opt/harbor && venv/bin/python -m harbor reconcile")
check("reconcile migrates the legacy pool", f"ok      {DOMAIN}" in mig and sh(f"systemctl is-active harbor-php-{user}") == "active"
      and not Path(f"/etc/php/8.3/fpm/pool.d/harbor-{user}.conf").exists(), mig)
check("site still answers after migration", web("/who.php").text.startswith(user + "|"))

# ---------- limits ----------
p.post(f"{SP}/limits", {"cpu_pct": "50", "memory_mb": "512", "processes": "2", "disk_mb": "0"}, page=SP)
unit = Path(f"/etc/systemd/system/harbor-php-{user}.service").read_text()
check("limits written to the service", "CPUQuota=50%" in unit and "MemoryMax=512M" in unit, unit)
Path(f"/srv/harbor/sites/{DOMAIN}/public/slow.php").write_text("<?php sleep(3); echo 'done';")
sh(f"chown {user}: /srv/harbor/sites/{DOMAIN}/public/slow.php")
t0 = time.time()
res = []
ths = [threading.Thread(target=lambda: res.append(web("/slow.php").text)) for _ in range(3)]
[t.start() for t in ths]; [t.join() for t in ths]
took = time.time() - t0
check("PHP process limit queues extra requests (2 at a time)", took >= 5.5 and res.count("done") == 3, (took, res))
check("live usage shown on overview", "PHP memory now" in p.c.get(SP).text and " of 512 MB" in p.c.get(SP).text)
p.post(f"{SP}/limits", {"cpu_pct": "100", "memory_mb": "1024", "processes": "10", "disk_mb": "0"}, page=SP)

# ---------- two-factor ----------
old_u = re.search(r'action="/users/(\d+)/delete" data-confirm="Delete user s1admin', p.c.get("/users").text)
if old_u:
    p.post(f"/users/{old_u.group(1)}/delete", page="/users")
p.post("/users", {"username": "s1admin", "password": "s1admin-password-1", "role": "admin"}, page="/users")
a = Panel()
a.login("s1admin", "s1admin-password-1")
a.post("/account/2fa/start")
secret = re.search(r'key by hand: <code class="wrap">([A-Z2-7 ]+)</code>', a.c.get("/account").text).group(1).replace(" ", "")
r = a.post("/account/2fa/confirm", {"code": totp(secret)})
codes = re.findall(r'data-copy="([0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4})"', r.page)
check("2FA turned on, 8 recovery codes shown", len(codes) == 8)
b = Panel()
r = b.post("/login", {"username": "s1admin", "password": "s1admin-password-1"}, page="/login")
check("password alone asks for a code", r.headers.get("location") == "/login/2fa")
time.sleep(31)  # next time step (the setup code can't be reused)
r = b.post("/login/2fa", {"code": totp(secret)}, page="/login/2fa")
check("TOTP code signs in", r.headers.get("location") == "/" and "Dashboard" in b.c.get("/").text)
c = Panel()
c.login("s1admin", "s1admin-password-1", lambda: codes[0])
check("recovery code signs in", "Dashboard" in c.c.get("/").text)

# ---------- fail2ban ----------
# Connect from a second address (added to lo for this test) so the server's own IP,
# which fail2ban rightly ignores, isn't the one being banned.
sh("ip addr add 198.51.100.50/32 dev lo 2>/dev/null")
ext = Panel("https://192.0.2.2:8443")
ext.c = httpx.Client(base_url="https://192.0.2.2:8443", verify=False, follow_redirects=False, timeout=30,
                     transport=httpx.HTTPTransport(local_address="198.51.100.50", verify=False))
blocked = False
for _ in range(8):
    try:
        ext.post("/login", {"username": "admin", "password": "wrong-guess"}, page="/login")
    except httpx.HTTPError:
        blocked = True  # the firewall dropped us mid-attack
        break
time.sleep(4)
try:
    ext.c.get("/login", timeout=5)
    reachable = True
except httpx.HTTPError:
    reachable = False
check("banned address can no longer connect", blocked or not reachable)
st = sh("fail2ban-client status harbor-panel")
check("fail2ban bans repeated panel failures", "198.51.100.50" in st, st)
sec = p.c.get("/security").text
check("ban shown on Security page", "198.51.100.50" in sec)
p.post("/security/unban", {"ip": "198.51.100.50", "jail": "harbor-panel"}, page="/security")
check("unban from the panel", "198.51.100.50" not in sh("fail2ban-client status harbor-panel"))
p.post("/security/ban", {"ip": "198.51.100.99"}, page="/security")
check("manual ban", "198.51.100.99" in sh("fail2ban-client status harbor-manual"))
p.post("/security/unban", {"ip": "198.51.100.99", "jail": "harbor-manual"}, page="/security")

# ---------- panel allowlist ----------
p.post("/security/access", {"ips": "203.0.113.5"}, page="/security")
r = httpx.get("https://192.0.2.2:8443/login", verify=False)
check("panel allowlist blocks other addresses", r.status_code == 403, r.status_code)
r = httpx.get("https://192.0.2.2:8443/ddns/update?token=x", verify=False)
check("Dynamic DNS still reachable", r.status_code == 400 and "badauth" in r.text, (r.status_code, r.text))
check("loopback still allowed", httpx.get(PANEL + "/login", verify=False).status_code == 200)
sh("cd /opt/harbor && venv/bin/python -m harbor allow-ip --clear"); time.sleep(1.5)
check("CLI clears the allowlist", httpx.get("https://192.0.2.2:8443/login", verify=False).status_code == 200)

# ---------- offsite backups (local S3 server) ----------
moto = subprocess.Popen(["moto_server", "-p", "5055"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(3)
import boto3  # noqa: E402
boto3.client("s3", endpoint_url="http://127.0.0.1:5055", region_name="us-east-1", aws_access_key_id="a",
             aws_secret_access_key="b").create_bucket(Bucket="harbor-live")
r = p.post("/settings/backups", {"endpoint": "http://127.0.0.1:5055", "region": "us-east-1", "bucket": "harbor-live",
                                 "prefix": "harbor", "key": "a", "secret": "b", "keep_days": "30", "auto": "1"},
           page="/settings/backups")
check("offsite settings tested and saved", "Connected and saved" in r.page)
Path(f"/srv/harbor/sites/{DOMAIN}/public/keep.txt").write_text("precious")
p.post(f"{SP}/backups", page=f"{SP}/backups")
for _ in range(30):
    t = p.c.get(f"{SP}/backups").text
    if "Copying offsite" not in t and "Backing up" not in t:
        break
    time.sleep(1)
check("backup copied offsite", 'pill ok" title="harbor/' in t, t[:200])
key = re.search(r'name="key" value="([^"]+)"', t)
check("offsite copy listed", "Offsite copies" in t)
sh(f"rm -f /srv/harbor/backups/{DOMAIN}/*.tar.gz")
t = p.c.get(f"{SP}/backups").text
key = re.search(r'name="key" value="(harbor/[^"]+)"', t)
if key:
    p.post(f"{SP}/backups/offsite/fetch", {"key": key.group(1)}, page=f"{SP}/backups")
    t = p.c.get(f"{SP}/backups").text
    bid = re.search(r"/backups/(\d+)/restore", t)
    Path(f"/srv/harbor/sites/{DOMAIN}/public/keep.txt").unlink()
    p.post(f"{SP}/backups/{bid.group(1)}/restore", {"files": "1"}, page=f"{SP}/backups")
    for _ in range(20):
        if Path(f"/srv/harbor/sites/{DOMAIN}/public/keep.txt").exists():
            break
        time.sleep(1)
    check("restore from an offsite copy", web("/keep.txt").text == "precious")
else:
    check("offsite key listed", False)
p.post("/settings/backups", {"bucket": "", "keep_days": "30"}, page="/settings/backups")

# ---------- alerts ----------
got = []


class Hook(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        got.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        self.send_response(200); self.end_headers()

    def log_message(self, *a):
        pass


srv = http.server.HTTPServer(("127.0.0.1", 0), Hook)
threading.Thread(target=srv.serve_forever, daemon=True).start()
# webhooks must be https in the form; point at the local listener through a tiny TLS-less exception:
sh(f"cd /opt/harbor && venv/bin/python -c \"from harbor import db; db.init(); db.set_setting('alert_webhook', 'http://127.0.0.1:{srv.server_port}/hook')\"")
r = p.post("/settings/alerts/test", page="/settings/alerts")
check("test alert delivered to webhook", any("Test alert" in g.get("title", "") for g in got), got)
Path(f"/srv/harbor/sites/{DOMAIN}/public/index.html").unlink(missing_ok=True)
Path(f"/srv/harbor/sites/{DOMAIN}/public/index.php").write_text("<?php echo 'home';")
sh(f"chown {user}: /srv/harbor/sites/{DOMAIN}/public/index.php")
sh(f"systemctl stop harbor-php-{user}")
for _ in range(2):
    p.post("/settings/alerts/check", page="/settings/alerts")
    time.sleep(6)
titles = [g.get("title", "") for g in got]
check("site down detected and alerted", any(f"{DOMAIN} is down" in t for t in titles), titles)
check("stopped PHP service alerted", any(f"harbor-php-{user}" in t for t in titles), titles)
sh(f"systemctl start harbor-php-{user}")
p.post("/settings/alerts/check", page="/settings/alerts"); time.sleep(6)
titles = [g.get("title", "") for g in got]
check("recovery announced", any("Resolved" in t and DOMAIN in t for t in titles), titles)
needs = re.search(r'<section class="card alert-list">(.*?)</section>', p.c.get("/").text, re.S)
check("dashboard clear again", not needs or f"{DOMAIN} is down" not in needs.group(1), needs and needs.group(1)[:300])
srv.shutdown()

# ---------- self-update ----------
work = Path(tempfile.mkdtemp())
with tarfile.open(PKG) as t:
    t.extractall(work, filter="data")
init = work / "harbor/harbor/__init__.py"


def build(version, broken=False):
    init.write_text(re.sub(r'__version__ = "[^"]+"', f'__version__ = "{version}"', init.read_text()))
    app_py = work / "harbor/harbor/app.py"
    orig = app_py.read_text()
    if broken:
        app_py.write_text("raise RuntimeError('deliberately broken release')\n")
    out = work / f"harbor-{version}.tar.gz"
    with tarfile.open(out, "w:gz") as t:
        t.add(work / "harbor", arcname="harbor")
    app_py.write_text(orig)
    return out


def wait_update():
    for _ in range(120):
        time.sleep(3)
        try:
            s = httpx.get(PANEL + "/settings/updates/status", cookies=p.c.cookies, verify=False, timeout=10).json()
            if s["status"] not in ("queued", "running"):
                return s
        except Exception:
            pass
    return {}


CUR = re.search(r'__version__ = "([^"]+)"', Path("/opt/harbor/harbor/__init__.py").read_text()).group(1)
good = build("9.9.1")
p.post("/settings/updates/upload", files={"package": ("harbor.tar.gz", good.read_bytes(), "application/gzip")},
       page="/settings/updates")
s = wait_update()
check("update installs and panel comes back", s.get("status") == "done" and s.get("version") == "9.9.1", s)
check("sites keep working after update", web("/who.php").text.startswith(user + "|"))
bad = build("9.9.2", broken=True)
p.post("/settings/updates/upload", files={"package": ("harbor.tar.gz", bad.read_bytes(), "application/gzip")},
       page="/settings/updates")
s = wait_update()
check("broken update is rolled back automatically", s.get("status") == "rolled_back" and s.get("version") == "9.9.1", s)
check("rollback log explains why", "deliberately broken release" in s.get("log", ""), s.get("log", "")[-300:])
rel = re.findall(r'name="release" value="(' + re.escape(CUR) + r'-[^"]+)"', p.c.get("/settings/updates").text)
check("the version from before the update is kept", rel, CUR)
if rel:
    p.post("/settings/updates/rollback", {"release": rel[0]}, page="/settings/updates")
    s = wait_update()
    check("roll back to a saved version", s.get("status") == "done" and s.get("version") == CUR, s)
shutil.rmtree(work, ignore_errors=True)

# cleanup
moto.terminate()
uid = re.search(r'action="/users/(\d+)/delete" data-confirm="Delete user s1admin', p.c.get("/users").text)
if uid:
    p.post(f"/users/{uid.group(1)}/delete", page="/users")
p.post(f"{SP}/delete", {"confirm": DOMAIN, "remove_files": "1", "drop_dbs": "1"}, page=SP)
check("deleting the site removes its PHP service", not Path(f"/etc/systemd/system/harbor-php-{user}.service").exists())

ok = sum(1 for _, r in results if r)
print(f"\n{ok}/{len(results)} checks passed")
