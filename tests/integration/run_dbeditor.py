#!/usr/bin/env python3
"""Live checks for the database editor (Databases tab -> Open) on a real Harbor server.

    python3 run_dbeditor.py <admin-password>
"""
import os
import re
import sqlite3
import subprocess
import sys

for _v in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY", "all_proxy"):
    os.environ.pop(_v, None)

import httpx  # noqa: E402
from urllib.parse import urljoin  # noqa: E402

PANEL = "https://127.0.0.1:8443"
PW = sys.argv[1]
SITE, OTHER = "dbedit-live.test", "dbedit-other.test"
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:500]}"), flush=True)


def sh(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


class Panel:
    def __init__(self):
        self.c = httpx.Client(base_url=PANEL, verify=False, follow_redirects=False, timeout=60)

    def csrf(self, page):
        return re.search(r'name="csrf" value="([^"]+)"', self.c.get(page).text).group(1)

    def post(self, url, data=None, page="/account"):
        return self.c.post(url, data=dict(data or {}, csrf=self.csrf(page)))


def site(p, domain):
    m = re.search(rf'href="/sites/(\d+)">{re.escape(domain)}<', p.c.get("/sites").text)
    if m:
        p.post(f"/sites/{m.group(1)}/delete", {"confirm": domain, "remove_files": "1", "drop_dbs": "1"}, page="/sites")
    r = p.post("/sites", {"domain": domain, "php_version": "8.3", "include_www": "0"}, page="/sites")
    sid = int(r.headers["location"].rsplit("/", 1)[1])
    p.post(f"/sites/{sid}/databases", {"name": "app"}, page=f"/sites/{sid}/databases")
    dbid, name = re.search(r'/databases/(\d+)/open".*?</form>', p.c.get(f"/sites/{sid}/databases").text, re.S).group(1), f"site{sid}_app"
    return sid, int(dbid), name


p = Panel()
r = p.post("/login", {"username": "admin", "password": PW}, page="/login")
check("login", r.status_code == 303 and r.headers["location"] != "/login")

anon = httpx.Client(base_url=PANEL, verify=False, follow_redirects=False)
r = anon.get("/dbadmin/")
check("editor needs a panel sign-in", r.status_code == 302 and r.headers.get("location", "").endswith("/login"), (r.status_code, r.headers))

sid, dbid, name = site(p, SITE)
osid, odbid, oname = site(p, OTHER)
sh(f"mysql {name} -e \"CREATE TABLE items (id INT PRIMARY KEY, label VARCHAR(50)); INSERT INTO items VALUES (1, 'hello-from-harbor')\"")
sh(f"mysql {oname} -e \"CREATE TABLE secrets (v VARCHAR(50)); INSERT INTO secrets VALUES ('do-not-show')\"")

r = p.post(f"/sites/{sid}/databases/{dbid}/open", page=f"/sites/{sid}/databases")
loc = r.headers.get("location", "")
check("Open sends the browser to the editor with a one-time token", r.status_code == 303 and loc.startswith("/dbadmin/?harbor="), (r.status_code, loc))
r = p.c.get(loc)
check("token is swapped for a login and the token leaves the address",
      r.status_code in (302, 303) and "username=hbr_ed_" in r.headers.get("location", "") and "harbor=" not in r.headers.get("location", ""),
      (r.status_code, r.headers.get("location"), r.text[:300]))
home = urljoin("/dbadmin/", r.headers["location"])
user = re.search(r"username=(hbr_ed_[0-9a-f]+)", home).group(1)
r = p.c.get(home)
check("editor opens the database and lists its tables", r.status_code == 200 and "items" in r.text, (r.status_code, r.text[:400]))
r = p.c.get(f"/dbadmin/?username={user}&db={name}&select=items")
check("table data is shown", "hello-from-harbor" in r.text, r.text[:400])
check("PHP for the editor runs as its own user", "harbor-dbadmin" in sh("ps -eo user,cmd | grep 'pool harbor-dbadmin' | grep -v grep"))

r = p.c.get(loc)
check("the same link can't be used twice", r.status_code == 403 and "expired" in r.text, (r.status_code, r.text[:200]))

grants = sh(f"mysql -N -e \"SHOW GRANTS FOR '{user}'@'localhost'\"")
check("temporary user can only use this database", f"`{name}`" in grants and "*.* TO" in grants and "ALL PRIVILEGES ON *.*" not in grants
      and oname not in grants, grants)
r = p.c.get(f"/dbadmin/?username={user}&db={oname}&select=secrets")
errs = " ".join(re.findall(r"class=['\"]error['\"][^>]*>(.*?)<", r.text, re.S))
check("another site's database is refused", "do-not-show" not in r.text and (oname in errs or "Invalid database" in errs or "denied" in r.text.lower()),
      errs or r.text[:400])
r = p.c.get(f"/dbadmin/?username={user}")
check("database list shows only this database", name in r.text and oname not in r.text and "information_schema" not in r.text, r.text[:400])

r = anon.post("/dbadmin/", data={"auth[driver]": "server", "auth[server]": "", "auth[username]": "root", "auth[password]": "", "auth[db]": ""})
check("direct logins are refused without a panel session", r.status_code == 302 and r.headers.get("location", "").endswith("/login"))
r = p.c.post("/dbadmin/", data={"auth[driver]": "server", "auth[server]": "", "auth[username]": "root", "auth[password]": "x", "auth[db]": ""},
             follow_redirects=True)
check("only Harbor's temporary users can sign in to the editor", "Open databases from Harbor" in r.text or "Open a database" in r.text, r.text[:400])

# expiry
con = sqlite3.connect("/var/lib/harbor/harbor.db")
con.execute("UPDATE db_editor_sessions SET expires_at = '2000-01-01 00:00:00' WHERE mysql_user = ?", (user,))
con.commit(); con.close()
out = sh("cd /opt/harbor && venv/bin/python -c 'from harbor.services import dbeditor; print(dbeditor.cleanup_expired())'")
check("expired temporary users are dropped", out.strip().endswith("1") and
      not sh(f"mysql -N -e \"SELECT User FROM mysql.user WHERE User = '{user}'\""), out)
r = p.c.get(f"/dbadmin/?username={user}&db={name}")
check("an expired session asks to open again from Harbor", "items" not in r.text and ("Open a database" in r.text or "denied" in r.text.lower()), r.text[:300])

# signing out of the panel closes the door
p.post("/logout", page="/sites")
r = p.c.get(f"/dbadmin/?username={user}&db={name}")
check("signed out of the panel: editor not reachable", r.status_code == 302 and r.headers.get("location", "").endswith("/login"))

# cleanup
p = Panel()
p.post("/login", {"username": "admin", "password": PW}, page="/login")
for d in (SITE, OTHER):
    m = re.search(rf'href="/sites/(\d+)">{re.escape(d)}<', p.c.get("/sites").text)
    if m:
        p.post(f"/sites/{m.group(1)}/delete", {"confirm": d, "remove_files": "1", "drop_dbs": "1"}, page="/sites")
check("no temporary users left behind", not sh("mysql -N -e \"SELECT User FROM mysql.user WHERE User LIKE 'hbr\\_ed\\_%'\""))

failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
