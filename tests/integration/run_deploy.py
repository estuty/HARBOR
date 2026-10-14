#!/usr/bin/env python3
"""Live checks for Git deploy on a real Harbor server (run as root).

Sets up a private Git server on this machine (user `gitsrv`, SSH, git-shell),
then: connect a site, deploy-key flow, first deploy with backup, kept paths,
build as the site user, push webhook through nginx (with GitHub signature, and
past the panel IP allowlist), failing build leaves the live site alone,
rollback, disconnect.

    python3 run_deploy.py <admin-password>
"""
import hashlib
import hmac
import json
import os
import pwd
import re
import subprocess
import sys
import time
from pathlib import Path

for _v in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY", "all_proxy"):
    os.environ.pop(_v, None)

import httpx  # noqa: E402

PANEL = "https://127.0.0.1:8443"
PW = sys.argv[1]
DOMAIN = "deploy-live.test"
GIT_HOME = Path("/srv/gitsrv")
WORK = Path("/tmp/claude-0/deploy-work")
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:700]}"), flush=True)


def sh(cmd, cwd=None):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=cwd)
    return (r.stdout + r.stderr).strip()


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


def web(path):
    return httpx.get(f"http://127.0.0.1{path}", headers={"Host": DOMAIN}, timeout=30)


def commit(msg, files):
    for name, text in files.items():
        f = WORK / name
        f.parent.mkdir(parents=True, exist_ok=True)
        if text is None:
            f.unlink(missing_ok=True)
        else:
            f.write_text(text)
    sh(f"git add -A && git -c user.name='Dev Person' -c user.email=dev@example.org commit -qm '{msg}' && "
       f"git push -q origin HEAD:main && chown -R gitsrv: {GIT_HOME}", cwd=WORK)
    return sh("git rev-parse HEAD", cwd=WORK)


def wait(sid, timeout=120):
    end = time.time() + timeout
    while time.time() < end:
        rows = p.c.get(f"/api/v1/sites/{sid}/deployments", headers=api_h).json()["deployments"]
        if rows and rows[0]["status"] not in ("queued", "running"):
            return rows[0]
        time.sleep(1)
    return rows[0] if rows else {}


# ---------- a private Git server on this machine ----------
sh("git config --global --get-all safe.directory | grep -qx '*' || git config --global --add safe.directory '*'")
if not sh("id -u gitsrv").isdigit():
    sh(f"useradd --system --home-dir {GIT_HOME} --create-home --shell /usr/bin/git-shell gitsrv")
sh(f"rm -rf {GIT_HOME}/site.git {WORK}; mkdir -p {GIT_HOME}/.ssh && git init -q --bare -b main {GIT_HOME}/site.git && "
   f"touch {GIT_HOME}/.ssh/authorized_keys && chown -R gitsrv: {GIT_HOME} && chmod 700 {GIT_HOME}/.ssh && "
   f"chmod 600 {GIT_HOME}/.ssh/authorized_keys")
WORK.mkdir(parents=True)
sh(f"git init -q -b main . && git remote add origin {GIT_HOME}/site.git", cwd=WORK)
v1 = commit("First version", {
    "src/index.php": "<?php echo 'APP v1';",
    "src/about.html": "<h1>About</h1>",
    "build.sh": "set -e\ntest ! -f FAIL || { echo 'tests failed'; exit 3; }\nrm -rf dist && mkdir dist\ncp -r src/. dist/\n"
                "echo \"$(git rev-parse --short HEAD) built by $(whoami)\" > dist/version.txt\n",
    "README.md": "deploy test",
})
check("test Git server ready", len(v1) == 40, v1)
URL = "gitsrv@127.0.0.1:site.git"

p = Panel()
r = p.post("/login", {"username": "admin", "password": PW}, page="/login")
check("login", r.status_code == 303 and r.headers["location"] != "/login")
tok = p.post("/account/tokens", {"name": "deploy-test"}, page="/account")
api_token = re.search(r"(hbr_[A-Za-z0-9_\-]+)", p.c.get("/account").text)
api_h = {"Authorization": f"Bearer {api_token.group(1)}"} if api_token else {}
check("API token for polling", bool(api_token))

# clean slate
m = re.search(rf'href="/sites/(\d+)">{re.escape(DOMAIN)}<', p.c.get("/sites").text)
if m:
    p.post(f"/sites/{m.group(1)}/delete", {"confirm": DOMAIN, "remove_files": "1", "drop_dbs": "1"}, page="/sites")
r = p.post("/sites", {"domain": DOMAIN, "php_version": "8.3", "include_www": "0"}, page="/sites")
sid = int(r.headers["location"].rsplit("/", 1)[1])
SP = f"/sites/{sid}/deploy"
user = f"site{sid}"
root = Path(f"/srv/harbor/sites/{DOMAIN}")
(root / "public/old.html").write_text("old site")
(root / "public/uploads").mkdir()
(root / "public/uploads/photo.jpg").write_bytes(b"\xff\xd8\xff" + b"0" * 100)
sh(f"chown -R {user}: {root}/public")

html = p.c.get(SP).text
check("Deploy tab shows the connect form", "Connect repository" in html and 'class="on">Deploy<' in html)
p.post(f"{SP}/connect", {"repo_url": "https://user:secret@github.com/a/b.git", "branch": "main"}, page=SP)
check("credentials in the address refused", "Don't put a password" in p.flash(SP))
p.post(f"{SP}/connect", {"repo_url": URL, "branch": "main", "subdir": "dist", "build_cmd": "bash build.sh",
                         "after_cmd": "echo after > after.txt", "keep_paths": ".well-known/\nuploads/",
                         "delete_extra": "1", "auto_deploy": "1"}, page=SP)
html = p.c.get(SP).text
key = re.search(r'data-copy="(ssh-ed25519 [^"]+)"', html)
hook = re.search(r'data-copy="(https://[^"]+/hooks/deploy/\d+/[^"]+)"', html)
check("connected: deploy key and webhook shown", key and hook, html[:300])
check("deploy key belongs to the site user, private part 600",
      sh(f"stat -c '%U %a' {root}/git/.ssh/id_ed25519") == f"{user} 600", sh(f"stat -c '%U %a' {root}/git/.ssh/id_ed25519"))

p.post(f"{SP}/check", page=SP)
msg = p.flash(SP)
check("check connection explains a missing deploy key", "refused the deploy key" in msg, msg)
Path(f"{GIT_HOME}/.ssh/authorized_keys").write_text(key.group(1) + "\n")
p.post(f"{SP}/check", page=SP)
msg = p.flash(SP)
check("check connection works once the key is added", "Connection works" in msg, msg)

# ---------- first deploy ----------
p.post(f"{SP}/run", page=SP)
d = wait(sid)
log = p.c.get(f"{SP}/{d['id']}/status").json()["log"]
check("first deploy succeeds", d.get("status") == "done" and d["commit_sha"] == v1, log[-1500:])
check("site serves the deployed PHP", web("/").text == "APP v1", web("/").text[:200])
check("build ran as the site user, in the repository", web("/version.txt").text.strip() == f"{v1[:7]} built by {user}",
      web("/version.txt").text)
check("files not in the repository removed", not (root / "public/old.html").exists())
check("kept path survived", (root / "public/uploads/photo.jpg").exists())
check("only the build folder published (no build.sh, no .git)",
      not (root / "public/build.sh").exists() and not (root / "public/.git").exists())
check("after-deploy command ran in the live folder", (root / "public/after.txt").read_text().strip() == "after")
check("published files owned by the site user", sh(f"stat -c %U {root}/public/index.php") == user)
check("a backup was taken before the first deploy", "Backup saved" in log and "backup taken" in p.c.get(SP).text, log[:800])
check("deploy shown as live", f"<code>{v1[:7]}</code> First version" in p.c.get(SP).text)

# ---------- push webhook through nginx, with the panel locked to another IP ----------
Path("/etc/nginx/harbor/panel-access.conf").write_text("allow 10.99.99.99;\ndeny all;\n")
sh("nginx -s reload"); time.sleep(0.5)
check("panel locked to another IP", httpx.get(PANEL + "/login", verify=False).status_code == 403)
v2 = commit("Second version", {"src/index.php": "<?php echo 'APP v2';"})
body = json.dumps({"ref": "refs/heads/main", "after": v2}).encode()
secret = hook.group(1).rsplit("/", 1)[1]
sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
hook_path = "/hooks/" + hook.group(1).split("/hooks/", 1)[1]
r = httpx.post(PANEL + hook_path, content=body, verify=False,
               headers={"X-GitHub-Event": "push", "X-Hub-Signature-256": sig, "Content-Type": "application/json"})
check("webhook accepted even with the panel locked down", r.status_code == 202, (r.status_code, r.text))
r2 = httpx.post(PANEL + hook_path.rsplit("/", 1)[0] + "/wrong", content=body, verify=False)
check("webhook with a wrong secret refused", r2.status_code == 404, r2.status_code)
Path("/etc/nginx/harbor/panel-access.conf").write_text("")
sh("nginx -s reload"); time.sleep(0.5)
d = wait(sid)
check("push deployed the new version", d.get("status") == "done" and d["commit_sha"] == v2 and d["trigger"] == "push"
      and web("/").text == "APP v2", (d, web("/").text))
check("no second backup", "Backup saved" not in p.c.get(f"{SP}/{d['id']}/status").json()["log"])

# ---------- a failing build leaves the live site alone ----------
v3 = commit("Broken version", {"FAIL": "x", "src/index.php": "<?php echo 'APP v3';"})
p.post(f"{SP}/run", page=SP)
d = wait(sid)
log = p.c.get(f"{SP}/{d['id']}/status").json()["log"]
check("failing build reported", d.get("status") == "failed" and "tests failed" in log and "build command failed" in log, log[-800:])
check("live site unchanged after a failed build", web("/").text == "APP v2" and "live site wasn't changed" in log)
html = p.c.get(SP).text
check("failed deploy shown, v2 still live", "pill bad\">Failed" in html and f"<code>{v2[:7]}</code> Second version" in html)

# ---------- rollback ----------
first_id = [x for x in p.c.get(f"/api/v1/sites/{sid}/deployments", headers=api_h).json()["deployments"]
            if x["commit_sha"] == v1][0]["id"]
p.post(f"{SP}/{first_id}/redeploy", page=SP)
d = wait(sid)
check("rollback to the first version", d.get("status") == "done" and d["trigger"] == "rollback" and web("/").text == "APP v1",
      (d, web("/").text))

# ---------- pushes to other branches are ignored; disconnect ----------
r = httpx.post(PANEL + hook_path, content=json.dumps({"ref": "refs/heads/dev"}).encode(), verify=False,
               headers={"X-GitHub-Event": "push"})
check("push to another branch ignored", r.status_code == 200 and "ignored" in r.text, r.text)
p.post(f"{SP}/disconnect", page=SP)
check("disconnect removes the repository copy and key, keeps the site",
      not (root / "git").exists() and web("/").text == "APP v1" and "Connect repository" in p.c.get(SP).text)
check("activity log records deploys", "deployed" in p.c.get("/activity").text)
check("nginx config valid", "successful" in sh("nginx -t 2>&1"))

# cleanup
p.post(f"/sites/{sid}/delete", {"confirm": DOMAIN, "remove_files": "1", "drop_dbs": "1"}, page="/sites")
failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
