"""Git deploy tab (dry-run): connect, validation, deploy, rollback, webhook, permissions, API."""
import hashlib
import hmac
import json
import time

from fastapi.testclient import TestClient

from conftest import csrf, flashes, login, post
from harbor import auth, db
from harbor.app import app
from harbor.services import get_site, site_root
from harbor.system import gitdeploy


def make_site(c, domain):
    r = post(c, "/sites", {"domain": domain, "php_version": "8.3", "include_www": "1"})
    return int(r.headers["location"].rsplit("/", 1)[1])


def wait_done(site_id, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        if not db.one("SELECT 1 FROM deployments WHERE site_id = ? AND status IN ('queued', 'running')", site_id):
            return db.all("SELECT * FROM deployments WHERE site_id = ? ORDER BY id DESC", site_id)
        time.sleep(0.05)
    raise AssertionError("deploy didn't finish")


CONNECT = {"repo_url": "https://github.com/estuty/HARBOR.git", "branch": "main", "subdir": "",
           "build_cmd": "echo build", "after_cmd": "", "keep_paths": ".well-known/\n.env",
           "delete_extra": "1", "auto_deploy": "1"}


def test_validation_and_connect():
    c = login("deployer", "deployer-password-1")
    sid = make_site(c, "deploy-one.test")
    page = f"/sites/{sid}/deploy"
    html = c.get(page).text
    assert "Deploy from Git" in html and "Connect repository" in html  # empty state
    assert f'href="/sites/{sid}/deploy" class="on"' in html  # tab is active

    for bad, msg in ((dict(CONNECT, repo_url="https://user:tok@github.com/a/b.git"), "Don't put a password"),
                     (dict(CONNECT, repo_url="file:///etc"), "Enter the repository address"),
                     (dict(CONNECT, repo_url="--upload-pack=touch /tmp/x"), "Enter the repository address"),
                     (dict(CONNECT, branch="a..b"), "Branch name"),
                     (dict(CONNECT, subdir="../../etc"), "Folder to publish"),
                     (dict(CONNECT, keep_paths="../secret"), "Kept paths")):
        post(c, f"{page}/connect", bad, page=page)
        assert msg in flashes(c, page)[0], bad
        assert not db.one("SELECT 1 FROM git_deploy WHERE site_id = ?", sid)

    post(c, f"{page}/connect", CONNECT, page=page)
    cfg = db.one("SELECT * FROM git_deploy WHERE site_id = ?", sid)
    assert cfg["repo_url"] == CONNECT["repo_url"] and json.loads(cfg["keep_paths"]) == [".well-known/", ".env"]
    html = c.get(page).text
    assert "ssh-ed25519" in html and f"/hooks/deploy/{sid}/{cfg['hook_secret']}" in html
    assert "Not deployed yet" in html and "No deploys yet" in html
    # second connect refused
    post(c, f"{page}/connect", CONNECT, page=page)
    assert "already connected" in flashes(c, page)[0]
    # check connection (dry-run remote has 'main')
    post(c, f"{page}/check", page=page)
    assert "Connection works" in flashes(c, page)[0]
    post(c, f"{page}/settings", dict(CONNECT, branch="production"), page=page)
    post(c, f"{page}/check", page=page)
    assert "no branch 'production'" in flashes(c, page)[0]


def test_deploy_rollback_and_backup():
    c = login("deployer2", "deployer2-password")
    sid = make_site(c, "deploy-two.test")
    page = f"/sites/{sid}/deploy"
    (site_root(get_site(sid)) / "public" / "old.php").write_text("<?php // existing site")
    post(c, f"{page}/connect", CONNECT, page=page)
    post(c, f"{page}/run", page=page)
    rows = wait_done(sid)
    first = rows[0]
    assert first["status"] == "done", first["log"]
    assert first["commit_sha"] == gitdeploy.DRY_SHA and first["trigger"] == "manual"
    assert first["backup_id"] and db.one("SELECT status FROM backups WHERE id = ?", first["backup_id"])["status"] == "done"
    assert "Running the build command" in first["log"] and "Live: ddddddd" in first["log"]
    html = c.get(page).text
    assert "Live</span> <code>ddddddd</code>" in html

    # second deploy: no backup, and the first one can be redeployed (rollback)
    post(c, f"{page}/run", page=page)
    rows = wait_done(sid)
    assert rows[0]["status"] == "done" and not rows[0]["backup_id"]
    post(c, f"{page}/{rows[1]['id']}/redeploy", page=page)
    rows = wait_done(sid)
    assert rows[0]["trigger"] == "rollback" and rows[0]["target_sha"] == gitdeploy.DRY_SHA and rows[0]["status"] == "done"
    # a version never deployed can't be "redeployed"
    db.execute("UPDATE deployments SET commit_sha = ? WHERE id = ?", "a" * 40, rows[2]["id"])
    db.execute("UPDATE deployments SET status = 'failed' WHERE id = ?", rows[2]["id"])
    post(c, f"{page}/{rows[2]['id']}/redeploy", page=page)
    assert "deployed before" in flashes(c, page)[0]
    # status endpoint
    st = c.get(f"{page}/{rows[0]['id']}/status").json()
    assert st["status"] == "done" and "Live:" in st["log"]

    # disconnect keeps files, forgets config
    post(c, f"{page}/disconnect", page=page)
    assert not db.one("SELECT 1 FROM git_deploy WHERE site_id = ?", sid)
    assert not db.one("SELECT 1 FROM deployments WHERE site_id = ?", sid)
    assert (site_root(get_site(sid)) / "public" / "old.php").exists()
    assert "Connect repository" in c.get(page).text


def test_queue_skips_older():
    c = login("deployer3", "deployer3-password")
    sid = make_site(c, "deploy-q.test")
    page = f"/sites/{sid}/deploy"
    post(c, f"{page}/connect", CONNECT, page=page)
    from harbor.services import deploy
    with deploy._lock:  # hold the worker so three deploys pile up
        for _ in range(3):
            db.execute("INSERT INTO deployments (site_id, status, trigger, actor, branch) VALUES (?, 'queued', 'push', 'webhook', 'main')", sid)
    deploy.start(sid, "push", "webhook")
    rows = wait_done(sid)
    assert [r["status"] for r in rows] == ["done", "skipped", "skipped", "skipped"]


def test_webhook():
    c = login("hooker", "hooker-password-1")
    sid = make_site(c, "deploy-hook.test")
    page = f"/sites/{sid}/deploy"
    post(c, f"{page}/connect", CONNECT, page=page)
    secret = db.one("SELECT hook_secret FROM git_deploy WHERE site_id = ?", sid)["hook_secret"]
    anon = TestClient(app)  # no session: the hook is public, the secret is the key
    url = f"/hooks/deploy/{sid}/{secret}"
    push = json.dumps({"ref": "refs/heads/main", "after": "x"}).encode()

    assert anon.post(f"/hooks/deploy/{sid}/wrong", content=push).status_code == 404
    assert anon.post(f"/hooks/deploy/99999/{secret}", content=push).status_code == 404
    assert anon.get(url).status_code == 405
    r = anon.post(url, content=b"{}", headers={"X-GitHub-Event": "ping"})
    assert r.status_code == 200 and "pong" in r.text
    r = anon.post(url, content=push, headers={"X-GitHub-Event": "push", "X-Hub-Signature-256": "sha256=00"})
    assert r.status_code == 403
    r = anon.post(url, content=json.dumps({"ref": "refs/heads/dev"}).encode(), headers={"X-GitHub-Event": "push"})
    assert r.status_code == 200 and "ignored" in r.text
    r = anon.post(url, content=b"{}", headers={"X-GitHub-Event": "issues"})
    assert r.status_code == 200 and "ignored" in r.text
    assert not db.one("SELECT 1 FROM deployments WHERE site_id = ?", sid)

    sig = "sha256=" + hmac.new(secret.encode(), push, hashlib.sha256).hexdigest()
    r = anon.post(url, content=push, headers={"X-GitHub-Event": "push", "X-Hub-Signature-256": sig})
    assert r.status_code == 202 and "queued" in r.text
    rows = wait_done(sid)
    assert rows[0]["trigger"] == "push" and rows[0]["actor"] == "webhook" and rows[0]["status"] == "done"
    # GitLab token header, Bitbucket payload
    assert anon.post(url, content=push, headers={"X-Gitlab-Event": "Push Hook", "X-Gitlab-Token": "nope"}).status_code == 403
    assert anon.post(url, content=push, headers={"X-Gitlab-Event": "Push Hook", "X-Gitlab-Token": secret}).status_code == 202
    wait_done(sid)
    bb = json.dumps({"push": {"changes": [{"new": {"name": "other"}}]}}).encode()
    assert "ignored" in anon.post(url, content=bb, headers={"X-Event-Key": "repo:push"}).text
    # auto-deploy off
    post(c, f"{page}/settings", dict(CONNECT, auto_deploy=""), page=page)
    r = anon.post(url, content=push, headers={"X-GitHub-Event": "push"})
    assert r.status_code == 200 and "automatic deploys are off" in r.text
    # rotating the secret retires the old address
    post(c, f"{page}/hook/rotate", page=page)
    assert anon.post(url, content=push).status_code == 404


def test_permissions_and_api():
    admin = login("depadmin", "depadmin-password")
    sid = make_site(admin, "deploy-perm.test")
    other = make_site(admin, "deploy-other.test")
    post(admin, f"/sites/{sid}/deploy/connect", CONNECT, page=f"/sites/{sid}/deploy")
    uid = auth.create_user("teamdev", "teamdev-password-1", "user")
    db.execute("INSERT INTO user_sites (user_id, site_id) VALUES (?, ?)", uid, sid)
    team = TestClient(app)
    post(team, "/login", {"username": "teamdev", "password": "teamdev-password-1"}, page="/login")
    assert team.get(f"/sites/{sid}/deploy").status_code == 200
    assert team.get(f"/sites/{other}/deploy").status_code == 403
    r = team.post(f"/sites/{other}/deploy/run", data={"csrf": csrf(team, "/account")}, follow_redirects=False)
    assert r.status_code == 403
    post(team, f"/sites/{sid}/deploy/run", page=f"/sites/{sid}/deploy")
    assert wait_done(sid)[0]["actor"] == "teamdev"
    # logged out: redirected to login
    assert TestClient(app).get(f"/sites/{sid}/deploy", follow_redirects=False).status_code == 303
    # CSRF required
    r = team.post(f"/sites/{sid}/deploy/run", data={"csrf": "bad"}, follow_redirects=False)
    assert "Security token expired" in flashes(team, f"/sites/{sid}/deploy")[0]

    token = auth.create_token(uid, "ci")
    api = TestClient(app)
    h = {"Authorization": f"Bearer {token}"}
    r = api.post(f"/api/v1/sites/{sid}/deploy", headers=h)
    assert r.status_code == 202, r.text
    wait_done(sid)
    assert api.post(f"/api/v1/sites/{other}/deploy", headers=h).status_code == 403
    hist = api.get(f"/api/v1/sites/{sid}/deployments", headers=h).json()["deployments"]
    assert hist[0]["status"] == "done" and hist[0]["actor"] == "teamdev (api)"
    assert api.post(f"/api/v1/sites/{sid}/deploy").status_code == 401


def test_site_delete_cleans_up():
    c = login("depdel", "depdel-password-1")
    sid = make_site(c, "deploy-del.test")
    post(c, f"/sites/{sid}/deploy/connect", CONNECT, page=f"/sites/{sid}/deploy")
    post(c, f"/sites/{sid}/deploy/run", page=f"/sites/{sid}/deploy")
    wait_done(sid)
    post(c, f"/sites/{sid}/delete", {"confirm": "deploy-del.test", "remove_files": "1", "drop_dbs": "1"}, page=f"/sites/{sid}")
    assert not db.one("SELECT 1 FROM git_deploy WHERE site_id = ?", sid)
    assert not db.one("SELECT 1 FROM deployments WHERE site_id = ?", sid)
