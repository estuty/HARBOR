"""End-to-end smoke test in dry-run mode: no system changes, everything else real.

    HARBOR_DRY_RUN=1 python -m pytest -q tests
"""
import io
import os
import re
import shutil
import tarfile
import tempfile

from fastapi.testclient import TestClient

from harbor import config, db
from harbor.app import app
from harbor.system import runner
from conftest import login, post


def test_requires_login():
    c = TestClient(app)
    r = c.get("/sites", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert c.get("/api/stats").status_code == 401


def test_bad_password_and_csrf():
    c = TestClient(app)
    r = post(c, "/login", {"username": "admin", "password": "nope"}, page="/login")
    assert r.headers["location"] == "/login"
    r = c.post("/login", data={"username": "admin", "password": "x", "csrf": "forged"}, follow_redirects=False)
    assert "Security token" in c.get("/login").text


def test_full_flow():
    c = login()
    assert "Dashboard" in c.get("/").text

    # invalid domain rejected
    post(c, "/sites", {"domain": "bad domain;rm -rf /", "php_version": "8.3"})
    assert "valid domain" in c.get("/sites").text

    # create site
    r = post(c, "/sites", {"domain": "Example.COM", "php_version": "8.3", "include_www": "1"})
    assert r.status_code == 303 and r.headers["location"].startswith("/sites/")
    sid = int(r.headers["location"].rsplit("/", 1)[1])
    site = db.one("SELECT * FROM sites WHERE id = ?", sid)
    assert site["domain"] == "example.com" and site["sysuser"] == f"site{sid}"
    vhost = (config.NGINX_AVAILABLE / "harbor-example.com.conf").read_text()
    assert "server_name example.com www.example.com" in vhost and f"harbor-site{sid}.sock" in vhost
    assert (config.ETC / "php" / f"site{sid}.conf").exists()
    unit = (config.p("/etc/systemd/system") / f"harbor-php-site{sid}.service").read_text()
    assert "CPUQuota=100%" in unit and "MemoryMax=1024M" in unit
    assert (config.SITES_DIR / "example.com/public/index.html").exists()
    assert any("useradd" in l for l in runner.DRY_LOG) and any(l == "nginx -t" for l in runner.DRY_LOG)

    # duplicate rejected
    post(c, "/sites", {"domain": "example.com", "php_version": "8.3"})
    assert "already exists" in c.get("/sites").text

    page = f"/sites/{sid}"
    assert "example.com" in c.get(page).text

    # HTTPS
    post(c, f"{page}/ssl/enable", page=page)
    vhost = (config.NGINX_AVAILABLE / "harbor-example.com.conf").read_text()
    assert "listen 443 ssl" in vhost and "return 301 https" in vhost
    assert any(l.startswith("certbot certonly") for l in runner.DRY_LOG)

    # SFTP with generated password -> shown once
    post(c, f"{page}/sftp", {"password": ""}, page=page)
    html = c.get(page).text
    assert "SFTP password" in html and "Shown once" in html
    assert "Shown once" not in c.get(page).text

    # databases
    post(c, f"{page}/databases", {"name": "wordpress"}, page=page)
    html = c.get(f"{page}/databases").text
    assert f"site{sid}_wordpress" in html and "save this password" in html
    post(c, f"{page}/databases", {"name": "x'; DROP"}, page=page)
    assert "lowercase letters" in c.get(f"{page}/databases").text
    dbid = db.one("SELECT id FROM databases WHERE site_id = ?", sid)["id"]
    post(c, f"{page}/databases/{dbid}/reset", page=page)
    assert "New database password" in c.get(f"{page}/databases").text

    # files: upload, edit, mkdir, rename, traversal blocked
    r = post(c, f"{page}/files/upload", {"dir": "public"},
             files={"files": ("hello.php", io.BytesIO(b"<?php echo 'hi';"), "text/plain")}, page=page)
    assert (config.SITES_DIR / "example.com/public/hello.php").read_text() == "<?php echo 'hi';"
    post(c, f"{page}/files/save", {"path": "public/hello.php", "content": "<?php echo 'bye';"}, page=page)
    assert "bye" in (config.SITES_DIR / "example.com/public/hello.php").read_text()
    assert "bye" in c.get(f"{page}/files/edit", params={"path": "public/hello.php"}).text
    post(c, f"{page}/files/op", {"op": "mkdir", "dir": "public", "name": "assets"}, page=page)
    assert (config.SITES_DIR / "example.com/public/assets").is_dir()
    post(c, f"{page}/files/op", {"op": "rename", "dir": "public", "target": "public/hello.php", "name": "hi.php"}, page=page)
    assert (config.SITES_DIR / "example.com/public/hi.php").exists()
    post(c, f"{page}/files/op", {"op": "mkdir", "dir": "../../../../etc", "name": "pwn"}, page=page)
    assert "outside the site folder" in c.get(f"{page}/files").text
    post(c, f"{page}/files/op", {"op": "delete", "dir": "", "target": "public"}, page=page)
    assert (config.SITES_DIR / "example.com/public").exists()
    os.symlink("/etc", config.SITES_DIR / "example.com/public/escape")
    r = c.get(f"{page}/files", params={"path": "public/escape"}, follow_redirects=True)
    assert "outside the site folder" in r.text
    assert c.get(f"{page}/files/download", params={"path": "public/hi.php"}).content == b"<?php echo 'bye';"

    # cron
    post(c, f"{page}/cron", {"schedule": "*/5 * * * *", "command": "php /x/artisan schedule:run"}, page=page)
    assert "schedule:run" in c.get(f"{page}/cron").text
    post(c, f"{page}/cron", {"schedule": "* * *", "command": "x"}, page=page)
    assert "5 cron fields" in c.get(f"{page}/cron").text
    job = db.one("SELECT id FROM cron_jobs WHERE site_id = ?", sid)["id"]
    post(c, f"{page}/cron/{job}/toggle", page=page)
    assert db.one("SELECT enabled FROM cron_jobs WHERE id = ?", job)["enabled"] == 0

    # backups (runs in background task; TestClient executes it before returning)
    post(c, f"{page}/backups", page=page)
    b = db.one("SELECT * FROM backups WHERE site_id = ?", sid)
    assert b["status"] == "done", b["error"]
    r = c.get(f"{page}/backups/{b['id']}/download")
    names = tarfile.open(fileobj=io.BytesIO(r.content)).getnames()
    assert "files/example.com/public/hi.php" in names and f"databases/site{sid}_wordpress.sql" in names

    # logs + activity + other pages render
    (config.SITES_DIR / "example.com/logs/error.log").write_text("line1\nline2\n")
    assert "line2" in c.get(f"{page}/logs").text
    assert "Created site example.com" in c.get("/activity").text
    assert c.get("/api/stats").json()["cpu"] >= 0

    # PHP switch to an uninstalled version fails cleanly
    post(c, f"{page}/php", {"php_version": "5.6"}, page=page)
    assert "not installed" in c.get(page).text

    # delete requires confirmation text
    post(c, f"{page}/delete", {"confirm": "nope"}, page=page)
    assert db.one("SELECT id FROM sites WHERE id = ?", sid)
    post(c, f"{page}/delete", {"confirm": "example.com", "remove_files": "1", "drop_dbs": "1"}, page=page)
    assert not db.one("SELECT id FROM sites WHERE id = ?", sid)
    assert not (config.NGINX_AVAILABLE / "harbor-example.com.conf").exists()
    assert not (config.SITES_DIR / "example.com").exists()
