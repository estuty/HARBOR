"""Stage 1: two-factor sign-in, panel allowlist & fail2ban, offsite backups,
alerts, resource limits, self-update."""
import io
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

from fastapi.testclient import TestClient

from conftest import flashes, login, post
from harbor import auth, config, db
from harbor.app import app
from harbor.system import runner


def make_site(c, domain):
    r = post(c, "/sites", {"domain": domain, "php_version": "8.3", "include_www": "1"})
    sid = int(r.headers["location"].rsplit("/", 1)[1])
    return sid, f"/sites/{sid}"


def test_totp_math():
    secret = auth.new_totp_secret()
    now = 1_700_000_000
    code = auth.totp_now(secret, now)
    assert auth.totp_match(secret, code, 0, now) == now // 30
    assert auth.totp_match(secret, code, now // 30, now) is None  # replay refused
    assert auth.totp_match(secret, auth.totp_now(secret, now - 30), 0, now) is not None  # drift ok
    assert auth.totp_match(secret, auth.totp_now(secret, now - 120), 0, now) is None
    # RFC 6238 test vector (SHA1, secret "12345678901234567890", T=59 -> 94287082, 6 digits = 287082)
    import base64
    rfc = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
    assert auth.totp_now(rfc, 59) == "287082"


def test_two_factor_flow():
    c = login("twofa", "twofa-password-1")
    post(c, "/account/2fa/start")
    html = c.get("/account").text
    assert "data:image/svg+xml" in html
    secret = re.search(r'key by hand: <code class="wrap">([A-Z2-7 ]+)</code>', html).group(1).replace(" ", "")
    post(c, "/account/2fa/confirm", {"code": "000000"})
    assert "didn't match" in flashes(c, "/account")[0]
    post(c, "/account/2fa/start")
    secret = re.search(r'key by hand: <code class="wrap">([A-Z2-7 ]+)</code>', c.get("/account").text).group(1).replace(" ", "")
    r = post(c, "/account/2fa/confirm", {"code": auth.totp_now(secret)})
    html = c.get("/account").text  # recovery codes shown once
    codes = re.findall(r'data-copy="([0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4})"', html)
    assert len(codes) == 8
    assert not re.findall(r'data-copy="[0-9a-f]{4}-', c.get("/account").text)

    # sign in again: password alone is not enough
    c2 = TestClient(app)
    r = post(c2, "/login", {"username": "twofa", "password": "twofa-password-1"}, page="/login")
    assert r.headers["location"] == "/login/2fa"
    assert c2.get("/", follow_redirects=False).headers["location"] == "/login"
    post(c2, "/login/2fa", {"code": "123456"}, page="/login/2fa")
    assert "didn't work" in flashes(c2, "/login/2fa")[0]
    log = config.AUTH_LOG.read_text()
    assert "harbor: failed 2fa for user 'twofa' from testclient" in log
    r = post(c2, "/login/2fa", {"code": codes[0]}, page="/login/2fa")  # recovery code
    assert r.headers["location"] == "/"
    # a recovery code works only once
    c3 = TestClient(app)
    post(c3, "/login", {"username": "twofa", "password": "twofa-password-1"}, page="/login")
    r = post(c3, "/login/2fa", {"code": codes[0]}, page="/login/2fa")
    assert "didn't work" in flashes(c3, "/login/2fa")[0]
    # TOTP (a step not used yet)
    uid = db.one("SELECT id FROM users WHERE username = 'twofa'")["id"]
    db.execute("UPDATE users SET totp_last = 0 WHERE id = ?", uid)
    r = post(c3, "/login/2fa", {"code": auth.totp_now(secret)}, page="/login/2fa")
    assert r.headers["location"] == "/"

    # require 2FA for admins: an admin without it is sent to set it up
    post(c, "/security/require-2fa", {"on": "1"}, page="/security")
    assert db.get_setting("require_2fa") == "1"
    plain = login("plainadmin", "plain-password-1")
    assert plain.get("/sites", follow_redirects=False).headers["location"] == "/account#twofactor"
    assert plain.get("/account").status_code == 200
    post(c, "/security/require-2fa", {"on": "0"}, page="/security")

    # admin can reset someone's 2FA; CLI-equivalent works too
    post(c, f"/users/{uid}/2fa/reset", page="/users")
    assert db.one("SELECT totp_enabled FROM users WHERE id = ?", uid)["totp_enabled"] == 0


def test_panel_allowlist_and_bans():
    c = login()
    # testclient's address is "testclient"; lockout protection refuses lists that don't include you
    post(c, "/security/access", {"ips": "203.0.113.5"}, page="/security")
    assert "lock you out" in flashes(c, "/security")[0]
    from harbor.services import protection
    protection.save_access("203.0.113.5, 198.51.100.0/24", True, "203.0.113.5", "test")
    access = (config.NGINX_HARBOR / "panel-access.conf").read_text()
    assert "allow 203.0.113.5/32;" in access and "allow 198.51.100.0/24;" in access and access.strip().endswith("deny all;")
    assert "deny all;" in (config.NGINX_HARBOR / "webmail-access.conf").read_text()
    ignore = (config.p("/etc/fail2ban/jail.d/harbor-ignore.local")).read_text()
    assert "203.0.113.5/32" in ignore and "203.0.113.10" in ignore  # allowlist + server IP never banned
    protection.save_access("", False, "x", "test")
    assert "allow" not in (config.NGINX_HARBOR / "panel-access.conf").read_text()

    post(c, "/security/ban", {"ip": "192.0.2.66"}, page="/security")
    assert "fail2ban-client set harbor-manual banip 192.0.2.66" in runner.DRY_LOG
    post(c, "/security/ban", {"ip": "203.0.113.10"}, page="/security")
    assert "own address" in flashes(c, "/security")[0]
    post(c, "/security/unban", {"ip": "192.0.2.66", "jail": "sshd"}, page="/security")
    assert "fail2ban-client set sshd unbanip 192.0.2.66" in runner.DRY_LOG
    html = c.get("/security").text
    assert "Harbor panel sign-ins" in html and "Recent failed panel sign-ins" in html


def test_offsite_backups():
    from moto import mock_aws
    import boto3
    with mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="harbor-test")
        c = login()
        post(c, "/settings/backups", {"endpoint": "", "region": "us-east-1", "bucket": "wrong-bucket", "prefix": "harbor",
                                      "key": "AK", "secret": "SK", "keep_days": "30", "auto": "1"}, page="/settings/backups")
        assert "NoSuchBucket" in flashes(c, "/settings/backups")[0]
        assert db.get_setting("offsite_bucket") != "wrong-bucket"
        post(c, "/settings/backups", {"endpoint": "", "region": "us-east-1", "bucket": "harbor-test", "prefix": "harbor",
                                      "key": "AK", "secret": "SK", "keep_days": "30", "auto": "1"}, page="/settings/backups")
        assert "Connected and saved" in flashes(c, "/settings/backups")[0]

        sid, page = make_site(c, "offsite.test")
        post(c, f"{page}/backups", page=f"{page}/backups")
        b = db.one("SELECT * FROM backups WHERE site_id = ?", sid)
        assert b["status"] == "done" and b["remote_status"] == "uploaded", b["remote_error"]
        assert b["remote_key"].startswith("harbor/") and b["remote_key"].endswith(b["filename"])
        html = c.get(f"{page}/backups").text
        assert "Offsite copies" in html and b["filename"] in html

        # lose the local copy, bring it back from offsite, restore works from it
        from harbor.system import backup
        backup.safe_file("offsite.test", b["filename"]).unlink()
        db.execute("DELETE FROM backups WHERE id = ?", b["id"])
        post(c, f"{page}/backups/offsite/fetch", {"key": b["remote_key"]}, page=f"{page}/backups")
        fetched = db.one("SELECT * FROM backups WHERE site_id = ? AND kind = 'offsite'", sid)
        assert fetched and backup.safe_file("offsite.test", fetched["filename"]).exists()
        post(c, f"{page}/backups/offsite/fetch", {"key": "harbor/other/x.tar.gz"}, page=f"{page}/backups")
        assert "doesn't belong" in flashes(c, f"{page}/backups")[0]
        # secret is never shown back
        assert "SK" not in re.sub(r"<script.*?</script>", "", c.get("/settings/backups").text).split('name="secret"')[1][:80]
        db.set_setting("offsite_bucket", "")


def test_alerts():
    from harbor.services import alerts
    c = login()
    post(c, "/settings/alerts", {"alert_email": "ops@example.org", "alert_webhook": "https://hooks.slack.com/services/x",
                                 "smtp_host": "smtp.example.org", "smtp_port": "587", "smtp_security": "starttls",
                                 "smtp_user": "u", "smtp_password": "p", "smtp_from": "alerts@example.org",
                                 "alert_disk_pct": "85"}, page="/settings/alerts")
    assert db.get_setting("smtp_password") == "p"
    post(c, "/settings/alerts/test", page="/settings/alerts")
    assert any("email to ops@example.org" in l and "Test alert" in l for l in runner.DRY_LOG)
    n = len(runner.DRY_LOG)
    alerts.fire("test:x", "Something broke", "details")
    alerts.fire("test:x", "Something broke", "details")  # not repeated within 24h
    sent = [l for l in runner.DRY_LOG[n:] if "Something broke" in l]
    assert len(sent) == 2  # one email + one webhook
    assert "Something broke" in c.get("/").text  # dashboard
    alerts.resolve("test:x")
    assert any("Resolved: Something broke" in l for l in runner.DRY_LOG[n:])
    assert not alerts.active()
    # disk check with a threshold that is always exceeded
    db.set_setting("alert_disk_pct", "1")
    alerts.check_disk()
    assert any(a["key"] == "disk:/" for a in alerts.active())
    db.set_setting("alert_disk_pct", "99")
    alerts.check_disk()
    assert not any(a["key"] == "disk:/" for a in alerts.active())
    post(c, "/settings/alerts", {"alert_email": "not an email"}, page="/settings/alerts")
    assert "valid email" in flashes(c, "/settings/alerts")[0]


def test_resource_limits():
    c = login()
    sid, page = make_site(c, "limits.test")
    post(c, f"{page}/limits", {"cpu_pct": "50", "memory_mb": "512", "processes": "4", "disk_mb": "200"}, page=page)
    unit = (config.p("/etc/systemd/system") / f"harbor-php-site{sid}.service").read_text()
    assert "CPUQuota=50%" in unit and "MemoryMax=512M" in unit and "MemoryHigh=460M" in unit and "TasksMax=20" in unit
    assert "pm.max_children = 4" in (config.ETC / "php" / f"site{sid}.conf").read_text()
    assert f"systemctl restart harbor-php-site{sid}" in runner.DRY_LOG
    post(c, f"{page}/limits", {"cpu_pct": "0", "memory_mb": "128", "processes": "4", "disk_mb": "0"}, page=page)
    assert "memory_limit" in flashes(c, page)[0]  # 128 MB < PHP memory_limit 256M
    post(c, f"{page}/limits", {"cpu_pct": "0", "memory_mb": "0", "processes": "10", "disk_mb": "1"}, page=page)
    assert "Disk allowance" in flashes(c, page)[0]
    # disk allowance: over the limit blocks uploads
    post(c, f"{page}/limits", {"cpu_pct": "0", "memory_mb": "0", "processes": "10", "disk_mb": "100"}, page=page)
    unit = (config.p("/etc/systemd/system") / f"harbor-php-site{sid}.service").read_text()
    assert "CPUQuota" not in unit and "MemoryMax" not in unit
    (config.SITES_DIR / "limits.test/public/big.bin").write_bytes(b"\0" * (101 * 1024 * 1024))
    from harbor.services import alerts
    alerts.check_disk_allowances()
    assert any(a["key"] == f"quota:{sid}" for a in alerts.active())
    post(c, f"{page}/files/upload", {"dir": "public"}, files={"files": ("a.txt", b"x", "text/plain")}, page=page)
    assert "over its disk allowance" in flashes(c, f"{page}/files")[0]
    (config.SITES_DIR / "limits.test/public/big.bin").unlink()
    alerts.check_disk_allowances()
    assert not any(a["key"] == f"quota:{sid}" for a in alerts.active())
    # team users can't change limits
    post(c, "/users", {"username": "limituser", "password": "limit-user-pass1", "role": "user", "sites": str(sid)}, page="/users")
    t = login("limituser", "limit-user-pass1", role="user")
    assert post(t, f"{page}/limits", {"cpu_pct": "0"}, page=page).status_code == 403


def _make_pkg(dest: Path, version: str, broken: bool = False) -> Path:
    src = Path(__file__).parent.parent
    work = Path(tempfile.mkdtemp())
    root = work / "harbor"
    shutil.copytree(src / "harbor", root / "harbor", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy2(src / "requirements.txt", root / "requirements.txt")
    init = root / "harbor" / "__init__.py"
    init.write_text(re.sub(r'__version__ = "[^"]+"', f'__version__ = "{version}"', init.read_text()))
    if broken:
        (root / "harbor" / "app.py").write_text("raise RuntimeError('broken release')\n")
    out = dest / f"harbor-{version}.tar.gz"
    with tarfile.open(out, "w:gz") as t:
        t.add(root, arcname="harbor")
    shutil.rmtree(work)
    return out


def test_updater_installs_and_rolls_back():
    """Run the real updater against a scratch install with a tiny health server."""
    import http.server
    import threading
    tmp = Path(tempfile.mkdtemp())
    app_dir, dbp = tmp / "opt", tmp / "harbor.db"
    shutil.copytree(Path(__file__).parent.parent / "harbor", app_dir / "harbor", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy2(Path(__file__).parent.parent / "requirements.txt", app_dir / "requirements.txt")
    con = sqlite3.connect(dbp)
    con.executescript("CREATE TABLE updates (id INTEGER PRIMARY KEY, from_version TEXT, to_version TEXT, status TEXT, "
                      "log TEXT, created_at TEXT, finished_at TEXT); CREATE TABLE keep (x); INSERT INTO keep VALUES (1);")
    con.commit(); con.close()

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            ok = "broken" not in (app_dir / "harbor" / "app.py").read_text()
            self.send_response(200 if ok else 500); self.end_headers()
        def log_message(self, *a): pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    env = {**os.environ, "HARBOR_APP_DIR": str(app_dir), "HARBOR_DB": str(dbp), "HARBOR_UPDATE_SKIP_PIP": "1",
           "HARBOR_HEALTH_URL": f"http://127.0.0.1:{srv.server_port}/", "HARBOR_RESTART_CMD": "true",
           "HARBOR_UPDATE_LOG": str(tmp / "update.log"), "HARBOR_SYSTEM_VERSION_FILE": str(tmp / "sv"),
           "PYTHONPATH": str(Path(__file__).parent.parent)}
    updater = str(Path(__file__).parent.parent / "harbor" / "updater.py")
    # import check uses the scratch app dir; it needs the dry-run env to import harbor.app
    env.update(HARBOR_DRY_RUN="1", HARBOR_SANDBOX=str(tmp / "sandbox"))
    env.pop("PYTHONPATH")

    good = _make_pkg(tmp, "9.9.9")
    r = subprocess.run([sys.executable, updater, str(good), "--update-id", "1"], env=env, capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stdout + r.stderr
    assert '__version__ = "9.9.9"' in (app_dir / "harbor/__init__.py").read_text()
    rels = list((app_dir / "releases").iterdir())
    assert len(rels) == 1 and (rels[0] / "harbor.db").exists()
    con = sqlite3.connect(dbp)
    assert con.execute("SELECT status, to_version FROM updates WHERE id = 1").fetchone() == ("done", "9.9.9")
    con.close()

    bad = _make_pkg(tmp, "10.0.0", broken=True)
    r = subprocess.run([sys.executable, updater, str(bad), "--update-id", "2"], env=env, capture_output=True, text=True, timeout=300)
    assert r.returncode == 2, r.stdout + r.stderr
    assert "Rolling back" in r.stdout and "broken release" in r.stdout
    assert '__version__ = "9.9.9"' in (app_dir / "harbor/__init__.py").read_text()
    assert "broken" not in (app_dir / "harbor/app.py").read_text()
    con = sqlite3.connect(dbp)
    assert con.execute("SELECT status FROM updates WHERE id = 2").fetchone() == ("rolled_back",)
    assert con.execute("SELECT x FROM keep").fetchone() == (1,)  # data survived
    con.close()

    junk = tmp / "junk.tar.gz"
    with tarfile.open(junk, "w:gz") as t:
        info = tarfile.TarInfo("readme.txt"); info.size = 2
        t.addfile(info, io.BytesIO(b"hi"))
    r = subprocess.run([sys.executable, updater, str(junk), "--update-id", "3"], env=env, capture_output=True, text=True)
    assert r.returncode == 1 and "isn't a Harbor package" in r.stdout
    srv.shutdown()
    shutil.rmtree(tmp, ignore_errors=True)


def test_new_pages_render():
    c = login()
    for u in ("/security", "/settings", "/settings/backups", "/settings/alerts", "/settings/updates", "/account"):
        r = c.get(u)
        assert r.status_code == 200 and "Traceback" not in r.text, u
