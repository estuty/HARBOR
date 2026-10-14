"""Feature tests (dry-run): web rules, security, PHP, backups/restore, stats,
team users, API tokens, DNS, email, apps, ModSecurity."""
import io
import json
import re
import tarfile

from fastapi.testclient import TestClient

from conftest import flashes, login, post
from harbor import config, db
from harbor.app import app
from harbor.system import runner


def make_site(c, domain):
    r = post(c, "/sites", {"domain": domain, "php_version": "8.3", "include_www": "1"})
    assert r.status_code == 303 and "/sites/" in r.headers["location"], flashes(c, "/sites")[0]
    sid = int(r.headers["location"].rsplit("/", 1)[1])
    return sid, f"/sites/{sid}"


def vhost(domain):
    return (config.NGINX_AVAILABLE / f"harbor-{domain}.conf").read_text()


def test_web_rules_and_security():
    c = login()
    sid, page = make_site(c, "rules.test")

    # redirects
    post(c, f"{page}/redirects", {"source": "/old", "target": "https://rules.test/new", "code": "301", "match": "exact"})
    post(c, f"{page}/redirects", {"source": "/blog", "target": "https://news.rules.test/", "code": "302", "match": "prefix"})
    v = vhost("rules.test")
    assert "location = /old { return 301 https://rules.test/new; }" in v
    assert "location ^~ /blog/ { rewrite ^/blog/(.*)$ https://news.rules.test/$1 redirect; }" in v
    msg, _ = (post(c, f"{page}/redirects", {"source": "/x", "target": "https://a.b/c; evil", "code": "301",
                                             "match": "exact"}), flashes(c, f"{page}/redirects"))[1]
    assert "Redirect target" in msg
    rid = db.site_settings(db.one("SELECT * FROM sites WHERE id = ?", sid))["redirects"][0]["id"]
    post(c, f"{page}/redirects/{rid}/delete")
    assert "location = /old" not in vhost("rules.test")
    post(c, f"{page}/canonical", {"canonical": "bare"})
    assert "if ($host = www.rules.test) { return 301 $scheme://rules.test$request_uri; }" in vhost("rules.test")

    # IP blocker
    post(c, f"{page}/security/ip", {"ips": "198.51.100.7, 203.0.113.0/24"})
    v = vhost("rules.test")
    assert "deny 198.51.100.7/32;" in v and "deny 203.0.113.0/24;" in v and "allow all;" in v
    post(c, f"{page}/security/ip", {"ips": "not-an-ip"})
    assert "not an IP address" in flashes(c, f"{page}/security")[0]
    post(c, f"{page}/security/ip/unblock", {"ip": "198.51.100.7/32"})
    assert "198.51.100.7" not in vhost("rules.test")

    # hotlink
    post(c, f"{page}/security/hotlink", {"enabled": "1", "exts": "jpg, png", "allowed": "partner.com"})
    v = vhost("rules.test")
    assert "valid_referers none blocked server_names *.rules.test partner.com;" in v
    assert "location ~* \\.(jpg|png)$" in v

    # directory privacy: folder without logins isn't protected yet
    post(c, f"{page}/security/dirs", {"path": "/admin", "realm": "Staff only"})
    assert "auth_basic_user_file" not in vhost("rules.test")
    d = db.one("SELECT * FROM protected_dirs WHERE site_id = ?", sid)
    post(c, f"{page}/security/dirs/{d['id']}/users", {"username": "boss", "password": "longenough1"})
    v = vhost("rules.test")
    assert 'location ^~ /admin/ {' in v and 'auth_basic "Staff only";' in v
    # PHP inside the protected folder is handled inside the protected block
    block = v.split("location ^~ /admin/ {")[1].split("\n    }\n")[0]
    assert "fastcgi_pass" in block
    ht = (config.NGINX_HARBOR / "htpasswd" / f"dir-{d['id']}").read_text()
    assert ht.startswith("boss:$6$")
    post(c, f"{page}/security/dirs/{d['id']}/delete")
    assert "auth_basic_user_file" not in vhost("rules.test")

    # indexes + error pages
    post(c, f"{page}/advanced/indexes", {"path": "/downloads", "enabled": "1"})
    assert "autoindex on;" in vhost("rules.test")
    post(c, f"{page}/advanced/indexes", {"path": "/", "enabled": "1"})
    assert "isn't allowed" in flashes(c, f"{page}/advanced")[0]
    post(c, f"{page}/advanced/errors", {"code": "404", "content": "<h1>Lost</h1>", "enabled": "1"})
    v = vhost("rules.test")
    assert "error_page 404 /__harbor_errors/404.html;" in v
    assert (config.SITES_DIR / "rules.test/errors/404.html").read_text() == "<h1>Lost</h1>"

    # injection attempts in paths are rejected
    post(c, f"{page}/advanced/indexes", {"path": "/a { } b/", "enabled": "1"})
    assert "Path may contain" in flashes(c, f"{page}/advanced")[0]


def test_php_ini():
    c = login()
    sid, page = make_site(c, "php.test")
    form = {"memory_limit": "512M", "upload_max_filesize": "200M", "post_max_size": "200M", "max_execution_time": "120",
            "max_input_time": "60", "max_input_vars": "5000", "session.gc_maxlifetime": "1440",
            "date.timezone": "Europe/London", "display_errors": "Off", "short_open_tag": "Off", "allow_url_fopen": "On"}
    post(c, f"{page}/php/ini", form)
    pool = (config.ETC / "php" / f"site{sid}.conf").read_text()
    assert "php_value[memory_limit] = 512M" in pool and "php_value[date.timezone] = Europe/London" in pool
    assert "client_max_body_size 201M;" in vhost("php.test")
    post(c, f"{page}/php/ini", dict(form, memory_limit="512M\nphp_admin_value[x]=1"))
    assert "use a size" in flashes(c, f"{page}/php")[0]
    post(c, f"{page}/php/ini", dict(form, post_max_size="10M"))
    assert "post_max_size must be" in flashes(c, f"{page}/php")[0]
    post(c, f"{page}/php", {"php_version": "8.2"})
    unit = (config.p("/etc/systemd/system") / f"harbor-php-site{sid}.service").read_text()
    assert "/usr/sbin/php-fpm8.2 --nodaemonize" in unit and "Harbor PHP 8.2" in unit


def test_backup_restore_schedule():
    c = login()
    sid, page = make_site(c, "bk.test")
    post(c, f"{page}/databases", {"name": "app"})
    idx = config.SITES_DIR / "bk.test/public/index.html"
    idx.write_text("version 1")
    post(c, f"{page}/backups")
    b = db.one("SELECT * FROM backups WHERE site_id = ? ORDER BY id DESC", sid)
    assert b["status"] == "done"
    idx.write_text("version 2")
    (config.SITES_DIR / "bk.test/public/new.txt").write_text("added later")
    post(c, f"{page}/backups/{b['id']}/restore", {"files": "1", "dbs": f"site{sid}_app"})
    assert idx.read_text() == "version 1"
    assert not (config.SITES_DIR / "bk.test/public/new.txt").exists()
    assert any(l.startswith(f"mysql site{sid}_app <") for l in runner.DRY_LOG)
    assert "restored files" in c.get("/activity").text

    # restoring a database the site doesn't own is refused
    post(c, f"{page}/backups/{b['id']}/restore", {"dbs": "otherdb"})
    assert "don't belong" in flashes(c, f"{page}/backups")[0]

    # upload: a non-backup is rejected, a real one is accepted
    junk = io.BytesIO()
    with tarfile.open(fileobj=junk, mode="w:gz") as t:
        data = b"hello"
        info = tarfile.TarInfo("random/file.txt"); info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    post(c, f"{page}/backups/upload", files={"archive": ("x.tar.gz", junk.getvalue(), "application/gzip")})
    assert "isn't a Harbor backup" in flashes(c, f"{page}/backups")[0]
    real = c.get(f"{page}/backups/{b['id']}/download").content
    post(c, f"{page}/backups/upload", files={"archive": ("mine.tar.gz", real, "application/gzip")})
    assert db.one("SELECT * FROM backups WHERE site_id = ? AND kind = 'uploaded'", sid)

    # schedule + scheduler + pruning
    post(c, f"{page}/backups/schedule", {"freq": "daily", "keep": "2"})
    from harbor.services import backups as bk
    for _ in range(3):
        db.execute("UPDATE backups SET created_at = '2000-01-01 00:00:00' WHERE kind = 'scheduled'")
        bk.scheduler_tick()
    assert db.one("SELECT COUNT(*) c FROM backups WHERE site_id = ? AND kind = 'scheduled'", sid)["c"] == 2


def test_stats():
    c = login()
    sid, page = make_site(c, "stats.test")
    from datetime import datetime
    day = datetime.now().strftime("%d/%b/%Y")
    lines = [
        f'198.51.100.1 - - [{day}:10:00:00 +0000] "GET / HTTP/1.1" 200 5120 "https://google.com/search" "Mozilla/5.0"',
        f'198.51.100.1 - - [{day}:10:00:01 +0000] "GET /style.css HTTP/1.1" 200 2048 "-" "Mozilla/5.0"',
        f'198.51.100.2 - - [{day}:10:01:00 +0000] "GET /about HTTP/1.1" 200 4096 "-" "Mozilla/5.0"',
        f'66.249.66.1 - - [{day}:10:02:00 +0000] "GET / HTTP/1.1" 200 5120 "-" "Googlebot/2.1"',
        f'198.51.100.3 - - [{day}:10:03:00 +0000] "GET /missing HTTP/1.1" 404 100 "-" "Mozilla/5.0"',
    ]
    (config.SITES_DIR / "stats.test/logs/access.log").write_text("\n".join(lines) + "\n")
    html = c.get(f"{page}/stats?days=7").text
    assert "google.com" in html and "/about" in html
    from harbor.system import weblogs
    d = weblogs.analyse(config.SITES_DIR / "stats.test/logs", "stats.test", 7)
    assert d["unique_visitors"] == 2 and d["totals"]["pages"] == 2 and d["totals"]["requests"] == 5


def test_team_users_and_api():
    admin = login()
    sid_a, _ = make_site(admin, "team-a.test")
    sid_b, _ = make_site(admin, "team-b.test")
    post(admin, "/users", {"username": "jane", "password": "jane-password-123", "role": "user", "sites": str(sid_a)},
         page="/users")
    jane = TestClient(app)
    post(jane, "/login", {"username": "jane", "password": "jane-password-123"}, page="/login")
    assert "team-a.test" in jane.get("/sites").text and "team-b.test" not in jane.get("/sites").text
    assert jane.get(f"/sites/{sid_a}").status_code == 200
    assert jane.get(f"/sites/{sid_b}").status_code == 403
    assert jane.get("/users").status_code == 403 and jane.get("/settings").status_code == 403
    assert jane.get("/", follow_redirects=False).headers["location"] == "/sites"
    r = post(jane, "/sites", {"domain": "sneaky.test", "php_version": "8.3"})
    assert r.status_code == 403
    r = post(jane, f"/sites/{sid_a}/delete", {"confirm": "team-a.test"})
    assert r.status_code == 403 and db.one("SELECT id FROM sites WHERE id = ?", sid_a)

    # API token for jane: same permissions
    post(jane, "/account/tokens", {"name": "ci"})
    shown = re.search(r'data-copy="(hbr_[^"]+)"', jane.get("/account").text)
    assert shown  # shown once...
    assert not re.search(r'data-copy="hbr_', jane.get("/account").text)  # ...then gone
    api = TestClient(app)
    assert api.get("/api/v1/sites").status_code == 401
    r = api.get("/api/v1/sites", headers={"Authorization": f"Bearer {shown.group(1)}"})
    assert r.status_code == 200
    from harbor import auth
    uid = db.one("SELECT id FROM users WHERE username = 'jane'")["id"]
    tok = auth.create_token(uid, "direct")
    h = {"Authorization": f"Bearer {tok}"}
    r = api.get("/api/v1/sites", headers=h)
    assert [s["domain"] for s in r.json()["sites"]] == ["team-a.test"]
    assert api.get(f"/api/v1/sites/{sid_b}", headers=h).status_code == 403
    assert api.post("/api/v1/sites", headers=h, json={"domain": "x.test"}).status_code == 403
    r = api.post(f"/api/v1/sites/{sid_a}/databases", headers=h, json={"name": "api"})
    assert r.status_code == 201 and r.json()["password"]
    admin_tok = auth.create_token(db.one("SELECT id FROM users WHERE username = 'admin'")["id"], "adm")
    r = api.post("/api/v1/sites", headers={"Authorization": f"Bearer {admin_tok}"}, json={"domain": "api-made.test"})
    assert r.status_code == 201 and r.json()["domain"] == "api-made.test"
    r = api.post("/api/v1/sites", headers={"Authorization": f"Bearer {admin_tok}"}, json={"domain": "bad domain"})
    assert r.status_code == 400

    # last admin can't be demoted or deleted
    admin_id = db.one("SELECT id FROM users WHERE username = 'admin'")["id"]
    post(admin, f"/users/{admin_id}/delete", page="/users")
    assert db.one("SELECT id FROM users WHERE id = ?", admin_id)


def test_dns():
    c = login()
    sid, page = make_site(c, "dns.test")
    z = db.one("SELECT * FROM dns_zones WHERE domain = 'dns.test'")
    assert z and z["site_id"] == sid
    zf = (config.BIND_ZONES / "db.dns.test").read_text()
    assert "@ 3600 IN A 203.0.113.10" in zf and "www 3600 IN CNAME dns.test." in zf
    assert "@ 3600 IN MX 10 mail.dns.test." in zf and '"v=spf1 a mx ~all"' in zf
    assert 'zone "dns.test"' in config.BIND_INCLUDE.read_text()

    zp = f"/dns/{z['id']}"
    post(c, f"{zp}/records", {"name": "api", "type": "A", "content": "192.0.2.5", "ttl": "300"}, page=zp)
    post(c, f"{zp}/records", {"name": "@", "type": "TXT", "content": 'google-site-verification="abc"'}, page=zp)
    post(c, f"{zp}/records", {"name": "x", "type": "A", "content": "999.1.1.1"}, page=zp)
    assert "IPv4" in flashes(c, zp)[0]
    post(c, f"{zp}/records", {"name": "@", "type": "CNAME", "content": "other.com"}, page=zp)
    assert "can't be a CNAME" in flashes(c, zp)[0]
    post(c, f"{zp}/records", {"name": "bad;name", "type": "A", "content": "1.2.3.4"}, page=zp)
    assert "Name:" in flashes(c, zp)[0]
    zf = (config.BIND_ZONES / "db.dns.test").read_text()
    assert "api 300 IN A 192.0.2.5" in zf and r'"google-site-verification=\"abc\""' in zf
    serial1 = db.one("SELECT serial FROM dns_zones WHERE id = ?", z["id"])["serial"]
    rec = db.one("SELECT id FROM dns_records WHERE zone_id = ? AND name = 'api'", z["id"])
    post(c, f"{zp}/records/{rec['id']}", {"name": "api", "content": "192.0.2.6", "ttl": "300"}, page=zp)
    assert db.one("SELECT serial FROM dns_zones WHERE id = ?", z["id"])["serial"] > serial1

    # long TXT values are split into 250-char strings
    post(c, f"{zp}/records", {"name": "long", "type": "TXT", "content": "a" * 600}, page=zp)
    line = [l for l in (config.BIND_ZONES / "db.dns.test").read_text().splitlines() if l.startswith("long ")][0]
    assert line.count('"') == 6

    # Dynamic DNS
    post(c, f"{zp}/ddns", {"name": "home"}, page=zp)
    from harbor.services import dns as dns_svc
    tok = dns_svc.create_ddns(z["id"], "office", "", "test")
    anon = TestClient(app)
    r = anon.get(f"/ddns/update?token={tok}&ip=198.51.100.77")
    assert r.text == "good 198.51.100.77"
    assert anon.get(f"/ddns/update?token={tok}&ip=198.51.100.77").text == "nochg 198.51.100.77"
    assert anon.get("/ddns/update?token=wrong&ip=1.2.3.4").text == "badauth"
    assert "office 300 IN A 198.51.100.77" in (config.BIND_ZONES / "db.dns.test").read_text()

    # server settings change name servers in every zone
    post(c, "/settings", {"hostname": "server.dns.test", "ns1": "ns1.dns.test", "ns2": "ns2.dns.test",
                          "hostmaster": "hostmaster@dns.test", "dns_auto_zone": "1"}, page="/settings")
    zf = (config.BIND_ZONES / "db.dns.test").read_text()
    assert "@ 3600 IN NS ns1.dns.test." in zf and "SOA ns1.dns.test. hostmaster.dns.test." in zf
    assert "ns1 3600 IN A 203.0.113.10" in zf and "ns2 3600 IN A 203.0.113.10" in zf  # glue for in-zone NS


def test_mail():
    c = login()
    sid, page = make_site(c, "mail.test")
    post(c, f"{page}/mail/enable", page=f"{page}/mail")
    d = db.one("SELECT * FROM mail_domains WHERE site_id = ?", sid)
    assert d and d["dkim_record"].startswith("v=DKIM1")
    zf = (config.BIND_ZONES / "db.mail.test").read_text()
    assert "harbor._domainkey 3600 IN TXT" in zf

    post(c, f"{page}/mail/boxes", {"local": "info", "password": "mailbox-pass-1", "quota": "1024"}, page=f"{page}/mail")
    post(c, f"{page}/mail/boxes", {"local": "anna", "password": "", "quota": "512"}, page=f"{page}/mail")
    assert "save this password" in c.get(f"{page}/mail").text
    post(c, f"{page}/mail/boxes", {"local": "bad local!", "password": "x" * 12}, page=f"{page}/mail")
    assert "Address:" in flashes(c, f"{page}/mail")[0]
    maps = config.POSTFIX_MAPS
    assert "mail.test OK" in (maps / "vdomains").read_text()
    assert "info@mail.test mail.test/info/" in (maps / "vmailbox").read_text()
    users = config.DOVECOT_USERS.read_text()
    assert re.search(r"^info@mail\.test:\{CRYPT\}\$6\$.*userdb_quota_rule=\*:storage=1024M$", users, re.M)

    # forwarders, keep-copy and catch-all
    post(c, f"{page}/mail/forwarders", {"local": "sales", "destinations": "a@example.org, b@example.org"}, page=f"{page}/mail")
    post(c, f"{page}/mail/forwarders", {"local": "info", "destinations": "boss@example.org"}, page=f"{page}/mail")
    post(c, f"{page}/mail/catchall", {"mode": "forward", "target": "info@mail.test"}, page=f"{page}/mail")
    valias = (maps / "valias").read_text()
    assert "sales@mail.test a@example.org, b@example.org" in valias
    assert "info@mail.test info@mail.test, boss@example.org" in valias
    assert "anna@mail.test anna@mail.test" in valias
    assert "@mail.test info@mail.test" in valias
    assert any(l.startswith("postmap ") for l in runner.DRY_LOG)

    # suspend login, autoresponder
    box = db.one("SELECT id FROM mailboxes WHERE local = 'anna'")["id"]
    bp = f"{page}/mail/boxes/{box}"
    post(c, f"{bp}/update", {"enabled": "0", "quota": "512"}, page=bp)
    assert "anna@mail.test:{CRYPT}!$6$" in config.DOVECOT_USERS.read_text()
    post(c, f"{bp}/autoresponder", {"enabled": "1", "subject": 'Away "now"', "body": "Back Monday.\n.hidden",
                                    "days": "1", "start": "2026-01-01", "end": "2026-12-31"}, page=bp)
    sieve = (config.MAIL_ROOT / "mail.test/anna/sieve/harbor.sieve").read_text()
    assert ':subject "Away \\"now\\""' in sieve and "\n..hidden\n" in sieve and 'currentdate :value "ge"' in sieve
    assert (config.MAIL_ROOT / "mail.test/anna/.dovecot.sieve").is_symlink()
    post(c, f"{bp}/autoresponder", {"enabled": "0", "subject": "x", "body": "", "days": "1"}, page=bp)
    assert not (config.MAIL_ROOT / "mail.test/anna/.dovecot.sieve").exists()

    # API
    from harbor import auth
    tok = auth.create_token(db.one("SELECT id FROM users WHERE username='admin'")["id"], "m")
    r = TestClient(app).post(f"/api/v1/sites/{sid}/mailboxes", headers={"Authorization": f"Bearer {tok}"},
                             json={"local": "api", "password": "api-mailbox-pass"})
    assert r.status_code == 201 and r.json()["address"] == "api@mail.test"

    post(c, f"{bp}/delete", page=bp)
    assert "anna@" not in config.DOVECOT_USERS.read_text()
    post(c, f"{page}/mail/disable", {"confirm": "mail.test"}, page=f"{page}/mail")
    assert "mail.test" not in (maps / "vdomains").read_text()
    assert "_domainkey" not in (config.BIND_ZONES / "db.mail.test").read_text()


def test_apps_and_publisher():
    c = login()
    sid, page = make_site(c, "apps.test")
    ap = f"{page}/apps"
    post(c, f"{ap}/wordpress", {"subdir": "", "title": "My Blog", "admin_user": "boss", "admin_email": "boss@apps.test",
                                "admin_pass": "wp-admin-password"}, page=ap)
    inst = db.one("SELECT * FROM app_installs WHERE site_id = ?", sid)
    assert inst["status"] == "installed", inst["error"]
    assert (config.SITES_DIR / "apps.test/public/wp-config.php").exists()
    assert db.one("SELECT * FROM databases WHERE site_id = ? AND name = ?", sid, f"site{sid}_wp")
    # second install in the same place is refused; subfolder works
    post(c, f"{ap}/wordpress", {"subdir": "", "title": "x", "admin_user": "boss", "admin_email": "boss@apps.test",
                                "admin_pass": "wp-admin-password"}, page=ap)
    assert "already installed" in flashes(c, ap)[0]
    post(c, f"{ap}/wordpress", {"subdir": "shop", "title": "Shop", "admin_user": "boss", "admin_email": "boss@apps.test",
                                "admin_pass": "wp-admin-password"}, page=ap)
    assert db.one("SELECT * FROM app_installs WHERE site_id = ? AND path = '/shop'", sid)["status"] == "installed"
    post(c, f"{ap}/wordpress", {"subdir": "../etc", "title": "x", "admin_user": "boss", "admin_email": "boss@apps.test",
                                "admin_pass": "wp-admin-password"}, page=ap)
    assert "Folder:" in flashes(c, ap)[0]
    shop = db.one("SELECT id FROM app_installs WHERE path = '/shop'")["id"]
    post(c, f"{ap}/{shop}/remove", {"files": "1", "db": "1"}, page=ap)
    assert not (config.SITES_DIR / "apps.test/public/shop").exists()
    assert (config.SITES_DIR / "apps.test/public/wp-config.php").exists()

    # Site Publisher: escapes user input, rejects javascript: links
    sid2, page2 = make_site(c, "pub.test")
    post(c, f"{page2}/publisher", {"template": "business", "title": "Bakery <script>alert(1)</script>",
                                   "tagline": "Fresh bread", "email": "hi@pub.test", "accent": "#aa3300",
                                   "links": "Insta | https://instagram.com/bakery", "services": "Bread\nCakes"},
         page=f"{page2}/apps")
    html = (config.SITES_DIR / "pub.test/public/index.html").read_text()
    assert "&lt;script&gt;" in html and "<script>alert" not in html and "--accent: #aa3300" in html
    assert list((config.SITES_DIR / "pub.test/public").glob("index.html.bak-*"))
    post(c, f"{page2}/publisher", {"template": "personal", "title": "Me", "links": "Bad | javascript:alert(1)"},
         page=f"{page2}/apps")
    assert "must start with http" in flashes(c, f"{page2}/apps")[0]
    for t in ("personal", "coming_soon"):
        post(c, f"{page2}/publisher", {"template": t, "title": "Me"}, page=f"{page2}/apps")
        assert "<title>Me" in (config.SITES_DIR / "pub.test/public/index.html").read_text()


def test_modsecurity():
    c = login()
    sid, page = make_site(c, "waf.test")
    post(c, f"{page}/security/modsec", {"mode": "detect", "disabled_rules": "942100, 920350"}, page=f"{page}/security")
    v = vhost("waf.test")
    assert "modsecurity on;" in v and f"modsecurity_rules_file {config.MODSEC_DIR}/site{sid}.conf;" in v
    rules = (config.MODSEC_DIR / f"site{sid}.conf").read_text()
    assert "SecRuleEngine DetectionOnly" in rules and "SecRuleRemoveById 920350" in rules
    post(c, f"{page}/security/modsec", {"mode": "on", "disabled_rules": "abc"}, page=f"{page}/security")
    assert "not a rule ID" in flashes(c, f"{page}/security")[0]
    # hits from the JSON audit log are shown for this site only
    config.MODSEC_AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    entry = {"transaction": {"client_ip": "203.0.113.9", "time_stamp": "Tue Oct 13 10:00:00 2026",
             "request": {"method": "GET", "uri": "/?id=1' OR 1=1", "headers": {"Host": "waf.test"}},
             "response": {"http_code": 200},
             "messages": [{"message": "SQL Injection Attack Detected", "details": {"ruleId": "942100", "severity": "2"}}]}}
    other = json.loads(json.dumps(entry)); other["transaction"]["request"]["headers"]["Host"] = "other.test"
    config.MODSEC_AUDIT_LOG.write_text(json.dumps(entry) + "\n" + json.dumps(other) + "\n")
    html = c.get(f"{page}/security").text
    assert "SQL Injection Attack Detected" in html and html.count("203.0.113.9") >= 1
    post(c, f"{page}/security/modsec/disable-rule", {"rule": "941100"}, page=f"{page}/security")
    assert "SecRuleRemoveById 941100" in (config.MODSEC_DIR / f"site{sid}.conf").read_text()
    post(c, f"{page}/security/modsec", {"mode": "off", "disabled_rules": ""}, page=f"{page}/security")
    assert "modsecurity on;" not in vhost("waf.test")


def test_every_page_renders():
    c = login()
    sid, page = make_site(c, "render.test")
    z = db.one("SELECT id FROM dns_zones WHERE domain = 'render.test'")["id"]
    post(c, f"{page}/mail/enable", page=f"{page}/mail")
    post(c, f"{page}/mail/boxes", {"local": "x", "password": "x-mailbox-pass", "quota": "1024"}, page=f"{page}/mail")
    box = db.one("SELECT id FROM mailboxes WHERE local = 'x'")["id"]
    urls = ["/", "/sites", "/mail", "/dns", f"/dns/{z}", "/users", "/settings", "/activity", "/account",
            page] + [f"{page}/{t}" for t in ("files", "databases", "mail", "apps", "redirects", "security", "php",
                                             "cron", "backups", "stats", "logs", "advanced")] + [f"{page}/mail/boxes/{box}"]
    for u in urls:
        r = c.get(u)
        assert r.status_code == 200, (u, r.status_code, r.text[:300])
        assert "Traceback" not in r.text
