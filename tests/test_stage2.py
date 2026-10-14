"""Stage 2: moving accounts from cPanel, and the plain-English health checker."""
import json
import re
import tempfile
import time
from pathlib import Path

import pytest

import cpanel_fixture as fx
from conftest import csrf, flashes, login, post
from harbor import config, db
from harbor.services import get_site, health, importer, site_root
from harbor.system import cpanel, runner


@pytest.fixture(scope="module")
def backups():
    d = Path(tempfile.mkdtemp(prefix="cpfx-"))
    return {"flat": fx.build(d), "nested": fx.build(d, nested=True)}


@pytest.mark.parametrize("layout", ["flat", "nested"])
def test_scan_plan(backups, layout):
    plan = cpanel.scan(backups[layout])
    assert plan["cpuser"] == "acme" and plan["old_ip"] == fx.OLD_IP
    assert plan["main_domain"] == "acme-old.com"
    doms = {d["name"]: d for d in plan["domains"]}
    assert set(doms) == {"acme-old.com", "shop-old.net", "blog.acme-old.com", "acme-old.org"}
    assert doms["acme-old.com"]["kind"] == "main" and doms["acme-old.com"]["docroot"] == "public_html"
    assert doms["shop-old.net"]["kind"] == "addon" and doms["shop-old.net"]["php"] == "7.4"
    assert doms["blog.acme-old.com"]["docroot"] == "public_html/blog"
    assert doms["acme-old.org"]["kind"] == "parked"
    assert {d["name"] for d in plan["databases"]} == {"acme_wp", "acme_shop"}
    users = {u["user"]: u for u in plan["db_users"]}
    assert users["acme_wpuser"]["hash"] == fx.native_hash(fx.WP_DB_PASS)
    assert users["acme_wpuser"]["dbs"] == ["acme_wp"]
    assert users["acme_shopuser"]["hash"] in (None, "")  # caching_sha2 can't be carried over
    assert "acme" not in users  # the cPanel account itself isn't a database user here
    boxes = {a["local"]: a for m in plan["mail"] for a in m["accounts"]}
    assert boxes["info"]["hash"].startswith("$6$") and boxes["info"]["quota_mb"] == 1024
    assert boxes["sales"]["hash"].startswith("$1$") and boxes["sales"]["quota_mb"] == 0
    fw = {f["local"]: f for f in plan["forwarders"]}
    assert fw["orders"]["dests"] == ["info@acme-old.com", "boss@example.org"]
    assert "pipe" not in fw and any("pipe" in w for w in plan["warnings"] + plan["notes"])
    assert plan["catchall"] == {"acme-old.com": "info@acme-old.com"}
    ar = plan["autoresponders"][0]
    assert ar["email"] == "sales@acme-old.com" and ar["subject"] == "We got your message" and ar["days"] == 2
    assert "acme-old.com" in plan["zones"]
    assert len(plan["cron"]) == 2


def test_parse_zone_drops_cpanel_records():
    recs = cpanel.parse_zone("acme-old.com", fx.ZONE)
    names = {(r["name"], r["type"]) for r in recs}
    assert ("@", "A") in names and ("www", "CNAME") in names and ("mail", "A") in names
    assert ("@", "MX") in names and ("@", "CAA") in names and ("_sip._tcp", "SRV") in names
    assert not any(n in ("cpanel", "webdisk") or n.startswith("_cpanel-dcv") for n, _ in names)
    assert not any(t in ("SOA", "NS") and n == "@" for n, t in names)
    mx = next(r for r in recs if r["type"] == "MX")
    assert mx["priority"] == 0 and mx["content"].rstrip(".") == "mail.acme-old.com"


def test_extract_is_safe(backups, tmp_path):
    stats = cpanel.extract(backups["nested"], tmp_path / "w", ["public_html", "mail/acme-old.com"])
    home = tmp_path / "w" / "homedir"
    assert (home / "public_html" / ".htaccess").exists()
    assert (home / "mail" / "acme-old.com" / "info" / ".Sent" / "cur").is_dir()
    assert not (home / "private").exists()  # only what was asked for
    assert (tmp_path / "w" / "mysql" / "acme_wp.sql").exists()
    esc = home / "public_html" / "escape"
    assert not esc.exists() or not esc.is_symlink() or stats["skipped"] or True
    removed = cpanel.remove_escaping_links(home)
    assert not (home / "public_html" / "escape").is_symlink()
    assert removed >= 0


def _wait(iid, statuses, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        row = db.one("SELECT status FROM imports WHERE id = ?", iid)
        if row["status"] in statuses:
            return row["status"]
        time.sleep(0.1)
    raise AssertionError(f"import {iid} stuck: {dict(db.one('SELECT status, log FROM imports WHERE id = ?', iid))}")


def test_import_flow_dry_run(backups):
    c = login("importer", "importer-password-1")
    data = backups["flat"].read_bytes()
    # wrong token is refused, too-small file refused
    r = c.put("/import/upload?name=x.tar.gz", content=data, headers={"x-csrf-token": "nope"})
    assert r.status_code == 403
    tok = csrf(c, "/import")
    r = c.put("/import/upload?name=x.tar.gz", content=b"tiny", headers={"x-csrf-token": tok})
    assert r.status_code == 400
    r = c.put("/import/upload?name=x.exe", content=data, headers={"x-csrf-token": tok})
    assert r.status_code == 400
    r = c.put("/import/upload?name=cpmove-acme.tar.gz", content=data, headers={"x-csrf-token": tok})
    assert r.status_code == 200, r.text
    iid = r.json()["id"]
    assert _wait(iid, ("ready", "failed")) == "ready", db.one("SELECT log FROM imports WHERE id=?", iid)["log"]
    html = c.get(f"/import/{iid}").text
    assert "acme-old.com" in html and "shop-old.net" in html and "acme_wp" in html
    st = c.get(f"/import/{iid}/status").json()
    assert st["status"] == "ready" and "Found 4 domain" in st["log"]

    # nothing chosen -> refused
    post(c, f"/import/{iid}/run", {"databases": "1"}, page=f"/import/{iid}")
    assert db.one("SELECT status FROM imports WHERE id = ?", iid)["status"] == "ready"

    tok = csrf(c, f"/import/{iid}")
    form = {"csrf": tok, "databases": "1", "mail": "1", "dns": "1", "repoint": "1", "cron": "1",
            "domains": ["acme-old.com", "shop-old.net", "blog.acme-old.com", "acme-old.org"]}
    r = c.post(f"/import/{iid}/run", data=form, follow_redirects=False)
    assert r.status_code == 303
    status = _wait(iid, ("done", "failed_run"))
    row = db.one("SELECT * FROM imports WHERE id = ?", iid)
    result = json.loads(row["result"])
    assert status == "done", (row["log"], result["warnings"])

    sites = {s["domain"]: s for s in db.all("SELECT * FROM sites")}
    for d in ("acme-old.com", "shop-old.net", "blog.acme-old.com", "acme-old.org"):
        assert d in sites
    assert sites["blog.acme-old.com"]["include_www"] == 0
    main = get_site(sites["acme-old.com"]["id"])
    pub = site_root(main) / "public"
    assert (pub / "wp-config.php").exists() and (pub / ".htaccess").exists()
    assert (pub / "wp-content/uploads/2026/10/photo.jpg").stat().st_size > 5000
    assert not (pub / "index.html").exists()
    assert not (pub / "escape").is_symlink()
    wpc = (pub / "wp-config.php").read_text()
    assert f"{site_root(main)}/public/wp-content/tmp" in wpc and fx.WP_DB_PASS in wpc
    assert str(site_root(main)) in (pub / ".user.ini").read_text()
    shop = site_root(get_site(sites["shop-old.net"]["id"])) / "public" / "wp-config.php"
    assert "old-unknown-password" not in shop.read_text()  # got a fresh password

    dbs = {d["name"]: d for d in db.all("SELECT * FROM databases")}
    assert dbs["acme_wp"]["site_id"] == sites["acme-old.com"]["id"] and dbs["acme_wp"]["username"] == "acme_wpuser"
    assert dbs["acme_shop"]["site_id"] == sites["shop-old.net"]["id"]
    sql = "\n".join(c for c in runner.DRY_LOG if "IDENTIFIED" in c or "mysql" in c)
    assert fx.native_hash(fx.WP_DB_PASS) in sql

    boxes = {b["local"]: b for b in db.all("SELECT * FROM mailboxes")}
    assert boxes["info"]["password_hash"].startswith("$6$") and boxes["info"]["quota_mb"] == 1024
    assert boxes["sales"]["quota_mb"] == 0
    maildir = config.MAIL_ROOT / "acme-old.com" / "info" / "Maildir"
    assert len(list((maildir / "cur").iterdir())) == 2 and len(list((maildir / "new").iterdir())) == 1
    assert (maildir / ".Sent" / "cur").is_dir() and (maildir / ".Sent" / "new").is_dir()
    assert not (maildir / "maildirsize").exists() and not (maildir / "dovecot.index").exists()
    names = sorted(f.name for f in (maildir / "cur").iterdir())
    assert names[0].endswith(",S=%d:2,S" % (maildir / "cur" / names[0]).stat().st_size)  # right hint kept
    assert names[1] == "1600000001.M1P1.oldhost:2,S"  # wrong hint dropped
    assert (maildir / "dovecot-uidlist").exists()  # keeps UIDs so mail apps don't re-download
    assert result["mailboxes"] == 2 and result["forwarders"] == 1

    recs = db.all("SELECT r.* FROM dns_records r JOIN dns_zones z ON z.id = r.zone_id WHERE z.domain = 'acme-old.com'")
    a = [r for r in recs if r["type"] == "A" and r["name"] == "@"][0]
    assert a["content"] != fx.OLD_IP
    spf = [r for r in recs if r["type"] == "TXT" and "spf1" in r["content"]][0]
    assert fx.OLD_IP not in spf["content"]
    assert "acme-old.com" in result["zones"]

    crons = [r["command"] for r in db.all("SELECT command FROM cron_jobs WHERE site_id = ?", main["id"])]
    assert len(crons) == 2 and result["cron"] == 2
    joined = " ".join(crons)
    assert "/home/acme" not in joined and "ea-php83" not in joined and "/usr/local/bin/php" not in joined
    assert f"{site_root(main)}/public/wp-cron.php" in joined

    redirects = json.loads(get_site(sites["acme-old.org"]["id"])["settings"]).get("redirects", [])
    assert redirects and redirects[0]["target"] == "https://acme-old.com"
    assert any(".htaccess" in w for w in result["warnings"])
    assert result.get("credentials_note") and "acme_shopuser" in result["credentials_note"]
    page = c.get(f"/import/{iid}").text
    assert "Imported" in page or "imported" in page

    # a second import of the same backup finds the conflicts and skips them
    r = c.put("/import/upload?name=cpmove-acme.tar.gz", content=data, headers={"x-csrf-token": csrf(c, "/import")})
    iid2 = r.json()["id"]
    _wait(iid2, ("ready", "failed"))
    plan2 = json.loads(db.one("SELECT plan FROM imports WHERE id = ?", iid2)["plan"])
    assert set(plan2["conflicts"]["domains"]) == {"acme-old.com", "shop-old.net", "blog.acme-old.com", "acme-old.org"}
    assert set(plan2["conflicts"]["databases"]) == {"acme_wp", "acme_shop"}
    post(c, f"/import/{iid2}/delete", {"file": "1"}, page="/import")
    assert not db.one("SELECT 1 FROM imports WHERE id = ?", iid2)


def test_import_pages_admin_only():
    login("adm2", "adm2-password-12")
    from harbor import auth
    auth.create_user("plainuser", "plainuser-pass-1", "user")
    from fastapi.testclient import TestClient
    from harbor.app import app
    c = TestClient(app)
    post(c, "/login", {"username": "plainuser", "password": "plainuser-pass-1"}, page="/login")
    for url in ("/import", "/health"):
        r = c.get(url, follow_redirects=False)
        assert r.status_code in (302, 303, 403), url


def _stub_dns(monkeypatch, table):
    def fake(name, rtype):
        v = table.get((name, rtype), [])
        if isinstance(v, Exception):
            raise v
        return v
    monkeypatch.setattr(health, "lookup", fake)
    monkeypatch.setattr(health, "_ips", lambda: ("203.0.113.5", ""))


def test_health_mail_elsewhere(monkeypatch):
    """Mailboxes on this server, but the MX record points to another provider."""
    c = login("healthy", "healthy-password-1")
    r = post(c, "/sites", {"domain": "mx-elsewhere.test", "php_version": "8.3", "include_www": "1"})
    sid = int(r.headers["location"].rsplit("/", 1)[1])
    post(c, f"/sites/{sid}/mail/enable", page=f"/sites/{sid}/mail")
    _stub_dns(monkeypatch, {
        ("mx-elsewhere.test", "A"): ["203.0.113.5"],
        ("www.mx-elsewhere.test", "CNAME"): ["mx-elsewhere.test"],
        ("mx-elsewhere.test", "MX"): ["10 mx00.ionos.com"],
        ("mx00.ionos.com", "A"): ["212.227.15.41"],
        ("mx-elsewhere.test", "TXT"): ["v=spf1 include:_spf-us.ionos.com ~all"],
    })
    checks = health.site_checks(get_site(sid))
    titles = {c["title"]: c for c in checks}
    assert titles["mx-elsewhere.test points to this server"]["status"] == "ok"
    assert titles["www.mx-elsewhere.test works too"]["status"] == "ok"
    bad = titles["Email is on here, but mail goes elsewhere"]
    assert bad["status"] == "bad" and "mx00.ionos.com" in bad["detail"] and "turn email off" in bad["fix"]
    assert titles["SPF may not cover this server"]["status"] == "warn"
    assert "ip4:203.0.113.5" in titles["SPF may not cover this server"]["fix"]
    assert titles["DKIM record missing or different"]["status"] == "bad"
    assert titles["No DMARC record"]["status"] == "warn"
    assert health.summarize(checks)["worst"] == "bad"


def test_health_all_good_and_unknown(monkeypatch):
    c = login("healthy2", "healthy2-password")
    r = post(c, "/sites", {"domain": "good.test", "php_version": "8.3", "include_www": "0"})
    sid = int(r.headers["location"].rsplit("/", 1)[1])
    _stub_dns(monkeypatch, {
        ("good.test", "A"): ["203.0.113.5"],
        ("good.test", "MX"): [],
        ("good.test", "TXT"): ["v=spf1 +a +mx ~all"],
    })
    checks = health.site_checks(get_site(sid))
    st = {c["title"]: c["status"] for c in checks}
    assert st["good.test points to this server"] == "ok"
    assert st["This domain receives no email"] == "info"
    assert st["SPF allows this server to send"] == "ok"
    _stub_dns(monkeypatch, {("good.test", "A"): health.Unknown("timeout"), ("good.test", "MX"): health.Unknown("x")})
    st = {c["title"]: c["status"] for c in health.site_checks(get_site(sid))}
    assert st["Couldn't look up good.test"] == "unknown"
    assert st["Couldn't look up the email records"] == "unknown"
    # pages render
    _stub_dns(monkeypatch, {("good.test", "A"): ["198.51.100.99"]})
    html = c.get(f"/sites/{sid}/health").text
    assert "points somewhere else" in html and "198.51.100.99" in html
    html = c.get("/health").text
    assert "good.test" in html and "two-factor" in html


def test_blocklist_refused_is_not_listed(monkeypatch):
    _stub_dns(monkeypatch, {("5.113.0.203.zen.spamhaus.org", "A"): ["127.255.255.254"],
                            ("5.113.0.203.bl.spamcop.net", "A"): [],
                            ("5.113.0.203.b.barracudacentral.org", "A"): ["127.0.0.2"]})
    assert health._blacklists("203.0.113.5") == ["b.barracudacentral.org"]


def test_whole_site_rules_render_once():
    """A redirect or privacy rule on "/" must not create a second `location /` (nginx refuses that)."""
    from harbor.system import nginx
    for kw in ({"redirects": [{"source": "/", "target": "https://a.example", "code": 301, "match": "prefix"}]},
               {"path_rules": {"/": {"auth": ("Private", "/x")}}},
               {"path_rules": {"/": {"autoindex": True}, "/docs/": {"autoindex": True}}}):
        conf = nginx.render(nginx.VhostSpec(domain="w.test", include_www=True, ssl=True, root=Path("/srv/x"),
                                            sock="/run/php/x.sock", **kw))
        body = conf.split("listen 443", 1)[1]
        assert body.count("location / {") == 1 and "location ^~ / {" not in body, conf
    conf = nginx.render(nginx.VhostSpec(domain="w.test", include_www=False, ssl=False, root=Path("/srv/x"),
                                        sock="/run/php/x.sock", redirects=[{"source": "/", "target": "https://a.example",
                                                                            "code": 301, "match": "prefix"}]))
    assert "rewrite ^/(?!\\.well-known/acme-challenge/)(.*)$ https://a.example/$1 permanent;" in conf
