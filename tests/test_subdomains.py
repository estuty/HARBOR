"""Subdomains: own document root under the parent site, shared PHP pool, own vhost."""
from harbor import config, db
from harbor.services import subdomains as subs, OpError
from harbor.system import runner
from conftest import login, post, csrf, flashes

import pytest


def _site(c, domain="shop.test"):
    r = post(c, "/sites", {"domain": domain, "php_version": "8.3", "include_www": "0"})
    return int(r.headers["location"].rsplit("/", 1)[1])


def test_create_subdomain_makes_vhost_docroot_and_dns():
    c = login()
    sid = _site(c, "parent.test")
    sub_id = subs.create_subdomain(sid, "blog", "", "tester")
    sub = db.one("SELECT * FROM subdomains WHERE id = ?", sub_id)
    assert sub["fqdn"] == "blog.parent.test"
    assert sub["docroot"] == "public/blog"
    # own nginx config, pointing at the docroot and sharing the parent pool socket
    conf = (config.NGINX_AVAILABLE / "harbor-sub-blog.parent.test.conf").read_text()
    assert "server_name blog.parent.test" in conf
    assert f"root {config.SITES_DIR}/parent.test/public/blog;" in conf
    assert f"harbor-site{sid}.sock" in conf
    # document root created and a welcome page written
    assert (config.SITES_DIR / "parent.test/public/blog/index.html").exists()
    # an A record was added to the parent zone (DNS is on by default in dry-run)
    zone = db.one("SELECT id FROM dns_zones WHERE domain = ?", "parent.test")
    rec = db.one("SELECT * FROM dns_records WHERE zone_id = ? AND name = 'blog' AND type = 'A' AND managed = 'sub'", zone["id"])
    assert rec is not None


def test_custom_docroot_and_label_normalised():
    c = login()
    sid = _site(c, "custom.test")
    sub_id = subs.create_subdomain(sid, "WWW.Dev", "sites/dev", "tester")
    sub = db.one("SELECT * FROM subdomains WHERE id = ?", sub_id)
    assert sub["label"] == "dev" and sub["fqdn"] == "dev.custom.test"  # leading www. stripped, lowercased
    assert sub["docroot"] == "sites/dev"
    assert (config.SITES_DIR / "custom.test/sites/dev").is_dir()


def test_duplicate_subdomain_refused():
    c = login()
    sid = _site(c, "dup.test")
    subs.create_subdomain(sid, "api", "", "tester")
    with pytest.raises(OpError):
        subs.create_subdomain(sid, "api", "", "tester")


def test_subdomain_clashing_with_a_real_site_refused():
    c = login()
    parent = _site(c, "clash.test")
    _site(c, "api.clash.test")  # a full site of its own
    with pytest.raises(OpError):
        subs.create_subdomain(parent, "api", "", "tester")


def test_enable_ssl_switches_vhost_to_https():
    c = login()
    sid = _site(c, "secure.test")
    sub_id = subs.create_subdomain(sid, "app", "", "tester")
    runner.DRY_LOG.clear()
    subs.enable_ssl(sid, sub_id, "tester")
    assert db.one("SELECT ssl FROM subdomains WHERE id = ?", sub_id)["ssl"] == 1
    assert any(l.startswith("certbot certonly") and "app.secure.test" in l for l in runner.DRY_LOG)
    conf = (config.NGINX_AVAILABLE / "harbor-sub-app.secure.test.conf").read_text()
    assert "listen 443 ssl" in conf and "return 301 https" in conf


def test_delete_removes_vhost_and_optionally_files():
    c = login()
    sid = _site(c, "gone.test")
    sub_id = subs.create_subdomain(sid, "old", "", "tester")
    docroot = config.SITES_DIR / "gone.test/public/old"
    assert docroot.exists()
    subs.delete_subdomain(sid, sub_id, remove_files=False, actor="tester")
    assert not (config.NGINX_AVAILABLE / "harbor-sub-old.gone.test.conf").exists()
    assert db.one("SELECT 1 FROM subdomains WHERE id = ?", sub_id) is None
    assert docroot.exists()  # files kept when remove_files is false


def test_delete_with_remove_files_deletes_docroot():
    c = login()
    sid = _site(c, "wipe.test")
    sub_id = subs.create_subdomain(sid, "tmp", "public/tmpsub", "tester")
    docroot = config.SITES_DIR / "wipe.test/public/tmpsub"
    assert docroot.exists()
    subs.delete_subdomain(sid, sub_id, remove_files=True, actor="tester")
    assert not docroot.exists()


def test_route_add_and_list_over_http():
    c = login()
    sid = _site(c, "http.test")
    data = {"csrf": csrf(c, f"/sites/{sid}/subdomains"), "label": "store", "docroot": ""}
    c.post(f"/sites/{sid}/subdomains", data=data, follow_redirects=False)
    assert "store.http.test" in c.get(f"/sites/{sid}/subdomains").text
    assert db.one("SELECT 1 FROM subdomains WHERE fqdn = ?", "store.http.test")
