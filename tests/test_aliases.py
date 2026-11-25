"""Domain aliases: a second domain serving the same site, or redirecting to it."""
from harbor import config, db
from harbor.services import aliases as al, sites as svc, OpError
from harbor.system import runner
from conftest import login, post, csrf

import pytest


def _site(c, domain):
    r = post(c, "/sites", {"domain": domain, "php_version": "8.3", "include_www": "1"})
    return int(r.headers["location"].rsplit("/", 1)[1])


def _vhost(domain):
    return (config.NGINX_AVAILABLE / f"harbor-{domain}.conf").read_text()


def test_same_content_alias_joins_server_name():
    c = login()
    sid = _site(c, "main.test")
    al.create_alias(sid, "main.net", redirect=False, actor="tester")
    conf = _vhost("main.test")
    assert "server_name main.test www.main.test main.net www.main.net" in conf
    # a DNS zone was created for the alias (DNS on by default in dry-run)
    assert db.one("SELECT 1 FROM dns_zones WHERE domain = ?", "main.net")


def test_redirect_alias_gets_its_own_block():
    c = login()
    sid = _site(c, "shop.test")
    al.create_alias(sid, "shop.org", redirect=True, actor="tester")
    conf = _vhost("shop.test")
    # not in the main server_name; has its own 301 block to the canonical domain
    assert "server_name shop.test www.shop.test;\n" in conf
    assert "server_name shop.org www.shop.org" in conf
    assert "return 301 http://shop.test$request_uri" in conf


def test_alias_on_cert_when_site_has_ssl():
    c = login()
    sid = _site(c, "ssl.test")
    svc.enable_ssl(sid, "tester")
    runner.DRY_LOG.clear()
    al.create_alias(sid, "ssl.net", redirect=False, actor="tester")
    issued = [l for l in runner.DRY_LOG if l.startswith("certbot certonly")]
    assert issued and "ssl.net" in issued[-1] and "www.ssl.net" in issued[-1]
    conf = _vhost("ssl.test")
    assert "listen 443 ssl" in conf and "server_name ssl.test www.ssl.test ssl.net www.ssl.net" in conf


def test_alias_must_be_free():
    c = login()
    sid = _site(c, "a.test")
    _site(c, "b.test")
    with pytest.raises(OpError):
        al.create_alias(sid, "b.test", redirect=False, actor="tester")  # already a site
    al.create_alias(sid, "a.net", redirect=False, actor="tester")
    with pytest.raises(OpError):
        al.create_alias(sid, "a.net", redirect=False, actor="tester")   # already an alias


def test_toggle_and_delete_alias():
    c = login()
    sid = _site(c, "toggle.test")
    aid = al.create_alias(sid, "toggle.net", redirect=False, actor="tester")
    assert "server_name toggle.test www.toggle.test toggle.net www.toggle.net" in _vhost("toggle.test")
    al.set_redirect(sid, aid, redirect=True, actor="tester")
    conf = _vhost("toggle.test")
    assert "server_name toggle.test www.toggle.test;\n" in conf  # alias left the main block
    assert "return 301 http://toggle.test$request_uri" in conf
    al.delete_alias(sid, aid, remove_zone=True, actor="tester")
    assert db.one("SELECT 1 FROM site_aliases WHERE id = ?", aid) is None
    assert "toggle.net" not in _vhost("toggle.test")
    assert db.one("SELECT 1 FROM dns_zones WHERE domain = ?", "toggle.net") is None


def test_route_add_over_http():
    c = login()
    sid = _site(c, "http2.test")
    data = {"csrf": csrf(c, f"/sites/{sid}/subdomains"), "domain": "http2.net", "redirect": ""}
    c.post(f"/sites/{sid}/aliases", data=data, follow_redirects=False)
    assert db.one("SELECT 1 FROM site_aliases WHERE domain = ?", "http2.net")
    assert "http2.net" in c.get(f"/sites/{sid}/subdomains").text
