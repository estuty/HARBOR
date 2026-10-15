"""A short host name like "harbor" is explained everywhere instead of failing at Let's Encrypt."""
from conftest import flashes, login, post
from harbor import db, validators
from harbor.services import health


def test_full_hostname_rule():
    assert validators.is_full_hostname("server1.example.com")
    assert validators.is_full_hostname("Server2.Afelon.com.")
    for bad in ("harbor", "Harbor", "localhost", "", None, "a.b"):
        assert not validators.is_full_hostname(bad)


def test_short_hostname_is_explained(monkeypatch):
    c = login("hostadmin", "hostadmin-password")
    db.set_setting("hostname", "harbor")
    html = c.get("/settings").text
    assert "'harbor' isn't a full domain name" in html
    assert "disabled>Get certificate" in html.replace("\n", "").replace("  ", "")
    post(c, "/settings/secure", page="/settings")
    msg = flashes(c, "/settings")[0]
    assert "isn't a full domain name" in msg and "server1.example.com" in msg
    monkeypatch.setattr(health, "_ips", lambda: ("203.0.113.5", ""))
    checks = {x["title"]: x for x in health.server_checks()}
    assert checks["The server host name 'harbor' isn't a full domain name"]["status"] == "bad"


def test_hostname_not_pointing_here_is_explained(monkeypatch):
    c = login("hostadmin2", "hostadmin2-password")
    db.set_setting("hostname", "server9.example.org")
    monkeypatch.setattr(health, "lookup", lambda name, rtype: [] if rtype != "A" else ["198.51.100.7"])
    import harbor.services.dns as dns_svc
    monkeypatch.setattr(dns_svc, "server_ip", lambda: "203.0.113.5")
    post(c, "/settings/secure", page="/settings")
    msg = flashes(c, "/settings")[0]
    assert "doesn't point to this server" in msg and "198.51.100.7" in msg and "203.0.113.5" in msg
    assert "disabled>Get certificate" not in c.get("/settings").text.replace("\n", "").replace("  ", "")
