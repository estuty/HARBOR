"""Custom (uploaded) TLS certificates and certificate status."""
from harbor import config, db
from harbor.services import sites as svc
from harbor.system import ssl
from conftest import login, post, csrf

SAMPLE_CERT = "-----BEGIN CERTIFICATE-----\nMIIFakeCertData\n-----END CERTIFICATE-----\n"
SAMPLE_KEY = "-----BEGIN PRIVATE KEY-----\nMIIFakeKeyData\n-----END PRIVATE KEY-----\n"
CHAIN = "-----BEGIN CERTIFICATE-----\nMIIFakeIntermediate\n-----END CERTIFICATE-----\n"


def _site(c, domain="cert.test"):
    r = post(c, "/sites", {"domain": domain, "php_version": "8.3", "include_www": "1"})
    return int(r.headers["location"].rsplit("/", 1)[1])


def test_install_custom_cert_writes_files_and_points_vhost():
    c = login()
    sid = _site(c, "custom-ssl.test")
    svc.install_custom_cert(sid, SAMPLE_CERT, SAMPLE_KEY, CHAIN, "tester")
    site = db.one("SELECT * FROM sites WHERE id = ?", sid)
    assert site["ssl"] == 1
    assert db.site_settings(site).get("cert") == "custom"
    d = ssl.custom_dir("custom-ssl.test")
    assert (d / "fullchain.pem").read_text().count("BEGIN CERTIFICATE") == 2  # cert + chain
    assert "PRIVATE KEY" in (d / "privkey.pem").read_text()
    conf = (config.NGINX_AVAILABLE / "harbor-custom-ssl.test.conf").read_text()
    assert f"ssl_certificate {d}/fullchain.pem;" in conf
    assert "listen 443 ssl" in conf


def test_bad_pem_rejected():
    c = login()
    sid = _site(c, "badpem.test")
    import pytest
    from harbor.services import OpError
    with pytest.raises(OpError):
        svc.install_custom_cert(sid, "not a certificate", SAMPLE_KEY, "", "tester")
    assert db.one("SELECT ssl FROM sites WHERE id = ?", sid)["ssl"] == 0


def test_enabling_letsencrypt_clears_custom_source():
    c = login()
    sid = _site(c, "revert.test")
    svc.install_custom_cert(sid, SAMPLE_CERT, SAMPLE_KEY, "", "tester")
    assert db.site_settings(db.one("SELECT * FROM sites WHERE id = ?", sid)).get("cert") == "custom"
    svc.enable_ssl(sid, "tester")  # "Get free certificate" path
    assert db.site_settings(db.one("SELECT * FROM sites WHERE id = ?", sid)).get("cert") is None
    conf = (config.NGINX_AVAILABLE / "harbor-revert.test.conf").read_text()
    assert f"{config.LE_LIVE}/revert.test/fullchain.pem" in conf


def test_remove_custom_turns_https_off_and_deletes_files():
    c = login()
    sid = _site(c, "rm-cert.test")
    svc.install_custom_cert(sid, SAMPLE_CERT, SAMPLE_KEY, "", "tester")
    assert ssl.has_custom("rm-cert.test")
    svc.remove_custom_cert(sid, "tester")
    assert db.one("SELECT ssl FROM sites WHERE id = ?", sid)["ssl"] == 0
    assert not ssl.has_custom("rm-cert.test")


def test_cert_info_parser():
    sample = (
        "subject=CN = example.com\n"
        "issuer=C = US, O = Let's Encrypt, CN = R3\n"
        "notBefore=Oct  1 00:00:00 2026 GMT\n"
        "notAfter=Dec 30 23:59:59 2026 GMT\n"
        "X509v3 Subject Alternative Name:\n"
        "    DNS:example.com, DNS:www.example.com\n"
    )
    info = ssl._parse_cert_text(sample)
    assert info["subject"] == "CN = example.com"
    assert "Let's Encrypt" in info["issuer"]
    assert info["not_after"] == "Dec 30 23:59:59 2026 GMT"
    assert info["sans"] == ["example.com", "www.example.com"]


def test_route_upload_over_http():
    c = login()
    sid = _site(c, "upload.test")
    data = {"csrf": csrf(c, f"/sites/{sid}"), "cert": SAMPLE_CERT, "key": SAMPLE_KEY, "chain": ""}
    c.post(f"/sites/{sid}/ssl/custom", data=data, follow_redirects=False)
    assert db.site_settings(db.one("SELECT * FROM sites WHERE id = ?", sid)).get("cert") == "custom"
    assert "uploaded certificate" in c.get(f"/sites/{sid}").text.lower()
