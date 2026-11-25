"""Remote MySQL: allow named hosts to reach a database, with MariaDB listening
switched on/off accordingly."""
from harbor import config, db
from harbor.services import remote_mysql as rm, sites as svc, OpError
from harbor.system import runner
from harbor.validators import ValidationError
from conftest import login, post, csrf

import pytest


def _reset_remote():
    # db_remote_hosts and the mysql_remote setting are server-wide; the sandbox DB is shared
    # across the test session, so start listening-sensitive tests from a clean slate.
    db.execute("DELETE FROM db_remote_hosts")
    db.set_setting("mysql_remote", "0")
    config.p("/etc/mysql/mariadb.conf.d/99-harbor-remote.cnf").unlink(missing_ok=True)


def _db(c, domain="rmdefault.test", suffix="app"):
    r = post(c, "/sites", {"domain": domain, "php_version": "8.3", "include_www": "0"})
    sid = int(r.headers["location"].rsplit("/", 1)[1])
    db_id, name, user, _pw = svc.create_database(sid, suffix, "tester")
    return sid, db_id, name, user


def _sql_log():
    return "\n".join(l for l in runner.DRY_LOG if l.startswith("mysql ") or "CREATE USER" in l or "GRANT" in l)


def test_add_host_creates_account_and_enables_listening():
    c = login()
    _reset_remote()
    sid, db_id, name, user = _db(c, "rmremote.test")
    runner.DRY_LOG.clear()
    rm.add_host(sid, db_id, "203.0.113.5", "tester")
    row = db.one("SELECT * FROM db_remote_hosts WHERE db_id = ?", db_id)
    assert row["host"] == "203.0.113.5"
    sql = "\n".join(runner.DRY_LOG)
    assert f"CREATE USER IF NOT EXISTS '{user}'@'203.0.113.5'" in sql
    assert f"GRANT ALL PRIVILEGES ON `{name}`.* TO '{user}'@'203.0.113.5'" in sql
    # MariaDB switched to external listening, recorded in settings
    assert db.get_setting("mysql_remote") == "1"
    assert any("systemctl restart mariadb" in l for l in runner.DRY_LOG)
    drop_in = config.p("/etc/mysql/mariadb.conf.d/99-harbor-remote.cnf")
    assert drop_in.exists() and "bind-address = 0.0.0.0" in drop_in.read_text()


def test_wildcard_and_validation():
    c = login()
    sid, db_id, _, _ = _db(c, "rmwild.test")
    rm.add_host(sid, db_id, "203.0.113.%", "tester")       # wildcard octet allowed
    assert db.one("SELECT 1 FROM db_remote_hosts WHERE host = '203.0.113.%'")
    with pytest.raises(ValidationError):
        rm.add_host(sid, db_id, "nope host!", "tester")     # rejected
    with pytest.raises(OpError):
        rm.add_host(sid, db_id, "203.0.113.%", "tester")    # duplicate rejected


def test_remove_last_host_disables_listening():
    c = login()
    _reset_remote()
    sid, db_id, name, user = _db(c, "rmoff.test")
    rm.add_host(sid, db_id, "198.51.100.9", "tester")
    assert db.get_setting("mysql_remote") == "1"
    host_id = db.one("SELECT id FROM db_remote_hosts WHERE db_id = ?", db_id)["id"]
    runner.DRY_LOG.clear()
    rm.remove_host(sid, db_id, host_id, "tester")
    assert db.one("SELECT 1 FROM db_remote_hosts WHERE id = ?", host_id) is None
    sql = "\n".join(runner.DRY_LOG)
    assert f"DROP USER IF EXISTS '{user}'@'198.51.100.9'" in sql
    assert db.get_setting("mysql_remote") == "0"
    assert not config.p("/etc/mysql/mariadb.conf.d/99-harbor-remote.cnf").exists()


def test_dropping_database_cleans_remote_hosts():
    c = login()
    _reset_remote()
    sid, db_id, name, user = _db(c, "rmwipe.test")
    rm.add_host(sid, db_id, "203.0.113.50", "tester")
    runner.DRY_LOG.clear()
    svc.delete_database(sid, db_id, "tester")
    assert db.one("SELECT COUNT(*) n FROM db_remote_hosts")["n"] == 0
    assert db.get_setting("mysql_remote") == "0"
    assert any(f"DROP USER IF EXISTS '{user}'@'203.0.113.50'" in l for l in runner.DRY_LOG)


def test_route_add_over_http():
    c = login()
    sid, db_id, _, _ = _db(c, "rmhttp.test")
    data = {"csrf": csrf(c, f"/sites/{sid}/databases"), "host": "192.0.2.7"}
    c.post(f"/sites/{sid}/databases/{db_id}/remote/add", data=data, follow_redirects=False)
    assert db.one("SELECT 1 FROM db_remote_hosts WHERE host = '192.0.2.7'")
    assert "192.0.2.7" in c.get(f"/sites/{sid}/databases").text
