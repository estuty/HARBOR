"""Databases tab -> Open: a temporary MySQL user for one database, handed to the editor once."""
import json

from fastapi.testclient import TestClient

from conftest import csrf, flashes, login, post
from harbor import auth, db
from harbor.app import app
from harbor.services import dbeditor
from harbor.system import runner


def site_with_db(c, domain):
    r = post(c, "/sites", {"domain": domain, "php_version": "8.3", "include_www": "1"})
    sid = int(r.headers["location"].rsplit("/", 1)[1])
    post(c, f"/sites/{sid}/databases", {"name": "wp"}, page=f"/sites/{sid}/databases")
    row = db.one("SELECT id, name FROM databases WHERE site_id = ?", sid)
    return sid, row["id"], row["name"]


def test_open_creates_scoped_temporary_login():
    c = login("dbedit", "dbedit-password-1")
    sid, dbid, name = site_with_db(c, "dbedit.test")
    html = c.get(f"/sites/{sid}/databases").text
    assert f'/sites/{sid}/databases/{dbid}/open' in html and "Open" in html
    runner.DRY_LOG.clear()
    r = post(c, f"/sites/{sid}/databases/{dbid}/open", page=f"/sites/{sid}/databases")
    assert r.status_code == 303 and r.headers["location"].startswith("/dbadmin/?harbor=")
    token = r.headers["location"].split("=", 1)[1]
    data = json.loads((dbeditor.TOKEN_DIR / f"{token}.json").read_text())
    assert data["db"] == name and data["username"].startswith("hbr_ed_") and len(data["password"]) >= 32
    sql = "\n".join(runner.DRY_LOG)
    assert f"CREATE USER '{data['username']}'@'localhost'" in sql
    assert f"GRANT ALL PRIVILEGES ON `{name}`.* TO '{data['username']}'@'localhost'" in sql
    assert "*.*" not in sql.split("GRANT", 1)[1]  # one database only
    row = db.one("SELECT * FROM db_editor_sessions WHERE mysql_user = ?", data["username"])
    assert row and row["db_name"] == name and row["actor"] == "dbedit"


def test_expired_logins_are_dropped_and_deleting_the_database_closes_them():
    c = login("dbedit2", "dbedit2-password")
    sid, dbid, name = site_with_db(c, "dbedit2.test")
    post(c, f"/sites/{sid}/databases/{dbid}/open", page=f"/sites/{sid}/databases")
    post(c, f"/sites/{sid}/databases/{dbid}/open", page=f"/sites/{sid}/databases")
    users = [r["mysql_user"] for r in db.all("SELECT mysql_user FROM db_editor_sessions WHERE db_name = ?", name)]
    assert len(users) == 2
    db.execute("UPDATE db_editor_sessions SET expires_at = '2000-01-01 00:00:00' WHERE mysql_user = ?", users[0])
    runner.DRY_LOG.clear()
    assert dbeditor.cleanup_expired() == 1
    assert f"DROP USER IF EXISTS '{users[0]}'@'localhost'" in "\n".join(runner.DRY_LOG)
    runner.DRY_LOG.clear()
    post(c, f"/sites/{sid}/databases/{dbid}/delete", page=f"/sites/{sid}/databases")
    assert f"DROP USER IF EXISTS '{users[1]}'@'localhost'" in "\n".join(runner.DRY_LOG)
    assert not db.one("SELECT 1 FROM db_editor_sessions WHERE db_name = ?", name)


def test_access_rules():
    admin = login("dbedit3", "dbedit3-password")
    sid, dbid, _ = site_with_db(admin, "dbedit3.test")
    other, other_db, _ = site_with_db(admin, "dbedit4.test")
    uid = auth.create_user("dbteam", "dbteam-password-1", "user")
    db.execute("INSERT INTO user_sites (user_id, site_id) VALUES (?, ?)", uid, sid)
    team = TestClient(app)
    post(team, "/login", {"username": "dbteam", "password": "dbteam-password-1"}, page="/login")
    r = post(team, f"/sites/{sid}/databases/{dbid}/open", page=f"/sites/{sid}/databases")
    assert r.headers["location"].startswith("/dbadmin/?harbor=")
    r = team.post(f"/sites/{other}/databases/{other_db}/open", data={"csrf": csrf(team, "/account")}, follow_redirects=False)
    assert r.status_code == 403
    # a database id from another site can't be opened through a site you can access
    post(team, f"/sites/{sid}/databases/{other_db}/open", page=f"/sites/{sid}/databases")
    assert "Database not found" in flashes(team, f"/sites/{sid}/databases")[0]
    # nginx's sign-in check
    assert team.get("/dbadmin-check").status_code == 204
    assert TestClient(app).get("/dbadmin-check").status_code == 401


def test_editor_not_installed(monkeypatch):
    c = login("dbedit5", "dbedit5-password")
    sid, dbid, _ = site_with_db(c, "dbedit5.test")
    monkeypatch.setattr(dbeditor, "available", lambda: False)
    html = c.get(f"/sites/{sid}/databases").text
    assert "isn't installed on this server yet" in html and f"/databases/{dbid}/open" not in html
    post(c, f"/sites/{sid}/databases/{dbid}/open", page=f"/sites/{sid}/databases")
    assert "isn't installed" in flashes(c, f"/sites/{sid}/databases")[0]
