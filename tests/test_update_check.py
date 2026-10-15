"""Update notifications from GitHub releases, and the one-click update."""
import json

import httpx
from fastapi.testclient import TestClient

from conftest import flashes, login, post
from harbor import __version__, auth, db
from harbor.app import app
from harbor.services import updates
from harbor.system import runner


def fake_github(monkeypatch, status=200, version="99.1.0", notes="- Faster backups\n- New editor look", calls=None):
    def get(url, **kw):
        if calls is not None:
            calls.append(url)
        data = {"tag_name": f"v{version}", "name": f"Harbor {version}", "body": notes, "published_at": "2026-11-02T10:00:00Z",
                "html_url": f"https://github.com/estuty/HARBOR/releases/tag/v{version}",
                "tarball_url": "https://api.github.com/repos/estuty/HARBOR/tarball/v" + version,
                "assets": [{"name": f"harbor-{version}.tar.gz",
                            "browser_download_url": f"https://github.com/estuty/HARBOR/releases/download/v{version}/harbor-{version}.tar.gz"}]}
        return httpx.Response(status, json=data if status == 200 else {"message": "Not Found"})
    monkeypatch.setattr(updates.httpx, "get", get)


def reset():
    for k in ("update_latest", "update_checked_at", "update_error", "update_notified", "update_repo", "update_check", "update_notify"):
        db.execute("DELETE FROM server_settings WHERE key = ?", k)


def test_version_compare():
    assert updates.newer("0.7.1", "0.7.0") and updates.newer("v1.0", "0.9.9") and updates.newer("0.10.0", "0.9.0")
    assert not updates.newer("0.7.0", "0.7.0") and not updates.newer("0.6.9", "0.7.0") and not updates.newer("", "0.7.0")


def test_new_release_is_announced_everywhere(monkeypatch):
    reset()
    c = login("upadmin", "upadmin-password-1")
    calls, sent = [], []
    fake_github(monkeypatch, calls=calls)
    monkeypatch.setattr("harbor.system.notify.channels_configured", lambda: True)
    monkeypatch.setattr("harbor.system.notify.send", lambda title, body: sent.append((title, body)) or [])
    assert "Harbor 99.1.0 is available" not in c.get("/").text
    post(c, "/settings/updates/check", page="/settings/updates")
    assert calls == ["https://api.github.com/repos/estuty/HARBOR/releases/latest"]
    assert "Harbor 99.1.0 is available" in flashes(c, "/settings/updates")[0]
    home = c.get("/").text
    assert "Harbor 99.1.0 is available." in home and "/settings/updates/latest" in home  # dashboard banner + one click
    assert 'class="nav-badge"' in home and "99.1.0 available" in home                  # sidebar badge + footer
    page = c.get("/settings/updates").text
    assert "Faster backups" in page and "Update now" in page and "releases/tag/v99.1.0" in page
    assert len(sent) == 1 and sent[0][0] == "Harbor 99.1.0 is available" and "/settings/updates" in sent[0][1]
    updates.check()                       # checking again doesn't notify twice
    assert len(sent) == 1


def test_one_click_update_downloads_and_starts(monkeypatch, tmp_path):
    reset()
    c = login("upadmin2", "upadmin2-password")
    fake_github(monkeypatch)
    updates.check()
    got = []
    pkg = tmp_path / "pkg.tar.gz"
    pkg.write_bytes(b"x")
    monkeypatch.setattr(updates, "download", lambda url: got.append(url) or pkg)
    db.execute("UPDATE updates SET status = 'done' WHERE status IN ('queued', 'running')")
    runner.DRY_LOG.clear()
    post(c, "/settings/updates/latest", page="/settings/updates")
    assert got == ["https://github.com/estuty/HARBOR/releases/download/v99.1.0/harbor-99.1.0.tar.gz"]
    assert any("systemd-run harbor-update-" in line for line in runner.DRY_LOG)
    assert "Update started" in flashes(c, "/settings/updates")[0]
    db.execute("UPDATE updates SET status = 'done' WHERE status IN ('queued', 'running')")


def test_up_to_date_no_releases_and_errors(monkeypatch):
    reset()
    c = login("upadmin3", "upadmin3-password")
    fake_github(monkeypatch, version=__version__)
    post(c, "/settings/updates/check", page="/settings/updates")
    assert "You're running the latest version" in flashes(c, "/settings/updates")[0]
    assert "Harbor is up to date" in c.get("/settings/updates").text and "nav-badge" not in c.get("/").text
    post(c, "/settings/updates/latest", page="/settings/updates")
    assert "already running the latest" in flashes(c, "/settings/updates")[0]
    fake_github(monkeypatch, status=404)
    post(c, "/settings/updates/check", page="/settings/updates")
    assert "No releases are published" in flashes(c, "/settings/updates")[0]
    def boom(url, **kw):
        raise httpx.ConnectError("no network")
    monkeypatch.setattr(updates.httpx, "get", boom)
    post(c, "/settings/updates/check", page="/settings/updates")
    assert "Couldn't reach GitHub" in flashes(c, "/settings/updates")[0]


def test_prefs_and_permissions(monkeypatch):
    reset()
    c = login("upadmin4", "upadmin4-password")
    post(c, "/settings/updates/prefs", {"repo": "not a repo", "check": "1"}, page="/settings/updates")
    assert "owner/name" in flashes(c, "/settings/updates")[0]
    post(c, "/settings/updates/prefs", {"repo": "https://github.com/someone/fork", "notify": "1"}, page="/settings/updates")
    assert updates.prefs() == {"repo": "someone/fork", "check": False, "notify": True}
    fake_github(monkeypatch)
    updates.check()
    auth.create_user("upteam", "upteam-password-1", "user")
    team = TestClient(app)
    post(team, "/login", {"username": "upteam", "password": "upteam-password-1"}, page="/login")
    assert "nav-badge" not in team.get("/sites").text
    assert team.post("/settings/updates/latest", data={}, follow_redirects=False).status_code == 403
    reset()


def test_release_notes_render_safely():
    from harbor.web import release_notes
    html = str(release_notes("## What's Changed\n* Faster backups by @a in https://github.com/x/y/pull/1\n"
                             "* <script>alert(1)</script>\n\n**Full Changelog**: https://github.com/x/y/compare/a...b"))
    assert "<h4>What&#39;s Changed</h4>" in html
    assert html.count("<li>") == 2 and "<script>" not in html and "&lt;script&gt;" in html
    assert '<a href="https://github.com/x/y/pull/1"' in html and "<strong>Full Changelog</strong>" in html
