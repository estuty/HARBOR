import os
import re
import shutil
import sys
import tempfile

SANDBOX = tempfile.mkdtemp(prefix="harbor-test-")
os.environ.update(HARBOR_DRY_RUN="1", HARBOR_SANDBOX=SANDBOX, HARBOR_COOKIE_SECURE="0", HARBOR_SCHEDULER="0")
sys.path.insert(0, os.path.dirname(__file__))

from fastapi.testclient import TestClient  # noqa: E402

CSRF_RE = re.compile(r'name="csrf" value="([^"]+)"')


def csrf(c, url="/login"):
    return CSRF_RE.search(c.get(url).text).group(1)


def post(c, url, data=None, files=None, page="/account"):
    data = dict(data or {}, csrf=csrf(c, page))
    return c.post(url, data=data, files=files, follow_redirects=False)


def login(username="admin", password="correct-horse-battery", role="admin"):
    from harbor import auth, db
    from harbor.app import app
    db.init()
    auth.create_user(username, password, role)
    c = TestClient(app)
    r = post(c, "/login", {"username": username, "password": password}, page="/login")
    assert r.status_code == 303, r.text
    return c


def flashes(c, url):
    html = c.get(url).text
    import html as h
    return h.unescape(" ".join(re.findall(r'class="flash[^"]*"[^>]*>([^<]*)<', html))), html


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(SANDBOX, ignore_errors=True)
