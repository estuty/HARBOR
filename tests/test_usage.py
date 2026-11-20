"""Per-domain usage aggregation (dry-run: live FPM numbers are empty, disk from the sandbox)."""
from conftest import login, post, flashes
from harbor.services import usage


def _make(c, domain):
    r = post(c, "/sites", {"domain": domain, "php_version": "8.3", "include_www": "0"})
    return int(r.headers["location"].rsplit("/", 1)[1])


def test_by_domain_rows_and_totals():
    c = login()
    _make(c, "usage-a.test")
    _make(c, "usage-b.test")
    out = usage.by_domain(cpu=False)
    domains = {r["domain"] for r in out["rows"]}
    assert {"usage-a.test", "usage-b.test"} <= domains
    r = next(x for x in out["rows"] if x["domain"] == "usage-a.test")
    assert r["disk"] == r["files"] + r["db"] and r["files"] >= 0
    assert "memory" in r and "cpu" in r and "workers" in r
    assert out["totals"]["disk"] == sum(x["disk"] for x in out["rows"])
    # sorted largest disk first
    disks = [x["disk"] for x in out["rows"]]
    assert disks == sorted(disks, reverse=True)


def test_usage_page_renders():
    c = login()
    _make(c, "usage-page.test")
    html = c.get("/usage").text
    assert "Usage by site" in html and "usage-page.test" in html and "Recalculate disk" in html


def test_usage_admin_only():
    from harbor import auth
    c = login()
    _make(c, "usage-perm.test")
    uid = auth.create_user("usageteam", "team-password-123", "user")
    t = login("usageteam", "team-password-123", "user")
    r = t.get("/usage", follow_redirects=False)
    assert r.status_code in (302, 303, 403)   # admin-only


def test_disk_bytes_real_du(tmp_path, monkeypatch):
    from harbor.system import stats
    from harbor import config
    monkeypatch.setattr(config, "DRY_RUN", False)   # exercise the real `du` path
    (tmp_path / "a").write_bytes(b"x" * 10000)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b").write_bytes(b"y" * 5000)
    n = stats.disk_bytes(tmp_path)
    assert n >= 15000                       # file contents at least; du rounds up to blocks
    assert stats.disk_bytes(tmp_path / "nope") == 0


def test_cpu_percent_math(monkeypatch):
    from harbor.system import phpfpm
    from harbor import config
    monkeypatch.setattr(config, "DRY_RUN", False)
    monkeypatch.setattr(phpfpm, "uses_unit", lambda u: True)
    monkeypatch.setattr(phpfpm, "unit_name", lambda u: f"harbor-php-{u}")
    monkeypatch.setattr(phpfpm.time, "sleep", lambda s: None)
    # second sample 1e9 ns (=1.0 CPU-second) higher over a 0.5s interval -> 200% of one core
    samples = iter([{"s1": 0, "s2": 500_000_000}, {"s1": 1_000_000_000, "s2": 500_000_000}])
    monkeypatch.setattr(phpfpm, "_cpu_nsec", lambda units: next(samples))
    out = phpfpm.cpu_percents(["s1", "s2"], interval=0.5)
    assert out["s1"] == 200.0 and out["s2"] == 0.0


def test_cpu_nsec_parses_systemctl(monkeypatch):
    from harbor.system import phpfpm
    monkeypatch.setattr(phpfpm, "run", lambda cmd, check=True: "CPUUsageNSec=123456789\n")
    assert phpfpm._cpu_nsec({"site1": "harbor-php-site1"}) == {"site1": 123456789}
    monkeypatch.setattr(phpfpm, "run", lambda cmd, check=True: "CPUUsageNSec=[not set]\n")
    assert phpfpm._cpu_nsec({"site1": "harbor-php-site1"}) == {"site1": 0}
