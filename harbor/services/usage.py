"""Resource usage for every site at once — the per-domain breakdown behind the
dashboard's server totals. Disk (files on disk) is cached briefly because `du`
over a large site isn't free; memory, CPU and worker counts are read live from
each site's PHP-FPM systemd unit, and database size from information_schema."""
import time

from .. import config, db
from ..system import mysql, phpfpm, stats
from . import site_limits, site_root

DISK_TTL = 600  # seconds to reuse a site's measured disk size
_disk_cache: dict[int, tuple[float, int]] = {}


def _files_bytes(site, fresh: bool = False) -> int:
    sid = site["id"]
    hit = _disk_cache.get(sid)
    if not fresh and hit and time.time() - hit[0] < DISK_TTL:
        return hit[1]
    root = site_root(site)
    size = stats.disk_bytes(root) if root.exists() else 0
    _disk_cache[sid] = (time.time(), size)
    return size


def by_domain(cpu: bool = True, fresh_disk: bool = False) -> dict:
    """Per-site usage rows (largest disk first) plus totals and server context."""
    sites = db.all("SELECT * FROM sites ORDER BY domain")
    dbrows = db.all("SELECT site_id, name FROM databases")
    names_by_site: dict[int, list] = {}
    for r in dbrows:
        names_by_site.setdefault(r["site_id"], []).append(r["name"])
    db_sizes = mysql.sizes([r["name"] for r in dbrows]) if dbrows else {}
    cpu_by_user = phpfpm.cpu_percents([s["sysuser"] for s in sites]) if cpu else {}
    server = stats.server()

    rows = []
    for s in sites:
        files = _files_bytes(s, fresh_disk)
        dbsize = sum(db_sizes.get(n, 0) for n in names_by_site.get(s["id"], []))
        live = phpfpm.usage(s["sysuser"]) or {}
        lim = site_limits(s)
        rows.append({
            "id": s["id"], "domain": s["domain"],
            "files": files, "db": dbsize, "disk": files + dbsize,
            "disk_pct": round((files + dbsize) / server["disk_total"] * 100, 1) if server.get("disk_total") else 0,
            "memory": live.get("memory"),
            "memory_limit": (lim.get("memory_mb") or 0) * 1024 * 1024,
            "cpu": cpu_by_user.get(s["sysuser"], 0.0),
            "cpu_limit": lim.get("cpu_pct") or 0,
            "workers": live.get("tasks"),
            "state": live.get("state", ""),
            "databases": len(names_by_site.get(s["id"], [])),
        })
    rows.sort(key=lambda r: r["disk"], reverse=True)
    totals = {
        "files": sum(r["files"] for r in rows),
        "db": sum(r["db"] for r in rows),
        "disk": sum(r["disk"] for r in rows),
        "memory": sum((r["memory"] or 0) for r in rows),
        "cpu": round(sum(r["cpu"] for r in rows), 1),
        "workers": sum((r["workers"] or 0) for r in rows),
    }
    return {"rows": rows, "totals": totals, "server": server, "cores": server.get("cores", 1),
            "cached_disk": not fresh_disk}


def refresh_disk() -> None:
    _disk_cache.clear()
