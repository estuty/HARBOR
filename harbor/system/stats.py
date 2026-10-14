import os
import time
from pathlib import Path

import psutil

from .. import config
from .runner import run


def server() -> dict:
    vm = psutil.virtual_memory()
    disk_path = "/srv" if Path("/srv").exists() else "/"
    du = psutil.disk_usage(disk_path)
    load = os.getloadavg() if hasattr(os, "getloadavg") else (0, 0, 0)
    return {
        "cpu": psutil.cpu_percent(interval=0.2),
        "cores": psutil.cpu_count() or 1,
        "load": load,
        "mem_used": vm.total - vm.available,
        "mem_total": vm.total,
        "mem_pct": vm.percent,
        "disk_used": du.used,
        "disk_total": du.total,
        "disk_pct": du.percent,
        "uptime": time.time() - psutil.boot_time(),
        "hostname": os.uname().nodename,
    }


def service_status(names: list[str]) -> dict[str, str]:
    result = {}
    for n in names:
        if config.DRY_RUN:
            result[n] = "active"
            continue
        out = run(["systemctl", "is-active", n], check=False).strip()
        result[n] = out or "unknown"
    return result


def dir_size(path: Path) -> int:
    total = 0
    for dirpath, _, files in os.walk(path, followlinks=False):
        for f in files:
            try:
                total += os.lstat(os.path.join(dirpath, f)).st_size
            except OSError:
                pass
    return total


def tail(path: Path, lines: int = 200) -> str:
    if not path.exists():
        return ""
    with open(path, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        block, data = 8192, b""
        while size > 0 and data.count(b"\n") <= lines:
            step = min(block, size)
            size -= step
            f.seek(size)
            data = f.read(step) + data
    return b"\n".join(data.splitlines()[-lines:]).decode(errors="replace")


def service_names() -> list[str]:
    from . import phpfpm
    names = ["nginx", "mariadb" if Path("/lib/systemd/system/mariadb.service").exists() else "mysql"]
    names += [f"php{v}-fpm" for v in phpfpm.available_versions()]
    f = config.features()
    if f["mail"]:
        names += ["postfix", "dovecot", "rspamd"]
    if f["dns"]:
        names.append("named")
    return names
