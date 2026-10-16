"""PHP for each site runs in its own PHP-FPM master process, as its own
systemd service (harbor-php-<site>.service). That gives every site:
  - its own Linux user (workers) and open_basedir,
  - its own php.ini overrides (the MultiPHP INI Editor),
  - hard CPU / memory / process limits enforced by the kernel (cgroups).
Sites created by Harbor 0.2 used a pool inside the shared php<ver>-fpm
service; write_pool() migrates them automatically."""
import re
from pathlib import Path

from .. import config
from .runner import run, CommandError

CONF_DIR = config.ETC / "php"
UNIT_DIR = config.p("/etc/systemd/system")

GLOBAL_TEMPLATE = """; Managed by Harbor - manual edits will be overwritten
[global]
pid = /run/php/harbor-{user}.pid
error_log = /var/log/harbor/php-fpm-{user}.log
emergency_restart_threshold = 10
emergency_restart_interval = 1m
process_control_timeout = 10s
"""

POOL_TEMPLATE = """
[{user}]
user = {user}
group = {user}
listen = {sock}
listen.owner = {web}
listen.group = {web}
listen.mode = 0660

pm = ondemand
pm.max_children = {children}
pm.process_idle_timeout = 30s
pm.max_requests = 500
request_terminate_timeout = {terminate}s

php_admin_value[open_basedir] = {root}/:/usr/share/php/
php_admin_value[upload_tmp_dir] = {root}/tmp
php_admin_value[session.save_path] = {root}/tmp
php_admin_value[sys_temp_dir] = {root}/tmp
php_admin_value[error_log] = {root}/logs/php-error.log
php_admin_flag[log_errors] = on
{ini}
"""

UNIT_TEMPLATE = """# Managed by Harbor - manual edits will be overwritten
[Unit]
Description=Harbor PHP {version} for {domain}
After=network.target

[Service]
Type=notify
ExecStartPre=/bin/mkdir -p /run/php /var/log/harbor
ExecStart=/usr/sbin/php-fpm{version} --nodaemonize --fpm-config {conf}
ExecReload=/bin/kill -USR2 $MAINPID
Restart=on-failure
RestartSec=2
{limits}

[Install]
WantedBy=multi-user.target
"""

# Defaults for new sites (0 = no limit)
DEFAULT_LIMITS = {"cpu_pct": 100, "memory_mb": 1024, "processes": 10, "disk_mb": 0}

# key -> (default, kind). kind "flag" values are On/Off.
INI_KEYS = {
    "memory_limit": ("256M", "size"),
    "upload_max_filesize": ("256M", "size"),
    "post_max_size": ("256M", "size"),
    "max_execution_time": ("60", "int"),
    "max_input_time": ("60", "int"),
    "max_input_vars": ("3000", "int"),
    "session.gc_maxlifetime": ("1440", "int"),
    "date.timezone": ("UTC", "tz"),
    "display_errors": ("Off", "flag"),
    "short_open_tag": ("Off", "flag"),
    "allow_url_fopen": ("On", "flag"),
}
ADMIN_ONLY = {"allow_url_fopen"}


def effective_ini(overrides: dict) -> dict:
    return {k: overrides.get(k, default) for k, (default, _) in INI_KEYS.items()}


def render_ini(overrides: dict) -> str:
    lines = []
    for k, v in effective_ini(overrides).items():
        kind = INI_KEYS[k][1]
        prefix = "php_admin" if k in ADMIN_ONLY else "php"
        if kind == "flag":
            lines.append(f"{prefix}_flag[{k}] = {'on' if v == 'On' else 'off'}")
        else:
            lines.append(f"{prefix}_value[{k}] = {v}")
    return "\n".join(lines)


def size_mb(v: str) -> int:
    """'64M' -> 64, '1G' -> 1024 (values are validated as <digits>M|G)."""
    v = v.strip().upper()
    if v == "-1" or v[-1] not in "MG":
        return 0
    return int(v[:-1]) * (1024 if v[-1] == "G" else 1)


def available_versions() -> list[str]:
    versions = []
    if config.PHP_ETC.exists():
        for d in config.PHP_ETC.iterdir():
            if (d / "fpm").is_dir():
                versions.append(d.name)
    if config.DRY_RUN:
        versions = list(set(versions) | {"8.3", "8.2"})
    return sorted(versions, key=lambda v: [int(x) for x in v.split(".") if x.isdigit()], reverse=True)


def default_version() -> str:
    versions = available_versions()
    if config.DEFAULT_PHP and config.DEFAULT_PHP in versions:
        return config.DEFAULT_PHP
    return versions[0] if versions else "8.3"


def socket_path(sysuser: str) -> str:
    return f"/run/php/harbor-{sysuser}.sock"


def unit_name(sysuser: str) -> str:
    return f"harbor-php-{sysuser}"


def unit_file(sysuser: str) -> Path:
    return UNIT_DIR / f"{unit_name(sysuser)}.service"


def conf_file(sysuser: str) -> Path:
    return CONF_DIR / f"{sysuser}.conf"


def uses_unit(sysuser: str) -> bool:
    return unit_file(sysuser).exists()


def legacy_pool_file(sysuser: str, version: str) -> Path:
    return config.PHP_ETC / version / "fpm" / "pool.d" / f"harbor-{sysuser}.conf"


def render_limits(limits: dict) -> str:
    out = []
    if int(limits.get("cpu_pct") or 0) > 0:
        out.append(f"CPUQuota={int(limits['cpu_pct'])}%")
    if int(limits.get("memory_mb") or 0) > 0:
        m = int(limits["memory_mb"])
        out += [f"MemoryHigh={max(m * 9 // 10, 32)}M", f"MemoryMax={m}M"]
    out.append(f"TasksMax={int(limits.get('processes') or DEFAULT_LIMITS['processes']) + 16}")
    return "\n".join(out)


def _write(path: Path, content: str) -> str | None:
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = path.read_text() if path.exists() else None
    path.write_text(content)
    return previous


def _restore(path: Path, previous: str | None) -> None:
    if previous is None:
        path.unlink(missing_ok=True)
    else:
        path.write_text(previous)


def write_pool(sysuser: str, domain: str, version: str, root: Path, ini_overrides: dict, limits: dict) -> None:
    limits = {**DEFAULT_LIMITS, **(limits or {})}
    ini = effective_ini(ini_overrides)
    terminate = max(int(ini["max_execution_time"]) + 30, 60)
    conf = (GLOBAL_TEMPLATE.format(user=sysuser) +
            POOL_TEMPLATE.format(user=sysuser, sock=socket_path(sysuser), web=config.WEB_USER, root=root,
                                 ini=render_ini(ini_overrides), children=int(limits["processes"]) or 10,
                                 terminate=terminate))
    unit = UNIT_TEMPLATE.format(version=version, domain=domain, conf=conf_file(sysuser), limits=render_limits(limits))
    new_unit = not unit_file(sysuser).exists()
    prev_conf = _write(conf_file(sysuser), conf)
    try:
        run([f"php-fpm{version}", "-t", "--fpm-config", str(conf_file(sysuser))])
    except CommandError:
        _restore(conf_file(sysuser), prev_conf)
        raise
    prev_unit = _write(unit_file(sysuser), unit)
    try:
        run(["systemctl", "daemon-reload"])
        _drop_legacy(sysuser)  # free the socket before the dedicated service binds it
        if new_unit:
            run(["systemctl", "enable", "--now", unit_name(sysuser)])
        else:
            run(["systemctl", "restart", unit_name(sysuser)])
    except CommandError:
        _restore(conf_file(sysuser), prev_conf)
        _restore(unit_file(sysuser), prev_unit)
        run(["systemctl", "daemon-reload"], check=False)
        if prev_unit is not None:
            run(["systemctl", "restart", unit_name(sysuser)], check=False)
        raise


def _drop_legacy(sysuser: str) -> None:
    dropped = False
    for v in available_versions():
        f = legacy_pool_file(sysuser, v)
        if f.exists():
            f.unlink()
            run(["systemctl", "reload", f"php{v}-fpm"], check=False)
            dropped = True
    if dropped:
        _wait_socket_free(socket_path(sysuser))


def _wait_socket_free(path: str, timeout: float = 15) -> None:
    """php-fpm reloads in the background; wait until the old pool has let go of
    the socket, or the new service would find it still in use."""
    import socket
    import time
    if config.DRY_RUN:
        return
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.connect(path)
        except OSError:
            return  # nobody listening any more
        finally:
            s.close()
        time.sleep(0.3)


def remove_pool(sysuser: str, version: str = "") -> None:
    if unit_file(sysuser).exists():
        run(["systemctl", "disable", "--now", unit_name(sysuser)], check=False)
        unit_file(sysuser).unlink(missing_ok=True)
        run(["systemctl", "daemon-reload"], check=False)
    conf_file(sysuser).unlink(missing_ok=True)
    _drop_legacy(sysuser)


def usage(sysuser: str) -> dict:
    """Live numbers from systemd: memory in bytes, CPU seconds, processes."""
    if config.DRY_RUN or not uses_unit(sysuser):
        return {}
    try:
        out = run(["systemctl", "show", unit_name(sysuser), "-p", "MemoryCurrent", "-p", "CPUUsageNSec",
                   "-p", "TasksCurrent", "-p", "ActiveState", "-p", "NRestarts"], check=False)
    except CommandError:
        return {}
    vals = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)

    def num(k):
        v = vals.get(k, "")
        return int(v) if re.fullmatch(r"\d+", v or "") and int(v) < 2 ** 63 else None
    return {"memory": num("MemoryCurrent"), "cpu_seconds": (num("CPUUsageNSec") or 0) / 1e9,
            "tasks": num("TasksCurrent"), "state": vals.get("ActiveState", ""), "restarts": num("NRestarts")}


def php_binary(version: str) -> str:
    return f"/usr/bin/php{version}"
