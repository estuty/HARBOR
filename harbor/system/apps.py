"""Application installers. Commands run as the site's own Linux user so the
installed files are owned by the site, never by root."""
from pathlib import Path

from .. import config
from .runner import run, chown


def as_site(sysuser: str, root: Path, php: str, args: list[str], stdin: str | None = None) -> str:
    cmd = ["runuser", "-u", sysuser, "--", "env", f"HOME={root}/tmp", "WP_CLI_CACHE_DIR=" + f"{root}/tmp/.wp-cli",
           php, str(config.WP_CLI)] + args
    return run(cmd, input=stdin, timeout=900)


def as_site_output(sysuser: str, root: Path, php: str, args: list[str], timeout: int = 900) -> tuple[str, int]:
    """Run wp-cli as the site user for a read-only check: return (stdout+stderr, exit code) and
    never raise. wp-cli reports findings (e.g. checksum mismatches) on stderr and exits non-zero,
    so both streams are captured."""
    import subprocess
    if config.DRY_RUN:
        return "", 0
    cmd = ["runuser", "-u", sysuser, "--", "env", f"HOME={root}/tmp", f"WP_CLI_CACHE_DIR={root}/tmp/.wp-cli",
           php, str(config.WP_CLI)] + args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return str(e), 1
    return (r.stdout + r.stderr), r.returncode


def install_wordpress(sysuser: str, root: Path, path: Path, php: str, url: str, title: str,
                      admin_user: str, admin_pass: str, admin_email: str,
                      db_name: str, db_user: str, db_pass: str, locale: str = "en_US") -> str:
    """Returns the installed WordPress version."""
    if config.DRY_RUN:
        path.mkdir(parents=True, exist_ok=True)
        (path / "wp-config.php").write_text(f"<?php // dry-run WordPress for {url}\n")
        (path / "index.php").write_text("<?php // dry-run\n")
        return "6.x (dry-run)"
    if not path.exists():
        path.mkdir(parents=True)
        chown(path, sysuser)
    wp = lambda args, stdin=None: as_site(sysuser, root, php, [f"--path={path}"] + args, stdin)
    wp(["core", "download", f"--locale={locale}"])
    wp(["config", "create", f"--dbname={db_name}", f"--dbuser={db_user}", "--dbhost=localhost",
        "--prompt=dbpass"], stdin=db_pass + "\n")
    wp(["core", "install", f"--url={url}", f"--title={title}", f"--admin_user={admin_user}",
        f"--admin_email={admin_email}", "--skip-email", "--prompt=admin_password"], stdin=admin_pass + "\n")
    return wp(["core", "version"]).strip()


def wp_version(sysuser: str, root: Path, path: Path, php: str) -> str:
    if config.DRY_RUN:
        return "6.x (dry-run)"
    return as_site(sysuser, root, php, [f"--path={path}", "core", "version"]).strip()


def update_wordpress(sysuser: str, root: Path, path: Path, php: str) -> str:
    if config.DRY_RUN:
        return "6.x (dry-run)"
    wp = lambda args: as_site(sysuser, root, php, [f"--path={path}"] + args)
    wp(["core", "update"])
    wp(["core", "update-db"])
    wp(["plugin", "update", "--all"])
    wp(["theme", "update", "--all"])
    return wp(["core", "version"]).strip()
