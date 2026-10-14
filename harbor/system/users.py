"""Each site gets its own locked-down Linux user.

Layout (chroot-compatible for SFTP):
    /srv/harbor/sites/<domain>/      root:<site>  0750   (SFTP chroot)
        public/                      <site>       0755   (web root)
        logs/                        <site>       0750
        tmp/                         <site>       0700
The web server user is added to the site group so nginx can read files.
"""
import shutil
from pathlib import Path

from .. import config
from .runner import run, chown, chmod

WELCOME = """<!doctype html>
<html><head><meta charset="utf-8"><title>{domain}</title>
<style>body{{font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#f5f3ee;color:#1d2a33}}
main{{text-align:center}}h1{{font-weight:600}}p{{color:#5b6670}}</style></head>
<body><main><h1>{domain}</h1><p>This site is hosted with Harbor. Upload your files to <code>public/</code>.</p></main></body></html>
"""


def site_root(domain: str) -> Path:
    return config.SITES_DIR / domain


def create(sysuser: str, domain: str) -> Path:
    root = site_root(domain)
    run(["useradd", "--system", "--user-group", "--home-dir", str(root), "--no-create-home",
         "--shell", "/usr/sbin/nologin", "--groups", config.SFTP_GROUP, sysuser])
    run(["usermod", "-aG", sysuser, config.WEB_USER])

    root.mkdir(parents=True, exist_ok=True)
    chown(root, "root", sysuser)
    chmod(root, 0o750)
    for sub, mode in (("public", 0o755), ("logs", 0o750), ("tmp", 0o700)):
        d = root / sub
        d.mkdir(exist_ok=True)
        chown(d, sysuser)
        chmod(d, mode)
    index = root / "public" / "index.html"
    if not index.exists():
        index.write_text(WELCOME.format(domain=domain))
        chown(index, sysuser)
    return root


def set_sftp_password(sysuser: str, password: str) -> None:
    run(["chpasswd"], input=f"{sysuser}:{password}\n")
    run(["usermod", "--unlock", sysuser], check=False)


def disable_sftp(sysuser: str) -> None:
    run(["usermod", "--lock", sysuser])


def delete(sysuser: str, domain: str, remove_files: bool) -> None:
    run(["pkill", "-u", sysuser], check=False)
    run(["gpasswd", "-d", config.WEB_USER, sysuser], check=False)
    run(["userdel", sysuser], check=False)
    run(["groupdel", sysuser], check=False)
    if remove_files:
        shutil.rmtree(site_root(domain), ignore_errors=True)
