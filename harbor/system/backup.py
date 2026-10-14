"""Full-site backups: site files + a dump of every database the site owns,
packed into one .tar.gz under /srv/harbor/backups/<domain>/."""
import shutil
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path

from .. import config
from . import mysql
from .runner import run, run_to_file, run_from_file, chown_recursive

RESTORABLE_DIRS = ("public", "errors")


def backup_dir(domain: str) -> Path:
    d = config.BACKUP_DIR / domain
    d.mkdir(parents=True, exist_ok=True)
    d.chmod(0o700)
    return d


def create(domain: str, db_names: list[str], label: str = "") -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = backup_dir(domain) / f"{domain}-{stamp}{'-' + label if label else ''}.tar.gz"
    work = Path(tempfile.mkdtemp(prefix="harbor-bk-"))
    try:
        dbdir = work / "databases"
        dbdir.mkdir()
        for name in db_names:
            run_to_file(mysql.dump_cmd(name), dbdir / f"{name}.sql")
        if config.DRY_RUN:
            with tarfile.open(out, "w:gz") as tar:
                tar.add(config.SITES_DIR / domain, arcname=f"files/{domain}")
                tar.add(dbdir, arcname="databases")
        else:
            run(["tar", "-czf", str(out),
                 "--transform", "s,^,files/,", "-C", str(config.SITES_DIR), domain,
                 "--transform", "s,^files/databases,databases,", "-C", str(work), "databases"], timeout=7200)
        out.chmod(0o600)
        return out
    finally:
        shutil.rmtree(work, ignore_errors=True)


def restore(domain: str, archive: Path, sysuser: str, restore_files: bool, db_names: list[str]) -> list[str]:
    """Restore files (public/ and errors/) and the listed databases from a backup.
    Returns what was restored."""
    done = []
    work = Path(tempfile.mkdtemp(prefix="harbor-rs-"))
    try:
        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(work, filter="data")  # refuses absolute paths, .. and device files
        src = work / "files" / domain
        if restore_files:
            if not src.is_dir():
                raise ValueError("This backup doesn't contain site files")
            root = config.SITES_DIR / domain
            for name in RESTORABLE_DIRS:
                if not (src / name).exists():
                    continue
                target = root / name
                old = root / f".{name}.restore-old"
                if target.exists():
                    target.rename(old)
                shutil.move(str(src / name), str(target))
                shutil.rmtree(old, ignore_errors=True)
                chown_recursive(target, sysuser)
            done.append("files")
        for name in db_names:
            dump = work / "databases" / f"{name}.sql"
            if dump.exists():
                run_from_file(["mysql", mysql._check(name)], dump)
                done.append(name)
        return done
    finally:
        shutil.rmtree(work, ignore_errors=True)


def archive_dbs(archive: Path) -> list[str]:
    try:
        with tarfile.open(archive, "r:gz") as tar:
            return sorted(Path(m.name).stem for m in tar.getmembers()
                          if m.name.startswith("databases/") and m.name.endswith(".sql"))
    except (tarfile.TarError, OSError):
        return []


def safe_file(domain: str, filename: str) -> Path:
    d = backup_dir(domain).resolve()
    f = (d / filename).resolve()
    if f.parent != d or not f.name.endswith(".tar.gz"):
        raise ValueError("Invalid backup file")
    return f
