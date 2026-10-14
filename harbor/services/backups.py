"""Manual, scheduled and restore operations for site backups."""
import threading
import time
from datetime import datetime, timedelta, timezone

from .. import db
from ..system import backup, offsite
from . import alerts
from . import OpError, get_site, log, update_settings

_lock = threading.Lock()


def start_backup(site_id: int, actor: str, kind: str = "manual") -> int:
    site = get_site(site_id)
    with _lock:
        if db.one("SELECT id FROM backups WHERE site_id = ? AND status IN ('running', 'restoring')", site_id):
            raise OpError("A backup or restore is already running for this site")
        bid = db.execute("INSERT INTO backups (site_id, kind) VALUES (?, ?)", site_id, kind)
    db.log(f"{site['domain']}: {kind} backup started", actor)
    return bid


def run_backup(backup_id: int) -> None:
    row = db.one("SELECT b.*, s.domain FROM backups b JOIN sites s ON s.id = b.site_id WHERE b.id = ?", backup_id)
    if not row:
        return
    dbs = [d["name"] for d in db.all("SELECT name FROM databases WHERE site_id = ?", row["site_id"])]
    try:
        path = backup.create(row["domain"], dbs, label="auto" if row["kind"] == "scheduled" else "")
        db.execute("UPDATE backups SET status = 'done', filename = ?, size = ? WHERE id = ?",
                   path.name, path.stat().st_size, backup_id)
        db.log(f"{row['domain']}: backup finished ({path.name})")
        alerts.resolve(f"backup:{row['site_id']}")
    except Exception as e:
        log.exception("backup failed")
        db.execute("UPDATE backups SET status = 'failed', error = ? WHERE id = ?", str(e)[:500], backup_id)
        db.log(f"{row['domain']}: backup failed: {e}", level="error")
        alerts.fire(f"backup:{row['site_id']}", f"Backup failed for {row['domain']}", str(e)[:300])
        return
    if offsite.configured() and offsite.settings()["offsite_auto"]:
        upload_offsite(backup_id)


def upload_offsite(backup_id: int) -> None:
    row = db.one("SELECT b.*, s.domain FROM backups b JOIN sites s ON s.id = b.site_id WHERE b.id = ?", backup_id)
    if not row or row["status"] != "done" or not row["filename"]:
        return
    key = offsite.key_for(row["domain"], row["filename"])
    db.execute("UPDATE backups SET remote_status = 'uploading', remote_error = NULL WHERE id = ?", backup_id)
    try:
        offsite.upload(backup.safe_file(row["domain"], row["filename"]), key)
        db.execute("UPDATE backups SET remote_status = 'uploaded', remote_key = ? WHERE id = ?", key, backup_id)
        db.log(f"{row['domain']}: copied {row['filename']} offsite")
        alerts.resolve(f"offsite:{row['site_id']}")
        try:
            removed = offsite.prune(row["domain"])
            if removed:
                db.log(f"{row['domain']}: removed {removed} old offsite backup(s)")
        except offsite.OffsiteError as e:
            log.warning("offsite prune failed: %s", e)
    except Exception as e:
        db.execute("UPDATE backups SET remote_status = 'failed', remote_error = ? WHERE id = ?", str(e)[:300], backup_id)
        db.log(f"{row['domain']}: offsite copy failed: {e}", level="error")
        alerts.fire(f"offsite:{row['site_id']}", f"Offsite backup copy failed for {row['domain']}", str(e)[:300])


def fetch_offsite(site_id: int, key: str, actor: str) -> int:
    """Download an offsite backup to this server so it can be restored."""
    site = get_site(site_id)
    prefix = offsite.key_for(site["domain"], "")
    if not key.startswith(prefix) or not key.endswith(".tar.gz") or "/" in key[len(prefix):]:
        raise OpError("That backup doesn't belong to this site")
    name = key.rsplit("/", 1)[-1]
    existing = db.one("SELECT id FROM backups WHERE site_id = ? AND filename = ? AND status = 'done'", site_id, name)
    target = backup.backup_dir(site["domain"]) / name
    if existing and target.exists():
        return existing["id"]
    try:
        offsite.download(key, target)
    except offsite.OffsiteError as e:
        raise OpError(f"Download failed: {e}")
    target.chmod(0o600)
    if existing:  # the local file had gone missing; the record stays
        db.log(f"{site['domain']}: downloaded offsite backup {name}", actor)
        return existing["id"]
    bid = db.execute("INSERT INTO backups (site_id, filename, size, status, kind, remote_status, remote_key) "
                     "VALUES (?, ?, ?, 'done', 'offsite', 'uploaded', ?)", site_id, name, target.stat().st_size, key)
    db.log(f"{site['domain']}: downloaded offsite backup {name}", actor)
    return bid


def register_upload(site_id: int, filename: str, size: int, actor: str) -> int:
    site = get_site(site_id)
    bid = db.execute("INSERT INTO backups (site_id, filename, size, status, kind) VALUES (?, ?, ?, 'done', 'uploaded')",
                     site_id, filename, size)
    db.log(f"{site['domain']}: uploaded backup {filename}", actor)
    return bid


def start_restore(site_id: int, backup_id: int, restore_files: bool, db_names: list[str], actor: str):
    site = get_site(site_id)
    row = db.one("SELECT * FROM backups WHERE id = ? AND site_id = ? AND status = 'done'", backup_id, site_id)
    if not row:
        raise OpError("Backup not found")
    owned = {d["name"] for d in db.all("SELECT name FROM databases WHERE site_id = ?", site_id)}
    bad = [n for n in db_names if n not in owned]
    if bad:
        raise OpError(f"These databases don't belong to this site (create them first): {', '.join(bad)}")
    if not restore_files and not db_names:
        raise OpError("Choose files and/or at least one database to restore")
    with _lock:
        if db.one("SELECT id FROM backups WHERE site_id = ? AND status IN ('running', 'restoring')", site_id):
            raise OpError("A backup or restore is already running for this site")
        db.execute("UPDATE backups SET status = 'restoring', error = NULL WHERE id = ?", backup_id)
    db.log(f"{site['domain']}: restore from {row['filename']} started", actor)
    return lambda: _run_restore(site_id, backup_id, restore_files, db_names)


def _run_restore(site_id: int, backup_id: int, restore_files: bool, db_names: list[str]) -> None:
    site = get_site(site_id)
    row = db.one("SELECT * FROM backups WHERE id = ?", backup_id)
    try:
        done = backup.restore(site["domain"], backup.safe_file(site["domain"], row["filename"]),
                              site["sysuser"], restore_files, db_names)
        db.log(f"{site['domain']}: restored {', '.join(done) or 'nothing'} from {row['filename']}")
        db.execute("UPDATE backups SET status = 'done', error = NULL WHERE id = ?", backup_id)
    except Exception as e:
        log.exception("restore failed")
        db.execute("UPDATE backups SET status = 'done', error = ? WHERE id = ?", f"Restore failed: {e}"[:500], backup_id)
        db.log(f"{site['domain']}: restore failed: {e}", level="error")


def delete_backup(site_id: int, backup_id: int, actor: str) -> None:
    site = get_site(site_id)
    row = db.one("SELECT * FROM backups WHERE id = ? AND site_id = ?", backup_id, site_id)
    if not row:
        raise OpError("Backup not found")
    if row["status"] in ("running", "restoring"):
        raise OpError("Wait for the current operation to finish")
    if row["filename"]:
        backup.safe_file(site["domain"], row["filename"]).unlink(missing_ok=True)
    db.execute("DELETE FROM backups WHERE id = ?", backup_id)
    db.log(f"{site['domain']}: deleted backup {row['filename'] or '#' + str(backup_id)}", actor)


def set_schedule(site_id: int, freq: str, keep: int, actor: str) -> None:
    if freq not in ("off", "daily", "weekly"):
        raise OpError("Unknown schedule")
    if not 1 <= keep <= 60:
        raise OpError("Keep between 1 and 60 backups")
    update_settings(site_id, lambda st: st.__setitem__("backup_schedule", {"freq": freq, "keep": keep}), apply=())
    db.log(f"{get_site(site_id)['domain']}: scheduled backups {freq}" + (f", keep {keep}" if freq != "off" else ""), actor)


def recover_interrupted() -> None:
    db.execute("UPDATE backups SET status = 'failed', error = 'Interrupted by panel restart' WHERE status = 'running'")
    db.execute("UPDATE backups SET status = 'done', error = 'Restore interrupted by panel restart' WHERE status = 'restoring'")


# ---------- scheduler ----------

def _due(site) -> bool:
    sched = db.site_settings(site).get("backup_schedule") or {}
    freq = sched.get("freq", "off")
    if freq == "off":
        return False
    last = db.one("SELECT created_at FROM backups WHERE site_id = ? AND kind = 'scheduled' ORDER BY id DESC LIMIT 1",
                  site["id"])
    if not last:
        return True
    when = datetime.fromisoformat(last["created_at"])
    return datetime.now(timezone.utc).replace(tzinfo=None) - when >= (timedelta(days=1) if freq == "daily" else timedelta(days=7)) - timedelta(minutes=5)


def _prune(site) -> None:
    keep = (db.site_settings(site).get("backup_schedule") or {}).get("keep", 7)
    old = db.all("SELECT id FROM backups WHERE site_id = ? AND kind = 'scheduled' AND status IN ('done', 'failed') "
                 "ORDER BY id DESC LIMIT -1 OFFSET ?", site["id"], keep)
    for r in old:
        try:
            delete_backup(site["id"], r["id"], "scheduler")
        except Exception:
            log.exception("prune failed")


def scheduler_tick() -> None:
    for site in db.all("SELECT * FROM sites"):
        try:
            if _due(site):
                bid = start_backup(site["id"], "scheduler", kind="scheduled")
                run_backup(bid)
                _prune(site)
        except OpError:
            pass
        except Exception:
            log.exception("scheduled backup failed")


def start_scheduler(interval: int = 600) -> None:
    def loop():
        time.sleep(30)
        while True:
            scheduler_tick()
            time.sleep(interval)
    threading.Thread(target=loop, name="harbor-backup-scheduler", daemon=True).start()
