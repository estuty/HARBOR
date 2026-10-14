"""Git deploy: connect a site to a repository branch and publish it.

A deploy is recorded in `deployments` and runs in a background thread per site.
Pushes that arrive while a deploy runs are queued; when the running one ends,
only the newest queued deploy runs (older ones are marked skipped)."""
import hashlib
import hmac
import json
import logging
import re
import secrets
import threading
from datetime import datetime, timezone

from .. import config, db, validators
from ..system import gitdeploy, phpfpm
from ..system.runner import CommandError, run
from . import OpError, get_site, site_root

log = logging.getLogger("harbor")
DEFAULT_KEEP = [".well-known/", ".user.ini"]
_workers: dict[int, threading.Thread] = {}
_lock = threading.Lock()


def get_config(site_id: int):
    return db.one("SELECT * FROM git_deploy WHERE site_id = ?", site_id)


def keep_list(cfg) -> list[str]:
    return json.loads(cfg["keep_paths"] or "[]") if cfg else list(DEFAULT_KEEP)


def _form(form) -> dict:
    return {
        "repo_url": validators.git_url(form.get("repo_url", "")),
        "branch": validators.git_branch(form.get("branch", "")),
        "subdir": validators.rel_path(form.get("subdir", ""), "Folder to publish"),
        "build_cmd": validators.script(form.get("build_cmd", ""), "Build command"),
        "after_cmd": validators.script(form.get("after_cmd", ""), "After-deploy command"),
        "keep_paths": json.dumps(validators.rel_path_list(form.get("keep_paths", ""))),
        "delete_extra": 1 if form.get("delete_extra") == "1" else 0,
        "auto_deploy": 1 if form.get("auto_deploy") == "1" else 0,
    }


def connect(site_id: int, form, actor: str) -> None:
    site = get_site(site_id)
    if get_config(site_id):
        raise OpError("This site is already connected to a repository")
    v = _form(form)
    gitdeploy.ensure_key(site_root(site), site["sysuser"], f"harbor-deploy@{site['domain']}")
    db.execute("""INSERT INTO git_deploy (site_id, repo_url, branch, subdir, build_cmd, after_cmd, keep_paths,
                  delete_extra, auto_deploy, hook_secret) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
               site_id, v["repo_url"], v["branch"], v["subdir"], v["build_cmd"], v["after_cmd"], v["keep_paths"],
               v["delete_extra"], v["auto_deploy"], secrets.token_urlsafe(24))
    db.log(f"{site['domain']}: connected to {v['repo_url']} ({v['branch']})", actor)


def update(site_id: int, form, actor: str) -> None:
    site = get_site(site_id)
    if not get_config(site_id):
        raise OpError("Connect a repository first")
    v = _form(form)
    db.execute("""UPDATE git_deploy SET repo_url = ?, branch = ?, subdir = ?, build_cmd = ?, after_cmd = ?,
                  keep_paths = ?, delete_extra = ?, auto_deploy = ? WHERE site_id = ?""",
               v["repo_url"], v["branch"], v["subdir"], v["build_cmd"], v["after_cmd"], v["keep_paths"],
               v["delete_extra"], v["auto_deploy"], site_id)
    db.log(f"{site['domain']}: deploy settings changed", actor)


def disconnect(site_id: int, actor: str) -> None:
    site = get_site(site_id)
    if _busy(site_id):
        raise OpError("Wait for the running deploy to finish")
    gitdeploy.remove_checkout(site_root(site))
    db.execute("DELETE FROM git_deploy WHERE site_id = ?", site_id)
    db.execute("DELETE FROM deployments WHERE site_id = ?", site_id)
    db.log(f"{site['domain']}: disconnected from Git (the live files were kept)", actor)


def check_connection(site_id: int) -> list[str]:
    site = get_site(site_id)
    cfg = get_config(site_id)
    if not cfg:
        raise OpError("Connect a repository first")
    return gitdeploy.ls_remote(site_root(site), site["sysuser"], cfg["repo_url"])


def rotate_secret(site_id: int, actor: str) -> None:
    site = get_site(site_id)
    db.execute("UPDATE git_deploy SET hook_secret = ? WHERE site_id = ?", secrets.token_urlsafe(24), site_id)
    db.log(f"{site['domain']}: new deploy webhook address", actor)


def rotate_key(site_id: int, actor: str) -> None:
    site = get_site(site_id)
    gitdeploy.rotate_key(site_root(site), site["sysuser"], f"harbor-deploy@{site['domain']}")
    db.log(f"{site['domain']}: new deploy key", actor)


def public_key(site) -> str:
    return gitdeploy.public_key(site_root(site))


# ---------------------------------------------------------------- deploys

def _busy(site_id: int) -> bool:
    return bool(db.one("SELECT 1 FROM deployments WHERE site_id = ? AND status IN ('queued', 'running')", site_id))


def start(site_id: int, trigger: str, actor: str, sha: str | None = None) -> int:
    """Queue a deploy (of the branch head, or of a commit for a rollback) and make sure a worker runs."""
    site = get_site(site_id)
    cfg = get_config(site_id)
    if not cfg:
        raise OpError("Connect a repository first")
    if sha is not None:
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise OpError("Unknown version")
        if not db.one("SELECT 1 FROM deployments WHERE site_id = ? AND commit_sha = ? AND status = 'done'", site_id, sha):
            raise OpError("Only versions that were deployed before can be deployed again")
    with _lock:
        dep_id = db.execute("INSERT INTO deployments (site_id, status, trigger, actor, target_sha, branch) "
                            "VALUES (?, 'queued', ?, ?, ?, ?)", site_id, trigger, actor, sha, cfg["branch"])
        worker = _workers.get(site_id)
        if not worker or not worker.is_alive():
            worker = threading.Thread(target=_work, args=(site_id,), daemon=True, name=f"deploy-{site_id}")
            _workers[site_id] = worker
            worker.start()
    what = f"version {sha[:7]}" if sha else cfg["branch"]
    db.log(f"{site['domain']}: deploy of {what} queued ({trigger})", actor)
    return dep_id


def _work(site_id: int) -> None:
    while True:
        with _lock:
            queued = db.all("SELECT id FROM deployments WHERE site_id = ? AND status = 'queued' ORDER BY id", site_id)
            if not queued:
                _workers.pop(site_id, None)
                return
            for older in queued[:-1]:
                db.execute("UPDATE deployments SET status = 'skipped', finished_at = CURRENT_TIMESTAMP, "
                           "log = 'A newer deploy was queued, so this one was skipped.' WHERE id = ?", older["id"])
            dep_id = queued[-1]["id"]
            db.execute("UPDATE deployments SET status = 'running', started_at = CURRENT_TIMESTAMP WHERE id = ?", dep_id)
        try:
            _deploy(dep_id)
        except Exception:
            log.exception("deploy worker")


class Log:
    def __init__(self, dep_id: int):
        self.id, self.lines = dep_id, []

    def __call__(self, msg: str) -> None:
        stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self.lines.append(msg if msg.startswith("    ") else f"{stamp} {msg}")
        if len(self.lines) % 5 == 0 or not msg.startswith("    "):
            self.flush()

    def flush(self) -> None:
        db.execute("UPDATE deployments SET log = ? WHERE id = ?", "\n".join(self.lines[-1500:]), self.id)


def _deploy(dep_id: int) -> None:
    dep = db.one("SELECT * FROM deployments WHERE id = ?", dep_id)
    out = Log(dep_id)
    status, live_changed = "failed", False
    try:
        site = get_site(dep["site_id"])
        cfg = get_config(site["id"])
        if not cfg:
            raise OpError("The site was disconnected from Git")
        root, user = site_root(site), site["sysuser"]
        public = root / "public"

        if dep["target_sha"]:
            sha = dep["target_sha"]
            out(f"Redeploying version {sha[:7]}")
            if not gitdeploy.has_commit(root, user, sha):
                out("That version isn't in the local copy any more; fetching…")
                gitdeploy.fetch(root, user, cfg["repo_url"], cfg["branch"], out)
                if not gitdeploy.has_commit(root, user, sha):
                    raise OpError(f"Version {sha[:7]} no longer exists in the repository")
        else:
            out(f"Fetching {cfg['branch']} from {cfg['repo_url']}…")
            sha = gitdeploy.fetch(root, user, cfg["repo_url"], cfg["branch"], out)
        info = gitdeploy.checkout(root, user, sha, out)
        db.execute("UPDATE deployments SET commit_sha = ?, commit_msg = ?, commit_author = ? WHERE id = ?",
                   info["sha"], info["message"], info["author"], dep_id)
        out(f"Checked out {info['sha'][:7]}: {info['message']} ({info['author']})")

        if cfg["build_cmd"]:
            out("Running the build command…")
            try:
                gitdeploy.run_script(root, user, cfg["build_cmd"], gitdeploy.repo_dir(root), out)
            except CommandError as e:
                raise OpError(f"The build command failed ({e})")
            out("Build finished.")

        # first deploy over existing files: keep a backup to go back to (once the build worked)
        first = not db.one("SELECT 1 FROM deployments WHERE site_id = ? AND status = 'done'", site["id"])
        if first and cfg["delete_extra"] and _has_content(public):
            from . import backups
            out("First deploy: backing up the current site files and databases before publishing…")
            bid = backups.start_backup(site["id"], "deploy", kind="manual")
            backups.run_backup(bid)
            b = db.one("SELECT status, filename, error FROM backups WHERE id = ?", bid)
            if b["status"] != "done":
                raise OpError(f"The backup failed ({b['error']}), so nothing was deployed")
            db.execute("UPDATE deployments SET backup_id = ? WHERE id = ?", bid, dep_id)
            out(f"Backup saved: {b['filename']} (Backups tab)")

        keep = keep_list(cfg)
        out("Publishing to the live site" + (f" (keeping {', '.join(keep)})" if keep else "") + "…")
        live_changed = True
        updated, removed = gitdeploy.sync(root, user, cfg["subdir"], keep, bool(cfg["delete_extra"]), out)
        out(f"{updated} file(s) updated" + (f", {removed} removed" if removed else "") + ".")

        if cfg["after_cmd"]:
            out("Running the after-deploy command in the live folder…")
            try:
                gitdeploy.run_script(root, user, cfg["after_cmd"], public, out)
            except CommandError as e:
                raise OpError(f"The after-deploy command failed ({e}). The new files are live")
        if phpfpm.uses_unit(user):
            run(["systemctl", "reload", phpfpm.unit_name(user)], check=False)  # fresh PHP opcache
        status = "done"
        out(f"Live: {info['sha'][:7]}.")
        db.log(f"{site['domain']}: deployed {info['sha'][:7]} ({dep['trigger']})", dep["actor"])
    except Exception as e:
        msg = str(e) if isinstance(e, (OpError, CommandError, OSError)) else f"Unexpected error: {e}"
        if not isinstance(e, (OpError, CommandError)):
            log.exception("deploy %s failed", dep_id)
        out(msg)
        out("The live site wasn't changed." if not live_changed else
            "Some files may have been updated. Redeploy a working version from the list to go back.")
        try:
            s = get_site(dep["site_id"])
            db.log(f"{s['domain']}: deploy failed: {msg[:200]}", dep["actor"], "error")
            from . import alerts
            alerts.fire(f"deploy:{s['id']}", f"Deploy failed for {s['domain']}", msg[:300])
        except Exception:
            pass
    finally:
        out.flush()
        db.execute("UPDATE deployments SET status = ?, finished_at = CURRENT_TIMESTAMP WHERE id = ?", status, dep_id)
        if status == "done":
            try:
                from . import alerts
                alerts.resolve(f"deploy:{dep['site_id']}")
            except Exception:
                pass


def _has_content(public) -> bool:
    if not public.exists():
        return False
    names = {p.name for p in public.iterdir()}
    return bool(names - {"index.html", ".well-known", ".user.ini"})


def recover_interrupted() -> None:
    db.execute("UPDATE deployments SET status = 'failed', finished_at = CURRENT_TIMESTAMP, "
               "log = COALESCE(log, '') || '\nThe panel restarted during this deploy. Deploy again.' "
               "WHERE status IN ('queued', 'running')")


def history(site_id: int, limit: int = 30):
    return db.all("SELECT * FROM deployments WHERE site_id = ? ORDER BY id DESC LIMIT ?", site_id, limit)


def live(site_id: int):
    return db.one("SELECT * FROM deployments WHERE site_id = ? AND status = 'done' ORDER BY id DESC LIMIT 1", site_id)


# ---------------------------------------------------------------- webhook

def handle_webhook(site_id: int, token: str, body: bytes, headers) -> tuple[int, str]:
    """Push notifications from GitHub, GitLab, Gitea/Forgejo, Bitbucket or a plain POST."""
    cfg = db.one("SELECT * FROM git_deploy WHERE site_id = ?", site_id)
    if not cfg or not hmac.compare_digest(cfg["hook_secret"], token or ""):
        return 404, "not found"
    sig = headers.get("x-hub-signature-256") or headers.get("x-gitea-signature")
    if sig:
        want = hmac.new(cfg["hook_secret"].encode(), body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig.removeprefix("sha256="), want):
            return 403, "signature doesn't match: set the webhook's secret to the same value as in Harbor, or leave it empty"
    gl = headers.get("x-gitlab-token")
    if gl and not hmac.compare_digest(gl, cfg["hook_secret"]):
        return 403, "GitLab secret token doesn't match"
    event = (headers.get("x-github-event") or headers.get("x-gitea-event") or headers.get("x-gitlab-event")
             or headers.get("x-event-key") or "push").lower()
    if event == "ping":
        return 200, "pong: Harbor is listening"
    if "push" not in event:
        return 200, f"ignored: {event} event"
    ref = None
    try:
        data = json.loads(body or b"{}")
        if isinstance(data, dict):
            ref = data.get("ref")
            if not ref and isinstance(data.get("push"), dict):  # Bitbucket
                changes = data["push"].get("changes") or []
                names = [(c.get("new") or {}).get("name") for c in changes if isinstance(c, dict)]
                ref = next((f"refs/heads/{n}" for n in names if n), None)
    except ValueError:
        pass
    if ref and ref != f"refs/heads/{cfg['branch']}":
        return 200, f"ignored: push to {ref}, this site deploys {cfg['branch']}"
    if not cfg["auto_deploy"]:
        return 200, "ignored: automatic deploys are off for this site"
    dep_id = start(site_id, "push", "webhook")
    return 202, f"deploy #{dep_id} queued"
