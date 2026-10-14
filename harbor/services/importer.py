"""Move a cPanel account to Harbor.

  1. receive(): store the uploaded / downloaded backup under /srv/harbor/imports
  2. scan():    read it once and build a plan (what will be created)
  3. run():     create sites, copy files, import databases (keeping their
                users' passwords), mailboxes (keeping passwords and mail),
                forwarders, autoresponders, DNS zones and cron jobs.
Everything is logged to the import's progress log, and problems that need a
person's attention end up in the summary."""
import json
import logging
import re
import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

from .. import auth, config, db, validators
from ..system import cpanel, mail as mailsys, mysql, phpfpm
from ..system.runner import chown, chown_recursive, run, CommandError
from . import OpError, get_site, site_root, update_settings

log = logging.getLogger("harbor")
IMPORT_DIR = config.p("/srv/harbor/imports")
_lock = threading.Lock()


# ---------------------------------------------------------------- bookkeeping

def get(import_id: int):
    row = db.one("SELECT * FROM imports WHERE id = ?", import_id)
    if not row:
        raise OpError("Import not found")
    return row


def plan_of(row) -> dict:
    return json.loads(row["plan"] or "{}")


class Progress:
    def __init__(self, import_id: int):
        self.id = import_id
        self.lines: list[str] = []
        self.last_flush = 0.0

    def __call__(self, msg: str, force: bool = False) -> None:
        stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        if self.lines and self.lines[-1].endswith("…") and msg.endswith("…") and msg.split()[0] == self.lines[-1].split()[1]:
            self.lines[-1] = f"{stamp} {msg}"  # replace repeating counters
        else:
            self.lines.append(f"{stamp} {msg}")
        if force or time.time() - self.last_flush > 1.5:
            self.flush()

    def flush(self) -> None:
        db.execute("UPDATE imports SET log = ? WHERE id = ?", "\n".join(self.lines[-400:]), self.id)
        self.last_flush = time.time()


def list_server_files() -> list[dict]:
    if not IMPORT_DIR.exists():
        return []
    out = []
    for f in sorted(IMPORT_DIR.iterdir(), key=lambda f: f.stat().st_mtime, reverse=True):
        if f.is_file() and re.search(r"\.(tar\.gz|tgz|tar)$", f.name):
            out.append({"name": f.name, "size": f.stat().st_size, "modified": f.stat().st_mtime})
    return out


def _safe_name(name: str) -> str:
    base = re.sub(r"[^A-Za-z0-9._-]", "_", Path(name or "backup.tar.gz").name)[:120]
    if not re.search(r"\.(tar\.gz|tgz|tar)$", base):
        raise OpError("Choose a cPanel backup file (.tar.gz)")
    return base


def new_upload_path(name: str) -> Path:
    IMPORT_DIR.mkdir(parents=True, exist_ok=True)
    IMPORT_DIR.chmod(0o700)
    base = _safe_name(name)
    target = IMPORT_DIR / base
    n = 1
    while target.exists():
        target = IMPORT_DIR / f"{n}-{base}"
        n += 1
    return target


def server_file(name: str) -> Path:
    f = (IMPORT_DIR / Path(name).name)
    if not f.is_file():
        raise OpError("That file isn't in /srv/harbor/imports")
    return f


def download(url: str) -> Path:
    import httpx
    if not re.match(r"^https?://\S+$", url or ""):
        raise OpError("Enter a direct http(s) link to the backup file")
    name = url.split("?")[0].rstrip("/").rsplit("/", 1)[-1] or "backup.tar.gz"
    if not re.search(r"\.(tar\.gz|tgz|tar)$", name):
        name = "backup.tar.gz"
    target = new_upload_path(name)
    try:
        with httpx.stream("GET", url, follow_redirects=True, timeout=120) as r:
            r.raise_for_status()
            with open(target, "wb") as out:
                for chunk in r.iter_bytes(1024 * 1024):
                    out.write(chunk)
    except Exception as e:
        target.unlink(missing_ok=True)
        raise OpError(f"Download failed: {e}")
    return target


# ---------------------------------------------------------------- step 1: scan

def start_download(url: str, actor: str) -> tuple[int, callable]:
    if not re.match(r"^https?://\S+$", url or ""):
        raise OpError("Enter a direct http(s) link to the backup file")
    iid = db.execute("INSERT INTO imports (source, status, actor) VALUES (?, 'downloading', ?)", url, actor)

    def job():
        p = Progress(iid)
        p("Downloading the backup…", force=True)
        try:
            path = download(url)
        except Exception as e:
            db.execute("UPDATE imports SET status = 'failed' WHERE id = ?", iid)
            p(str(e), force=True)
            return
        db.execute("UPDATE imports SET source = ?, size = ?, status = 'scanning' WHERE id = ?",
                   str(path), path.stat().st_size, iid)
        _scan_job(iid, path, p)
    return iid, job


def start_scan(source: Path, actor: str) -> tuple[int, callable]:
    iid = db.execute("INSERT INTO imports (source, size, status, actor) VALUES (?, ?, 'scanning', ?)",
                     str(source), source.stat().st_size, actor)
    db.log(f"cPanel import: reading {source.name}", actor)

    return iid, lambda: _scan_job(iid, source, Progress(iid))


def _scan_job(iid: int, source: Path, p) -> None:
    p(f"Reading {source.name} ({source.stat().st_size / 1048576:.0f} MB)…", force=True)
    try:
        plan = cpanel.scan(source, progress=p)
        plan["conflicts"] = conflicts(plan)
        db.execute("UPDATE imports SET status = 'ready', plan = ? WHERE id = ?", json.dumps(plan), iid)
        p(f"Found {len(plan['domains'])} domain(s), {len(plan['databases'])} database(s), "
          f"{sum(len(m['accounts']) for m in plan['mail'])} mailbox(es)", force=True)
    except Exception as e:
        log.exception("scan failed")
        db.execute("UPDATE imports SET status = 'failed' WHERE id = ?", iid)
        p(f"Couldn't read the backup: {e}", force=True)


def conflicts(plan: dict) -> dict:
    existing_sites = {r["domain"] for r in db.all("SELECT domain FROM sites")}
    out = {"domains": [d["name"] for d in plan["domains"] if d["name"] in existing_sites]}
    known_dbs = {r["name"] for r in db.all("SELECT name FROM databases")}
    out["databases"] = [d["name"] for d in plan["databases"] if d["name"] in known_dbs]
    return out


# ---------------------------------------------------------------- step 2: run

def start_run(import_id: int, choices: dict, actor: str):
    row = get(import_id)
    if row["status"] not in ("ready", "failed_run"):
        raise OpError("This import isn't ready")
    plan = plan_of(row)
    need = (plan["sizes"]["homedir"] + plan["sizes"]["databases"] * 2) * 1.2
    free = psutil.disk_usage(str(config.SITES_DIR if config.SITES_DIR.exists() else "/")).free
    if not config.DRY_RUN and need > free:
        raise OpError(f"Not enough disk space: the import needs about {need / 1e9:.1f} GB, "
                      f"{free / 1e9:.1f} GB is free.")
    with _lock:
        if db.one("SELECT id FROM imports WHERE status = 'importing'"):
            raise OpError("Another import is running; wait for it to finish")
        db.execute("UPDATE imports SET status = 'importing', choices = ? WHERE id = ?", json.dumps(choices), import_id)
    db.log(f"cPanel import of {plan['main_domain']} started", actor)
    return lambda: _run(import_id, choices, actor)


def _run(import_id: int, choices: dict, actor: str) -> None:
    row = get(import_id)
    plan = plan_of(row)
    p = Progress(import_id)
    p.lines = (row["log"] or "").splitlines()
    result = {"sites": [], "databases": [], "mailboxes": 0, "forwarders": 0, "zones": [], "cron": 0,
              "warnings": list(plan.get("warnings", [])), "notes": list(plan.get("notes", [])), "credentials": []}
    work = IMPORT_DIR / f"work-{import_id}"
    try:
        _do_import(Path(row["source"]), plan, choices, work, p, result, actor)
        status = "done"
        p("Import finished.", force=True)
        db.log(f"cPanel import of {plan['main_domain']} finished", actor)
    except Exception as e:
        log.exception("import failed")
        status = "failed_run"
        result["warnings"].insert(0, f"The import stopped: {e}")
        p(f"Import stopped: {e}", force=True)
        db.log(f"cPanel import of {plan['main_domain']} stopped: {e}", actor, "error")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    secret_creds = result.pop("credentials")
    if secret_creds:
        result["credentials_note"] = ("New database passwords were set for: " +
                                      ", ".join(c["user"] for c in secret_creds) +
                                      ". They were written into the apps' settings files listed above.")
    db.execute("UPDATE imports SET status = ?, result = ?, finished_at = CURRENT_TIMESTAMP WHERE id = ?",
               status, json.dumps(result), import_id)


def _do_import(source: Path, plan: dict, choices: dict, work: Path, p, result: dict, actor: str) -> None:
    from . import dns as dns_svc, mail as mail_svc, sites as site_svc, web as web_svc
    cpuser = plan["cpuser"]
    php_default = phpfpm.default_version()
    available_php = phpfpm.available_versions()
    chosen = set(choices.get("domains", []))
    domains = [d for d in plan["domains"] if d["name"] in chosen and d["name"] not in plan["conflicts"]["domains"]]
    for d in plan["domains"]:
        if d["name"] in chosen and d["name"] in plan["conflicts"]["domains"]:
            result["warnings"].append(f"{d['name']} already exists here, so it was skipped")

    # ---- extract what's needed
    want = sorted({d["docroot"] for d in domains if d["docroot"]})
    if choices.get("mail"):
        want += [f"mail/{m['domain']}" for m in plan["mail"]]
    p("Unpacking the backup (files, databases, mail)…", force=True)
    stats = cpanel.extract(source, work, want, progress=p)
    if stats["skipped"]:
        result["warnings"].append(f"{stats['skipped']} unsafe entries in the backup were skipped "
                                  "(links pointing outside the account or special files)")
    home = work / "homedir"

    # ---- sites and files
    site_ids: dict[str, int] = {}
    main_domain = plan["main_domain"]
    for d in domains:
        php = d["php"] if d["php"] in available_php else php_default
        if d["php"] and d["php"] not in available_php:
            result["notes"].append(f"{d['name']} used PHP {d['php']}, which isn't installed here; it runs on PHP {php}. "
                                   f"Install it with: sudo /opt/harbor/source/install.sh --extra-php \"{d['php']}\"")
        p(f"Creating site {d['name']}…", force=True)
        sid = site_svc.create_site(d["name"], php, d["kind"] != "sub", actor, create_zone=False)
        site_ids[d["name"]] = sid
        site = get_site(sid)
        root = site_root(site)
        result["sites"].append({"id": sid, "domain": d["name"], "kind": d["kind"], "php": php})
        if d["kind"] == "parked":
            try:
                web_svc.add_redirect(sid, "/", f"https://{main_domain}", 301, "prefix", actor)
                result["notes"].append(f"{d['name']} was an alias (parked domain) of {main_domain}; it now redirects there")
            except Exception as e:
                result["warnings"].append(f"{d['name']}: couldn't add the redirect to {main_domain} ({e}); add it on its Redirects tab")
            continue
        src = home / d["docroot"]
        if not src.is_dir():
            result["warnings"].append(f"{d['name']}: its folder ({d['docroot']}) wasn't in the backup")
            continue
        public = root / "public"
        if any(src.glob("index.*")):
            (public / "index.html").unlink(missing_ok=True)
        p(f"Copying files for {d['name']}…", force=True)
        cpanel.copy_tree(src, public)
        removed = cpanel.remove_escaping_links(root)
        if removed:
            result["warnings"].append(f"{d['name']}: removed {removed} link(s) pointing outside the site")
        changed = cpanel.rewrite(public, [(f"/home/{cpuser}/{d['docroot']}", str(public)),
                                          (f"/home/{cpuser}/", str(root) + "/")])
        if changed:
            result["notes"].append(f"{d['name']}: updated folder paths in {', '.join(changed[:6])}")
        chown_recursive(public, site["sysuser"])
        custom = cpanel.htaccess_custom_lines(public)
        if custom:
            result["warnings"].append(f"{d['name']}: {custom} custom .htaccess rule(s). This server uses nginx, "
                                      "which doesn't read .htaccess: check the site and recreate redirects in the "
                                      "Redirects tab, password protection in Security")

    def owner_site(names: list[str]) -> int | None:
        """The site whose files mention one of these names (database or user)."""
        for d in domains:
            if d["name"] not in site_ids or d["kind"] == "parked":
                continue
            public = site_root(get_site(site_ids[d["name"]])) / "public"
            for f in cpanel.config_files(public):
                try:
                    t = f.read_text(errors="replace")
                except OSError:
                    continue
                if any(n in t for n in names):
                    return site_ids[d["name"]]
        return site_ids.get(main_domain) or (next(iter(site_ids.values())) if site_ids else None)

    # ---- databases
    if choices.get("databases") and site_ids:
        db_renames: dict[str, str] = {}
        for dbi in plan["databases"]:
            name = dbi["name"]
            dump = work / "mysql" / f"{name}.sql"
            if not dump.exists():
                result["warnings"].append(f"Database {name}: dump missing from the backup")
                continue
            target = name
            if db.one("SELECT 1 FROM databases WHERE name = ?", name) or (not config.DRY_RUN and mysql.exists(name)):
                target = _free_name(name)
                db_renames[name] = target
            p(f"Importing database {target} ({dbi['size'] / 1048576:.0f} MB)…", force=True)
            mysql.create_db(target)
            try:
                mysql.import_dump(target, dump)
            except CommandError as e:
                result["warnings"].append(f"Database {name}: some statements failed: {str(e)[:300]}")
            dump.unlink(missing_ok=True)
        users_by_db: dict[str, str] = {}
        for u in plan["db_users"]:
            user, new_user = u["user"], u["user"]
            if not config.DRY_RUN and mysql.user_exists(user):
                new_user = _free_name(user, user=True)
            dbs = [db_renames.get(x, x) for x in u["dbs"]]
            sid = owner_site([user] + u["dbs"])
            site_root_path = site_root(get_site(sid))
            if u["hash"] and new_user == user:
                mysql.create_user_with_hash(new_user, u["hash"].upper())
            else:
                pw = mysql.generate_password()
                mysql.create_user(new_user, pw)
                changed = cpanel.set_wp_password(site_root_path / "public", user, pw)
                result["credentials"].append({"user": new_user})
                if not changed:
                    result["warnings"].append(f"Database user {user} got a new password; update it in your app's "
                                              f"settings (see Databases tab → New password to set a known one)")
            if new_user != user:
                result["notes"].append(f"Database user {user} already existed here, so it's now {new_user}")
            for x in dbs:
                mysql.grant(new_user, x)
                users_by_db.setdefault(x, new_user)
            # names that changed must change in the app's settings too
            reps = [(f"'{old}'", f"'{new}'") for old, new in db_renames.items()] + \
                   [(f'"{old}"', f'"{new}"') for old, new in db_renames.items()]
            if new_user != user:
                reps += [(f"'{user}'", f"'{new_user}'"), (f'"{user}"', f'"{new_user}"')]
            if reps:
                changed = cpanel.rewrite(site_root_path / "public", reps)
                if changed:
                    result["notes"].append(f"Updated database names in {', '.join(changed[:6])}")
        for dbi in plan["databases"]:
            target = db_renames.get(dbi["name"], dbi["name"])
            user = users_by_db.get(target)
            if not user:
                user = _free_name(f"{target[:20]}_u", user=True)
                pw = mysql.generate_password()
                mysql.create_user(user, pw)
                mysql.grant(user, target)
                result["notes"].append(f"Database {target} had no user of its own; created {user} "
                                       "(set its password on the Databases tab)")
            sid = owner_site([dbi["name"], target])
            db.execute("INSERT INTO databases (site_id, name, username) VALUES (?, ?, ?)", sid, target, user)
            result["databases"].append(target)

    # ---- email
    if choices.get("mail") and site_ids and config.features()["mail"]:
        for m in plan["mail"]:
            sid = site_ids.get(m["domain"])
            if not sid:
                continue
            p(f"Setting up email for {m['domain']}…", force=True)
            mail_svc.enable_domain(sid, actor)
            dom = mail_svc.get_domain(sid)
            for a in m["accounts"]:
                quota = a["quota_mb"] or 0
                h = a["hash"] or ("!" + auth.sha512_crypt(mysql.generate_password()))
                bid = db.execute("INSERT INTO mailboxes (domain_id, local, password_hash, quota_mb) VALUES (?, ?, ?, ?)",
                                 dom["id"], a["local"], h, quota)
                home_dir = mailsys.ensure_home(m["domain"], a["local"])
                src = home / "mail" / m["domain"] / a["local"]
                if src.is_dir():
                    dst = home_dir / "Maildir"
                    if dst.exists():
                        shutil.rmtree(dst)
                    shutil.copytree(src, dst, symlinks=False)
                    for junk in ("maildirsize", "dovecot.index", "dovecot.index.log", "dovecot.index.cache",
                                 "dovecot.list.index", "dovecot.list.index.log", "dovecot-uidvalidity"):
                        for f in dst.rglob(junk):
                            f.unlink(missing_ok=True)
                    # every Maildir folder needs cur/new/tmp (empty ones aren't always in backups)
                    for folder in [dst] + [f for f in dst.iterdir() if f.is_dir() and f.name.startswith(".")]:
                        for sub in ("cur", "new", "tmp"):
                            (folder / sub).mkdir(exist_ok=True)
                        fixed = _fix_maildir_sizes(folder)
                        if fixed:
                            result["notes"].append(f"{a['local']}@{m['domain']}: corrected the size in {fixed} message file name(s)")
                    chown_recursive(home_dir, mailsys.VMAIL)
                    run(["chmod", "-R", "u+rwX,go-rwx", str(home_dir)], check=False)
                result["mailboxes"] += 1
                if not a["hash"]:
                    result["warnings"].append(f"{a['local']}@{m['domain']}: set a password on the Email tab before using it")
            mail_svc.sync()
        for f in plan["forwarders"]:
            sid = site_ids.get(f["domain"])
            if sid and mail_svc.get_domain(sid):
                try:
                    mail_svc.add_forwarder(sid, f["local"], ", ".join(f["dests"]), actor)
                    result["forwarders"] += 1
                except Exception as e:
                    result["warnings"].append(f"Forwarder {f['local']}@{f['domain']}: {e}")
        for domain, target in plan["catchall"].items():
            sid = site_ids.get(domain)
            if sid and mail_svc.get_domain(sid):
                try:
                    mail_svc.set_catch_all(sid, target, actor)
                except Exception as e:
                    result["warnings"].append(f"Catch-all for {domain}: {e}")
        for ar in plan["autoresponders"]:
            local, _, domain = ar["email"].partition("@")
            sid = site_ids.get(domain)
            box = None
            if sid and mail_svc.get_domain(sid):
                box = db.one("SELECT id FROM mailboxes WHERE domain_id = ? AND local = ?",
                             mail_svc.get_domain(sid)["id"], local)
            if box:
                try:
                    mail_svc.set_autoresponder(sid, box["id"], True, ar["subject"], ar["body"] or " ", ar["days"], "", "", actor)
                except Exception as e:
                    result["warnings"].append(f"Autoresponder for {ar['email']}: {e}")
    elif choices.get("mail") and plan["mail"] and not config.features()["mail"]:
        result["warnings"].append("Email isn't installed on this server, so mailboxes weren't imported")

    # ---- DNS
    if choices.get("dns") and config.features()["dns"]:
        new_ip = dns_svc.server_ip()
        for zone_name, text in plan["zones"].items():
            if zone_name not in site_ids and zone_name not in chosen:
                continue
            if db.one("SELECT 1 FROM dns_zones WHERE domain = ?", zone_name):
                result["warnings"].append(f"DNS zone {zone_name} already exists here; not replaced")
                continue
            try:
                records = cpanel.parse_zone(zone_name, text)
            except cpanel.CpanelError as e:
                result["warnings"].append(str(e))
                continue
            p(f"Creating DNS zone {zone_name} ({len(records)} records)…", force=True)
            zid = db.execute("INSERT INTO dns_zones (domain, site_id) VALUES (?, ?)", zone_name, site_ids.get(zone_name))
            bad = 0
            for r in records:
                content = r["content"]
                if choices.get("repoint") and plan["old_ip"]:
                    if r["type"] == "A" and content == plan["old_ip"]:
                        content = new_ip
                    elif r["type"] == "TXT" and "v=spf1" in content:
                        content = content.replace(f"ip4:{plan['old_ip']}", f"ip4:{new_ip}")
                try:
                    content, prio = validators.dns_content(r["type"], content, r["priority"])
                    db.execute("INSERT INTO dns_records (zone_id, name, type, content, ttl, priority, managed) "
                               "VALUES (?, ?, ?, ?, ?, ?, 'imported')",
                               zid, validators.dns_name(r["name"]), r["type"], content, r["ttl"], prio)
                except Exception:
                    bad += 1
            try:
                dns_svc.publish(zid)
                dns_svc._publish_list()
                result["zones"].append(zone_name)
                md = db.one("SELECT dkim_selector, dkim_record FROM mail_domains WHERE domain = ?", zone_name)
                if md and md["dkim_record"]:
                    dns_svc.set_dkim(zone_name, md["dkim_selector"], md["dkim_record"])
            except Exception as e:
                db.execute("DELETE FROM dns_zones WHERE id = ?", zid)
                result["warnings"].append(f"DNS zone {zone_name}: {e}")
            if bad:
                result["warnings"].append(f"DNS zone {zone_name}: {bad} record(s) couldn't be imported")

    # ---- cron
    if choices.get("cron") and plan["cron"] and site_ids:
        main_sid = site_ids.get(main_domain) or next(iter(site_ids.values()))
        main_site = get_site(main_sid)
        main_root = site_root(main_site)
        main_doc = next((d["docroot"] for d in domains if d["name"] == main_domain), "public_html")
        php_bin = phpfpm.php_binary(main_site["php_version"])
        for line in plan["cron"]:
            m = re.match(r"^\s*(@\w+|(?:\S+\s+){4}\S+)\s+(.+)$", line)
            if not m:
                continue
            sched, cmd = m.group(1), m.group(2)
            cmd = cmd.replace(f"/home/{cpuser}/{main_doc}", str(main_root / "public"))
            cmd = cmd.replace(f"/home/{cpuser}/", str(main_root) + "/")
            cmd = re.sub(r"(/usr/local/bin/php|/usr/bin/php|/opt/cpanel/ea-php\d+/root/usr/bin/php(-cli)?|"
                         r"/opt/alt/php\d+/usr/bin/php)(?=\s)", php_bin, cmd)
            try:
                site_svc.add_cron(main_sid, sched, cmd, actor)
                result["cron"] += 1
            except Exception as e:
                result["warnings"].append(f"Cron job '{line[:60]}': {e}")

    result["notes"].append("Not imported: SSL certificates (get free ones on each site's Overview once DNS points "
                           "here), FTP accounts (use SFTP on the Overview tab), email filters and statistics.")


_SIZE_RE = re.compile(r",S=(\d+)")


def _fix_maildir_sizes(folder: Path) -> int:
    """Message file names carry their size (",S=1234"). If a backup tool changed the
    files, Dovecot refuses to open them ("Broken physical size"), so drop wrong hints."""
    fixed = 0
    for sub in ("cur", "new"):
        d = folder / sub
        for f in d.iterdir() if d.is_dir() else []:
            m = _SIZE_RE.search(f.name)
            if m and f.is_file() and int(m.group(1)) != f.stat().st_size:
                base, colon, flags = f.name.partition(":")
                base = re.sub(r",[SW]=\d+", "", base)
                f.rename(f.with_name(base + colon + flags))
                fixed += 1
    return fixed


def _free_name(name: str, user: bool = False) -> str:
    limit = 80 if user else 64
    for i in range(2, 100):
        cand = f"{name[:limit - 4]}_h{i}"
        taken = (db.one("SELECT 1 FROM databases WHERE username = ?", cand) if user
                 else db.one("SELECT 1 FROM databases WHERE name = ?", cand))
        if not taken and (config.DRY_RUN or not (mysql.user_exists(cand) if user else mysql.exists(cand))):
            return cand
    raise OpError(f"No free name for {name}")


def delete(import_id: int, delete_file: bool, actor: str) -> None:
    row = get(import_id)
    if row["status"] in ("scanning", "importing"):
        raise OpError("Wait for it to finish")
    if delete_file:
        f = Path(row["source"])
        if f.parent.resolve() == IMPORT_DIR.resolve():
            f.unlink(missing_ok=True)
    db.execute("DELETE FROM imports WHERE id = ?", import_id)
    db.log(f"Removed import #{import_id}" + (" and its backup file" if delete_file else ""), actor)


def recover_interrupted() -> None:
    db.execute("UPDATE imports SET status = 'failed' WHERE status IN ('scanning', 'downloading')")
    db.execute("UPDATE imports SET status = 'failed_run' WHERE status = 'importing'")
