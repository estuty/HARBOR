"""Read cPanel account backups (pkgacct "cpmove-USER.tar.gz" and
"backup-DATE_USER.tar.gz" files from Backup / Backup Wizard / WHM transfers).

The archive is read as a stream (it can be many GB): one pass collects the
small metadata files and sizes into a plan; a second pass extracts only the
parts the import needs. Both the current layout (homedir/ folder) and the old
one (homedir.tar inside the archive) are supported."""
import json
import re
import shutil
import tarfile
from pathlib import Path, PurePosixPath

import yaml

META_TOP = {"mysql.sql", "pds", "sds", "sds2", "addons", "version", "homedir_paths", "shadow"}
META_DIRS = ("cp/", "userdata/", "va/", "vf/", "dnszones/", "cron/")
MAX_META = 8 * 1024 * 1024
SKIP_ZONE_NAMES = {"cpanel", "whm", "webdisk", "cpcalendars", "cpcontacts", "autodiscover", "autoconfig",
                   "_cpanel-dcv-test-record"}


class CpanelError(Exception):
    pass


# ---------------------------------------------------------------- scanning

class _Collector:
    def __init__(self):
        self.meta: dict[str, bytes] = {}
        self.sizes = {"total": 0, "homedir": 0, "mail": 0, "databases": 0}
        self.db_sizes: dict[str, int] = {}
        self.mail_sizes: dict[str, int] = {}     # "domain/local" -> bytes
        self.dir_sizes: dict[str, int] = {}      # top-level homedir folder -> bytes
        self.members = 0
        self.links_out = 0

    def add(self, rel: str, member: tarfile.TarInfo, fileobj_fn):
        self.members += 1
        if member.isfile():
            self.sizes["total"] += member.size
        if rel.startswith("homedir/"):
            hrel = rel[len("homedir/"):]
            if member.isfile():
                self.sizes["homedir"] += member.size
                top = hrel.split("/", 1)[0]
                self.dir_sizes[top] = self.dir_sizes.get(top, 0) + member.size
            m = re.match(r"mail/([^/]+\.[^/]+)/([^/]+)/", hrel)
            if m and member.isfile():
                key = f"{m.group(1)}/{m.group(2)}"
                self.mail_sizes[key] = self.mail_sizes.get(key, 0) + member.size
                self.sizes["mail"] += member.size
            if member.isfile() and member.size <= MAX_META and (
                    re.fullmatch(r"etc/[^/]+/(passwd|shadow|quota)", hrel) or hrel.startswith(".autorespond/")):
                self.meta[rel] = fileobj_fn().read()
            return
        if rel.startswith("mysql/") and rel.endswith(".sql") and member.isfile():
            name = PurePosixPath(rel).stem
            self.db_sizes[name] = member.size
            self.sizes["databases"] += member.size
            return
        if member.isfile() and member.size <= MAX_META and (rel in META_TOP or rel.startswith(META_DIRS)):
            self.meta[rel] = fileobj_fn().read()


def _clean(name: str) -> str:
    """Drop a leading "./" or "/" (but keep dot-files like .autorespond)."""
    while name.startswith("./"):
        name = name[2:]
    return name.lstrip("/")


def _root_and_rel(name: str, root: str | None) -> tuple[str | None, str]:
    name = _clean(name)
    parts = name.split("/", 1)
    if root is None:
        root = parts[0]
    if parts[0] != root:
        return root, ""
    return root, parts[1] if len(parts) > 1 else ""


def scan(path: Path, progress=None) -> dict:
    """Return the import plan for a cPanel backup."""
    c = _Collector()
    root = None
    try:
        with tarfile.open(path, "r|*") as tar:
            for m in tar:
                root, rel = _root_and_rel(m.name, root)
                if not rel:
                    continue
                if rel == "homedir.tar" and m.isfile():  # older backups nest the home folder
                    inner = tar.extractfile(m)
                    with tarfile.open(fileobj=inner, mode="r|*") as itar:
                        for im in itar:
                            irel = _clean(im.name)
                            if irel:
                                c.add("homedir/" + irel, im, lambda im=im: itar.extractfile(im))
                    continue
                c.add(rel, m, lambda m=m: tar.extractfile(m))
                if progress and c.members % 2000 == 0:
                    progress(f"Read {c.members:,} entries…")
    except (tarfile.TarError, EOFError, OSError) as e:
        raise CpanelError(f"This file couldn't be read as a backup archive: {e}")
    if not any(k.startswith("userdata/") for k in c.meta) and "mysql.sql" not in c.meta:
        raise CpanelError("This doesn't look like a cPanel account backup (no userdata or mysql.sql inside). "
                          "Use a full account backup: cPanel → Backup → Download a Full Account Backup.")
    return build_plan(c, root)


# ---------------------------------------------------------------- parsing helpers

def _text(c: _Collector, key: str) -> str:
    return c.meta.get(key, b"").decode("utf-8", "replace")


def _yaml(c: _Collector, key: str) -> dict:
    try:
        data = yaml.safe_load(_text(c, key)) or {}
        return data if isinstance(data, dict) else {}
    except yaml.YAMLError:
        return {}


def php_from_cpanel(v: str | None) -> str | None:
    m = re.search(r"(?:ea-|alt-)?php(\d)(\d+)", v or "")
    return f"{m.group(1)}.{m.group(2)}" if m else None


def parse_grants(sql: str, cpuser: str) -> tuple[dict, dict]:
    """-> ({user: hash}, {user: [db, ...]}) for localhost users."""
    hashes, dbs = {}, {}
    for m in re.finditer(r"['`]([^'`]+)['`]@['`]([^'`]+)['`][^;]*?(?:IDENTIFIED BY PASSWORD|IDENTIFIED WITH\s+'?\w+'?\s+AS)\s+'([^']+)'",
                         sql, re.I):
        user, host, h = m.groups()
        if host == "localhost" and user != cpuser:
            hashes[user] = h
    for m in re.finditer(r"GRANT\s+.+?\s+ON\s+`([^`]+)`\.\*\s+TO\s+['`]([^'`]+)['`]@['`]([^'`]+)['`]", sql, re.I):
        db, user, host = m.groups()
        if host != "localhost" or user == cpuser:
            continue
        db = db.replace("\\_", "_").replace("\\%", "%")
        if "%" in db:
            continue
        dbs.setdefault(user, [])
        if db not in dbs[user]:
            dbs[user].append(db)
    return hashes, dbs


def parse_forwarders(text: str, domain: str) -> tuple[list, str | None, list]:
    """-> (forwarders [(local, [dest])], catch_all_target_or_None, notes)"""
    fwds, catch, notes = [], None, []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().strip('"'), value.strip()
        dests, skipped = [], []
        for d in [x.strip().strip('"') for x in value.split(",") if x.strip()]:
            if re.fullmatch(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}", d):
                dests.append(d.lower())
            else:
                skipped.append(d)
        if key == "*":
            if dests:
                catch = dests[0]
            elif value and not value.startswith(":fail:") and not value.startswith(":blackhole:"):
                notes.append(f"{domain}: the default address ({value[:60]}) can't be recreated; unknown addresses will be rejected")
            continue
        local = key.split("@", 1)[0].lower()
        if dests:
            fwds.append((local, dests))
        if skipped:
            notes.append(f"{key}: skipped {', '.join(s[:40] for s in skipped)} (pipes to programs and special targets aren't supported)")
    return fwds, catch, notes


def parse_autoresponder(text: str) -> tuple[str, str]:
    head, _, body = text.replace("\r\n", "\n").partition("\n\n")
    subject = ""
    for line in head.splitlines():
        if line.lower().startswith("subject:"):
            subject = line.split(":", 1)[1].strip()
    return subject or "Auto reply", body.strip()


# ---------------------------------------------------------------- plan

def build_plan(c: _Collector, root: str | None) -> dict:
    warnings, notes = [], []
    cp_files = [k for k in c.meta if k.startswith("cp/")]
    cpuser = cp_files[0][3:] if cp_files else (root or "").replace("cpmove-", "").split("_")[-1]
    cp_text = _text(c, cp_files[0]) if cp_files else ""
    cp = dict(line.split("=", 1) for line in cp_text.splitlines() if "=" in line)
    old_ip = cp.get("IP", "")

    main = _yaml(c, "userdata/main")
    main_domain = main.get("main_domain") or cp.get("DNS", "")
    if not main_domain:
        raise CpanelError("The backup doesn't say which domain is the main one (userdata/main is missing)")
    addon_map = main.get("addon_domains") or {}
    subs = list(main.get("sub_domains") or [])
    parked = list(main.get("parked_domains") or [])
    addon_subs = set(addon_map.values()) if isinstance(addon_map, dict) else set()

    def docroot_rel(ud: dict, default: str) -> str:
        dr = str(ud.get("documentroot") or "")
        home = f"/home/{cpuser}/"
        for prefix in (home, f"/home2/{cpuser}/", f"/home3/{cpuser}/"):
            if dr.startswith(prefix):
                return dr[len(prefix):].strip("/")
        m = re.match(rf"^/[^/]+/{re.escape(cpuser)}/(.*)$", dr)
        return m.group(1).strip("/") if m else default

    domains = []
    ud = _yaml(c, f"userdata/{main_domain}")
    domains.append({"name": main_domain, "kind": "main", "docroot": docroot_rel(ud, "public_html"),
                    "php": php_from_cpanel(ud.get("phpversion"))})
    for addon, sub in (addon_map.items() if isinstance(addon_map, dict) else []):
        ud = _yaml(c, f"userdata/{sub}")
        domains.append({"name": addon, "kind": "addon", "docroot": docroot_rel(ud, f"public_html/{addon}"),
                        "php": php_from_cpanel(ud.get("phpversion"))})
    for sub in subs:
        if sub in addon_subs:
            continue  # the hidden subdomain behind an addon domain
        ud = _yaml(c, f"userdata/{sub}")
        domains.append({"name": sub, "kind": "sub", "docroot": docroot_rel(ud, f"public_html/{sub.split('.')[0]}"),
                        "php": php_from_cpanel(ud.get("phpversion"))})
    for p in parked:
        domains.append({"name": p, "kind": "parked", "docroot": "", "php": None})
    for d in domains:
        d["size"] = c.dir_sizes.get(d["docroot"].split("/", 1)[0], 0) if d["docroot"] else 0

    # databases & users
    hashes, grants = parse_grants(_text(c, "mysql.sql"), cpuser)
    databases = [{"name": n, "size": s} for n, s in sorted(c.db_sizes.items())]
    db_names = {d["name"] for d in databases}
    db_users = []
    for user in sorted(set(hashes) | set(grants)):
        dbs = [d for d in grants.get(user, []) if d in db_names]
        if not dbs:
            continue
        h = hashes.get(user, "")
        db_users.append({"user": user, "hash": h if re.fullmatch(r"\*[0-9A-Fa-f]{40}", h) else "",
                         "dbs": dbs})
        if not re.fullmatch(r"\*[0-9A-Fa-f]{40}", h):
            notes.append(f"Database user {user}: its password type can't be copied; a new password will be set "
                         "and saved into WordPress/Joomla/Laravel settings where found")

    # mail
    mail = []
    for key in sorted(k for k in c.meta if re.fullmatch(r"homedir/etc/[^/]+/shadow", k)):
        domain = key.split("/")[2]
        shadow = {l.split(":")[0]: l.split(":")[1] for l in _text(c, key).splitlines() if l.count(":") >= 1}
        quota = {}
        for l in _text(c, f"homedir/etc/{domain}/quota").splitlines():
            if ":" in l:
                u, q = l.split(":", 1)
                quota[u] = int(q.strip()) if q.strip().isdigit() else 0
        accounts = []
        for local, h in sorted(shadow.items()):
            if not local or not re.fullmatch(r"[a-z0-9._+\-]+", local.lower()):
                continue
            if not re.match(r"^\$(1|5|6|y|2[aby])\$", h or ""):
                warnings.append(f"{local}@{domain}: password format not recognised; a new password must be set after import")
                h = ""
            q = quota.get(local, 0)
            accounts.append({"local": local.lower(), "hash": h, "quota_mb": round(q / 1048576) if q else 0,
                             "size": c.mail_sizes.get(f"{domain}/{local}", 0)})
        if accounts:
            mail.append({"domain": domain, "accounts": accounts})

    forwarders, catchall = [], {}
    for key in sorted(k for k in c.meta if k.startswith("va/")):
        domain = key[3:]
        fwds, catch, fnotes = parse_forwarders(_text(c, key), domain)
        notes.extend(fnotes)
        forwarders += [{"domain": domain, "local": l, "dests": d} for l, d in fwds]
        if catch:
            catchall[domain] = catch

    autoresponders = []
    for key in sorted(k for k in c.meta if k.startswith("homedir/.autorespond/") and "@" in k and not k.endswith(".json")):
        email = key.rsplit("/", 1)[-1]
        subject, body = parse_autoresponder(_text(c, key))
        days = 1
        try:
            conf = json.loads(_text(c, key + ".json") or "{}")
            days = max(1, min(30, int(conf.get("interval", 24) or 24) // 24))
        except (ValueError, TypeError):
            pass
        autoresponders.append({"email": email.lower(), "subject": subject[:200], "body": body[:10000], "days": days})

    zones = {k[len("dnszones/"):-3]: _text(c, k) for k in c.meta if k.startswith("dnszones/") and k.endswith(".db")}
    cron = [l for l in "\n".join(_text(c, k) for k in c.meta if k.startswith("cron/")).splitlines()
            if l.strip() and not l.strip().startswith("#") and not re.match(r"^\s*[A-Z_]+\s*=", l)]

    if any(k.startswith("vf/") and _text(c, k).strip() and "Exim filter" not in _text(c, k)[:40] for k in c.meta):
        notes.append("Email filters (cPanel Email Filters) aren't imported; recreate important ones in webmail (Settings → Filters)")
    other_dirs = sorted(k for k, v in c.dir_sizes.items() if v > 0 and k not in
                        {d["docroot"].split("/", 1)[0] for d in domains if d["docroot"]} and
                        k not in {"mail", "etc", "logs", "access-logs", "tmp", "ssl", ".cpanel", ".trash", ".cagefs",
                                  ".autorespond", ".spamassassin", ".htpasswds", ".softaculous", ".cl.selector",
                                  ".subaccounts", ".caldav", ".razor", ".koality", "cache", ".cache", ".local",
                                  ".config", ".bash_history", ".lastlogin", ".contactemail", ".wp-toolkit", "perl5",
                                  "php", ".php", ".pki", ".gnupg", ".ssh"} and not k.startswith(".")
                        and not k.endswith((".log", ".gz")))
    if other_dirs:
        notes.append("These folders outside the websites aren't copied: " + ", ".join(other_dirs[:12]) +
                     (" …" if len(other_dirs) > 12 else "") + ". Download them from the backup if an app needs them.")

    return {
        "cpuser": cpuser, "old_ip": old_ip, "main_domain": main_domain, "domains": domains,
        "databases": databases, "db_users": db_users, "mail": mail, "forwarders": forwarders,
        "catchall": catchall, "autoresponders": autoresponders, "zones": zones, "cron": cron,
        "sizes": c.sizes, "members": c.members, "warnings": warnings, "notes": notes,
    }


# ---------------------------------------------------------------- extraction

def extract(path: Path, dest: Path, want_homedir: list[str], progress=None) -> dict:
    """Extract mysql/*.sql and the listed homedir sub-paths into dest.
    Returns counts of skipped unsafe entries."""
    dest.mkdir(parents=True, exist_ok=True)
    stats = {"files": 0, "skipped": 0}
    want = tuple(w.strip("/") + "/" for w in want_homedir) + tuple(w.strip("/") for w in want_homedir)

    def keep_home(hrel: str) -> bool:
        return any(hrel == w.rstrip("/") or hrel.startswith(w if w.endswith("/") else w + "/") for w in want)

    def put(tar, member, rel):
        member.name = rel
        try:
            tar.extract(member, dest, filter="data")  # "data" refuses absolute paths, .. and device files
            stats["files"] += 1
        except (tarfile.FilterError, OSError):
            stats["skipped"] += 1
        if progress and stats["files"] % 2000 == 0 and stats["files"]:
            progress(f"Extracted {stats['files']:,} files…")

    root = None
    with tarfile.open(path, "r|*") as tar:
        for m in tar:
            root, rel = _root_and_rel(m.name, root)
            if not rel:
                continue
            if rel == "homedir.tar" and m.isfile():
                with tarfile.open(fileobj=tar.extractfile(m), mode="r|*") as itar:
                    for im in itar:
                        irel = _clean(im.name)
                        if irel and keep_home(irel):
                            put(itar, im, "homedir/" + irel)
                continue
            if rel.startswith("homedir/") and keep_home(rel[len("homedir/"):]):
                put(tar, m, rel)
            elif rel.startswith("mysql/") and rel.endswith(".sql"):
                put(tar, m, rel)
    return stats


def remove_escaping_links(base: Path) -> int:
    """Delete symlinks that point outside `base` (a backup could contain links to system files)."""
    base = base.resolve()
    removed = 0
    for p in list(base.rglob("*")):
        if p.is_symlink():
            try:
                target = p.resolve()
            except OSError:
                target = None
            if target is None or (target != base and base not in target.parents):
                p.unlink()
                removed += 1
    return removed


def copy_tree(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dst, symlinks=True, dirs_exist_ok=True)


# ---------------------------------------------------------------- config rewriting

CONFIG_NAMES = {"wp-config.php", "configuration.php", ".user.ini", ".htaccess", "wordfence-waf.php", ".env",
                "config.php", "settings.php", "local.xml", "env.php", "parameters.yml", "database.php"}


def config_files(base: Path, max_depth: int = 4):
    base_depth = len(base.parts)
    for p in base.rglob("*"):
        if len(p.parts) - base_depth > max_depth:
            continue
        if p.is_file() and not p.is_symlink() and p.name in CONFIG_NAMES and p.stat().st_size < 2 * 1024 * 1024:
            yield p


def rewrite(base: Path, replacements: list[tuple[str, str]]) -> list[str]:
    """Replace strings in known configuration files. Returns changed files."""
    changed = []
    for f in config_files(base):
        try:
            text = f.read_text(errors="surrogateescape")
        except OSError:
            continue
        new = text
        for old, rep in replacements:
            if old and old != rep:
                new = new.replace(old, rep)
        if new != text:
            f.write_text(new, errors="surrogateescape")
            changed.append(str(f.relative_to(base)))
    return changed


def set_wp_password(base: Path, user: str, password: str) -> list[str]:
    """Update DB_PASSWORD in wp-config.php files whose DB_USER is `user`."""
    changed = []
    for f in config_files(base):
        if f.name != "wp-config.php":
            continue
        text = f.read_text(errors="surrogateescape")
        if re.search(r"define\(\s*['\"]DB_USER['\"]\s*,\s*['\"]" + re.escape(user) + r"['\"]", text):
            new = re.sub(r"(define\(\s*['\"]DB_PASSWORD['\"]\s*,\s*)(['\"]).*?\2", lambda m: f"{m.group(1)}'{password}'", text)
            if new != text:
                f.write_text(new, errors="surrogateescape")
                changed.append(str(f))
    return changed


STANDARD_HTACCESS = re.compile(
    r"^\s*(#.*|RewriteEngine\s+On|RewriteBase\s+/\S*|RewriteRule\s+\^index\\\.php\$\s+-\s+\[L\]|"
    r"RewriteCond\s+%\{REQUEST_FILENAME\}\s+!-[fd]|RewriteRule\s+\.\s+/\S*index\.php\s+\[L\]|"
    r"RewriteRule\s+\.\*\s+-\s+\[E=HTTP_AUTHORIZATION:%\{HTTP:Authorization\}\]|"
    r"</?IfModule[^>]*>|AddHandler\s+application/x-httpd-ea-php\d+.*|"
    r"<FilesMatch[^>]*>|</FilesMatch>|SetHandler\s+application/x-httpd-ea-php\d+.*|"
    r"php_(value|flag)\s+.*|Options\s+-Indexes|)\s*$", re.I)


def htaccess_custom_lines(base: Path) -> int:
    """Count .htaccess lines beyond the standard WordPress/cPanel boilerplate.
    nginx doesn't read .htaccess, so these need a look after moving."""
    n = 0
    for f in base.rglob(".htaccess"):
        if f.is_symlink() or f.stat().st_size > 512 * 1024:
            continue
        for line in f.read_text(errors="replace").splitlines():
            if not STANDARD_HTACCESS.match(line):
                n += 1
    return n


# ---------------------------------------------------------------- DNS

def parse_zone(domain: str, text: str) -> list[dict]:
    import dns.exception
    import dns.rdatatype
    import dns.zone
    try:
        z = dns.zone.from_text(text, origin=domain + ".", relativize=True, check_origin=False)
    except (dns.exception.DNSException, ValueError) as e:
        raise CpanelError(f"Zone for {domain} couldn't be read: {e}")
    out = []
    origin = z.origin

    def fq(target) -> str:
        """Targets are stored fully qualified ("mail.example.com.") so they read the same everywhere."""
        return target.derelativize(origin).to_text().lower() if target.to_text() != "@" else "@"

    for name, node in z.nodes.items():
        label = name.to_text()
        label = "@" if label == "@" else label.lower()
        first = label.split(".")[0]
        if first in SKIP_ZONE_NAMES or label.startswith("_cpanel-dcv") or label.startswith("_acme-challenge"):
            continue
        for rds in node.rdatasets:
            t = dns.rdatatype.to_text(rds.rdtype)
            if t in ("SOA",) or (t == "NS" and label == "@"):
                continue
            for rd in rds:
                rec = {"name": label, "type": t, "ttl": max(60, min(int(rds.ttl), 604800)), "priority": None}
                if t in ("A", "AAAA"):
                    rec["content"] = rd.address
                elif t in ("CNAME", "NS"):
                    rec["content"] = fq(rd.target)
                elif t == "MX":
                    rec["content"], rec["priority"] = fq(rd.exchange), rd.preference
                elif t == "TXT":
                    rec["content"] = b"".join(rd.strings).decode("utf-8", "replace")
                elif t == "SRV":
                    rec["content"] = f"{rd.weight} {rd.port} {fq(rd.target)}"
                    rec["priority"] = rd.priority
                elif t == "CAA":
                    rec["content"] = f'{rd.flags} {rd.tag.decode()} "{rd.value.decode()}"'
                else:
                    continue
                out.append(rec)
    return out
