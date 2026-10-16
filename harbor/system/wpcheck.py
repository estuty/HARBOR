"""WordPress-aware security checks, run after the ClamAV scan of a site.

A file scanner can't see the things that matter most on a hacked WordPress site:
code injected into a legitimate file (so it still looks like that plugin/theme),
a malicious drop-in, or an admin account the attacker created. These checks find
those by comparing against WordPress's official checksums and by looking at the
site's structure — not by matching malware byte-patterns (ClamAV and its
signature sets do that).

Everything here only reads; it never changes the site. Findings are reported for
a person to act on (reinstall a modified file, remove a rogue admin), because
each needs judgement. All file access stays inside the install and never follows
symlinks."""
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Drop-ins WordPress will execute automatically if present in wp-content/.
DROPINS = ("db.php", "object-cache.php", "advanced-cache.php", "sunrise.php", "wp-cache-config.php")
# Caching/related plugins that legitimately create those drop-ins.
DROPIN_OWNERS = {
    "db.php": ("w3-total-cache", "litespeed-cache", "wp-db.php", "query-monitor", "sqlite-database-integration"),
    "object-cache.php": ("w3-total-cache", "redis-cache", "wp-redis", "memcached", "litespeed-cache", "docket-cache", "batcache"),
    "advanced-cache.php": ("w3-total-cache", "wp-super-cache", "litespeed-cache", "wp-rocket", "comet-cache", "cache-enabler"),
    "sunrise.php": ("wordpress-mu-domain-mapping", "mercator"),
    "wp-cache-config.php": ("wp-super-cache",),
}
NEW_ADMIN_DAYS = 30
BIG_SINGLE_FILE = 300 * 1024      # a "plugin" that is one enormous PHP file is a classic fake
UPLOADS_PHP_SHOWN = 20


@dataclass
class Finding:
    kind: str                     # "core-modified", "plugin-modified", "dropin", "fake-plugin", "uploads-php", "new-admin", "user-ini", "unverifiable-plugin"
    severity: str                 # "high" | "review"
    title: str
    detail: str = ""


@dataclass
class WpResult:
    path: str                     # install path, relative to the site folder
    findings: list = field(default_factory=list)
    error: str = ""


def find_installs(root: Path, max_depth: int = 4) -> list[Path]:
    """WordPress installs under the site folder (a folder with wp-config.php or wp-includes/version.php)."""
    root = Path(root)
    found = []
    base_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        depth = len(Path(dirpath).parts) - base_depth
        if depth >= max_depth:
            dirnames[:] = []
        dirnames[:] = [d for d in dirnames if d not in ("logs", "git", "node_modules", ".git", "wp-content")]
        if "wp-config.php" in filenames or (Path(dirpath) / "wp-includes" / "version.php").exists():
            found.append(Path(dirpath))
            dirnames[:] = []      # don't descend into an install we already found
    return found


def check(install: Path, site_root: Path, run_wp, now: datetime | None = None) -> WpResult:
    """run_wp(args) -> (stdout+stderr, returncode); runs wp-cli as the site user for this install."""
    now = now or datetime.now(timezone.utc)
    rel = os.path.relpath(install, site_root)
    res = WpResult(path="" if rel == "." else rel)

    res.findings += _dropins(install)
    res.findings += _fake_plugins(install)
    res.findings += _uploads_php(install)
    res.findings += _user_ini(install)

    # Checks that need WordPress (wp-cli). If it can't run, say so but keep the file findings.
    try:
        res.findings += _checksums(run_wp)
        res.findings += _admins(run_wp, now)
    except WpUnavailable as e:
        res.error = str(e)
    return res


class WpUnavailable(Exception):
    pass


# ---------- integrity: official checksums ----------

def _checksums(run_wp) -> list[Finding]:
    findings: list[Finding] = []
    out, _ = run_wp(["core", "verify-checksums"])
    if "Error establishing" in out or "command not found" in out or "Error: This does not seem to be a WordPress" in out:
        raise WpUnavailable("WordPress couldn't be loaded to verify it (database down or not a WordPress install).")
    for path in _verify_lines(out):
        findings.append(Finding("core-modified", "high", f"Core file altered or added: {path}",
                                "A WordPress core file doesn't match the official release. Injected code hides here. "
                                "Fix with: wp core download --force"))
    out, _ = run_wp(["plugin", "verify-checksums", "--all"])
    unverifiable = set()
    for line in out.splitlines():
        if "Could not retrieve the checksums" in line or "not in the WordPress.org" in line or "is not on WordPress.org" in line:
            m = re.search(r"of plugin ['\"]?([\w-]+)|plugin ['\"]?([\w-]+)['\"]?,? |for ['\"]([\w-]+)['\"]", line)
            if m:
                unverifiable.add(next(g for g in m.groups() if g))
    for path in _verify_lines(out):
        findings.append(Finding("plugin-modified", "high", f"Plugin file altered or added: {path}",
                                "A plugin file doesn't match the official release. Reinstall the plugin from wordpress.org."))
    for slug in sorted(unverifiable):
        findings.append(Finding("unverifiable-plugin", "review", f"Plugin can't be verified: {slug}",
                                "Not on wordpress.org, so its files can't be checked against an official copy. "
                                "Normal for paid plugins; a concern if you don't recognise it or it looks fake."))
    return findings


def _verify_lines(out: str) -> list[str]:
    """Paths from 'File doesn't verify against checksum:' and 'File should not exist:' lines."""
    paths = []
    for line in out.splitlines():
        m = re.search(r"(?:doesn't verify against checksum|should not exist):\s*(.+?)\s*$", line)
        if m:
            p = m.group(1).strip()
            if p and "\n" not in p:
                paths.append(p)
    return paths[:200]


# ---------- admin accounts ----------

def _admins(run_wp, now: datetime) -> list[Finding]:
    out, code = run_wp(["user", "list", "--role=administrator", "--fields=user_login,user_registered,user_email",
                        "--format=csv"])
    if "Error" in out and "user_login" not in out:
        raise WpUnavailable("WordPress couldn't be loaded to list its users.")
    findings = []
    cutoff = now - timedelta(days=NEW_ADMIN_DAYS)
    for row in out.splitlines()[1:]:
        parts = _csv_row(row)
        if len(parts) < 2:
            continue
        login, registered = parts[0], parts[1]
        email = parts[2] if len(parts) > 2 else ""
        when = _parse_date(registered)
        if when and when >= cutoff:
            findings.append(Finding("new-admin", "review", f"Admin account created recently: {login}",
                                    f"Registered {registered} ({email}). Attackers add an admin to keep access — "
                                    "remove it if you didn't create it."))
    return findings


def _csv_row(row: str) -> list[str]:
    out, cur, q = [], "", False
    for ch in row:
        if ch == '"':
            q = not q
        elif ch == "," and not q:
            out.append(cur); cur = ""
        else:
            cur += ch
    out.append(cur)
    return [c.strip() for c in out]


def _parse_date(s: str) -> datetime | None:
    s = s.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


# ---------- structural checks (filesystem only) ----------

def _installed_plugin_slugs(install: Path) -> set:
    d = install / "wp-content" / "plugins"
    try:
        return {p.name for p in d.iterdir() if p.is_dir()}
    except OSError:
        return set()


def _dropins(install: Path) -> list[Finding]:
    findings = []
    wp_content = install / "wp-content"
    plugins = _installed_plugin_slugs(install)
    for name in DROPINS:
        f = wp_content / name
        try:
            if not f.is_symlink() and f.is_file():
                owners = DROPIN_OWNERS.get(name, ())
                known = any(o in plugins for o in owners)
                sev = "review" if known else "high"
                why = ("A caching/related plugin that uses it is installed, so it may be legitimate — confirm."
                       if known else
                       "No plugin that normally creates it is installed. db.php and friends load on every request "
                       "and are a common malware backdoor. Remove it unless you know it's yours.")
                findings.append(Finding("dropin", sev, f"Drop-in present: wp-content/{name}", why))
        except OSError:
            pass
    return findings


def _fake_plugins(install: Path) -> list[Finding]:
    """A plugin folder that is one very large PHP file, or whose declared name is unrelated to its folder."""
    findings = []
    pdir = install / "wp-content" / "plugins"
    try:
        entries = list(pdir.iterdir())
    except OSError:
        return findings
    for p in entries:
        try:
            if p.is_symlink() or not p.is_dir():
                continue
            php = [f for f in p.iterdir() if f.suffix == ".php" and not f.is_symlink() and f.is_file()]
            has_readme = any(f.name.lower() in ("readme.txt", "readme.md") for f in p.iterdir())
            big = [f for f in php if f.stat().st_size > BIG_SINGLE_FILE]
            if len(php) == 1 and not has_readme and php[0].stat().st_size > BIG_SINGLE_FILE:
                findings.append(Finding("fake-plugin", "high", f"Suspicious plugin: {p.name}",
                                        f"The whole plugin is a single {php[0].stat().st_size // 1024} KB PHP file with no readme — "
                                        "the shape of a planted backdoor, not a real plugin."))
                continue
            name = _plugin_header_name(php)
            if name and not _name_matches_folder(name, p.name):
                findings.append(Finding("fake-plugin", "review", f"Plugin name doesn't match its folder: {p.name}",
                                        f"The folder is '{p.name}' but it calls itself '{name}'. Malware often disguises "
                                        "itself this way — confirm it's a plugin you installed."))
        except OSError:
            pass
    return findings


def _plugin_header_name(php_files) -> str:
    for f in php_files:
        try:
            head = f.read_bytes()[:4096].decode("utf-8", "replace")
        except OSError:
            continue
        m = re.search(r"Plugin Name:\s*(.+)", head)
        if m:
            return m.group(1).strip()
    return ""


def _name_matches_folder(name: str, folder: str) -> bool:
    def toks(s):
        return set(re.findall(r"[a-z0-9]+", s.lower()))
    nt, ft = toks(name), toks(folder)
    return bool(nt & ft) or not nt


def _uploads_php(install: Path) -> list[Finding]:
    uploads = install / "wp-content" / "uploads"
    hits = []
    for dirpath, dirnames, filenames in os.walk(uploads, followlinks=False):
        for f in filenames:
            if f.lower().endswith((".php", ".php5", ".phtml", ".phar")) and f.lower() != "index.php":
                hits.append(os.path.relpath(os.path.join(dirpath, f), install))
    hits = [h for h in hits if "/cache/" not in "/" + h.replace(os.sep, "/")]   # known plugin template caches
    if not hits:
        return []
    detail = ", ".join(hits[:UPLOADS_PHP_SHOWN]) + (f", and {len(hits) - UPLOADS_PHP_SHOWN} more" if len(hits) > UPLOADS_PHP_SHOWN else "")
    return [Finding("uploads-php", "review", f"{len(hits)} PHP file(s) in uploads",
                    "The uploads folder is for media; runnable PHP there is often a planted backdoor "
                    f"(plugin cache files are ignored). Files: {detail}")]


def _user_ini(install: Path) -> list[Finding]:
    findings = []
    for name in (".user.ini", "php.ini"):
        f = install / name
        try:
            if f.is_file() and not f.is_symlink():
                text = f.read_bytes()[:8192].decode("utf-8", "replace")
                m = re.search(r"^\s*auto_(?:prepend|append)_file\s*=\s*(.+)$", text, re.I | re.M)
                if m:
                    findings.append(Finding("user-ini", "high", f"{name} forces a file to run on every page",
                                            f"auto_prepend/append set to {m.group(1).strip()}. Legitimate only for a few "
                                            "security plugins (e.g. Wordfence); otherwise it's a backdoor loader."))
        except OSError:
            pass
    return findings
