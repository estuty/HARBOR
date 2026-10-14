"""Strict input validation. Everything that ends up in a config file passes
through one of these, so user input can never inject extra directives."""
import ipaddress
import re
from zoneinfo import available_timezones


class ValidationError(ValueError):
    pass


DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")
DB_SUFFIX_RE = re.compile(r"^[a-z0-9_]{1,24}$")
CRON_FIELD_RE = re.compile(r"^[0-9a-zA-Z*/,\-]+$")
CRON_MACROS = {"@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly"}
URL_PATH_RE = re.compile(r"^/[A-Za-z0-9._~\-/%]*$")
TARGET_RE = re.compile(r"^(https?://[A-Za-z0-9.\-]+(:\d{1,5})?)?/[A-Za-z0-9._~\-/%?&=+#:@!,]*$|^https?://[A-Za-z0-9.\-]+(:\d{1,5})?$")
USERNAME_RE = re.compile(r"^[a-z][a-z0-9_.\-]{1,31}$")
HTUSER_RE = re.compile(r"^[A-Za-z0-9_.@\-]{1,64}$")
REALM_RE = re.compile(r"^[A-Za-z0-9 _.,\-]{1,64}$")
EXT_RE = re.compile(r"^[a-z0-9]{1,8}$")
MAIL_LOCAL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._+\-]{0,62}[a-z0-9])?$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9\-]{1,63}\.)+[A-Za-z]{2,63}$")
SIZE_RE = re.compile(r"^\d{1,5}[MG]$")
LABEL_RE = re.compile(r"^(@|\*|(\*\.)?(?:(?!-)[a-z0-9_\-]{1,63}(?<!-))(?:\.(?!-)[a-z0-9_\-]{1,63}(?<!-))*)$")


def domain(value: str) -> str:
    v = (value or "").strip().lower().rstrip(".")
    if v.startswith("www."):
        v = v[4:]
    if not DOMAIN_RE.match(v):
        raise ValidationError("Enter a valid domain name, e.g. example.com")
    return v


def hostname(value: str) -> str:
    v = (value or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.match(v):
        raise ValidationError(f"'{value}' is not a valid host name")
    return v


def db_suffix(value: str) -> str:
    v = (value or "").strip().lower()
    if not DB_SUFFIX_RE.match(v):
        raise ValidationError("Database name: 1-24 characters, lowercase letters, digits and _ only")
    return v


def cron_schedule(value: str) -> str:
    v = " ".join((value or "").split())
    if v in CRON_MACROS:
        return v
    parts = v.split(" ")
    if len(parts) != 5 or not all(CRON_FIELD_RE.match(x) for x in parts):
        raise ValidationError("Schedule must be 5 cron fields (e.g. */15 * * * *) or a macro like @daily")
    return v


def cron_command(value: str) -> str:
    v = (value or "").strip()
    if not v or "\n" in v or "\r" in v or len(v) > 1000:
        raise ValidationError("Command must be a single line (max 1000 characters)")
    return v


def password(value: str, min_len: int = 10) -> str:
    v = value or ""
    if len(v) < min_len:
        raise ValidationError(f"Password must be at least {min_len} characters")
    if any(c in v for c in "\n\r:'\"\\`") or len(v) > 128:
        raise ValidationError("Password contains unsupported characters (quotes, backslash, colon or newline)")
    return v


def username(value: str) -> str:
    v = (value or "").strip().lower()
    if not USERNAME_RE.match(v):
        raise ValidationError("Username: 2-32 characters, starting with a letter (a-z, 0-9, . _ -)")
    return v


# ---------- web rules ----------

def url_path(value: str, directory: bool = False) -> str:
    v = (value or "").strip()
    if not v.startswith("/"):
        v = "/" + v
    v = re.sub(r"/+", "/", v)
    if ".." in v or not URL_PATH_RE.match(v):
        raise ValidationError("Path may contain letters, digits and . _ ~ - / % only, e.g. /old-page")
    if directory and not v.endswith("/"):
        v += "/"
    return v


def redirect_target(value: str) -> str:
    v = (value or "").strip()
    if not TARGET_RE.match(v) or len(v) > 500:
        raise ValidationError("Redirect target must be a path (/new) or a full http(s):// URL without spaces")
    return v


def ip_or_network(value: str) -> str:
    v = (value or "").strip()
    try:
        return str(ipaddress.ip_network(v, strict=False))
    except ValueError:
        raise ValidationError(f"'{v}' is not an IP address or CIDR range (e.g. 203.0.113.7 or 10.0.0.0/8)")


def htuser(value: str) -> str:
    v = (value or "").strip()
    if not HTUSER_RE.match(v):
        raise ValidationError("Username: letters, digits and . _ @ - only")
    return v


def realm(value: str) -> str:
    v = (value or "").strip() or "Restricted"
    if not REALM_RE.match(v):
        raise ValidationError("Name shown in the login prompt: letters, digits, spaces and . , _ - only")
    return v


def extensions(value: str) -> list[str]:
    exts = [e.strip().lstrip(".").lower() for e in re.split(r"[,\s]+", value or "") if e.strip()]
    if not exts or not all(EXT_RE.match(e) for e in exts):
        raise ValidationError("File types: comma-separated extensions like jpg, png, gif")
    return sorted(set(exts))


def referer_domains(value: str) -> list[str]:
    out = []
    for d in re.split(r"[,\s]+", value or ""):
        d = d.strip().lower()
        if not d:
            continue
        bare = d[2:] if d.startswith("*.") else d
        if not DOMAIN_RE.match(bare):
            raise ValidationError(f"'{d}' is not a valid domain")
        out.append(d)
    return out


def ini_value(key: str, value: str, kind: str) -> str:
    v = (value or "").strip()
    if kind == "size":
        if key == "memory_limit" and v == "-1":
            return v
        v = v.upper()
        if not SIZE_RE.match(v):
            raise ValidationError(f"{key}: use a size like 128M or 1G")
        return v
    if kind == "int":
        if not v.isdigit() or not (0 <= int(v) <= 1_000_000):
            raise ValidationError(f"{key}: must be a whole number")
        return str(int(v))
    if kind == "flag":
        if v not in ("On", "Off"):
            raise ValidationError(f"{key}: must be On or Off")
        return v
    if kind == "tz":
        if v not in available_timezones():
            raise ValidationError(f"{key}: unknown time zone (e.g. Europe/London)")
        return v
    raise ValidationError("Unknown setting")


# ---------- mail ----------

def mail_local(value: str) -> str:
    v = (value or "").strip().lower()
    if not MAIL_LOCAL_RE.match(v):
        raise ValidationError("Address: letters, digits and . _ + - only (before the @)")
    return v


def email(value: str) -> str:
    v = (value or "").strip().lower()
    if not EMAIL_RE.match(v):
        raise ValidationError(f"'{value}' is not a valid email address")
    return v


def single_line(value: str, field: str, max_len: int = 200) -> str:
    v = (value or "").strip()
    if "\n" in v or "\r" in v or len(v) > max_len:
        raise ValidationError(f"{field} must be one line (max {max_len} characters)")
    return v


# ---------- DNS ----------

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA", "NS")


def dns_name(value: str) -> str:
    v = (value or "").strip().lower().rstrip(".") or "@"
    if not LABEL_RE.match(v) or len(v) > 200:
        raise ValidationError("Name: @ for the domain itself, or a sub-name like www, mail, *.dev")
    return v


def dns_ttl(value) -> int:
    try:
        t = int(value or 3600)
    except ValueError:
        raise ValidationError("TTL must be a number of seconds")
    if not 60 <= t <= 604800:
        raise ValidationError("TTL must be between 60 and 604800 seconds")
    return t


def dns_content(rtype: str, value: str, priority) -> tuple[str, int | None]:
    v = (value or "").strip()
    if rtype not in RECORD_TYPES:
        raise ValidationError("Unsupported record type")
    if rtype == "A":
        try:
            if ipaddress.ip_address(v).version != 4:
                raise ValueError
        except ValueError:
            raise ValidationError("A record needs an IPv4 address")
        return v, None
    if rtype == "AAAA":
        try:
            if ipaddress.ip_address(v).version != 6:
                raise ValueError
        except ValueError:
            raise ValidationError("AAAA record needs an IPv6 address")
        return str(ipaddress.ip_address(v)), None
    if rtype in ("CNAME", "NS"):
        return _target_host(v), None
    if rtype == "MX":
        return _target_host(v), _priority(priority)
    if rtype == "TXT":
        if not v or len(v) > 2000 or any(ord(c) < 32 for c in v):
            raise ValidationError("TXT value must be printable text")
        return v, None  # quoted/escaped when the zone file is rendered
    if rtype == "SRV":
        parts = v.split()
        if len(parts) != 3 or not parts[0].isdigit() or not parts[1].isdigit():
            raise ValidationError("SRV value: weight port target, e.g. 5 5060 sip.example.com")
        return f"{int(parts[0])} {int(parts[1])} {_target_host(parts[2])}", _priority(priority)
    if rtype == "CAA":
        m = re.match(r'^(\d{1,3})\s+(issue|issuewild|iodef)\s+"?([A-Za-z0-9.\-:/@;= ]+)"?$', v)
        if not m:
            raise ValidationError('CAA value: flags tag "value", e.g. 0 issue "letsencrypt.org"')
        return f'{m.group(1)} {m.group(2)} "{m.group(3)}"', None
    raise ValidationError("Unsupported record type")


def _target_host(v: str) -> str:
    v = v.strip().lower()
    if v == "@":
        return v
    bare = v.rstrip(".")
    if not DOMAIN_RE.match(bare) and not re.match(r"^[a-z0-9\-]{1,63}$", bare):
        raise ValidationError(f"'{v}' is not a valid host name")
    return v


def _priority(p) -> int:
    try:
        n = int(p if p not in (None, "") else 10)
    except ValueError:
        raise ValidationError("Priority must be a number")
    if not 0 <= n <= 65535:
        raise ValidationError("Priority must be 0-65535")
    return n


def rule_ids(value: str) -> list[int]:
    ids = []
    for part in re.split(r"[,\s]+", value or ""):
        if not part:
            continue
        if not part.isdigit() or not 1 <= int(part) <= 9999999:
            raise ValidationError(f"'{part}' is not a rule ID")
        ids.append(int(part))
    return sorted(set(ids))


# ---------- Git deploy ----------

GIT_HTTPS_RE = re.compile(r"^https://[A-Za-z0-9.\-]+(:\d{1,5})?/[A-Za-z0-9._~/\-]+$")
GIT_SSH_RE = re.compile(r"^(?:ssh://)?[A-Za-z0-9._\-]+@[A-Za-z0-9.\-]+(?::\d{1,5})?[:/][A-Za-z0-9._~/\-]+$")
GIT_BRANCH_RE = re.compile(r"^(?!-)(?!.*\.\.)(?!.*//)(?!.*@\{)[A-Za-z0-9._/\-]{1,100}(?<!\.lock)(?<![/.])$")
REL_PATH_RE = re.compile(r"^[A-Za-z0-9._@+\-][A-Za-z0-9._@+\-/]*$")


def git_url(value: str) -> str:
    v = (value or "").strip()
    if v.startswith("https://") and "@" in v.split("/")[2]:
        raise ValidationError("Don't put a password or token in the address. For a private repository use the "
                              "SSH address (git@github.com:owner/repo.git) and add the deploy key shown here.")
    if not (GIT_HTTPS_RE.match(v) or GIT_SSH_RE.match(v)) or len(v) > 300 or ".." in v:
        raise ValidationError("Enter the repository address, e.g. https://github.com/owner/repo.git "
                              "or git@github.com:owner/repo.git")
    return v


def git_branch(value: str) -> str:
    v = (value or "").strip() or "main"
    if v.startswith("refs/heads/"):
        v = v[len("refs/heads/"):]
    if not GIT_BRANCH_RE.match(v):
        raise ValidationError("Branch name isn't valid")
    return v


def rel_path(value: str, field: str = "Folder") -> str:
    v = (value or "").strip().strip("/")
    if not v:
        return ""
    if len(v) > 200 or not REL_PATH_RE.match(v) or any(part in ("..", ".") for part in v.split("/")):
        raise ValidationError(f"{field}: use a path inside the repository, like dist or public")
    return v


def rel_path_list(value: str, field: str = "Kept paths") -> list[str]:
    out = []
    for line in (value or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        is_dir = line.endswith("/")
        p = rel_path(line, field)
        if p and p not in [x.rstrip("/") for x in out]:
            out.append(p + ("/" if is_dir else ""))
    if len(out) > 50:
        raise ValidationError(f"{field}: at most 50 lines")
    return out


def script(value: str, field: str, max_len: int = 4000) -> str:
    v = (value or "").replace("\r\n", "\n").strip()
    if len(v) > max_len or "\x00" in v:
        raise ValidationError(f"{field} is too long (max {max_len} characters)")
    return v
