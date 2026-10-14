"""Runtime configuration.

Every real system path goes through `p()`. With HARBOR_DRY_RUN=1 all paths are
redirected into a sandbox folder and no system commands are executed, so the
panel can be explored safely on any machine.
"""
import os
import shutil
from pathlib import Path

DRY_RUN = os.environ.get("HARBOR_DRY_RUN") == "1"
_ROOT = Path(os.environ.get("HARBOR_SANDBOX", "/tmp/harbor-sandbox")) if DRY_RUN else Path("/")


def p(path: str) -> Path:
    return _ROOT / path.lstrip("/")


DATA_DIR = p(os.environ.get("HARBOR_DATA", "/var/lib/harbor"))
LOG_DIR = p("/var/log/harbor")
AUTH_LOG = LOG_DIR / "auth.log"          # failed sign-ins, read by fail2ban
APP_DIR = p("/opt/harbor")
DB_PATH = DATA_DIR / "harbor.db"
ETC = p("/etc/harbor")
SECRET_FILE = ETC / "secret"
SITES_DIR = p("/srv/harbor/sites")
BACKUP_DIR = p("/srv/harbor/backups")
NGINX_AVAILABLE = p("/etc/nginx/sites-available")
NGINX_ENABLED = p("/etc/nginx/sites-enabled")
NGINX_HARBOR = p("/etc/nginx/harbor")          # htpasswd files, modsecurity per-site rules
PHP_ETC = p("/etc/php")
LE_LIVE = "/etc/letsencrypt/live"

# DNS (BIND 9)
BIND_ZONES = p("/var/lib/bind/harbor")   # inside the AppArmor-allowed path
BIND_INCLUDE = p("/etc/bind/named.conf.harbor")

# Mail (Postfix + Dovecot + Rspamd)
POSTFIX_MAPS = p("/etc/postfix/harbor")
DOVECOT_USERS = p("/etc/dovecot/harbor-users")
MAIL_ROOT = p("/var/mail/vhosts")
DKIM_DIR = p("/var/lib/rspamd/dkim")
VMAIL_UID = 5000

# ModSecurity
MODSEC_DIR = p("/etc/nginx/harbor/modsec")
MODSEC_AUDIT_LOG = p("/var/log/nginx/modsec_audit.log")

# Applications
WP_CLI = p("/usr/local/bin/wp")

IPV6 = Path("/proc/net/if_inet6").exists() or DRY_RUN

DEFAULT_PHP = os.environ.get("HARBOR_DEFAULT_PHP", "")
ACME_EMAIL = os.environ.get("HARBOR_ACME_EMAIL", "")
SFTP_GROUP = "harbor-sftp"
WEB_USER = "www-data"

MAX_EDIT_BYTES = 2 * 1024 * 1024
MAX_UPLOAD_BYTES = int(os.environ.get("HARBOR_MAX_UPLOAD_MB", "256")) * 1024 * 1024


def features() -> dict[str, bool]:
    """Which optional subsystems are installed on this server."""
    if DRY_RUN:
        return {"mail": True, "dns": True, "modsec": True, "webmail": True, "apps": True, "fail2ban": True}
    return {
        "mail": shutil.which("postfix") is not None and shutil.which("doveadm") is not None,
        "dns": shutil.which("named-checkzone") is not None,
        "modsec": Path("/usr/share/nginx/modules-available/mod-http-modsecurity.conf").exists()
                  or Path("/usr/lib/nginx/modules/ngx_http_modsecurity_module.so").exists(),
        "webmail": Path("/usr/share/roundcube").exists(),
        "apps": WP_CLI.exists(),
        "fail2ban": shutil.which("fail2ban-client") is not None,
    }
