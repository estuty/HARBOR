#!/usr/bin/env bash
# Harbor installer for a fresh Ubuntu 24.04 / 22.04 or Debian 12 server.
#
#   sudo ./install.sh --hostname server1.example.com --email you@example.com
#
# Options:
#   --hostname NAME    Server host name (used for mail; default: current FQDN)
#   --email ADDR       Let's Encrypt account email (expiry notices)
#   --admin NAME       First admin username (default: admin)
#   --port N           Panel port (default: 8443)
#   --extra-php "8.2 8.1"  Also install these PHP versions (adds the Ondřej Surý repository)
#   --no-mail --no-dns --no-modsec --no-webmail   Skip optional components
#
# Safe to re-run: it upgrades Harbor and keeps all data and settings.
set -euo pipefail

ACME_EMAIL=""; ADMIN_USER="admin"; PANEL_PORT="8443"; HOSTNAME_ARG=""; EXTRA_PHP=""
WITH_MAIL=1; WITH_DNS=1; WITH_MODSEC=1; WITH_WEBMAIL=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --email) ACME_EMAIL="$2"; shift 2 ;;
    --admin) ADMIN_USER="$2"; shift 2 ;;
    --port) PANEL_PORT="$2"; shift 2 ;;
    --hostname) HOSTNAME_ARG="$2"; shift 2 ;;
    --extra-php) EXTRA_PHP="$2"; shift 2 ;;
    --no-mail) WITH_MAIL=0; WITH_WEBMAIL=0; shift ;;
    --no-dns) WITH_DNS=0; shift ;;
    --no-modsec) WITH_MODSEC=0; shift ;;
    --no-webmail) WITH_WEBMAIL=0; shift ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP=/opt/harbor
TLS=/etc/harbor/tls
say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33mWarning: %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31mError: %s\033[0m\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root (sudo ./install.sh)"
. /etc/os-release
case "$ID:$VERSION_ID" in
  ubuntu:22.04|ubuntu:24.04|debian:12) ;;
  *) warn "Untested OS ($PRETTY_NAME). Continuing in 5s…"; sleep 5 ;;
esac
if [[ "$ACME_EMAIL" =~ @(example\.(com|org|net)|test|localhost)$ ]]; then
  warn "--email $ACME_EMAIL is a placeholder; Let's Encrypt would reject it. Continuing without an email."
  ACME_EMAIL=""
fi
SAVED_HOST=""
if [[ -f /var/lib/harbor/harbor.db ]] && command -v sqlite3 >/dev/null; then
  SAVED_HOST="$(sqlite3 /var/lib/harbor/harbor.db "SELECT value FROM server_settings WHERE key='hostname'" 2>/dev/null || true)"
fi
HOST="${HOSTNAME_ARG:-${SAVED_HOST:-$(hostname -f 2>/dev/null || hostname)}}"
HAS_V6=0; [[ -f /proc/net/if_inet6 ]] && HAS_V6=1
v6() { [[ $HAS_V6 == 1 ]] && echo "$1" || true; }   # emit an IPv6 listen line only where IPv6 exists
export DEBIAN_FRONTEND=noninteractive
apt_install() { apt-get install -y -q --no-install-recommends "$@"; }

# ---------------------------------------------------------------- base stack
say "Installing web stack (nginx, MariaDB, PHP-FPM, certbot)"
apt-get update -q
apt_install nginx mariadb-server mariadb-client certbot openssl tar cron curl ca-certificates gnupg sqlite3 rsyslog \
  php-fpm php-cli php-mysql php-curl php-gd php-mbstring php-xml php-zip php-intl php-bcmath php-imagick \
  python3 python3-venv python3-pip openssh-server openssh-client git rsync

if [[ -n "$EXTRA_PHP" ]]; then
  say "Adding PHP versions: $EXTRA_PHP"
  if [[ "$ID" == ubuntu ]]; then
    apt_install software-properties-common && add-apt-repository -y ppa:ondrej/php
  else
    curl -fsSL https://packages.sury.org/php/apt.gpg -o /usr/share/keyrings/sury-php.gpg
    echo "deb [signed-by=/usr/share/keyrings/sury-php.gpg] https://packages.sury.org/php/ $VERSION_CODENAME main" \
      > /etc/apt/sources.list.d/sury-php.list
  fi
  apt-get update -q
  for v in $EXTRA_PHP; do
    apt_install "php$v-fpm" "php$v-cli" "php$v-mysql" "php$v-curl" "php$v-gd" "php$v-mbstring" "php$v-xml" \
      "php$v-zip" "php$v-intl" "php$v-bcmath" || warn "PHP $v could not be installed"
  done
fi
if [[ $HAS_V6 == 0 ]]; then  # nginx refuses to start with [::] listeners on IPv6-less hosts
  sed -i '/listen \[::\]/d' /etc/nginx/sites-available/default 2>/dev/null || true
fi
systemctl enable --now nginx mariadb cron
for d in /etc/php/*/fpm; do v=$(basename "$(dirname "$d")"); systemctl enable --now "php${v}-fpm"; done
mkdir -p /run/php

say "Securing MariaDB defaults"
mysql --batch <<'SQL' || true
DELETE FROM mysql.global_priv WHERE User='';
DROP DATABASE IF EXISTS test;
FLUSH PRIVILEGES;
SQL

# ---------------------------------------------------------------- Harbor app
say "Installing Harbor to $APP"
mkdir -p "$APP"
rm -rf "$APP/harbor"
cp -r "$SRC/harbor" "$SRC/requirements.txt" "$APP/"
if [[ "$(readlink -f "$SRC")" != "$(readlink -f "$APP/source")" ]]; then
  rm -rf "$APP/source" && mkdir -p "$APP/source"
  cp -r "$SRC/harbor" "$SRC/requirements.txt" "$SRC/install.sh" "$APP/source/"
  [[ -f "$SRC/README.md" ]] && cp "$SRC/README.md" "$APP/source/"
fi
[[ -x "$APP/venv/bin/python" ]] || python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --upgrade pip
"$APP/venv/bin/pip" install -q -r "$APP/requirements.txt"

mkdir -p /srv/harbor/sites /srv/harbor/backups /srv/harbor/imports /var/lib/harbor /etc/harbor "$TLS" /etc/nginx/harbor/htpasswd \
  /etc/harbor/php /var/log/harbor
chmod 750 /var/log/harbor
touch /var/log/harbor/auth.log /var/log/harbor/manual.log /etc/nginx/harbor/panel-access.conf /etc/nginx/harbor/webmail-access.conf
chmod 755 /srv /srv/harbor /srv/harbor/sites
chmod 700 /srv/harbor/backups /srv/harbor/imports /var/lib/harbor /etc/harbor
chmod 750 /etc/nginx/harbor/htpasswd && chown root:www-data /etc/nginx/harbor/htpasswd
[[ -f /etc/harbor/secret ]] || { openssl rand -base64 48 | tr -d '\n' > /etc/harbor/secret; chmod 600 /etc/harbor/secret; }
cat > /etc/harbor/harbor.env <<EOF
HARBOR_ACME_EMAIL=${ACME_EMAIL}
HARBOR_HOST=127.0.0.1
HARBOR_PORT=8090
EOF
chmod 600 /etc/harbor/harbor.env

if [[ ! -e "$TLS/cert.pem" ]]; then
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 -subj "/CN=$HOST" \
    -keyout "$TLS/key.pem" -out "$TLS/cert.pem" 2>/dev/null
  chmod 600 "$TLS/key.pem"
fi
chmod 711 /etc/harbor   # services read the TLS files below it; nothing else is world-readable

say "Installing WP-CLI (one-click WordPress)"
if curl -fsSL -o /usr/local/bin/wp.new https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar; then
  chmod 755 /usr/local/bin/wp.new && mv /usr/local/bin/wp.new /usr/local/bin/wp
else
  warn "Could not download WP-CLI; the WordPress installer will be unavailable"
fi

# ---------------------------------------------------------------- SFTP
say "Configuring SFTP (chrooted per site)"
getent group harbor-sftp >/dev/null || groupadd --system harbor-sftp
if ! grep -q "BEGIN HARBOR" /etc/ssh/sshd_config; then
  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.harbor-bak
  cat >> /etc/ssh/sshd_config <<'EOF'

# BEGIN HARBOR - SFTP-only, chrooted site users
Match Group harbor-sftp
    ChrootDirectory %h
    ForceCommand internal-sftp -u 0022
    PasswordAuthentication yes
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
# END HARBOR
EOF
  mkdir -p /run/sshd
  if sshd -t; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd || true
  else
    cp /etc/ssh/sshd_config.harbor-bak /etc/ssh/sshd_config
    warn "sshd rejected the SFTP config; restored the original. SFTP will not work."
  fi
fi

# ---------------------------------------------------------------- ModSecurity
if [[ $WITH_MODSEC == 1 ]]; then
  say "Installing ModSecurity + OWASP Core Rule Set"
  if apt_install libnginx-mod-http-modsecurity modsecurity-crs; then
    mkdir -p /etc/nginx/harbor/modsec
    sed -e 's/^SecRuleEngine .*/SecRuleEngine DetectionOnly/' \
        -e 's/^SecResponseBodyAccess .*/SecResponseBodyAccess Off/' \
        -e 's|^SecAuditLog .*|SecAuditLog /var/log/nginx/modsec_audit.log|' \
        -e 's/^SecAuditLogParts .*/SecAuditLogParts ABHZ/' \
        -e 's/^SecAuditLogType .*/SecAuditLogType Serial/' \
        -e 's|^SecUnicodeMapFile .*|SecUnicodeMapFile /etc/nginx/unicode.mapping 20127|' \
        /etc/nginx/modsecurity.conf > /etc/nginx/harbor/modsec/base.conf
    grep -q '^SecAuditLogFormat' /etc/nginx/harbor/modsec/base.conf || echo 'SecAuditLogFormat JSON' >> /etc/nginx/harbor/modsec/base.conf
    {
      echo "# Managed by Harbor: base settings + OWASP Core Rule Set. Sites opt in individually."
      echo "Include /etc/nginx/harbor/modsec/base.conf"
      for f in /etc/modsecurity/crs/crs-setup.conf /etc/modsecurity/crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf; do
        [[ -f $f ]] && echo "Include $f"
      done
      echo "Include /usr/share/modsecurity-crs/rules/*.conf"   # libmodsecurity has no IncludeOptional
      f=/etc/modsecurity/crs/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf
      [[ -f $f ]] && echo "Include $f"
      true
    } > /etc/nginx/harbor/modsec/main.conf
    cat > /etc/nginx/conf.d/harbor-modsecurity.conf <<'EOF'
# Load the rules once; each Harbor site turns the engine on in its own server block.
modsecurity off;
modsecurity_rules_file /etc/nginx/harbor/modsec/main.conf;
EOF
    touch /var/log/nginx/modsec_audit.log && chown www-data:adm /var/log/nginx/modsec_audit.log
    nginx -t || { rm -f /etc/nginx/conf.d/harbor-modsecurity.conf; warn "nginx rejected ModSecurity; disabled"; }
  else
    warn "ModSecurity packages not available on this OS; skipping"
  fi
fi

# ---------------------------------------------------------------- DNS
if [[ $WITH_DNS == 1 ]]; then
  say "Installing BIND (authoritative DNS)"
  apt_install bind9 bind9-utils bind9-dnsutils
  mkdir -p /var/lib/bind/harbor && chown root:bind /var/lib/bind/harbor && chmod 750 /var/lib/bind/harbor
  touch /etc/bind/named.conf.harbor
  grep -q named.conf.harbor /etc/bind/named.conf.local || echo 'include "/etc/bind/named.conf.harbor";' >> /etc/bind/named.conf.local
  if ! grep -q "Managed by Harbor" /etc/bind/named.conf.options; then
    cp /etc/bind/named.conf.options /etc/bind/named.conf.options.harbor-bak
    cat > /etc/bind/named.conf.options <<'EOF'
// Managed by Harbor: authoritative only (no open resolver)
options {
    directory "/var/cache/bind";
    recursion no;
    allow-query { any; };
    allow-transfer { none; };
    dnssec-validation auto;
    listen-on { any; };
    listen-on-v6 { any; };
    version none;
};
EOF
  fi
  named-checkconf
  systemctl enable --now named 2>/dev/null || systemctl enable --now bind9
  systemctl reload named 2>/dev/null || systemctl reload bind9 || true
fi

# ---------------------------------------------------------------- Mail
if [[ $WITH_MAIL == 1 ]]; then
  say "Installing mail server (Postfix, Dovecot, Rspamd)"
  debconf-set-selections <<EOF
postfix postfix/main_mailer_type select Internet Site
postfix postfix/mailname string $HOST
EOF
  apt_install postfix dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-sieve dovecot-managesieved rspamd redis-server
  getent group vmail >/dev/null || groupadd --system --gid 5000 vmail
  id vmail >/dev/null 2>&1 || useradd --system --uid 5000 --gid 5000 --home-dir /var/mail/vhosts --shell /usr/sbin/nologin vmail
  mkdir -p /var/mail/vhosts /etc/postfix/harbor /var/lib/rspamd/dkim
  chown vmail:vmail /var/mail/vhosts && chmod 750 /var/mail/vhosts
  chown root:_rspamd /var/lib/rspamd/dkim && chmod 750 /var/lib/rspamd/dkim
  for m in vdomains vmailbox valias senders; do [[ -f /etc/postfix/harbor/$m ]] || touch /etc/postfix/harbor/$m; postmap /etc/postfix/harbor/$m; done
  touch /etc/dovecot/harbor-users && chown root:dovecot /etc/dovecot/harbor-users && chmod 640 /etc/dovecot/harbor-users

  postconf -e \
    "myhostname = $HOST" \
    "mydestination = localhost" \
    "mynetworks = 127.0.0.0/8 [::1]/128" \
    "inet_interfaces = all" \
    "virtual_mailbox_domains = hash:/etc/postfix/harbor/vdomains" \
    "virtual_mailbox_maps = hash:/etc/postfix/harbor/vmailbox" \
    "virtual_alias_maps = hash:/etc/postfix/harbor/valias" \
    "virtual_transport = lmtp:unix:private/dovecot-lmtp" \
    "smtpd_tls_cert_file = $TLS/cert.pem" \
    "smtpd_tls_key_file = $TLS/key.pem" \
    "smtpd_tls_security_level = may" \
    "smtp_tls_security_level = may" \
    "smtpd_sasl_type = dovecot" \
    "smtpd_sasl_path = private/auth" \
    "smtpd_sender_login_maps = hash:/etc/postfix/harbor/senders" \
    "smtpd_helo_required = yes" \
    "smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination" \
    "smtpd_milters = inet:localhost:11332" \
    "non_smtpd_milters = inet:localhost:11332" \
    "milter_default_action = accept" \
    "milter_protocol = 6" \
    "message_size_limit = 52428800" \
    "mailbox_size_limit = 0" \
    "recipient_delimiter = +" \
    "disable_vrfy_command = yes"
  postconf -M submission/inet="submission inet n - y - - smtpd"
  postconf -P "submission/inet/syslog_name=postfix/submission" \
              "submission/inet/smtpd_tls_security_level=encrypt" \
              "submission/inet/smtpd_sasl_auth_enable=yes" \
              "submission/inet/smtpd_tls_auth_only=yes" \
              "submission/inet/smtpd_client_restrictions=permit_sasl_authenticated,reject" \
              "submission/inet/smtpd_sender_restrictions=reject_sender_login_mismatch" \
              "submission/inet/smtpd_recipient_restrictions=permit_sasl_authenticated,reject"
  postconf -M submissions/inet="submissions inet n - y - - smtpd"
  postconf -P "submissions/inet/syslog_name=postfix/submissions" \
              "submissions/inet/smtpd_tls_wrappermode=yes" \
              "submissions/inet/smtpd_sasl_auth_enable=yes" \
              "submissions/inet/smtpd_client_restrictions=permit_sasl_authenticated,reject" \
              "submissions/inet/smtpd_sender_restrictions=reject_sender_login_mismatch" \
              "submissions/inet/smtpd_recipient_restrictions=permit_sasl_authenticated,reject"

  cat > /etc/dovecot/conf.d/99-harbor.conf <<EOF
# Managed by Harbor
protocols = imap pop3 lmtp sieve
listen = $([[ $HAS_V6 == 1 ]] && echo '*, ::' || echo '*')
mail_location = maildir:/var/mail/vhosts/%d/%n/Maildir
mail_uid = vmail
mail_gid = vmail
first_valid_uid = 5000
last_valid_uid = 5000
mail_privileged_group = vmail
auth_mechanisms = plain login
disable_plaintext_auth = yes
ssl = yes
ssl_cert = <$TLS/cert.pem
ssl_key = <$TLS/key.pem
ssl_min_protocol = TLSv1.2
mail_plugins = \$mail_plugins quota

passdb {
  driver = passwd-file
  args = scheme=CRYPT username_format=%u /etc/dovecot/harbor-users
}
userdb {
  driver = passwd-file
  args = username_format=%u /etc/dovecot/harbor-users
  default_fields = uid=vmail gid=vmail home=/var/mail/vhosts/%d/%n
}

namespace inbox {
  inbox = yes
  mailbox Drafts {
    special_use = \\Drafts
    auto = subscribe
  }
  mailbox Sent {
    special_use = \\Sent
    auto = subscribe
  }
  mailbox Junk {
    special_use = \\Junk
    auto = subscribe
  }
  mailbox Trash {
    special_use = \\Trash
    auto = subscribe
  }
}

service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
protocol lmtp {
  mail_plugins = \$mail_plugins sieve
  postmaster_address = postmaster@$HOST
}
protocol imap {
  mail_plugins = \$mail_plugins imap_quota
}
plugin {
  quota = maildir:User quota
  quota_exceeded_message = Mailbox is full
  sieve = file:~/sieve;active=~/.dovecot.sieve
  sieve_before = /etc/dovecot/sieve/harbor-spam.sieve
}
EOF
  # Ubuntu's 10-auth.conf enables system users by default; Harbor only uses its own user file
  sed -i 's/^!include auth-system.conf.ext/#!include auth-system.conf.ext/' /etc/dovecot/conf.d/10-auth.conf
  mkdir -p /etc/dovecot/sieve
  cat > /etc/dovecot/sieve/harbor-spam.sieve <<'EOF'
require ["fileinto"];
# Rspamd adds "X-Spam: Yes" to likely spam; file it into Junk.
if header :is "X-Spam" "Yes" { fileinto "Junk"; stop; }
EOF
  sievec /etc/dovecot/sieve/harbor-spam.sieve || true

  mkdir -p /etc/rspamd/local.d
  cat > /etc/rspamd/local.d/dkim_signing.conf <<'EOF'
# Managed by Harbor: sign mail for every domain that has a key file
path = "/var/lib/rspamd/dkim/$domain.$selector.key";
selector = "harbor";
allow_username_mismatch = true;
use_esld = false;
EOF
  cp /etc/rspamd/local.d/dkim_signing.conf /etc/rspamd/local.d/arc.conf
  cat > /etc/rspamd/local.d/milter_headers.conf <<'EOF'
use = ["x-spamd-bar", "x-spam-level", "authentication-results"];
extended_spam_headers = true;
EOF
  cat > /etc/rspamd/local.d/actions.conf <<'EOF'
reject = 15;
add_header = 6;
greylist = 4;
EOF
  cat > /etc/rspamd/local.d/redis.conf <<'EOF'
servers = "127.0.0.1";
EOF
  systemctl enable --now redis-server rspamd dovecot postfix
  systemctl restart rspamd dovecot postfix
fi

# ---------------------------------------------------------------- Webmail
if [[ $WITH_WEBMAIL == 1 && $WITH_MAIL == 1 ]]; then
  say "Installing Roundcube webmail (port 2096)"
  debconf-set-selections <<'EOF'
roundcube-core roundcube/dbconfig-install boolean true
roundcube-core roundcube/database-type select sqlite3
EOF
  if apt_install roundcube roundcube-sqlite3 roundcube-plugins; then
    RC=/etc/roundcube/config.inc.php
    sed -i "s|^\$config\['imap_host'\].*|\$config['imap_host'] = 'localhost:143';|" "$RC"
    sed -i "s|^\$config\['smtp_host'\].*|\$config['smtp_host'] = 'tls://localhost:587';|" "$RC"
    grep -q "Harbor" "$RC" || cat >> "$RC" <<'EOF'
// Harbor: talk to the local mail server; skip certificate checks on localhost only
$config['smtp_user'] = '%u';
$config['smtp_pass'] = '%p';
$config['smtp_conn_options'] = ['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]];
$config['imap_conn_options'] = ['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]];
$config['product_name'] = 'Webmail';
$config['plugins'] = ['archive', 'zipdownload', 'managesieve', 'markasjunk'];
$config['managesieve_host'] = 'localhost';
EOF
    PHPV=$(ls /etc/php | sort -V | tail -1)
    cat > /etc/nginx/conf.d/harbor-webmail.conf <<EOF
# Roundcube webmail for every hosted domain: https://<server>:2096/
server {
    listen 2096 ssl;
    $(v6 "listen [::]:2096 ssl;")
    server_name _;
    ssl_certificate $TLS/cert.pem;
    ssl_certificate_key $TLS/key.pem;
    root /var/lib/roundcube/public_html;
    index index.php;
    client_max_body_size 50M;
    location ~ ^/(config|temp|logs|bin|SQL|installer)/ { deny all; }
    location ~ /\. { deny all; }
    include /etc/nginx/harbor/webmail-access.conf;   # Security -> Panel access (optional)
    location / { try_files \$uri \$uri/ /index.php?\$args; }
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php${PHPV}-fpm.sock;
    }
}
EOF
  else
    warn "Roundcube could not be installed; webmail unavailable"
  fi
fi

# ---------------------------------------------------------------- fail2ban
say "Setting up automatic blocking of password guessing (fail2ban)"
apt_install fail2ban python3-systemd   # python3-systemd: the sshd jail reads the systemd journal
mkdir -p /var/log/roundcube && touch /var/log/roundcube/errors.log && chown -R www-data:www-data /var/log/roundcube 2>/dev/null || true
[[ -f /var/log/mail.log ]] || { touch /var/log/mail.log; chown syslog:adm /var/log/mail.log 2>/dev/null || true; }
cat > /etc/fail2ban/filter.d/harbor-panel.conf <<'F2BEOF'
# Harbor panel: failed passwords and failed two-factor codes.
# fail2ban removes the leading timestamp before matching.
[Definition]
failregex = ^\s*harbor: failed (?:sign-in|2fa) for user '.*' from <HOST>\s*$
ignoreregex =
F2BEOF
cat > /etc/fail2ban/filter.d/harbor-manual.conf <<'F2BEOF'
# Addresses are added by Harbor (Security -> Block); nothing is read from the log
[Definition]
failregex =
ignoreregex =
F2BEOF
cat > /etc/fail2ban/jail.d/harbor.local <<F2BEOF
# Managed by Harbor
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true

[harbor-panel]
enabled = true
backend = auto
logpath = /var/log/harbor/auth.log
action = %(banaction_allports)s

[harbor-manual]
enabled = true
backend = auto
logpath = /var/log/harbor/manual.log
bantime = -1
action = %(banaction_allports)s
F2BEOF
if [[ $WITH_MAIL == 1 ]]; then
  cat >> /etc/fail2ban/jail.d/harbor.local <<'F2BEOF'

[postfix-sasl]
enabled = true
backend = auto
logpath = /var/log/mail.log
port = smtp,465,submission

[dovecot]
enabled = true
backend = auto
logpath = /var/log/mail.log
port = pop3,pop3s,imap,imaps,submission,465,sieve
F2BEOF
fi
if [[ $WITH_WEBMAIL == 1 && -d /var/lib/roundcube ]]; then
  cat >> /etc/fail2ban/jail.d/harbor.local <<'F2BEOF'

[roundcube-auth]
enabled = true
backend = auto
logpath = /var/log/roundcube/errors.log
port = 2096
F2BEOF
fi
cat >> /etc/fail2ban/jail.d/harbor.local <<'F2BEOF'

[nginx-http-auth]
enabled = true
backend = auto
logpath = /var/log/nginx/error.log
          /srv/harbor/sites/*/logs/error.log
port = http,https
F2BEOF
[[ -f /etc/fail2ban/jail.d/harbor-ignore.local ]] || printf '[DEFAULT]\nignoreip = 127.0.0.1/8 ::1\n' > /etc/fail2ban/jail.d/harbor-ignore.local
if fail2ban-client -t >/dev/null 2>&1; then
  systemctl enable fail2ban
  systemctl restart fail2ban || warn "fail2ban didn't start; see: journalctl -u fail2ban -n 50"
else
  warn "fail2ban rejected its configuration:"; fail2ban-client -t || true
fi

# ---------------------------------------------------------------- Database editor
say "Setting up the database editor (Adminer)"
ADMINER_VERSION="5.4.1"
ADMINER_SHA256="44f8f1fad049dca2245d0cc851f87139d73955d968f7ba825462fb9675470116"
id harbor-dbadmin >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin harbor-dbadmin
install -d -m 0750 -o root -g harbor-dbadmin /var/lib/harbor-dbadmin
install -d -m 0770 -o root -g harbor-dbadmin /var/lib/harbor-dbadmin/tokens      # one-time logins from the panel
install -d -m 0700 -o harbor-dbadmin -g harbor-dbadmin /var/lib/harbor-dbadmin/sessions /var/lib/harbor-dbadmin/tmp
install -d -m 0755 "$APP/adminer"
if ! echo "$ADMINER_SHA256  $APP/adminer/adminer.php" | sha256sum -c --status 2>/dev/null; then
  tmp_adminer="$(mktemp)"
  if curl -fsSL --retry 3 -o "$tmp_adminer" \
       "https://github.com/vrana/adminer/releases/download/v${ADMINER_VERSION}/adminer-${ADMINER_VERSION}-mysql.php" \
     && echo "$ADMINER_SHA256  $tmp_adminer" | sha256sum -c --status; then
    install -m 0644 "$tmp_adminer" "$APP/adminer/adminer.php"
  else
    warn "Couldn't download the database editor (Adminer ${ADMINER_VERSION}); the Databases tab explains how to add it later"
  fi
  rm -f "$tmp_adminer"
fi
DBADMIN_PHP="$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')"
cat > "/etc/php/${DBADMIN_PHP}/fpm/pool.d/harbor-dbadmin.conf" <<EOF
; Managed by Harbor: the database editor runs as its own user, not as root or a site
[harbor-dbadmin]
user = harbor-dbadmin
group = harbor-dbadmin
listen = /run/php/harbor-dbadmin.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = ondemand
pm.max_children = 4
pm.process_idle_timeout = 60s
php_admin_value[open_basedir] = $APP/harbor/dbadmin/:$APP/adminer/:/var/lib/harbor-dbadmin/
php_admin_value[session.save_path] = /var/lib/harbor-dbadmin/sessions
php_admin_value[session.gc_maxlifetime] = 7200
php_admin_value[upload_tmp_dir] = /var/lib/harbor-dbadmin/tmp
php_admin_value[sys_temp_dir] = /var/lib/harbor-dbadmin/tmp
php_admin_value[upload_max_filesize] = 256M
php_admin_value[post_max_size] = 256M
php_admin_value[memory_limit] = 512M
php_admin_value[max_execution_time] = 300
php_admin_flag[display_errors] = off
php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec
EOF
if "php-fpm${DBADMIN_PHP}" -t >/dev/null 2>&1; then
  systemctl reload "php${DBADMIN_PHP}-fpm" || systemctl restart "php${DBADMIN_PHP}-fpm"
else
  warn "PHP-FPM rejected the database editor settings; see: php-fpm${DBADMIN_PHP} -t"
fi

# ---------------------------------------------------------------- Panel
say "Serving the panel on port $PANEL_PORT"
cat > /etc/nginx/conf.d/harbor-panel.conf <<EOF
# Harbor control panel. The certificate in $TLS is replaced with a trusted one from Settings.
server {
    listen ${PANEL_PORT} ssl;
    $(v6 "listen [::]:${PANEL_PORT} ssl;")
    server_name _;
    ssl_certificate $TLS/cert.pem;
    ssl_certificate_key $TLS/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 1G;
    proxy_set_header Host \$http_host;
    proxy_set_header X-Forwarded-For \$remote_addr;
    proxy_set_header X-Forwarded-Proto https;
    proxy_read_timeout 900;
    proxy_request_buffering off;
    location / {
        include /etc/nginx/harbor/panel-access.conf;    # Security -> Panel access
        proxy_pass http://127.0.0.1:8090;
    }
    location /ddns/ {                                     # Dynamic DNS must work from anywhere
        proxy_pass http://127.0.0.1:8090;
    }
    location /hooks/ {                                    # Git push webhooks (secret in the address)
        client_max_body_size 6m;
        proxy_pass http://127.0.0.1:8090;
    }
    location = /dbadmin { return 301 /dbadmin/; }
    location = /dbadmin/ {                                # Databases tab -> Open (Adminer)
        include /etc/nginx/harbor/panel-access.conf;
        auth_request /internal/dbadmin-check;             # only people signed in to the panel
        error_page 401 = @dbadmin_signin;
        client_max_body_size 256m;
        fastcgi_read_timeout 300;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $APP/harbor/dbadmin/index.php;
        fastcgi_param SCRIPT_NAME /dbadmin/;
        fastcgi_param HTTPS on;
        fastcgi_pass unix:/run/php/harbor-dbadmin.sock;
    }
    location = /internal/dbadmin-check {
        internal;
        proxy_pass http://127.0.0.1:8090/dbadmin-check;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
    }
    location @dbadmin_signin { return 302 /login; }
    location = /import/upload {                           # cPanel backups can be many GB
        include /etc/nginx/harbor/panel-access.conf;
        client_max_body_size 0;
        proxy_read_timeout 3600;
        proxy_send_timeout 3600;
        proxy_pass http://127.0.0.1:8090;
    }
}
EOF
nginx -t && systemctl reload nginx

cat > /etc/logrotate.d/harbor <<'EOF'
/var/log/harbor/*.log {
    weekly
    rotate 8
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
/srv/harbor/sites/*/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
/var/log/nginx/modsec_audit.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    copytruncate
}
EOF

cat > /etc/systemd/system/harbor.service <<EOF
[Unit]
Description=Harbor hosting control panel
After=network.target nginx.service mariadb.service

[Service]
WorkingDirectory=$APP
EnvironmentFile=-/etc/harbor/harbor.env
ExecStart=$APP/venv/bin/python -m harbor serve
Restart=on-failure
RestartSec=3
UMask=0022

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable harbor
systemctl restart harbor
systemctl enable --now certbot.timer 2>/dev/null || true

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  say "Opening firewall ports"
  ufw allow OpenSSH; ufw allow 80/tcp; ufw allow 443/tcp; ufw allow "${PANEL_PORT}/tcp"
  [[ $WITH_DNS == 1 ]] && ufw allow 53
  [[ $WITH_MAIL == 1 ]] && for p in 25 465 587 993 995 143 110; do ufw allow "$p/tcp"; done
  [[ $WITH_WEBMAIL == 1 ]] && ufw allow 2096/tcp
fi

# ---------------------------------------------------------------- admin
cd "$APP"
"$APP/venv/bin/python" - "$HOST" <<'PY'
import sys
from harbor import db
db.init()
if not db.get_setting("hostname"):
    db.set_setting("hostname", sys.argv[1])
PY
PW_NOTE="(unchanged)"
if ! "$APP/venv/bin/python" -c "from harbor import db; db.init(); import sys; sys.exit(0 if db.one('SELECT 1 FROM users') else 1)"; then
  say "Creating admin account '$ADMIN_USER'"
  if [[ -t 0 ]]; then
    "$APP/venv/bin/python" -m harbor create-admin "$ADMIN_USER"
    PW_NOTE="(the password you just entered)"
  else
    PW="$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)"
    "$APP/venv/bin/python" -m harbor create-admin "$ADMIN_USER" --password "$PW" >/dev/null
    PW_NOTE="$PW"
  fi
fi

say "Applying site configuration (each site's PHP runs as its own service with limits)"
"$APP/venv/bin/python" -m harbor reconcile || warn "Some sites could not be updated; see the lines above"
"$APP/venv/bin/python" -c "import harbor; print(harbor.SYSTEM_VERSION)" > /etc/harbor/system_version

PANEL_UP=0
for i in $(seq 1 30); do
  if curl -fsS -o /dev/null http://127.0.0.1:8090/login; then PANEL_UP=1; break; fi
  sleep 1
done
[[ $PANEL_UP == 1 ]] || warn "The panel didn't start. See: journalctl -u harbor -n 50"

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
cat <<EOF

  Harbor is running.

  Panel:     https://${IP:-your-server-ip}:${PANEL_PORT}
  Username:  ${ADMIN_USER}
  Password:  ${PW_NOTE}

  Next: open Settings in the panel, check the host name ($HOST) and name servers,
  then click "Get certificate" to replace the self-signed certificate.
  Reset a password any time:  cd $APP && sudo venv/bin/python -m harbor create-admin ${ADMIN_USER}

EOF
