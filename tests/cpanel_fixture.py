"""Build realistic cPanel account backups for tests.

Layout follows cPanel's documented pkgacct format (cpmove-USER/ with homedir/,
mysql/, mysql.sql, userdata/, va/, dnszones/, cron/, cp/ …). `nested=True`
produces the older layout (homedir.tar inside, backup-DATE_USER/ root)."""
import hashlib
import io
import json
import subprocess
import tarfile
import time
from pathlib import Path

USER = "acme"
OLD_IP = "198.51.100.20"
WP_DB_PASS = "S3cret-wp-pass"
MAIL_PASS = "info-mail-pass-1"
SALES_PASS = "sales-mail-pass-1"


def native_hash(pw: str) -> str:
    return "*" + hashlib.sha1(hashlib.sha1(pw.encode()).digest()).hexdigest().upper()


def crypt(pw: str, kind: str) -> str:
    return subprocess.run(["openssl", "passwd", f"-{kind}", "-stdin"], input=pw, capture_output=True,
                          text=True, check=True).stdout.strip()


def message(subject: str, frm: str = "friend@example.org", to: str = "info@acme-old.com") -> bytes:
    return (f"From: {frm}\r\nTo: {to}\r\nSubject: {subject}\r\nDate: Mon, 12 Oct 2026 10:00:00 +0000\r\n"
            f"Message-ID: <{abs(hash(subject))}@example.org>\r\n\r\nHello from the old server: {subject}\r\n").encode()


WP_CONFIG = """<?php
define( 'DB_NAME', 'acme_wp' );
define( 'DB_USER', 'acme_wpuser' );
define( 'DB_PASSWORD', '%s' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_';
define( 'WP_TEMP_DIR', '/home/acme/public_html/wp-content/tmp' );
if ( ! defined( 'ABSPATH' ) ) { define( 'ABSPATH', __DIR__ . '/' ); }
""" % WP_DB_PASS

SHOP_CONFIG = """<?php
define( 'DB_NAME', 'acme_shop' );
define( 'DB_USER', 'acme_shopuser' );
define( 'DB_PASSWORD', 'old-unknown-password' );
define( 'DB_HOST', 'localhost' );
"""

DB_PAGE = """<?php
require __DIR__ . '/wp-config.php';
$db = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
if ($db->connect_errno) { http_response_code(500); echo 'DB ERROR ' . $db->connect_error; exit; }
$r = $db->query("SELECT option_value FROM wp_options WHERE option_name = 'blogname'")->fetch_row();
echo 'BLOG:' . $r[0] . '|TMP:' . WP_TEMP_DIR;
"""

HTACCESS = """# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
Redirect 301 /old-page /new-page
"""

ZONE = f"""; cPanel first:110.0.20 (update_time):1760000000
$TTL 14400
acme-old.com. 86400 IN SOA ns1.oldhost.example. admin.oldhost.example. 2026101201 3600 1800 1209600 86400
acme-old.com. 86400 IN NS ns1.oldhost.example.
acme-old.com. 86400 IN NS ns2.oldhost.example.
acme-old.com. 14400 IN A {OLD_IP}
www 14400 IN CNAME acme-old.com.
mail 14400 IN A {OLD_IP}
ftp 14400 IN A {OLD_IP}
cpanel 14400 IN A {OLD_IP}
webdisk 14400 IN A {OLD_IP}
_cpanel-dcv-test-record 300 IN TXT "_cpanel-dcv-test-record=abc"
acme-old.com. 14400 IN MX 0 mail.acme-old.com.
acme-old.com. 14400 IN TXT "v=spf1 +a +mx +ip4:{OLD_IP} ~all"
default._domainkey 14400 IN TXT "v=DKIM1; k=rsa; p=MIIBoldkey"
acme-old.com. 14400 IN CAA 0 issue "letsencrypt.org"
_sip._tcp 14400 IN SRV 10 5 5060 sip.example.org.
crm 3600 IN CNAME acme.crmprovider.example.
"""


def build(dest: Path, nested: bool = False) -> Path:
    files: dict[str, bytes] = {}
    links: dict[str, str] = {}
    h = {}  # homedir entries

    files["cp/acme"] = f"DNS=acme-old.com\nIP={OLD_IP}\nPLAN=business\nUSER={USER}\nOWNER=root\n".encode()
    files["userdata/main"] = b"""---
addon_domains:
  shop-old.net: shop.acme-old.com
cp_php_magic_include_path.conf: 0
main_domain: acme-old.com
parked_domains:
  - acme-old.org
sub_domains:
  - shop.acme-old.com
  - blog.acme-old.com
"""
    files["userdata/acme-old.com"] = b"documentroot: /home/acme/public_html\nphpversion: ea-php83\nservername: acme-old.com\nserveralias: www.acme-old.com mail.acme-old.com\n"
    files["userdata/shop.acme-old.com"] = b"documentroot: /home/acme/shop-old.net\nphpversion: ea-php74\nservername: shop.acme-old.com\n"
    files["userdata/blog.acme-old.com"] = b"documentroot: /home/acme/public_html/blog\nservername: blog.acme-old.com\n"
    files["version"] = b"pkgacct version: 10\narchive version: 4\n"
    files["mysql.sql"] = (
        f"GRANT USAGE ON *.* TO 'acme'@'localhost' IDENTIFIED BY PASSWORD '{native_hash('main-account')}';\n"
        f"GRANT ALL PRIVILEGES ON `acme\\_%`.* TO 'acme'@'localhost';\n"
        f"GRANT USAGE ON *.* TO 'acme_wpuser'@'localhost' IDENTIFIED BY PASSWORD '{native_hash(WP_DB_PASS)}';\n"
        f"GRANT ALL PRIVILEGES ON `acme\\_wp`.* TO 'acme_wpuser'@'localhost';\n"
        f"CREATE USER 'acme_shopuser'@'localhost' IDENTIFIED WITH 'caching_sha2_password' AS '$A$005$abcdefghijklmnopqrstuvwxyz0123456789ABCDEF';\n"
        f"GRANT ALL PRIVILEGES ON `acme\\_shop`.* TO `acme_shopuser`@`localhost`;\n"
        f"GRANT ALL PRIVILEGES ON `acme\\_wp`.* TO 'acme_wpuser'@'203.0.113.9';\n").encode()
    files["mysql/acme_wp.sql"] = b"""-- MySQL dump
CREATE TABLE `wp_options` (`option_id` bigint unsigned NOT NULL AUTO_INCREMENT, `option_name` varchar(191) NOT NULL,
  `option_value` longtext NOT NULL, PRIMARY KEY (`option_id`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
INSERT INTO `wp_options` VALUES (1,'blogname','Acme Coffee Roasters'),(2,'siteurl','https://acme-old.com');
"""
    files["mysql/acme_shop.sql"] = b"CREATE TABLE `orders` (`id` int PRIMARY KEY, `total` decimal(8,2));\nINSERT INTO `orders` VALUES (1, 42.50);\n"
    files["va/acme-old.com"] = (b"orders@acme-old.com: info@acme-old.com, boss@example.org\n"
                                b"pipe@acme-old.com: \"|/home/acme/bin/ticket.php\"\n"
                                b"*: info@acme-old.com\n")
    files["va/shop-old.net"] = b"*: :fail: No Such User Here\n"
    files["vf/acme-old.com"] = b""
    files["dnszones/acme-old.com.db"] = ZONE.encode()
    files["cron/acme"] = (b'MAILTO=""\nSHELL="/bin/bash"\n'
                          b"*/15 * * * * /usr/local/bin/php /home/acme/public_html/wp-cron.php >/dev/null 2>&1\n"
                          b"30 3 * * * /opt/cpanel/ea-php83/root/usr/bin/php /home/acme/public_html/cleanup.php\n")

    h["public_html/index.php"] = DB_PAGE.encode()
    h["public_html/wp-config.php"] = WP_CONFIG.encode()
    h["public_html/.htaccess"] = HTACCESS.encode()
    h["public_html/.user.ini"] = b"auto_prepend_file = '/home/acme/public_html/wordfence-waf.php'\n"
    h["public_html/wordfence-waf.php"] = b"<?php // firewall\n"
    h["public_html/wp-cron.php"] = b"<?php echo 'cron ran';\n"
    h["public_html/wp-content/uploads/2026/10/photo.jpg"] = b"\xff\xd8\xff" + b"0" * 5000
    h["public_html/blog/index.html"] = b"<h1>Acme blog</h1>"
    h["shop-old.net/index.php"] = (b"<?php require __DIR__.'/wp-config.php'; $db = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);"
                                   b" if ($db->connect_errno) { echo 'DB ERROR'; exit; }"
                                   b" echo 'TOTAL:' . $db->query('SELECT total FROM orders')->fetch_row()[0];\n")
    h["shop-old.net/wp-config.php"] = SHOP_CONFIG.encode()
    h["private/notes.txt"] = b"not in a website folder"
    h["etc/acme-old.com/passwd"] = (b"info:x:1001:1001::/home/acme/mail/acme-old.com/info:/bin/bash\n"
                                    b"sales:x:1001:1001::/home/acme/mail/acme-old.com/sales:/bin/bash\n")
    h["etc/acme-old.com/shadow"] = (f"info:{crypt(MAIL_PASS, '6')}:19000::::::\n"
                                    f"sales:{crypt(SALES_PASS, '1')}:19000::::::\n").encode()
    h["etc/acme-old.com/quota"] = b"info:1073741824\nsales:0\n"
    welcome, order = message("Welcome to Acme"), message("Order #1001")
    h[f"mail/acme-old.com/info/cur/1600000000.M1P1.oldhost,S={len(welcome)}:2,S"] = welcome
    h["mail/acme-old.com/info/cur/1600000001.M1P1.oldhost,S=300,W=310:2,S"] = order  # wrong size hint
    h["mail/acme-old.com/info/new/1600000099.M9P9.oldhost"] = message("Unread invoice")
    h["mail/acme-old.com/info/.Sent/cur/1600000050.M5P5.oldhost:2,S"] = message("Re: hello", "info@acme-old.com", "friend@example.org")
    h["mail/acme-old.com/info/maildirsize"] = b"1073741824S\n1200 3\n"
    h["mail/acme-old.com/info/dovecot-uidlist"] = b"3 V1600000000 N4\n"
    h["mail/acme-old.com/info/dovecot.index"] = b"stale-index"
    h["mail/acme-old.com/info/tmp/.keep"] = b""
    h["mail/acme-old.com/sales/cur/1600000100.M1P1.oldhost:2,S"] = message("Wholesale enquiry", to="sales@acme-old.com")
    h[".autorespond/sales@acme-old.com"] = b"From: \"Sales\" <sales@acme-old.com>\nSubject: We got your message\nCharset: utf-8\n\nThanks, we'll reply within a day.\n"
    h[".autorespond/sales@acme-old.com.json"] = json.dumps({"interval": 48, "start": 0, "stop": None}).encode()
    links["public_html/escape"] = "/etc/passwd"

    root = f"backup-10.13.2026_10-00-00_{USER}" if nested else f"cpmove-{USER}"
    out = dest / f"{root}.tar.gz"
    now = time.time()

    def add(tar, name, data, mode=0o644):
        info = tarfile.TarInfo(name)
        info.size, info.mtime, info.mode = len(data), now, mode
        tar.addfile(info, io.BytesIO(data))

    def add_link(tar, name, target):
        info = tarfile.TarInfo(name)
        info.type, info.linkname, info.mtime = tarfile.SYMTYPE, target, now
        tar.addfile(info)

    def home_tar() -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            for name, data in h.items():
                add(t, name, data)
            for name, target in links.items():
                add_link(t, name, target)
        return buf.getvalue()

    with tarfile.open(out, "w:gz") as tar:
        for name, data in files.items():
            add(tar, f"{root}/{name}", data)
        if nested:
            add(tar, f"{root}/homedir.tar", home_tar())
        else:
            for name, data in h.items():
                add(tar, f"{root}/homedir/{name}", data)
            for name, target in links.items():
                add_link(tar, f"{root}/homedir/{name}", target)
    return out
