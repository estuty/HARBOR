#!/usr/bin/env python3
# Usage on a real Harbor server (as root):  python3 run_live.py <admin-password>
# Needs: pip install httpx paramiko; apt install bind9-dnsutils. Creates and then deletes the site itest.example.
"""Live integration test against a real Harbor install (nginx, PHP-FPM, MariaDB,
BIND, Postfix, Dovecot, Rspamd, ModSecurity) on this machine."""
import base64
import email
import imaplib
import re
import smtplib
import ssl
import subprocess
import sys
import time

import httpx

PANEL = "https://127.0.0.1:8443"
PW = sys.argv[1]
DOMAIN = "itest.example"
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def sh(cmd, inp=None):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, input=inp)
    return (r.stdout + r.stderr).strip()


c = httpx.Client(base_url=PANEL, verify=False, follow_redirects=False, timeout=600)


def csrf(page):
    return re.search(r'name="csrf" value="([^"]+)"', c.get(page).text).group(1)


def post(url, data=None, page="/account", files=None):
    d = dict(data or {}, csrf=csrf(page))
    r = c.post(url, data=d, files=files)
    time.sleep(0.7)  # nginx reload is asynchronous: give new workers a moment
    loc = r.headers.get("location")
    if r.status_code == 303 and loc and not loc.startswith("http"):
        import html as _h
        page_html = c.get(loc).text
        r.page = page_html
        errs = re.findall(r'class="flash error"[^>]*>([^<]*)<', page_html)
        for e in errs:
            print(f"   ! {url}: {_h.unescape(e)[:300]}")
        r.harbor_errors = errs
    return r


def flash(page):
    import html
    t = c.get(page).text
    return html.unescape(" ".join(re.findall(r'class="flash[^"]*"[^>]*>([^<]*)<', t))), t


def web(path, host=DOMAIN, **kw):
    return httpx.get(f"http://127.0.0.1{path}", headers={"Host": host, **kw.pop("headers", {})},
                     follow_redirects=False, timeout=30, **kw)


for _ in range(30):
    try:
        if c.get("/login").status_code == 200: break
    except Exception: pass
    time.sleep(1)
r = post("/login", {"username": "admin", "password": PW}, page="/login")
check("login", r.status_code == 303 and r.headers["location"] == "/", r.text[:200])

# server settings
post("/settings", {"hostname": "mail.harbor-test.local", "ns1": "ns1.harbor-test.local", "ns2": "ns2.harbor-test.local",
                   "server_ipv4": "192.0.2.2", "hostmaster": "hostmaster@harbor-test.local", "dns_auto_zone": "1"},
     page="/settings")

# ---------- site ----------
existing = re.search(rf'href="/sites/(\d+)">{re.escape(DOMAIN)}<', c.get("/sites").text)
if existing:
    sid = existing.group(1)
    post(f"/sites/{sid}/delete", {"confirm": DOMAIN, "remove_files": "1", "drop_dbs": "1"}, page=f"/sites/{sid}")
r = post("/sites", {"domain": DOMAIN, "php_version": "8.3", "include_www": "1"}, page="/sites")
check("create site", r.status_code == 303 and "/sites/" in r.headers.get("location", ""), flash("/sites")[0])
sid = r.headers["location"].rsplit("/", 1)[1]
SP = f"/sites/{sid}"
user = f"site{sid}"
check("linux user created", sh(f"id -u {user}").isdigit(), sh(f"id {user}"))
check("welcome page served by nginx", DOMAIN in web("/").text, web("/").status_code)
check("www alias served", web("/", host=f"www.{DOMAIN}").status_code == 200)

# PHP runs as the site user, in its own pool
post(f"{SP}/files/op", {"op": "newfile", "dir": "public", "name": "who.php"}, page=SP)
post(f"{SP}/files/save", {"path": "public/who.php",
                         "content": "<?php echo posix_getpwuid(posix_geteuid())['name'], '|', ini_get('memory_limit'), '|', ini_get('open_basedir');"},
     page=SP)
out = web("/who.php").text
check("PHP runs as site user", out.startswith(user + "|"), out[:200])
check("open_basedir confines PHP", f"/srv/harbor/sites/{DOMAIN}/" in out, out)
leak = None
post(f"{SP}/files/op", {"op": "newfile", "dir": "public", "name": "leak.php"}, page=SP)
post(f"{SP}/files/save", {"path": "public/leak.php", "content": "<?php var_dump(@file_get_contents('/etc/shadow'));"}, page=SP)
check("PHP can't read /etc/shadow", "bool(false)" in web("/leak.php").text, web("/leak.php").text[:200])

# PHP INI editor
form = {"memory_limit": "384M", "upload_max_filesize": "100M", "post_max_size": "100M", "max_execution_time": "90",
        "max_input_time": "60", "max_input_vars": "3000", "session.gc_maxlifetime": "1440", "date.timezone": "Europe/Paris",
        "display_errors": "Off", "short_open_tag": "Off", "allow_url_fopen": "On"}
post(f"{SP}/php/ini", form, page=f"{SP}/php")
check("php.ini override applied", "|384M|" in web("/who.php").text, web("/who.php").text)

# DNS
time.sleep(1)
dig = sh(f"dig +short @127.0.0.1 {DOMAIN} A")
check("DNS zone answers (A)", "192.0.2.2" in dig, dig)
check("DNS MX record (server host name)", "mail.harbor-test.local." in sh(f"dig +short @127.0.0.1 {DOMAIN} MX"), sh(f"dig +short @127.0.0.1 {DOMAIN} MX"))
check("DNS NS uses settings", "ns1.harbor-test.local." in sh(f"dig +short @127.0.0.1 {DOMAIN} NS"), sh(f"dig +short @127.0.0.1 {DOMAIN} NS"))
check("BIND is not an open resolver", "REFUSED" in sh("dig @127.0.0.1 example.com A") or sh("dig +short @127.0.0.1 example.com A") == "",
      sh("dig @127.0.0.1 example.com A | head -5"))
zid = re.search(r'href="/dns/(\d+)">' + re.escape(DOMAIN), c.get("/dns").text).group(1)
post(f"/dns/{zid}/records", {"name": "api", "type": "A", "content": "198.51.100.20", "ttl": "300"}, page=f"/dns/{zid}")
check("DNS record added live", sh(f"dig +short @127.0.0.1 api.{DOMAIN} A") == "198.51.100.20", sh(f"dig +short @127.0.0.1 api.{DOMAIN} A"))
# Dynamic DNS
rr = post(f"/dns/{zid}/ddns", {"name": "home"}, page=f"/dns/{zid}")
tok = re.search(r"token=([A-Za-z0-9_\-]{20,})", rr.page)
if tok:
    r = httpx.get(f"{PANEL}/ddns/update?token={tok.group(1)}&ip=203.0.113.50", verify=False)
    check("Dynamic DNS update", r.text == "good 203.0.113.50" and sh(f"dig +short @127.0.0.1 home.{DOMAIN}") == "203.0.113.50", r.text)
else:
    check("Dynamic DNS token shown", False)

# Redirects, error pages, indexes
post(f"{SP}/redirects", {"source": "/old", "target": "/who.php", "code": "301", "match": "exact"}, page=f"{SP}/redirects")
post(f"{SP}/redirects", {"source": "/blog", "target": "https://news.example.net/", "code": "302", "match": "prefix"}, page=f"{SP}/redirects")
r = web("/old")
check("exact redirect", r.status_code == 301 and r.headers["location"].endswith("/who.php"), (r.status_code, r.headers.get("location")))
r = web("/blog/hello-world")
check("prefix redirect keeps path", r.status_code == 302 and r.headers["location"] == "https://news.example.net/hello-world",
      (r.status_code, r.headers.get("location")))
post(f"{SP}/canonical", {"canonical": "bare"}, page=f"{SP}/redirects")
r = web("/x", host=f"www.{DOMAIN}")
check("www → bare canonical", r.status_code == 301 and r.headers["location"] == f"http://{DOMAIN}/x", r.headers.get("location"))
post(f"{SP}/advanced/errors", {"code": "404", "content": "<h1>Harbor custom 404</h1>", "enabled": "1"}, page=f"{SP}/advanced")
r = web("/does-not-exist.html")
check("custom 404 page", r.status_code == 404 and "Harbor custom 404" in r.text, (r.status_code, r.text[:100]))
r = web("/missing.php")
check("custom 404 for missing PHP", r.status_code == 404 and "Harbor custom 404" in r.text, (r.status_code, r.text[:100]))
post(f"{SP}/files/op", {"op": "mkdir", "dir": "public", "name": "downloads"}, page=SP)
post(f"{SP}/files/upload", {"dir": "public/downloads"}, files={"files": ("readme.txt", b"hi", "text/plain")}, page=SP)
check("no directory listing by default", web("/downloads/").status_code in (403, 404))
post(f"{SP}/advanced/indexes", {"path": "/downloads/", "enabled": "1"}, page=f"{SP}/advanced")
check("directory listing on", "readme.txt" in web("/downloads/").text, web("/downloads/").status_code)

# Directory privacy (including PHP inside the folder)
post(f"{SP}/files/op", {"op": "mkdir", "dir": "public", "name": "admin"}, page=SP)
post(f"{SP}/files/op", {"op": "newfile", "dir": "public/admin", "name": "index.php"}, page=SP)
post(f"{SP}/files/save", {"path": "public/admin/index.php", "content": "<?php echo 'secret-area';"}, page=SP)
post(f"{SP}/security/dirs", {"path": "/admin/", "realm": "Staff", "username": "boss", "password": "boss-pass-123"}, page=f"{SP}/security")
check("protected folder asks for login", web("/admin/").status_code == 401, web("/admin/").status_code)
check("protected PHP file asks for login", web("/admin/index.php").status_code == 401, web("/admin/index.php").status_code)
auth = "Basic " + base64.b64encode(b"boss:boss-pass-123").decode()
r = web("/admin/", headers={"Authorization": auth})
check("correct login opens protected PHP", r.status_code == 200 and r.text == "secret-area", (r.status_code, r.text[:80]))
bad = "Basic " + base64.b64encode(b"boss:wrong").decode()
check("wrong password rejected", web("/admin/", headers={"Authorization": bad}).status_code == 401)

# Hotlink protection
open_img = f"/srv/harbor/sites/{DOMAIN}/public/pic.png"
sh(f"printf 'PNG' > {open_img} && chown {user}:{user} {open_img}")
post(f"{SP}/security/hotlink", {"enabled": "1", "exts": "png, jpg", "allowed": "friend.example"}, page=f"{SP}/security")
check("hotlink: direct access ok", web("/pic.png").status_code == 200)
check("hotlink: own pages ok", web("/pic.png", headers={"Referer": f"http://{DOMAIN}/page"}).status_code == 200)
check("hotlink: allowed site ok", web("/pic.png", headers={"Referer": "https://friend.example/x"}).status_code == 200)
check("hotlink: other site blocked", web("/pic.png", headers={"Referer": "https://evil.example/x"}).status_code == 403)

# IP blocker
post(f"{SP}/security/ip", {"ips": "127.0.0.1"}, page=f"{SP}/security")
check("IP blocker denies", web("/").status_code == 403, web("/").status_code)
post(f"{SP}/security/ip/unblock", {"ip": "127.0.0.1/32"}, page=f"{SP}/security")
check("IP unblock", web("/").status_code == 200)

# ModSecurity
post(f"{SP}/security/modsec", {"mode": "on", "disabled_rules": ""}, page=f"{SP}/security")
attack = "/who.php?id=1%27%20OR%201%3D1--"
check("ModSecurity blocks SQL injection", web(attack).status_code == 403, web(attack).status_code)
check("ModSecurity allows normal request", web("/who.php?id=42").status_code == 200)
time.sleep(1)
check("ModSecurity hit shown in panel", "SQL Injection" in c.get(f"{SP}/security").text)
post(f"{SP}/security/modsec", {"mode": "detect", "disabled_rules": ""}, page=f"{SP}/security")
check("ModSecurity detect-only lets it through", web(attack).status_code == 200, web(attack).status_code)
post(f"{SP}/security/modsec", {"mode": "on", "disabled_rules": "942100"}, page=f"{SP}/security")
r942 = web("/who.php?id=1%27%20OR%201%3D1--").status_code
print("   (status with rule 942100 removed:", r942, ")")
post(f"{SP}/security/modsec", {"mode": "off", "disabled_rules": ""}, page=f"{SP}/security")
check("ModSecurity off", web(attack).status_code == 200)

# Databases
t = post(f"{SP}/databases", {"name": "shop"}, page=f"{SP}/databases").page
m = re.search(r'Password</dt><dd><code class="wrap">([A-Za-z0-9]+)</code>', t)
dbname = f"{user}_shop"
check("database created", m is not None and dbname in t)
if m:
    out = sh(f"mysql -u {dbname} -p{m.group(1)} -h localhost -e 'CREATE TABLE t (id int); INSERT INTO t VALUES (7); SELECT * FROM t;' {dbname}")
    check("database user can log in and write", out.strip().endswith("7"), out)
    out = sh(f"mysql -u {dbname} -p{m.group(1)} -e 'SHOW DATABASES' 2>&1")
    check("database user sees only its own db", "mysql" not in out.split() and dbname in out, out)

# Cron
post(f"{SP}/cron", {"schedule": "*/5 * * * *", "command": "echo hi"}, page=f"{SP}/cron")
check("crontab installed for site user", "*/5 * * * * echo hi" in sh(f"crontab -u {user} -l"), sh(f"crontab -u {user} -l"))

# SFTP (chroot)
sh("/etc/init.d/ssh start")
post(f"{SP}/sftp", {"password": "sftp-password-123"}, page=SP)
try:
    import paramiko
    t = paramiko.Transport(("127.0.0.1", 22)); t.connect(username=user, password="sftp-password-123")
    sftp = paramiko.SFTPClient.from_transport(t)
    listing = sftp.listdir("/")
    check("SFTP login, chrooted to site folder", set(["public", "logs", "tmp"]) <= set(listing), listing)
    try:
        sftp.listdir("/etc")
        check("SFTP can't leave chroot", False, "listed /etc")
    except IOError:
        check("SFTP can't leave chroot", True)
    with sftp.open("/public/sftp.txt", "w") as f:
        f.write("uploaded via sftp")
    check("SFTP upload served", web("/sftp.txt").text == "uploaded via sftp")
    t.close()
except Exception as e:
    check("SFTP login", False, repr(e))
try:
    t = paramiko.SSHClient(); t.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    t.connect("127.0.0.1", username=user, password="sftp-password-123", allow_agent=False, look_for_keys=False)
    _, out, _ = t.exec_command("id")
    got = out.read().decode()
    check("no shell access for site user", "uid=" not in got, got)
except Exception as e:
    check("no shell access for site user", True)

# Backups & restore (real tar + mysqldump)
post(f"{SP}/backups", page=f"{SP}/backups")
for _ in range(30):
    if "Backing up" not in c.get(f"{SP}/backups").text:
        break
    time.sleep(1)
t = c.get(f"{SP}/backups").text
bid = re.search(r'/backups/(\d+)/download', t)
check("backup created", bid is not None, t[:300])
if bid and m:
    sh(f"mysql {dbname} -e 'DELETE FROM t'")
    sh(f"rm /srv/harbor/sites/{DOMAIN}/public/sftp.txt")
    post(f"{SP}/backups/{bid.group(1)}/restore", {"files": "1", "dbs": dbname}, page=f"{SP}/backups")
    for _ in range(30):
        if "Restoring" not in c.get(f"{SP}/backups").text:
            break
        time.sleep(1)
    check("restore brought DB rows back", sh(f"mysql -N {dbname} -e 'SELECT * FROM t'") == "7", sh(f"mysql -N {dbname} -e 'SELECT * FROM t'"))
    check("restore brought files back", web("/sftp.txt").text == "uploaded via sftp")
    check("restored files owned by site user", sh(f"stat -c %U /srv/harbor/sites/{DOMAIN}/public/sftp.txt") == user)

# Stats
for p in ("/", "/who.php", "/downloads/"):
    web(p, headers={"User-Agent": "Mozilla/5.0", "Referer": "https://search.example/q"})
st = c.get(f"{SP}/stats").text
check("stats page shows traffic", "search.example" in st and "/who.php" in st)

# ---------- email ----------
post(f"{SP}/mail/enable", page=f"{SP}/mail")
check("DKIM key generated", "_domainkey" in c.get(f"{SP}/mail").text)
dkim = sh(f"dig +short @127.0.0.1 harbor._domainkey.{DOMAIN} TXT")
check("DKIM record published in DNS", "v=DKIM1" in dkim, dkim[:120])
post(f"{SP}/mail/boxes", {"local": "alice", "password": "alice-mail-pass", "quota": "1024"}, page=f"{SP}/mail")
post(f"{SP}/mail/boxes", {"local": "bob", "password": "bob-mail-pass1", "quota": "1024"}, page=f"{SP}/mail")
post(f"{SP}/mail/forwarders", {"local": "sales", "destinations": f"bob@{DOMAIN}"}, page=f"{SP}/mail")
time.sleep(1)


def imap_count(user_, pw, folder="INBOX"):
    im = imaplib.IMAP4_SSL("127.0.0.1", 993, ssl_context=ssl._create_unverified_context())
    im.login(user_, pw)
    im.select(folder)
    _, data = im.search(None, "ALL")
    ids = data[0].split()
    msgs = []
    for i in ids:
        _, d = im.fetch(i, "(RFC822)")
        msgs.append(email.message_from_bytes(d[0][1]))
    im.logout()
    return msgs


def wait_for(user_, pw, n, folder="INBOX"):
    for _ in range(20):
        try:
            ms = imap_count(user_, pw, folder)
            if len(ms) >= n:
                return ms
        except Exception:
            pass
        time.sleep(1)
    return imap_count(user_, pw, folder)


# inbound SMTP on port 25 (as from the internet)
s = smtplib.SMTP("127.0.0.1", 25); s.ehlo("sender.example")
s.sendmail("someone@sender.example", [f"alice@{DOMAIN}"], f"From: someone@sender.example\r\nTo: alice@{DOMAIN}\r\nSubject: hello alice\r\n\r\nHi!\r\n")
s.quit()
ms = wait_for(f"alice@{DOMAIN}", "alice-mail-pass", 1)
check("inbound mail delivered to mailbox (IMAP 993)", any(x["Subject"] == "hello alice" for x in ms), [x["Subject"] for x in ms])
# relay attempt must be refused
try:
    s = smtplib.SMTP("192.0.2.2", 25); s.ehlo("x")  # non-local address, like a stranger on the internet
    s.sendmail("a@sender.example", ["victim@gmail.com"], "Subject: spam\r\n\r\nx")
    check("open relay refused", False, "relay accepted")
except smtplib.SMTPRecipientsRefused:
    check("open relay refused", True)
finally:
    try: s.quit()
    except Exception: pass
# unknown address bounces (no catch-all)
try:
    s = smtplib.SMTP("127.0.0.1", 25); s.ehlo("x")
    s.sendmail("a@sender.example", [f"nobody@{DOMAIN}"], "Subject: x\r\n\r\nx")
    check("unknown address rejected", False)
except smtplib.SMTPRecipientsRefused:
    check("unknown address rejected", True)
finally:
    try: s.quit()
    except Exception: pass

# authenticated submission (587 STARTTLS) from bob to alice, signed with DKIM
s = smtplib.SMTP("127.0.0.1", 587); s.ehlo("client"); s.starttls(context=ssl._create_unverified_context()); s.ehlo("client")
s.login(f"bob@{DOMAIN}", "bob-mail-pass1")
s.sendmail(f"bob@{DOMAIN}", [f"alice@{DOMAIN}"], f"From: bob@{DOMAIN}\r\nTo: alice@{DOMAIN}\r\nSubject: from bob\r\nDate: {email.utils.formatdate()}\r\nMessage-ID: <{time.time()}@{DOMAIN}>\r\n\r\nSigned?\r\n")
s.quit()
ms = wait_for(f"alice@{DOMAIN}", "alice-mail-pass", 2)
fb = [x for x in ms if x["Subject"] == "from bob"]
check("SMTP submission (587) works", bool(fb))
check("outgoing mail DKIM-signed", bool(fb) and "d=" + DOMAIN in (fb[0].get("DKIM-Signature") or ""), fb[0].get("DKIM-Signature") if fb else None)
# sender spoofing blocked
try:
    s = smtplib.SMTP_SSL("127.0.0.1", 465, context=ssl._create_unverified_context()); s.login(f"bob@{DOMAIN}", "bob-mail-pass1")
    s.sendmail(f"alice@{DOMAIN}", [f"alice@{DOMAIN}"], "Subject: spoof\r\n\r\nx")
    check("sender spoofing blocked (465)", False, "accepted")
except smtplib.SMTPException:
    check("sender spoofing blocked (465)", True)
# forwarder
s = smtplib.SMTP("127.0.0.1", 25); s.ehlo("x")
s.sendmail("c@sender.example", [f"sales@{DOMAIN}"], f"Subject: to sales\r\n\r\nx")
s.quit()
ms = wait_for(f"bob@{DOMAIN}", "bob-mail-pass1", 1)
check("forwarder delivers to bob", any(x["Subject"] == "to sales" for x in ms))
# autoresponder: bob turns it on, alice writes, alice gets the reply
box_bob = re.search(r'href="/sites/\d+/mail/boxes/(\d+)">bob@', c.get(f"{SP}/mail").text).group(1)
post(f"{SP}/mail/boxes/{box_bob}/autoresponder", {"enabled": "1", "subject": "Bob is away", "body": "Back soon.", "days": "1"},
     page=f"{SP}/mail/boxes/{box_bob}")
s = smtplib.SMTP("127.0.0.1", 587); s.ehlo("c"); s.starttls(context=ssl._create_unverified_context()); s.ehlo("c")
s.login(f"alice@{DOMAIN}", "alice-mail-pass")
s.sendmail(f"alice@{DOMAIN}", [f"bob@{DOMAIN}"], f"From: alice@{DOMAIN}\r\nTo: bob@{DOMAIN}\r\nSubject: are you there\r\nMessage-ID: <q{time.time()}@{DOMAIN}>\r\n\r\n?\r\n")
s.quit()
ms = wait_for(f"alice@{DOMAIN}", "alice-mail-pass", 3)
check("autoresponder reply received", any("Bob is away" in (x["Subject"] or "") for x in ms), [x["Subject"] for x in ms])
# suspended login
box_alice = re.search(r'href="/sites/\d+/mail/boxes/(\d+)">alice@', c.get(f"{SP}/mail").text).group(1)
post(f"{SP}/mail/boxes/{box_alice}/update", {"enabled": "0", "quota": "1024"}, page=f"{SP}/mail/boxes/{box_alice}")
try:
    imap_count(f"alice@{DOMAIN}", "alice-mail-pass")
    check("suspended mailbox can't log in", False)
except imaplib.IMAP4.error:
    check("suspended mailbox can't log in", True)
post(f"{SP}/mail/boxes/{box_alice}/update", {"enabled": "1", "quota": "1024"}, page=f"{SP}/mail/boxes/{box_alice}")
check("quota usage shown", "of 1024 MB" in c.get(f"{SP}/mail").text)
# webmail login page works
r = httpx.get("https://127.0.0.1:2096/", verify=False)
check("Roundcube webmail loads", r.status_code == 200 and "roundcube" in r.text.lower(), r.status_code)
# catch-all
post(f"{SP}/mail/catchall", {"mode": "forward", "target": f"bob@{DOMAIN}"}, page=f"{SP}/mail")
s = smtplib.SMTP("127.0.0.1", 25); s.ehlo("x")
s.sendmail("d@sender.example", [f"anything@{DOMAIN}"], "Subject: catchall test\r\n\r\nx")
s.quit()
ms = wait_for(f"bob@{DOMAIN}", "bob-mail-pass1", 3)
check("catch-all delivers", any(x["Subject"] == "catchall test" for x in ms))

# ---------- API ----------
tok = re.search(r'data-copy="(hbr_[^"]+)"', post("/account/tokens", {"name": "itest"}).page).group(1)
r = httpx.get(f"{PANEL}/api/v1/sites", headers={"Authorization": f"Bearer {tok}"}, verify=False)
check("API lists sites", any(s_["domain"] == DOMAIN for s_ in r.json()["sites"]), r.text[:200])

# ---------- WordPress (needs internet access to wordpress.org) ----------
post(f"{SP}/apps/wordpress", {"subdir": "blog", "title": "Test Blog", "admin_user": "wpadmin",
                              "admin_email": f"alice@{DOMAIN}", "admin_pass": "wp-admin-pass-123"}, page=f"{SP}/apps")
for _ in range(120):
    t = c.get(f"{SP}/apps").text
    if "Installing" not in t:
        break
    time.sleep(2)
installed = "pill ok\">Installed" in t
err = re.search(r'pill bad">Failed</span>\s*<div class="muted small">([^<]*)', t)
print("   WordPress:", "installed" if installed else ("failed: " + (err.group(1)[:300] if err else "?")))
if installed:
    r = web("/blog/")
    check("WordPress front page served", r.status_code == 200 and "Test Blog" in r.text, r.status_code)
    check("WordPress files owned by site user", sh(f"stat -c %U /srv/harbor/sites/{DOMAIN}/public/blog/wp-config.php") == user)

# Site Publisher on a second site
r = post("/sites", {"domain": "publish.example", "php_version": "8.3", "include_www": "1"}, page="/sites")
if r.status_code == 303 and "/sites/" in r.headers.get("location", ""):
    sid2 = r.headers["location"].rsplit("/", 1)[1]
    post(f"/sites/{sid2}/publisher", {"template": "business", "title": "Corner Bakery", "tagline": "Fresh bread daily",
                                      "email": "hi@publish.example", "accent": "#b4532a", "services": "Bread\nCakes"},
         page=f"/sites/{sid2}/apps")
    check("Site Publisher page live", "Fresh bread daily" in web("/", host="publish.example").text)
    post(f"/sites/{sid2}/delete", {"confirm": "publish.example", "remove_files": "1", "drop_dbs": "1"}, page=f"/sites/{sid2}")

# ---------- team user ----------
post("/users", {"username": "jane", "password": "jane-password-12", "role": "user", "sites": sid}, page="/users")
j = httpx.Client(base_url=PANEL, verify=False, follow_redirects=False)
tk = re.search(r'name="csrf" value="([^"]+)"', j.get("/login").text).group(1)
j.post("/login", data={"username": "jane", "password": "jane-password-12", "csrf": tk})
check("team user sees their site", DOMAIN in j.get("/sites").text)
check("team user blocked from settings", j.get("/settings").status_code == 403)
uid = re.search(r'action="/users/(\d+)/delete" data-confirm="Delete user jane', c.get("/users").text).group(1)
post(f"/users/{uid}/delete", page="/users")

# ---------- delete site cleans up ----------
post(f"{SP}/delete", {"confirm": DOMAIN, "remove_files": "1", "drop_dbs": "1"}, page=SP)
time.sleep(1)
check("site deleted: user gone", "no such user" in sh(f"id {user}"), sh(f"id {user}"))
check("site deleted: vhost gone", web("/").status_code != 200 or DOMAIN not in web("/").text)
check("site deleted: database dropped", dbname not in sh("mysql -N -e 'SHOW DATABASES'"))
check("site deleted: DNS zone gone", sh(f"dig +short @127.0.0.1 {DOMAIN} A") == "")
check("site deleted: mail domain gone", DOMAIN not in open("/etc/postfix/harbor/vdomains").read())

ok = sum(1 for _, r in results if r)
print(f"\n{ok}/{len(results)} checks passed")
