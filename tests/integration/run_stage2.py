#!/usr/bin/env python3
"""Live checks for stage 2 on a real Harbor server (run as root):
move a realistic cPanel account (both backup layouts) and check that the sites,
databases (original passwords), mailboxes (original passwords and mail),
forwarders, catch-all, autoresponder, DNS and cron all work; plus the health page.

    python3 run_stage2.py <admin-password> [flat|nested]
"""
import email
import imaplib
import os
import re
import smtplib
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

for _v in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY", "all_proxy"):
    os.environ.pop(_v, None)

import httpx  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import cpanel_fixture as fx  # noqa: E402

PANEL = "https://127.0.0.1:8443"
PW = sys.argv[1]
LAYOUT = sys.argv[2] if len(sys.argv) > 2 else "flat"
DOMAINS = ["acme-old.com", "shop-old.net", "blog.acme-old.com", "acme-old.org"]
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:600]}"), flush=True)


def sh(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


class Panel:
    def __init__(self):
        self.c = httpx.Client(base_url=PANEL, verify=False, follow_redirects=False, timeout=300)

    def csrf(self, page):
        return re.search(r'name="csrf" value="([^"]+)"', self.c.get(page).text).group(1)

    def post(self, url, data=None, page="/account"):
        r = self.c.post(url, data=dict(data or {}, csrf=self.csrf(page)))
        loc = r.headers.get("location", "")
        if r.status_code == 303 and loc.startswith("/"):
            for e in re.findall(r'class="flash error"[^>]*>([^<]*)<', self.c.get(loc).text):
                print("   !", url, e[:300])
        return r


def web(path, host, **kw):
    return httpx.get(f"http://127.0.0.1{path}", headers={"Host": host}, timeout=60, **kw)


def imap(user, pw, folder="INBOX"):
    im = imaplib.IMAP4_SSL("127.0.0.1", 993, ssl_context=ssl._create_unverified_context())
    im.login(user, pw)
    _, boxes = im.list()
    typ, _ = im.select(folder)
    msgs = []
    if typ == "OK":
        _, data = im.search(None, "ALL")
        for i in data[0].split():
            _, d = im.fetch(i, "(RFC822)")
            msgs.append(email.message_from_bytes(d[0][1]))
    im.logout()
    return msgs, [b.decode() for b in boxes]


def wait_subject(user, pw, subject, folder="INBOX"):
    for _ in range(25):
        try:
            msgs, _ = imap(user, pw, folder)
            if any(m["Subject"] == subject for m in msgs):
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


p = Panel()
r = p.post("/login", {"username": "admin", "password": PW}, page="/login")
check("login", r.status_code == 303 and r.headers["location"] != "/login", r.headers)

# ---------- clean slate ----------
sites_html = p.c.get("/sites").text
for d in DOMAINS:
    m = re.search(rf'href="/sites/(\d+)">{re.escape(d)}<', sites_html)
    if m:
        p.post(f"/sites/{m.group(1)}/delete", {"confirm": d, "remove_files": "1", "drop_dbs": "1"}, page="/sites")
for u in ("acme_wpuser", "acme_shopuser"):
    sh(f"mysql -e \"DROP USER IF EXISTS '{u}'@'localhost'\"")
for d in ("acme_wp", "acme_shop"):
    sh(f"mysql -e 'DROP DATABASE IF EXISTS `{d}`'")

# ---------- upload through nginx (streamed PUT) ----------
work = Path(tempfile.mkdtemp())
backup = fx.build(work, nested=(LAYOUT == "nested"))
check("nginx allows big uploads for imports", "client_max_body_size 0" in Path("/etc/nginx/conf.d/harbor-panel.conf").read_text())
tok = p.csrf("/import")


def chunks():
    with open(backup, "rb") as f:
        while b := f.read(4096):
            yield b


r = p.c.put(f"/import/upload?name={backup.name}", content=chunks(), headers={"x-csrf-token": tok})
check("backup uploaded", r.status_code == 200 and "id" in r.json(), r.text)
iid = r.json()["id"]
for _ in range(60):
    st = p.c.get(f"/import/{iid}/status").json()
    if st["status"] != "scanning":
        break
    time.sleep(0.5)
check("backup read and plan built", st["status"] == "ready", st)
page = p.c.get(f"/import/{iid}").text
check("plan lists domains, databases and mailboxes",
      all(x in page for x in DOMAINS + ["acme_wp", "acme_shop", "info@acme-old.com", "sales@acme-old.com"]), page[:2000])

# ---------- run ----------
form = {"csrf": p.csrf(f"/import/{iid}"), "databases": "1", "mail": "1", "dns": "1", "repoint": "1", "cron": "1",
        "domains": DOMAINS}
r = p.c.post(f"/import/{iid}/run", data=form)
check("import started", r.status_code == 303, r.status_code)
t0 = time.time()
while time.time() - t0 < 300:
    st = p.c.get(f"/import/{iid}/status").json()
    if st["status"] in ("done", "failed_run"):
        break
    time.sleep(1)
check("import finished", st["status"] == "done", st)
print("   import took", round(time.time() - t0, 1), "s")
page = p.c.get(f"/import/{iid}").text
print("\n".join("   | " + l for l in st["log"].splitlines()[-12:]))

# ---------- websites ----------
r = web("/", "acme-old.com")
check("WordPress-like site works with its ORIGINAL database password",
      r.status_code == 200 and "BLOG:Acme Coffee Roasters" in r.text, (r.status_code, r.text[:300]))
check("paths in wp-config rewritten to the new home", "|TMP:/srv/harbor/sites/acme-old.com/public/wp-content/tmp" in r.text, r.text[:300])
r = web("/", "shop-old.net")
check("second app's database (unportable hash) works with the new password written into its config",
      r.status_code == 200 and "TOTAL:42.50" in r.text, (r.status_code, r.text[:300]))
r = web("/", "blog.acme-old.com")
check("subdomain site serves its folder", "Acme blog" in r.text, r.text[:200])
r = web("/some/page?x=1", "acme-old.org")
check("parked domain redirects to the main domain", r.status_code == 301 and
      r.headers.get("location", "").startswith("https://acme-old.com/some/page"), (r.status_code, r.headers.get("location")))
check("uploads copied", web("/wp-content/uploads/2026/10/photo.jpg", "acme-old.com").content[:3] == b"\xff\xd8\xff")
check("link escaping the account was not restored", not os.path.lexists("/srv/harbor/sites/acme-old.com/public/escape"))
check("files owned by the site's user", sh("stat -c %U /srv/harbor/sites/acme-old.com/public/wp-config.php").startswith("site"))
check(".user.ini path rewritten", "/srv/harbor/sites/acme-old.com/public/wordfence-waf.php" in
      Path("/srv/harbor/sites/acme-old.com/public/.user.ini").read_text())
check("summary flags custom .htaccess rules", ".htaccess" in page and "Redirect" in page or "custom .htaccess" in page)
check("nginx config valid", "successful" in sh("nginx -t 2>&1"))

# ---------- databases ----------
out = sh("mysql -N -e \"SELECT CONCAT(user, '@', host) FROM mysql.user WHERE user LIKE 'acme%'\"")
check("database users recreated (local only)", "acme_wpuser@localhost" in out and "acme_shopuser@localhost" in out
      and "203.0.113.9" not in out, out)
out = sh(f"mysql -N -u acme_wpuser -p'{fx.WP_DB_PASS}' acme_wp -e 'SELECT COUNT(*) FROM wp_options'")
check("original password works from the command line too", out == "2", out)
check("cPanel account's own MySQL login not created", "acme@" not in sh("mysql -N -e \"SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user = 'acme'\""))
dbpage = p.c.get(f"/sites/{re.search(r'/sites/(\d+)', page).group(1)}/databases").text if re.search(r'/sites/(\d+)', page) else ""
check("databases listed in the panel", "acme_wp" in dbpage, dbpage[:500])

# ---------- mail ----------
try:
    msgs, boxes = imap("info@acme-old.com", fx.MAIL_PASS)
    check("mailbox login with ORIGINAL password ($6$ SHA-512)", True)
    subj = sorted(m["Subject"] for m in msgs)
    check("old mail is in the inbox (read + unread)", subj == ["Order #1001", "Unread invoice", "Welcome to Acme"], subj)
    check("old folders kept", any("Sent" in b for b in boxes), boxes)
    sent_name = next((re.findall(r'"([^"]*Sent)"|(\S*Sent)\s*$', b)[0] for b in boxes if "Sent" in b), None)
    sent_name = next((x for x in sent_name if x), "Sent") if sent_name else "Sent"
    sent, _ = imap("info@acme-old.com", fx.MAIL_PASS, sent_name)
    check("sent mail is in the Sent folder", [m["Subject"] for m in sent] == ["Re: hello"], [m["Subject"] for m in sent])
except imaplib.IMAP4.error as e:
    check("mailbox login with ORIGINAL password ($6$ SHA-512)", False, e)
try:
    msgs, _ = imap("sales@acme-old.com", fx.SALES_PASS)
    check("mailbox login with ORIGINAL password ($1$ MD5)", [m["Subject"] for m in msgs] == ["Wholesale enquiry"],
          [m["Subject"] for m in msgs])
except imaplib.IMAP4.error as e:
    check("mailbox login with ORIGINAL password ($1$ MD5)", False, e)
try:
    imap("info@acme-old.com", "wrong-password")
    check("wrong password refused", False)
except imaplib.IMAP4.error:
    check("wrong password refused", True)
check("quota kept (1 GB) and 'no limit' kept", "1024" in sh("grep '^info@acme-old.com' /etc/dovecot/harbor-users")
      and "storage" not in sh("grep '^sales@acme-old.com' /etc/dovecot/harbor-users"),
      sh("grep acme-old /etc/dovecot/harbor-users | cut -d: -f1,8-"))

s = smtplib.SMTP("127.0.0.1", 25); s.ehlo("sender.example")
s.sendmail("someone@sender.example", ["orders@acme-old.com"],
           "From: someone@sender.example\r\nTo: orders@acme-old.com\r\nSubject: new order 77\r\n\r\nx\r\n")
s.sendmail("someone@sender.example", ["whoever@acme-old.com"],
           "From: someone@sender.example\r\nTo: whoever@acme-old.com\r\nSubject: catchall test\r\n\r\nx\r\n")
s.sendmail("info@acme-old.com", ["sales@acme-old.com"],
           "From: info@acme-old.com\r\nTo: sales@acme-old.com\r\nSubject: price list?\r\n\r\nx\r\n")
s.quit()
check("forwarder delivers (orders@ → info@)", wait_subject("info@acme-old.com", fx.MAIL_PASS, "new order 77"))
check("catch-all delivers to info@", wait_subject("info@acme-old.com", fx.MAIL_PASS, "catchall test"))
check("message delivered to sales@", wait_subject("sales@acme-old.com", fx.SALES_PASS, "price list?"))
check("autoresponder replied (sales@ → info@)", wait_subject("info@acme-old.com", fx.MAIL_PASS, "We got your message"))

# ---------- DNS ----------
ip = sh("cd /opt/harbor && venv/bin/python -c 'from harbor.services.dns import server_ip; print(server_ip())'")
a = sh("dig +short @127.0.0.1 acme-old.com A")
check("zone imported and A record repointed to this server", a == ip, (a, ip))
check("mail.acme-old.com repointed too", sh("dig +short @127.0.0.1 mail.acme-old.com A") == ip)
check("other records kept (CNAME, CAA, SRV)", "acme.crmprovider.example." in sh("dig +short @127.0.0.1 crm.acme-old.com CNAME")
      and "letsencrypt.org" in sh("dig +short @127.0.0.1 acme-old.com CAA")
      and "5060" in sh("dig +short @127.0.0.1 _sip._tcp.acme-old.com SRV"))
check("MX kept", "mail.acme-old.com." in sh("dig +short @127.0.0.1 acme-old.com MX"), sh("dig +short @127.0.0.1 acme-old.com MX"))
spf = sh("dig +short @127.0.0.1 acme-old.com TXT")
check("SPF updated to this server's IP", f"ip4:{ip}" in spf and fx.OLD_IP not in spf, spf)
check("cPanel-only records dropped", sh("dig +short @127.0.0.1 cpanel.acme-old.com A") == "")
check("this server's DKIM key published", "v=DKIM1" in sh("dig +short @127.0.0.1 harbor._domainkey.acme-old.com TXT"))
check("name servers are this server's", "acme-old.com" not in sh("dig +short @127.0.0.1 acme-old.com NS")
      and "oldhost" not in sh("dig +short @127.0.0.1 acme-old.com NS"), sh("dig +short @127.0.0.1 acme-old.com NS"))

# ---------- cron ----------
user = sh("stat -c %U /srv/harbor/sites/acme-old.com/public")
cron = sh(f"crontab -l -u {user}")
check("cron jobs installed with new paths and PHP", "/srv/harbor/sites/acme-old.com/public/wp-cron.php" in cron
      and "/home/acme" not in cron and "ea-php" not in cron and "/usr/local/bin/php" not in cron, cron)

# ---------- summary page ----------
check("summary shows counts and next steps", "2 mailbox" in page.replace("</strong>", "").replace("<strong>", "")
      or "Mailboxes" in page, page[:500])

# ---------- health ----------
t0 = time.time()
r = p.c.get("/health")
took = time.time() - t0
check("health page renders quickly", r.status_code == 200 and took < 40 and "acme-old.com" in r.text, (r.status_code, took))
sid = re.search(r'href="/sites/(\d+)">acme-old.com<', p.c.get("/sites").text).group(1)
r = p.c.get(f"/sites/{sid}/health")
check("site health tab renders", r.status_code == 200 and "Website" in r.text and "Email" in r.text, r.text[:400])

# second import of the same file: everything is a conflict
r = p.c.put(f"/import/upload?name={backup.name}", content=backup.read_bytes(), headers={"x-csrf-token": p.csrf("/import")})
iid2 = r.json()["id"]
for _ in range(60):
    st = p.c.get(f"/import/{iid2}/status").json()
    if st["status"] != "scanning":
        break
    time.sleep(0.5)
check("re-import flags existing domains", "already" in p.c.get(f"/import/{iid2}").text)
p.post(f"/import/{iid2}/delete", {"file": "1"}, page="/import")

failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
