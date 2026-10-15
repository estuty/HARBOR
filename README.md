# Harbor

A self-hosted alternative to cPanel for one Linux server: websites, email, DNS,
databases, security and backups in one panel. One install script, no licence fees.

Stack: **Nginx + PHP-FPM + MariaDB**, **Postfix + Dovecot + Rspamd** (mail), **BIND 9** (DNS),
**ModSecurity + OWASP CRS** (firewall), **Roundcube** (webmail), **WP-CLI** (WordPress).

## Features, mapped to cPanel

| cPanel | Harbor |
|---|---|
| Domains / Addon / Subdomains | **Sites**: Linux user, web root, isolated PHP-FPM pool, nginx vhost, DNS zone in one step |
| SSL/TLS | Free Let's Encrypt certificates, auto-renewal, HTTP→HTTPS, HSTS |
| Redirects | Exact or "path and everything below" redirects, 301/302, www ↔ bare preferred address |
| Zone Editor | **DNS**: A, AAAA, CNAME, MX, TXT, SRV, CAA, NS; default web/mail/SPF/DMARC/CAA records; glue for in-zone name servers |
| Dynamic DNS | Per-host update keys; routers or a cron job call an update URL |
| Email Accounts | Mailboxes with quotas, usage, password reset, login suspension |
| Forwarders / Default Address | Forwarders (keep a copy when forwarding a real mailbox) and catch-all |
| Autoresponders | Sieve vacation replies with date range and reply interval |
| Email Deliverability | DKIM keys generated and signed automatically (Rspamd); DNS records published or shown to copy |
| Spam Filters | Rspamd; spam is filed into Junk |
| Webmail | Roundcube on port 2096 |
| MySQL Databases / Wizard | Database + user in one click; password shown once; sizes |
| phpMyAdmin | **Databases tab → Open**: Adminer signed in to that one database (temporary MySQL user, 2 hours), browse, edit, import and export |
| File Manager | Browse, drag-and-drop upload, edit, rename, delete, download; locked to the site |
| FTP Accounts | **SFTP** per site, chrooted to the site folder |
| Directory Privacy | Password-protected folders (including PHP inside them) |
| IP Blocker | Single IPs or CIDR ranges per site; one-click block from stats and firewall hits |
| Hotlink Protection | File types + allowed sites |
| ModSecurity | Per site: Off / Detect only / Block; disable rules; recent hits with one-click rule disable |
| MultiPHP Manager / INI Editor | PHP version per site; memory, upload size, timeouts, time zone, etc. |
| Error Pages | Custom 400/401/403/404/500/502/503 pages |
| Indexes | Directory listing per folder |
| Cron Jobs | Per-site, run as the site user, pause/resume |
| Backup / Backup Wizard | Full backups (files + databases), daily/weekly schedule with retention, upload, restore files and/or databases |
| Metrics (Awstats, Bandwidth) | Visitors, page views, bandwidth per day, top pages, referrers, busiest IPs |
| Application Manager | One-click WordPress (root or subfolder), "Update all", remove |
| Site Publisher | Three templates (Business, Personal, Coming soon) filled from a form |
| Team users / Manage API Tokens | Admins and team users with per-site access; API tokens with the owner's permissions; JSON API |
| Two-factor authentication | Authenticator-app codes + one-time recovery codes; can be required for all admins |
| cPHulk brute-force protection | **fail2ban** for SSH, panel, SMTP/IMAP, webmail and protected folders; ban/unban in Security |
| Host access control | Panel (and optionally webmail) limited to your IP addresses |
| Backup to remote destinations | Offsite copies to any S3-compatible storage (Spaces, B2, S3, Wasabi, R2), retention, restore from offsite |
| Contact information / notifications | Alerts by email (any SMTP) or webhook (Slack, Discord, ntfy): disk, services, certificates, sites down, stuck mail, backups, disk allowance |
| Resource usage limits (CloudLinux LVE) | Per-site CPU, memory and PHP-process limits enforced by systemd cgroups; disk allowance |
| Updates | Notifies you of new releases (panel, email, webhook); one-click update; automatic rollback if it fails; roll back to saved versions |
| Audit log | Activity page records every change |
| Git Version Control | **Deploy** tab per site: connect a GitHub/GitLab/Gitea/Bitbucket repository (deploy key for private ones), build command run as the site user, kept paths (uploads, `.env`), push-to-deploy webhook, deploy history with one-click rollback, API trigger for CI |
| Transfer Tool / Restore a full backup | **Move from cPanel**: upload (any size), link or scp a cPanel account backup; review the plan; one click brings sites, files, databases (users keep their passwords), mailboxes (keep passwords, all mail and folders), forwarders, catch-all, autoresponders, DNS zones (repointed here) and cron jobs |
| (none) | **Health**: plain-English checks of what the internet sees: DNS pointing elsewhere, MX vs. mailboxes, SPF/DKIM/DMARC, reverse DNS, blocked port 25, blocklists, certificates, slow or broken home pages, PHP errors, missing 2FA/backups/alerts, each with the exact fix |

## Install

On a **fresh** Ubuntu 24.04 / 22.04 or Debian 12 VPS:

```bash
tar xzf harbor.tar.gz && cd harbor
sudo ./install.sh --hostname server1.example.com --email you@example.com
```

Open `https://SERVER-IP:8443` (self-signed certificate warning the first time) and sign in with
the printed password. Then in **Settings**: confirm the host name and IP, set your name servers,
and click **Get certificate** to give the panel, webmail and mail server a trusted certificate.

Options: `--admin NAME`, `--port N`, `--extra-php "8.2 8.1"` (adds the Ondřej Surý PHP
repository), `--no-mail`, `--no-dns`, `--no-modsec`, `--no-webmail`.
Re-running the installer upgrades Harbor in place and keeps all data.

### Before you rely on email
- Ask your VPS provider to open outbound port 25 (many block it) and to set **reverse DNS**
  (PTR) for the server IP to your host name.
- The host name needs an A record pointing at the server.
- If DNS for a domain is hosted elsewhere, add the MX/SPF/DKIM/DMARC records shown on its
  Email tab.

### Hosting DNS here
Create "glue" records `ns1.yourdomain.com` / `ns2.yourdomain.com` → server IP at your registrar,
set them in Settings, and use them as each domain's name servers. BIND runs authoritative-only
(no open resolver). For real redundancy, add a secondary DNS provider later.

## After installing: secure the server

1. **My account → Two-factor sign-in.** Scan the QR code and save the recovery codes.
2. **Security → Two-factor sign-in → Require for all admins.**
3. **Security → Panel access.** Add your own IP address(es). Locked out later?
   `sudo /opt/harbor/venv/bin/python -m harbor allow-ip --clear`
4. **Settings → Offsite backups.** Connect a private bucket, then turn on daily backups per site (Backups tab).
5. **Settings → Alerts.** Add your email and an SMTP server (outgoing port 25 is often blocked), or a
   Slack/Discord webhook, and click *Send test alert*.
6. **Settings → General → Default limits**, and per site on its Overview tab.

Each site's PHP now runs as its own service, `harbor-php-<site>` (`systemctl status harbor-php-site1`),
so limits are enforced by the kernel and one site can't starve the others. Upgrading from 0.2 moves
existing sites over automatically.

## Deploying from Git

Each site has a **Deploy** tab.

1. **Connect** the repository address and branch. Public repositories work with their `https://` address; for a
   private one use the SSH address (`git@github.com:owner/repo.git`) and add the **deploy key** Harbor shows as a
   read-only key in the repository (GitHub: Settings → Deploy keys). **Check connection** confirms it.
2. Optional: a **build command** (`composer install --no-dev`, `npm ci && npm run build`) that runs in the
   repository as the site's own user, a **folder to publish** (e.g. `dist`), an **after-deploy command** that runs in
   the live folder (`php artisan migrate --force`), and **paths to keep** on the live site (`wp-content/uploads/`, `.env`).
3. **Deploy now.** Harbor fetches the branch, builds, then copies the result into the site with rsync. If the fetch or
   build fails, the live site isn't touched. The first deploy backs up the current files and databases first.
4. **Deploy on push:** add the webhook address shown on the tab to the repository (JSON, push events). Pushes to other
   branches are ignored; GitHub/Gitea signatures and GitLab tokens are checked when sent. The webhook path `/hooks/`
   stays reachable when the panel is limited to your IP addresses.
5. **Roll back** with *Redeploy this version* on any earlier deploy. From CI:
   `curl -X POST -H "Authorization: Bearer hbr_…" https://server:8443/api/v1/sites/ID/deploy`.

The working copy lives in `/srv/harbor/sites/<domain>/git/` (outside the web root). Disconnecting deletes it and the
key; the live files stay.

## Moving from cPanel

1. On the old host: cPanel → **Backup → Download a Full Account Backup** (destination: Home Directory).
   On WHM, a `cpmove-USER.tar.gz` from the Transfer Tool or `pkgacct` works too.
2. Harbor → **Move from cPanel**: drop the file on the page, paste a download link, or copy it to
   `/srv/harbor/imports/` with scp (best for many-GB backups) and click *Use this*.
3. Review the plan (domains, databases, mailboxes, DNS, cron), untick what you don't want, **Import now**.
4. Follow the *Next steps* on the result page: preview with a hosts-file line, point DNS, turn on HTTPS,
   move MX last. The **Health** page then tells you what still points at the old host.

What carries over: main, addon, sub and parked domains (parked ones redirect to the main domain); files with
`/home/USER` paths rewritten in configs; databases and their users with the same passwords (MySQL 8
`caching_sha2` users get a new password, written into WordPress/Joomla/Laravel settings); mailboxes with their
original passwords, quotas, every folder and read/unread state; forwarders, catch-all, autoresponders; DNS zones
without cPanel-only records and with the old IP replaced; cron jobs with new paths and PHP. Not carried over:
SSL certificates (re-issued free), FTP accounts (use SFTP), mail filters, statistics, and `.htaccess` rules
(nginx doesn't read them: the summary lists sites with custom rules to recreate under Redirects/Security).
The old account is never touched.

## Updating

Harbor checks for a new release every 6 hours. When one is out, the dashboard shows a banner with
**Update now**, Settings gets an "Update" badge, and admins are told by email or webhook (whatever is set
under Settings → Alerts), once per release. **Settings → Updates** shows the release notes and has
**Check now** and the update settings (turn checking or notifications off).

Updating saves the current code and database, installs, restarts and checks that the panel answers. If
anything fails it puts the previous version back by itself. When a release also changes server components,
the installer runs automatically as part of the update (it keeps data and settings).

You can also upload a `harbor.tar.gz` (or paste a link) on the same page, or from SSH:
`sudo /opt/harbor/venv/bin/python -m harbor update harbor.tar.gz`.

Servers installed before 0.7.0 don't have update checks yet: update once by hand: in the folder you cloned
Harbor into, run `git pull && sudo ./install.sh` (or upload the 0.7.0 package on Settings → Updates).

## Ports

| Port | Use |
|---|---|
| 80, 443 | Websites |
| 8443 | Panel |
| 2096 | Webmail |
| 25, 465, 587 | SMTP (inbound, submission SSL, submission STARTTLS) |
| 993, 995 (143, 110) | IMAP, POP3 |
| 53 | DNS |
| 22 | SSH / SFTP |

## API

Create a token under your account (top-left user name → API tokens):

```bash
curl -H "Authorization: Bearer hbr_…" https://server:8443/api/v1/sites
curl -X POST -H "Authorization: Bearer hbr_…" -H "Content-Type: application/json" \
     -d '{"domain":"example.com"}' https://server:8443/api/v1/sites
```

Endpoints: sites (list/create/show/HTTPS), databases, backups, mailboxes, DNS records, Git deploys
(`POST /api/v1/sites/ID/deploy`, `GET /api/v1/sites/ID/deployments`).
The account page lists them all.

## Security model

- Every site runs PHP as its own Linux user with `open_basedir`; one compromised site can't read
  another's files. SFTP users are chrooted and have no shell.
- The panel listens on `127.0.0.1:8090` behind nginx TLS. Sessions are signed, Secure, HttpOnly,
  SameSite=Strict; all forms have CSRF tokens; logins are throttled; strict CSP.
- System commands run as argument lists (never through a shell). Every value written to a
  config file goes through strict validation, so input can't inject directives.
- Every nginx, PHP-FPM, BIND and Postfix change is checked (`nginx -t`, `php-fpm -t`,
  `named-checkzone`, `postmap`) and rolled back if rejected.
- Mail: no open relay; authenticated senders can only send as their own address; DKIM on all
  outgoing mail.
- The panel itself runs as root (it creates users and manages services). If you can, allow
  port 8443 only from your own IPs: `ufw allow from 203.0.113.4 to any port 8443`.

## Files on the server

| Path | What |
|---|---|
| `/srv/harbor/sites/<domain>/{public,logs,tmp,errors}` | Site files |
| `/srv/harbor/backups/<domain>/` | Backups |
| `/srv/harbor/imports/` | cPanel backups to import (delete them after moving) |
| `/srv/harbor/sites/<domain>/git/` | Git deploy working copy and deploy key |
| `/opt/harbor/adminer/`, `/var/lib/harbor-dbadmin/` | Database editor (Adminer) and its sessions; runs as the `harbor-dbadmin` user |
| `/var/mail/vhosts/<domain>/<user>/` | Mailboxes (Maildir) |
| `/etc/nginx/sites-available/harbor-*.conf` | Generated vhosts |
| `/etc/php/<ver>/fpm/pool.d/harbor-*.conf` | Generated PHP pools |
| `/var/lib/bind/harbor/db.<domain>` | Generated DNS zones |
| `/etc/postfix/harbor/`, `/etc/dovecot/harbor-users` | Generated mail maps |
| `/var/lib/harbor/harbor.db` | Panel database (SQLite) |
| `/etc/harbor/` | Secret key, env, panel TLS |

Operate: `systemctl status harbor`, `journalctl -u harbor -f`.

Command line (`cd /opt/harbor && sudo venv/bin/python -m harbor …`):

| Command | Does |
|---|---|
| `create-admin NAME` | Create an admin or reset a password |
| `disable-2fa NAME` | Remove two-factor sign-in (lost phone and recovery codes) |
| `allow-ip --clear` / `--add IP` | Fix a panel lockout |
| `reconcile` | Rewrite every site's nginx/PHP config from the panel database |
| `update FILE.tar.gz` | Update with automatic rollback |

## Development

```bash
pip install -r requirements.txt pytest httpx moto
python -m pytest -q tests                      # dry-run tests: no system changes
HARBOR_DRY_RUN=1 python -m harbor create-admin admin --password 'long-password-here'
HARBOR_DRY_RUN=1 HARBOR_COOKIE_SECURE=0 python -m harbor serve --port 8090
```

Dry-run mode sandboxes every path and logs commands instead of running them.
`tests/integration/run_live.py` (73 checks: web, PHP isolation, DNS, mail delivery/DKIM/relay
protection, autoresponders, SFTP chroot, ModSecurity, backups/restore, team users, API) and
`tests/integration/run_stage1.py` (38 checks: per-site PHP services and limits, migration from 0.2,
2FA, fail2ban bans, panel allowlist, offsite backup and restore, alerts, update and rollback) and
`tests/integration/run_stage2.py` (46 checks: importing a realistic cPanel account in both backup
layouts, then checking sites, original database and mailbox passwords, old mail and folders, forwarders,
catch-all, autoresponder, DNS, cron, health pages) and `tests/integration/run_deploy.py` (32 checks: Git deploy
from a private SSH repository with a deploy key, build as the site user, kept paths, push webhook through nginx past
the panel allowlist, failed build leaves the site alone, rollback, disconnect) exercise a real server end to end.

## Not included yet
- Staging sites, Node.js/Python apps
- DNSSEC signing and secondary DNS; reseller packages
- Disk limits are soft (alerts + upload block), not filesystem quotas; cron jobs aren't covered by CPU/memory limits
