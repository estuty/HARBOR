# Harbor

Self-hosted hosting control panel (cPanel alternative) for one Ubuntu/Debian server. Python 3 + FastAPI,
server-rendered Jinja2 templates, SQLite. The panel runs as root (it creates users and manages services)
on 127.0.0.1:8090 behind nginx TLS on port 8443. The marketing website lives in its own repository.

## Layout

- `harbor/app.py`: FastAPI app, access-control middleware (`PUBLIC`, `ADMIN_ONLY`, per-site checks for team users), router list.
- `harbor/routes/*.py`: one router per area (sites, mail, dns, apps, admin, imports, health, deploy, api …). Pages render templates via `web.render`; POST handlers use `async with guard(request)` + `form_of(request)` (CSRF check) and redirect with `back(...)` plus a `flash(...)`.
- `harbor/services/*.py`: operations that combine the DB and the system (raise `OpError` for user-facing errors).
- `harbor/system/*.py`: low-level system changes (nginx, PHP-FPM units, BIND, Postfix/Dovecot, MySQL, git deploy). Commands always run as argument lists via `system/runner.py`, never through a shell.
- `harbor/validators.py`: every value that reaches a config file or command is validated here first.
- `harbor/db.py`: SQLite schema as numbered `MIGRATIONS` (append a new entry; never edit old ones).
- `harbor/templates/`, `harbor/static/` (`style.css`, `app.js`): panel UI. Site pages include `_site_head.html` (the tab bar).
- `install.sh`: installs/upgrades the server stack and the panel. Bump `SYSTEM_VERSION` in `harbor/__init__.py` when the installer must be re-run (new packages or system config).

## Conventions

- New site feature: route in `harbor/routes/`, service in `harbor/services/`, template extending `base.html` and including `_site_head.html`, add the tab in `_site_head.html`, register the router in `app.py`.
- Copy is plain, sentence case, and errors say how to fix the problem.
- Anything the panel (root) does inside a site folder must not follow links the site could plant: see
  `system/malware.py` (`O_NOFOLLOW` walk from the site folder) for quarantine/restore.
- Malware scanning (`system/malware.py`) runs `clamscan` on demand; ClamAV's own DB misses website malware, so
  the installer adds the Linux Malware Detect and InterServer signature sets via `freshclam` `DatabaseCustomURL`.
- Generated configs are tested (`nginx -t`, `php-fpm -t`, `named-checkzone`, `postmap`) and rolled back on failure.

## Tests

```bash
pip install -r requirements.txt pytest httpx moto
python -m pytest -q tests          # dry-run: HARBOR_DRY_RUN=1 sandboxes every path, records commands in runner.DRY_LOG
```

`tests/integration/run_*.py` exercise a real server end to end (run as root on a test VPS after `./install.sh`):
`run_live.py PASSWORD`, `run_stage1.py PASSWORD harbor.tar.gz`, `run_stage2.py PASSWORD [flat|nested]`,
`run_deploy.py PASSWORD`, `run_dbeditor.py PASSWORD`, `run_updates.py PASSWORD`, `run_malware.py PASSWORD`.

Run a dev panel without touching the system:

```bash
HARBOR_DRY_RUN=1 python -m harbor create-admin admin --password 'long-password-here'
HARBOR_DRY_RUN=1 HARBOR_COOKIE_SECURE=0 python -m harbor serve --port 8090
```

## Releases

Bump `__version__` in `harbor/__init__.py` and merge to `main`: `.github/workflows/release.yml` runs the tests,
then publishes release `vX.Y.Z` with `harbor-X.Y.Z.tar.gz`. Panels check `estuty/HARBOR`'s latest release every
6 hours, notify admins, and offer one-click "Update now" (the installer runs by itself when `SYSTEM_VERSION` went up).
