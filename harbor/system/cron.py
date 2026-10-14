"""Per-site crontabs. The panel's database is the source of truth; the site
user's crontab is rewritten from it on every change."""
from .runner import run

HEADER = "# Managed by Harbor - edit cron jobs in the panel\nSHELL=/bin/sh\nPATH=/usr/local/bin:/usr/bin:/bin\n"


def sync(sysuser: str, jobs) -> None:
    active = [j for j in jobs if j["enabled"]]
    if not active:
        run(["crontab", "-r", "-u", sysuser], check=False)
        return
    lines = [HEADER] + [f"{j['schedule']} {j['command']}" for j in active]
    run(["crontab", "-u", sysuser, "-"], input="\n".join(lines) + "\n")
