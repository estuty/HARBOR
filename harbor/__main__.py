"""Command line.

    python -m harbor serve
    python -m harbor create-admin NAME [--password P]     create an admin or reset a password
    python -m harbor disable-2fa NAME                      if someone lost their phone and codes
    python -m harbor allow-ip --clear | --add IP          fix a panel lockout
    python -m harbor reconcile                             rewrite every site's config from the panel database
    python -m harbor update PACKAGE.tar.gz                 update from the command line (with rollback)
"""
import argparse
import getpass
import os
import sys


def main() -> None:
    parser = argparse.ArgumentParser(prog="harbor", description="Harbor hosting control panel")
    sub = parser.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="Run the panel")
    s.add_argument("--host", default=os.environ.get("HARBOR_HOST", "127.0.0.1"))
    s.add_argument("--port", type=int, default=int(os.environ.get("HARBOR_PORT", "8090")))
    a = sub.add_parser("create-admin", help="Create an admin or reset its password")
    a.add_argument("username")
    a.add_argument("--password", help="Read from a prompt if omitted")
    d = sub.add_parser("disable-2fa", help="Turn off two-factor sign-in for a user")
    d.add_argument("username")
    al = sub.add_parser("allow-ip", help="Change who may open the panel")
    al.add_argument("--clear", action="store_true", help="Allow every address again")
    al.add_argument("--add", help="Add an address or range")
    sub.add_parser("reconcile", help="Rewrite nginx/PHP config for every site from the database")
    up = sub.add_parser("update", help="Install an update package (rolls back automatically on failure)")
    up.add_argument("package")
    args = parser.parse_args()

    from . import config
    if not config.DRY_RUN and os.geteuid() != 0:
        sys.exit("Harbor manages system users and services and must run as root (or set HARBOR_DRY_RUN=1).")

    if args.cmd == "serve":
        import uvicorn
        uvicorn.run("harbor.app:app", host=args.host, port=args.port, proxy_headers=True,
                    forwarded_allow_ips="127.0.0.1", log_level="info")
        return

    from . import auth, db, validators
    db.init()

    if args.cmd == "create-admin":
        pw = args.password or getpass.getpass("Password: ")
        if not args.password and pw != getpass.getpass("Repeat password: "):
            sys.exit("Passwords do not match")
        try:
            validators.password(pw, min_len=12)
        except validators.ValidationError as e:
            sys.exit(str(e))
        auth.create_admin(args.username.strip().lower(), pw)
        print(f"Admin '{args.username}' is ready.")

    elif args.cmd == "disable-2fa":
        row = db.one("SELECT id FROM users WHERE username = ?", args.username.strip().lower())
        if not row:
            sys.exit("No such user")
        auth.disable_2fa(row["id"])
        db.log(f"Two-factor sign-in removed for {args.username} from the command line", "cli")
        print(f"Two-factor sign-in removed for {args.username}.")

    elif args.cmd == "allow-ip":
        from .services import protection
        if args.clear:
            ips = []
        elif args.add:
            ips = protection.allowlist() + [validators.ip_or_network(args.add)]
        else:
            print("Allowed:", ", ".join(protection.allowlist()) or "everyone")
            return
        protection.save_access(" ".join(ips), db.get_setting("panel_allow_webmail") == "1", "127.0.0.1", "cli")
        print("Panel open to: " + (", ".join(ips) if ips else "every address"))

    elif args.cmd == "reconcile":
        from .services import apply_pool, apply_vhost, protection
        failed = 0
        for site in db.all("SELECT id, domain FROM sites ORDER BY id"):
            try:
                apply_pool(site["id"])
                apply_vhost(site["id"])
                print(f"ok      {site['domain']}")
            except Exception as e:
                failed += 1
                print(f"FAILED  {site['domain']}: {e}")
        try:
            from .system import firewall
            firewall.set_panel_access(protection.allowlist(), db.get_setting("panel_allow_webmail") == "1")
            protection.sync_ignore()
        except Exception as e:
            print(f"warning: panel access list: {e}")
        if failed:
            sys.exit(1)

    elif args.cmd == "update":
        import subprocess
        from pathlib import Path
        script = Path(__file__).parent / "updater.py"
        uid = db.execute("INSERT INTO updates (status) VALUES ('queued')")
        sys.exit(subprocess.call([sys.executable, str(script), args.package, "--update-id", str(uid)]))


if __name__ == "__main__":
    main()
