"""Let's Encrypt certificates via certbot's webroot mode (no downtime)."""
from .. import config
from .runner import run


def issue(domain: str, include_www: bool, webroot: str, deploy_hook: str = "systemctl reload nginx") -> None:
    cmd = ["certbot", "certonly", "--webroot", "-w", webroot, "-d", domain]
    if include_www:
        cmd += ["-d", f"www.{domain}"]
    cmd += ["--cert-name", domain, "--non-interactive", "--agree-tos", "--keep-until-expiring",
            "--expand", "--deploy-hook", deploy_hook]
    if config.ACME_EMAIL:
        cmd += ["-m", config.ACME_EMAIL]
    else:
        cmd += ["--register-unsafely-without-email"]
    run(cmd, timeout=600)


def delete(domain: str) -> None:
    run(["certbot", "delete", "--cert-name", domain, "--non-interactive"], check=False)
