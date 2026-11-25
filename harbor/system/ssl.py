"""Let's Encrypt certificates via certbot's webroot mode (no downtime), plus
support for certificates the user uploads themselves."""
import tempfile
from pathlib import Path

from .. import config
from .runner import run, chmod, CommandError


def issue(domain: str, include_www: bool, webroot: str, deploy_hook: str = "systemctl reload nginx",
          extra: list[str] | None = None) -> None:
    cmd = ["certbot", "certonly", "--webroot", "-w", webroot, "-d", domain]
    if include_www:
        cmd += ["-d", f"www.{domain}"]
    for name in extra or []:
        cmd += ["-d", name]
    cmd += ["--cert-name", domain, "--non-interactive", "--agree-tos", "--keep-until-expiring",
            "--expand", "--deploy-hook", deploy_hook]
    if config.ACME_EMAIL:
        cmd += ["-m", config.ACME_EMAIL]
    else:
        cmd += ["--register-unsafely-without-email"]
    run(cmd, timeout=600)


def delete(domain: str) -> None:
    run(["certbot", "delete", "--cert-name", domain, "--non-interactive"], check=False)


# ---------- uploaded ("custom") certificates ----------

class CertError(Exception):
    pass


def custom_dir(domain: str) -> Path:
    return config.NGINX_HARBOR / "certs" / domain


def has_custom(domain: str) -> bool:
    d = custom_dir(domain)
    return (d / "fullchain.pem").exists() and (d / "privkey.pem").exists()


def cert_dir(domain: str, custom: bool) -> str:
    """Directory holding fullchain.pem / privkey.pem for nginx, for either source."""
    return str(custom_dir(domain)) if custom else f"{config.LE_LIVE}/{domain}"


def _public_key(pem: str, kind: str) -> str:
    """The public key of a certificate or private key, so the two can be checked as a pair."""
    with tempfile.NamedTemporaryFile("w", suffix=".pem") as f:
        f.write(pem)
        f.flush()
        if kind == "cert":
            return run(["openssl", "x509", "-in", f.name, "-noout", "-pubkey"], check=False).strip()
        return run(["openssl", "pkey", "-in", f.name, "-pubout"], check=False).strip()


def install_custom(domain: str, cert_pem: str, key_pem: str, chain_pem: str = "") -> None:
    """Validate an uploaded certificate and key, then store them for nginx."""
    if "BEGIN CERTIFICATE" not in cert_pem:
        raise CertError("The certificate doesn't look like a PEM certificate (expected BEGIN CERTIFICATE).")
    if "BEGIN" not in key_pem or "PRIVATE KEY" not in key_pem:
        raise CertError("The private key doesn't look like a PEM private key.")
    cert_pub, key_pub = _public_key(cert_pem, "cert"), _public_key(key_pem, "key")
    if not config.DRY_RUN:
        if not cert_pub or not key_pub:
            raise CertError("Could not read the certificate or key. Make sure the key isn't password-protected.")
        if cert_pub != key_pub:
            raise CertError("The private key doesn't match the certificate.")

    d = custom_dir(domain)
    d.mkdir(parents=True, exist_ok=True)
    body = cert_pem.strip() + "\n"
    if chain_pem.strip():
        body += chain_pem.strip() + "\n"
    full, key = d / "fullchain.pem", d / "privkey.pem"
    full.write_text(body)
    key.write_text(key_pem.strip() + "\n")
    chmod(full, 0o644)
    chmod(key, 0o600)


def remove_custom(domain: str) -> None:
    import shutil
    shutil.rmtree(custom_dir(domain), ignore_errors=True)


def _parse_cert_text(text: str) -> dict:
    """Parse `openssl x509 -subject -issuer -startdate -enddate -ext subjectAltName` output."""
    info: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("subject="):
            info["subject"] = line.split("=", 1)[1].strip()
        elif line.startswith("issuer="):
            info["issuer"] = line.split("=", 1)[1].strip()
        elif line.startswith("notBefore="):
            info["not_before"] = line.split("=", 1)[1].strip()
        elif line.startswith("notAfter="):
            info["not_after"] = line.split("=", 1)[1].strip()
        elif line.startswith("DNS:"):
            info["sans"] = [p.strip()[4:] for p in line.split(",") if p.strip().startswith("DNS:")]
    return info


def info(domain: str, custom: bool):
    """Subject, issuer, validity and SANs of the active certificate, or None if it can't be read."""
    path = Path(cert_dir(domain, custom)) / "fullchain.pem"
    out = run(["openssl", "x509", "-in", str(path), "-noout",
               "-subject", "-issuer", "-startdate", "-enddate", "-ext", "subjectAltName"], check=False)
    parsed = _parse_cert_text(out or "")
    return parsed or None
