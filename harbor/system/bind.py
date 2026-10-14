"""Authoritative DNS with BIND 9. Zone files and the zone list are generated
from panel state, checked with named-checkzone/named-checkconf, then reloaded."""
from pathlib import Path

from .. import config
from .runner import run, chown, CommandError


def zone_path(domain: str) -> Path:
    return config.BIND_ZONES / f"db.{domain}"


def _fqdn(v: str, origin: str) -> str:
    if v == "@":
        return f"{origin}."
    if v.endswith("."):
        return v
    return f"{v}." if "." in v else v  # bare label stays relative to the zone


def _txt(v: str) -> str:
    esc = v.replace("\\", "\\\\").replace('"', '\\"')
    chunks = [esc[i:i + 250] for i in range(0, len(esc), 250)] or [""]
    return " ".join(f'"{c}"' for c in chunks)


def render(domain: str, serial: int, ns: list[str], hostmaster: str, records,
           glue_ipv4: str = "", glue_ipv6: str = "") -> str:
    out = [
        "; Managed by Harbor - manual edits will be overwritten",
        f"$ORIGIN {domain}.",
        "$TTL 3600",
        f"@ IN SOA {_fqdn(ns[0], domain)} {hostmaster.replace('@', '.')}. (",
        f"    {serial} ; serial",
        "    3600 ; refresh", "    900 ; retry", "    1209600 ; expire", "    300 ) ; negative cache",
    ]
    has_ns = any(r["type"] == "NS" and r["name"] == "@" for r in records)
    if not has_ns:
        out += [f"@ 3600 IN NS {_fqdn(n, domain)}" for n in ns]
    # Name servers inside this zone (ns1.example.com for example.com) need
    # address records here ("glue"), or BIND refuses the zone.
    for n in ns:
        n = n.rstrip(".")
        if n.endswith("." + domain):
            label = n[: -len(domain) - 1]
            if not any(r["name"] == label and r["type"] in ("A", "AAAA") for r in records):
                if glue_ipv4:
                    out.append(f"{label} 3600 IN A {glue_ipv4}")
                if glue_ipv6:
                    out.append(f"{label} 3600 IN AAAA {glue_ipv6}")
    for r in sorted(records, key=lambda r: (r["name"] != "@", r["name"], r["type"])):
        t, name, ttl, c = r["type"], r["name"], r["ttl"], r["content"]
        if t in ("CNAME", "NS"):
            val = _fqdn(c, domain)
        elif t == "MX":
            val = f"{r['priority']} {_fqdn(c, domain)}"
        elif t == "SRV":
            w, port, target = c.split()
            val = f"{r['priority']} {w} {port} {_fqdn(target, domain)}"
        elif t == "TXT":
            val = _txt(c)
        else:
            val = c
        out.append(f"{name} {ttl} IN {t} {val}")
    return "\n".join(out) + "\n"


def write_zone(domain: str, content: str) -> None:
    config.BIND_ZONES.mkdir(parents=True, exist_ok=True)
    f = zone_path(domain)
    previous = f.read_text() if f.exists() else None
    tmp = f.with_name(f.name + ".new")
    tmp.write_text(content)
    try:
        run(["named-checkzone", domain, str(tmp)])
    except CommandError:
        tmp.unlink(missing_ok=True)
        raise
    tmp.replace(f)
    f.chmod(0o640)
    chown(f, "root", "bind")
    try:
        run(["rndc", "reload", domain], check=previous is not None)
    except CommandError:
        run(["rndc", "reconfig"])


def write_zone_list(domains: list[str]) -> None:
    lines = ["// Managed by Harbor"]
    for d in sorted(domains):
        lines.append(f'zone "{d}" {{ type master; file "{zone_path(d)}"; allow-transfer {{ none; }}; }};')
    inc = config.BIND_INCLUDE
    inc.parent.mkdir(parents=True, exist_ok=True)
    previous = inc.read_text() if inc.exists() else None
    inc.write_text("\n".join(lines) + "\n")
    try:
        run(["named-checkconf"])
        run(["rndc", "reconfig"])
    except CommandError:
        if previous is not None:
            inc.write_text(previous)
        raise


def remove_zone_file(domain: str) -> None:
    zone_path(domain).unlink(missing_ok=True)
