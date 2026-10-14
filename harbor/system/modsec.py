"""ModSecurity v3 (libmodsecurity) with the OWASP Core Rule Set.

The installer loads the base config and the CRS once at the http level
(/etc/nginx/conf.d/harbor-modsecurity.conf, engine off). Each site that opts in
gets a small rules file, merged on top, that sets its own engine mode and
rule exclusions."""
import json
from pathlib import Path

from .. import config

SITE_TEMPLATE = """# Managed by Harbor
SecRuleEngine {engine}
{removals}
"""


def write_site_rules(path: str, mode: str, disabled: list[int]) -> None:
    f = Path(path)
    f.parent.mkdir(parents=True, exist_ok=True)
    engine = {"on": "On", "detect": "DetectionOnly", "off": "Off"}[mode]
    removals = "\n".join(f"SecRuleRemoveById {i}" for i in disabled)
    f.write_text(SITE_TEMPLATE.format(engine=engine, removals=removals))


def recent_hits(domain: str, limit: int = 100) -> list[dict]:
    """Parse the JSON audit log (newest first) for requests to this domain."""
    log = config.MODSEC_AUDIT_LOG
    if not log.exists():
        return []
    hosts = {domain, f"www.{domain}"}
    hits = []
    with open(log, "rb") as fh:
        fh.seek(0, 2)
        size = fh.tell()
        fh.seek(max(0, size - 8 * 1024 * 1024))  # last 8 MB is plenty
        lines = fh.read().splitlines()
    for raw in reversed(lines):
        try:
            t = json.loads(raw)["transaction"]
        except (ValueError, KeyError, TypeError):
            continue
        req = t.get("request", {})
        headers = {k.lower(): v for k, v in (req.get("headers") or {}).items()}
        if headers.get("host", "").split(":")[0].lower() not in hosts:
            continue
        for m in t.get("messages", []):
            d = m.get("details", {})
            hits.append({
                "time": t.get("time_stamp", ""), "ip": t.get("client_ip", ""),
                "method": req.get("method", ""), "uri": req.get("uri", "")[:200],
                "rule": d.get("ruleId", ""), "message": m.get("message", "")[:200],
                "severity": d.get("severity", ""),
                "blocked": (t.get("response") or {}).get("http_code") == 403,
            })
        if len(hits) >= limit:
            break
    return hits[:limit]
