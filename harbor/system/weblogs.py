"""Visitor and bandwidth statistics from nginx access logs (combined format),
including rotated (.1) and compressed (.gz) logs. Results are cached briefly."""
import gzip
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<day>\d{2}/\w{3}/\d{4}):[^\]]+\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"')
STATIC_RE = re.compile(r"\.(css|js|jpe?g|png|gif|webp|avif|svg|ico|woff2?|ttf|map|mp4|webm|mp3)$", re.I)
BOT_RE = re.compile(r"bot|crawl|spider|slurp|curl|wget|python-requests|httpclient|monitor|preview", re.I)
MAX_LINES = 2_000_000
_cache: dict[str, tuple[float, dict]] = {}


def _files(log_dir: Path) -> list[Path]:
    if not log_dir.exists():
        return []
    files = [f for f in log_dir.iterdir() if f.name.startswith("access.log")]

    def order(f: Path):
        m = re.search(r"\.(\d+)(\.gz)?$", f.name)
        return int(m.group(1)) if m else 0
    return sorted(files, key=order)


def _open(f: Path):
    return gzip.open(f, "rt", errors="replace") if f.suffix == ".gz" else open(f, errors="replace")


def analyse(log_dir: Path, domain: str, days: int = 30) -> dict:
    key = f"{log_dir}:{days}"
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < 300:
        return hit[1]

    since = (datetime.now() - timedelta(days=days - 1)).date()
    per_day = defaultdict(lambda: {"requests": 0, "bytes": 0, "visitors": set(), "pages": 0})
    pages, refs, ips, statuses, agents = Counter(), Counter(), Counter(), Counter(), Counter()
    lines = 0
    own_hosts = {domain, f"www.{domain}"}
    for f in _files(log_dir):
        try:
            fh = _open(f)
        except OSError:
            continue
        with fh:
            for line in fh:
                lines += 1
                if lines > MAX_LINES:
                    break
                m = LINE_RE.match(line)
                if not m:
                    continue
                try:
                    day = datetime.strptime(m["day"], "%d/%b/%Y").date()
                except ValueError:
                    continue
                if day < since:
                    continue
                size = 0 if m["bytes"] == "-" else int(m["bytes"])
                d = per_day[day]
                d["requests"] += 1
                d["bytes"] += size
                statuses[m["status"][0] + "xx"] += 1
                ips[m["ip"]] += 1
                is_bot = bool(BOT_RE.search(m["ua"]))
                agents["Bots" if is_bot else "People"] += 1
                path = m["path"].split("?")[0]
                if not is_bot and not STATIC_RE.search(path) and m["status"].startswith(("2", "3")):
                    d["pages"] += 1
                    d["visitors"].add(m["ip"])
                    pages[path[:120]] += 1
                ref = m["ref"]
                if ref not in ("-", ""):
                    host = (urlsplit(ref).hostname or "").lower()
                    if host and host not in own_hosts:
                        refs[host] += 1

    series = []
    for i in range(days):
        day = since + timedelta(days=i)
        d = per_day.get(day)
        series.append({"day": day.isoformat(), "requests": d["requests"] if d else 0,
                       "bytes": d["bytes"] if d else 0, "visitors": len(d["visitors"]) if d else 0,
                       "pages": d["pages"] if d else 0})
    result = {
        "series": series,
        "totals": {k: sum(s[k] for s in series) for k in ("requests", "bytes", "pages")},
        "unique_visitors": len({ip for d in per_day.values() for ip in d["visitors"]}),
        "top_pages": pages.most_common(15),
        "top_referrers": refs.most_common(10),
        "top_ips": ips.most_common(10),
        "statuses": sorted(statuses.items()),
        "agents": agents.most_common(),
        "truncated": lines > MAX_LINES,
    }
    _cache[key] = (time.time(), result)
    return result
