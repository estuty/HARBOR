"""Nginx virtual hosts, generated from panel state.

Every change is validated with `nginx -t` and rolled back if the test fails,
so a bad config never takes the server down. All values inserted here are
validated beforehand (see validators.py) so they can't inject directives.
"""
from dataclasses import dataclass, field
from pathlib import Path

from .. import config
from .runner import run, CommandError

STATIC_EXT = "css|js|jpg|jpeg|png|gif|webp|avif|svg|ico|woff|woff2|ttf|mp4|webm|mp3|pdf"


@dataclass
class VhostSpec:
    domain: str
    include_www: bool
    ssl: bool
    root: Path
    sock: str
    canonical: str = "none"                      # none | www | bare
    redirects: list = field(default_factory=list)  # {source, target, code, match}
    ip_deny: list = field(default_factory=list)
    error_codes: list = field(default_factory=list)
    path_rules: dict = field(default_factory=dict)  # "/path/" -> {"autoindex": bool, "auth": (realm, file)}
    hotlink: dict | None = None                  # {"exts": [...], "allowed": [...]}
    modsec_file: str | None = None
    max_body_mb: int = 64


def _php_block(sock: str, indent: str) -> str:
    lines = [
        "location ~ \\.php$ {",
        "    try_files $uri =404;",
        "    fastcgi_split_path_info ^(.+\\.php)(/.+)$;",
        f"    fastcgi_pass unix:{sock};",
        "    fastcgi_index index.php;",
        "    include fastcgi_params;",
        "    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;",
        "    fastcgi_read_timeout 300;",
        "}",
    ]
    return "\n".join(indent + l for l in lines)


def _body(s: VhostSpec) -> str:
    out = [
        f"    root {s.root}/public;",
        # Serve a symlink only if it belongs to the same user as its target, so a
        # site can't link to another site's (or the system's) files.
        "    disable_symlinks if_not_owner from=$document_root;",
        "    index index.php index.html index.htm;",
        f"    client_max_body_size {s.max_body_mb}M;",
        f"    access_log {s.root}/logs/access.log;",
        f"    error_log {s.root}/logs/error.log;",
    ]
    if s.canonical == "www" and s.include_www:
        out.append(f"    if ($host = {s.domain}) {{ return 301 $scheme://www.{s.domain}$request_uri; }}")
    elif s.canonical == "bare" and s.include_www:
        out.append(f"    if ($host = www.{s.domain}) {{ return 301 $scheme://{s.domain}$request_uri; }}")

    if s.ip_deny:
        out.append("")
        out += [f"    deny {ip};" for ip in s.ip_deny]
        out.append("    allow all;")

    if s.modsec_file:
        out += ["", "    modsecurity on;", f"    modsecurity_rules_file {s.modsec_file};"]

    if s.error_codes:
        out.append("")
        for code in s.error_codes:
            out.append(f"    error_page {code} /__harbor_errors/{code}.html;")
        out.append("    fastcgi_intercept_errors on;")
        out.append(f"    location ^~ /__harbor_errors/ {{ internal; alias {s.root}/errors/; }}")

    out += ["",
            "    location /.well-known/acme-challenge/ { allow all; auth_basic off; }",
            "    location ~ /\\.(?!well-known) { deny all; }"]

    root_redirect = None  # a prefix redirect of "/" sends the whole site elsewhere
    for r in s.redirects:
        flag = "permanent" if r["code"] == 301 else "redirect"
        if r["match"] == "exact":
            out.append(f"    location = {r['source']} {{ return {r['code']} {r['target']}; }}")
            continue
        src = r["source"].replace(".", "\\.")
        target = r["target"]
        if r["source"].endswith("/") and not target.endswith("/"):
            target += "/"  # /old/x -> /new/x, and / -> https://other.example/x
        if r["source"] == "/":
            # whole site: at server level so PHP files redirect too; certificate checks still answer here
            root_redirect = f"rewrite ^/(?!\\.well-known/acme-challenge/)(.*)$ {target}$1 {flag};"
            out.append(f"    {root_redirect}")
        else:
            out.append(f"    location ^~ {r['source']} {{ rewrite ^{src}(.*)$ {target}$1 {flag}; }}")

    whole = s.path_rules.get("/")  # rules for the whole site go at server level ("location /" exists below)
    if whole and not root_redirect:
        if whole.get("auth"):
            realm, file = whole["auth"]
            out += [f'    auth_basic "{realm}";', f"    auth_basic_user_file {file};"]
        if whole.get("autoindex"):
            out += ["    autoindex on;", "    autoindex_exact_size off;"]

    for path, rule in sorted(s.path_rules.items(), key=lambda kv: -len(kv[0])):
        if path == "/":
            continue
        if any(r["source"] == path and r["match"] == "prefix" for r in s.redirects):
            continue  # a redirect already owns this prefix
        out += ["", f"    location ^~ {path} {{"]
        if rule.get("auth"):
            realm, file = rule["auth"]
            out += [f'        auth_basic "{realm}";', f"        auth_basic_user_file {file};"]
        if rule.get("autoindex"):
            out += ["        autoindex on;", "        autoindex_exact_size off;", "        try_files $uri $uri/ =404;"]
        else:
            out.append("        try_files $uri $uri/ /index.php?$args;")
        out.append("        location ~ /\\.(?!well-known) { deny all; }")
        out.append(_php_block(s.sock, "        "))
        out.append("    }")

    out += ["", "    location / {", "        try_files $uri $uri/ /index.php?$args;",
            "    }", "",
            _php_block(s.sock, "    "), ""]

    if s.hotlink:
        # server_names already covers the domain and www alias; listing them again is an nginx error
        own = {s.domain, f"www.{s.domain}", f"*.{s.domain}"}
        allowed = " ".join([f"*.{s.domain}"] + [a for a in dict.fromkeys(s.hotlink["allowed"]) if a not in own])
        exts = "|".join(s.hotlink["exts"])
        out += [f"    location ~* \\.({exts})$ {{",
                f"        valid_referers none blocked server_names {allowed};",
                "        if ($invalid_referer) { return 403; }",
                "        expires 30d;",
                "        access_log off;",
                "    }"]
    out += [f"    location ~* \\.({STATIC_EXT})$ {{", "        expires 30d;", "        access_log off;",
            "        try_files $uri =404;", "    }"]
    return "\n".join(out)


def render(s: VhostSpec) -> str:
    names = s.domain + (f" www.{s.domain}" if s.include_www else "")
    head = "# Managed by Harbor - manual edits will be overwritten\n"
    v6_80 = "    listen [::]:80;\n" if config.IPV6 else ""
    v6_443 = "    listen [::]:443 ssl http2;\n" if config.IPV6 else ""
    if not s.ssl:
        return head + (
            f"server {{\n    listen 80;\n{v6_80}"
            f"    server_name {names};\n{_body(s)}\n}}\n")
    return head + (
        f"server {{\n    listen 80;\n{v6_80}"
        f"    server_name {names};\n"
        f"    location /.well-known/acme-challenge/ {{ root {s.root}/public; }}\n"
        "    location / { return 301 https://$host$request_uri; }\n}\n\n"
        f"server {{\n    listen 443 ssl http2;\n{v6_443}"
        f"    server_name {names};\n"
        f"    ssl_certificate {config.LE_LIVE}/{s.domain}/fullchain.pem;\n"
        f"    ssl_certificate_key {config.LE_LIVE}/{s.domain}/privkey.pem;\n"
        "    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_prefer_server_ciphers off;\n"
        "    ssl_session_cache shared:harbor_ssl:10m;\n"
        '    add_header Strict-Transport-Security "max-age=31536000" always;\n'
        f"{_body(s)}\n}}\n")


def conf_name(domain: str) -> str:
    return f"harbor-{domain}.conf"


def test_and_reload() -> None:
    run(["nginx", "-t"])
    run(["systemctl", "reload", "nginx"])


def write(spec: VhostSpec) -> None:
    config.NGINX_AVAILABLE.mkdir(parents=True, exist_ok=True)
    config.NGINX_ENABLED.mkdir(parents=True, exist_ok=True)
    avail = config.NGINX_AVAILABLE / conf_name(spec.domain)
    enabled = config.NGINX_ENABLED / conf_name(spec.domain)
    previous = avail.read_text() if avail.exists() else None

    avail.write_text(render(spec))
    if not enabled.is_symlink() and not enabled.exists():
        enabled.symlink_to(avail)
    try:
        test_and_reload()
    except CommandError:
        if previous is None:
            enabled.unlink(missing_ok=True)
            avail.unlink(missing_ok=True)
        else:
            avail.write_text(previous)
        raise


def remove(domain: str) -> None:
    (config.NGINX_ENABLED / conf_name(domain)).unlink(missing_ok=True)
    (config.NGINX_AVAILABLE / conf_name(domain)).unlink(missing_ok=True)
    test_and_reload()
