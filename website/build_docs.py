#!/usr/bin/env python3
"""Build website/docs.html from the project README, so the documentation on the
website always matches the repository.

    pip install markdown        # only needed to rebuild the page
    python3 website/build_docs.py
"""
import html
import re
from pathlib import Path

import markdown

HERE = Path(__file__).resolve().parent
README = HERE.parent / "README.md"
OUT = HERE / "docs.html"
REPO = "https://github.com/estuty/HARBOR"

text = README.read_text(encoding="utf-8")
# the README's own title and first paragraph become the page intro
title_block, _, body = text.partition("\n## ")
body = "## " + body
intro_md = re.sub(r"^# .*\n", "", title_block).strip()

md = markdown.Markdown(extensions=["tables", "fenced_code", "toc", "sane_lists"],
                       extension_configs={"toc": {"permalink": False, "toc_depth": "2-3"}})
content = md.convert(body)
toc_tokens = md.toc_tokens
intro = markdown.markdown(intro_md)

# tables scroll inside their own box on narrow screens
content = re.sub(r"<table>", '<div class="table-scroll"><table>', content)
content = content.replace("</table>", "</table></div>")
# external links open with rel=noopener
content = re.sub(r'<a href="(https?://[^"]+)"', r'<a href="\1" rel="noopener"', content)

toc_links = []
for t in toc_tokens:
    toc_links.append(f'<a href="#{t["id"]}">{html.escape(html.unescape(t["name"]))}</a>')
    for c in t.get("children", []):
        toc_links.append(f'<a class="sub" href="#{c["id"]}">{html.escape(html.unescape(c["name"]))}</a>')

page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Harbor documentation</title>
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="claude:viewport-fit-sides" content="cover">
<meta name="description" content="Install Harbor, secure the server, deploy from Git, move from cPanel, use the API, and find every file Harbor manages.">
<meta name="theme-color" content="#0a1f2c">
<link rel="icon" href="favicon.svg" type="image/svg+xml">
<meta property="og:type" content="article">
<meta property="og:site_name" content="Harbor">
<meta property="og:title" content="Harbor documentation">
<meta property="og:description" content="Installation, security, Git deploys, moving from cPanel, API and server layout.">
<meta property="og:image" content="assets/og.png">
<link rel="preload" href="assets/fonts/schibsted-grotesk-latin-wght-normal.woff2" as="font" type="font/woff2" crossorigin>
<link rel="preload" href="assets/fonts/public-sans-latin-wght-normal.woff2" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="styles.css">
<script src="site.js" defer></script>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="nav" id="top">
  <div class="wrap">
    <a class="brand" href="index.html"><svg viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="7" fill="#12303a"/><g fill="none" stroke="#5fd3c0" stroke-width="2.4" stroke-linecap="round"><circle cx="16" cy="8" r="2.8"/><path d="M16 11v15M10 15h12M6.5 19c1 4.5 4.8 7 9.5 7s8.5-2.5 9.5-7"/></g></svg>Harbor</a>
    <button class="nav-toggle" type="button" aria-expanded="false" aria-controls="nav-links">Menu</button>
    <ul class="nav-links" id="nav-links">
      <li><a href="index.html#product">Product</a></li>
      <li><a href="index.html#features">Features</a></li>
      <li><a href="index.html#cpanel">From cPanel</a></li>
      <li><a href="index.html#how">How it works</a></li>
      <li><a href="docs.html" aria-current="page">Documentation</a></li>
      <li><a href="{REPO}" rel="noopener">GitHub</a></li>
    </ul>
    <a class="btn btn-primary nav-cta" href="#install">Get started</a>
  </div>
</header>
<div class="wrap docs-layout">
  <nav class="toc" aria-label="On this page"><p class="toc-title">On this page</p>
    {"".join(toc_links)}
  </nav>
  <main class="doc" id="main">
    <h1>Harbor documentation</h1>
    <div class="doc-intro">{intro}</div>
    <div class="doc-meta">
      <a class="btn btn-solid" href="#install">Install</a>
      <a class="btn btn-line" href="{REPO}" rel="noopener">Source on GitHub</a>
    </div>
    {content}
    <p class="caption">This page is generated from the project's README.md.</p>
  </main>
</div>
<footer class="footer">
  <div class="wrap">
    <div>
      <a class="brand" href="index.html"><svg viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="7" fill="#12303a"/><g fill="none" stroke="#5fd3c0" stroke-width="2.4" stroke-linecap="round"><circle cx="16" cy="8" r="2.8"/><path d="M16 11v15M10 15h12M6.5 19c1 4.5 4.8 7 9.5 7s8.5-2.5 9.5-7"/></g></svg>Harbor</a>
      <p>A self-hosted control panel for one Linux server: websites, email, DNS, databases, backups and security in one place.</p>
    </div>
    <nav aria-label="Product"><h2>Product</h2><ul>
      <li><a href="index.html#product">Screens</a></li><li><a href="index.html#features">Features</a></li>
      <li><a href="index.html#cpanel">Coming from cPanel</a></li><li><a href="index.html#technical">Under the hood</a></li></ul></nav>
    <nav aria-label="Documentation"><h2>Documentation</h2><ul>
      <li><a href="#install">Install</a></li><li><a href="#deploying-from-git">Deploying from Git</a></li>
      <li><a href="#api">API</a></li><li><a href="{REPO}" rel="noopener">GitHub repository</a></li></ul></nav>
    <p class="fine">Harbor documentation, built from README.md.</p>
  </div>
</footer>
</body>
</html>
"""
OUT.write_text(page, encoding="utf-8")
print(f"wrote {OUT.relative_to(HERE.parent)} ({len(page) // 1024} KB, {len(toc_links)} entries)")
