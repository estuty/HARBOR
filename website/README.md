# Harbor website

The public website for Harbor: a static site with no build step, separate from the control panel.

| File | What |
|---|---|
| `index.html` | Home page: product screens, features, cPanel map, how it works, technical details |
| `docs.html` | Documentation, generated from the project `README.md` |
| `styles.css`, `site.js` | Shared styles (light and dark) and the small script for the menu, screen tabs and contour background |
| `assets/screens/` | Screenshots of the real panel (light and dark), WebP |
| `assets/fonts/` | Schibsted Grotesk, Public Sans, JetBrains Mono (latin, variable), SIL OFL 1.1, see `OFL.txt` |
| `assets/og.png` | Social preview image, rendered from `og-source.html` at 1200×630 |
| `favicon.svg` | The panel's anchor mark |

## Preview

```bash
cd website && python3 -m http.server 8000    # then open http://localhost:8000
```

## Publish

Upload the folder to any static host (GitHub Pages, Netlify, Cloudflare Pages, or an nginx site on a Harbor server
with the folder as its public directory). All links are relative.

## Keep it current

- After changing `README.md`: `pip install markdown && python3 website/build_docs.py` rebuilds `docs.html`.
- New screenshots: capture the panel at 1440×900 (2× pixel density), save as WebP at 1600 px wide
  (1920 for the dashboard), as `name-light.webp` and `name-dark.webp`.
- Screens come from a test server with example domains; replace them with your own if you prefer.
