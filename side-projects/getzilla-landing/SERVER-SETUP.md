# Static hosting: getzilla.app

The page works on ordinary HTTPS static hosting at the domain root. The HTML contains its CSS and small interface script. Fonts, images and crawl files are public assets; no runtime or build service is needed. These instructions are manual guidance, not an activated hosting policy.

## Publish assets first, HTML last

1. Download and retain the **actual old production HTML** and note the existing public asset inventory before making changes. Store this rollback copy outside the public document root. The repository base and the current live page differ; do not substitute the base HTML for that backup.
2. Upload `assets/fonts/*.woff2`, `assets/fonts/OFL.txt` with its complete license text preserved (one trailing space normalized; see `ASSETS.md`), all `assets/images/*` (including `social-card.png`), root `favicon.png`, `robots.txt` and `sitemap.xml`, keeping the exact directory structure. Check their URLs over HTTPS before publishing the page.
3. Upload `index.html` **last**. Open the canonical root and verify fonts/photos, share metadata, Pricing, anchors, skip link, comparison controls and workflow tabs. Confirm all six workflow panels remain readable with JavaScript disabled.

Do not upload `template/`, `analytics/`, `screenshots/`, `ASSETS.md`, README, this document, tests or reports. Do not upload the whole repository or this whole folder indiscriminately. Only the public inventory above belongs in the document root.

| File type | Expected Content-Type |
| --- | --- |
| `.html` | `text/html; charset=utf-8` |
| `.woff2` | `font/woff2` |
| `.avif` | `image/avif` |
| `.webp` | `image/webp` |
| `.jpg` | `image/jpeg` |
| `.png` | `image/png` |
| `robots.txt`, `OFL.txt` | `text/plain; charset=utf-8` |
| `sitemap.xml` | `application/xml` or `text/xml` |

Use the host's existing HTTPS and canonical redirects. If MIME mappings or caching need adjustment, review a host-specific change separately. Content-hashed fonts and photographs may use long-lived immutable caching; `index.html`, `robots.txt`, `sitemap.xml`, `favicon.png` and `social-card.png` keep stable names and must remain revalidatable. Enable HTML/text compression only through the host's normal reviewed configuration. No `.htaccess`, CSP, framing policy or HSTS activation is part of this patch.

## Verification after publishing

Confirm the root returns HTTP 200 and the intended canonical URL. Fetch every referenced asset and check its Content-Type and dimensions; check `robots.txt` and `sitemap.xml`. Inspect the rendered page at 320px and desktop widths, and confirm the Onest font downloads from this domain.

In a normal browser with analytics allowed, inspect requests for `googletagmanager.com/gtag/js`, `google-analytics.com/g/collect`, `mc.yandex.ru/metrika/tag.js` and `mc.yandex.ru/watch/113486449`. Keep the installed IDs `G-V2LPCG0E3X` and `113486449`. Requests can be affected by browser extensions and vendor availability; a local source hash or intercepted request cannot prove successful collection. Check the vendor dashboards separately when appropriate. Local Lighthouse measurements are lab results, not field Core Web Vitals.

## Rollback

Restore the retained actual old production HTML as `index.html` first. Keep the newly uploaded assets available until cached copies of the new HTML have expired, so neither version gets broken references. Restore previous versions of stable-name favicon/share/crawl files from the deployment backup if they changed. Remove newly added hashed assets later only when they are no longer referenced; never remove unrelated existing files.

A source rollback uses the known reviewed commit or reverts the product commit on an isolated branch through the normal review path. A source rollback does not automatically restore the production page or change hosting settings.
