# getzilla.app landing page

The static marketing page for https://getzilla.app/. It keeps the existing design, English copy, photographs, Pricing and inline CSS/small interface JavaScript. Onest and the responsive photographs are served locally; there is no build step or runtime dependency.

Only the migration introduction was updated to current branding: “Upgrading an existing installation?” The other offer and Pricing copy stays unchanged.

## Public deployment inventory

Upload only these paths, preserving their names and directory structure:

| Path | Purpose |
| --- | --- |
| `assets/fonts/*.woff2` | Original Onest variable font: Latin and symbols needed by the current page, weights 400–800, with `font-display: swap`. |
| `assets/fonts/OFL.txt` | SIL Open Font License shipped with Onest; license text preserved, with one trailing space removed (see `ASSETS.md`). |
| `assets/images/*` | Eight original Unsplash crops, each in AVIF/WebP/JPEG at three widths; `social-card.png` is the 1200×630 share image. |
| `favicon.png` | 96×96 raster version of the existing Getzilla checkmark. |
| `robots.txt` | Allows crawling and advertises the canonical sitemap. |
| `sitemap.xml` | The sole canonical page, `https://getzilla.app/`; no invented modification date. |
| `index.html` | The page; upload this **last**, after its referenced assets. |

`ASSETS.md` records exact source URLs, license URLs, retrieval date, dimensions and SHA-256 hashes. The photographs retain their existing alt text, crops and footer credit. Images remain lazy loaded with asynchronous decoding; the hero text uses the principal Latin font preload.

Repository-only material: `template/`, `analytics/`, `screenshots/`, this README, `SERVER-SETUP.md` and `ASSETS.md`. Do not upload these reference snippets, templates, screenshots, reports or docs into the public document root. The analytics snippets are immutable reference copies; the installed tracking code remains inline in the page.

## Analytics and controls

GA4 `G-V2LPCG0E3X` and Yandex.Metrika `113486449` remain immediately after `<meta charset>` in their original order and bytes. The Metrika `<noscript>` pixel remains the first element of `<body>`. Metrika retains Webvisor, click map, link tracking, accurate bounce tracking and the shared `dataLayer`; loading and initialization are unchanged.

The comparison opens on After, using ordinary mutually exclusive pressed buttons. The workflow opens on Build with one tab stop, Left/Right wrapping, Home/End and a focusable panel. Without JavaScript, all six workflow panels remain readable and the inactive controls stay hidden. The main content has a skip link and sticky-header fragment offsets; reduced-motion behavior is retained.

## Reuse the template

Replacing these two placeholders reproduces this site's `index.html` byte for byte:

```bash
sed -e 's/__GA_MEASUREMENT_ID__/G-V2LPCG0E3X/g' \
    -e 's/__YM_COUNTER_ID__/113486449/g' \
    template/index.template.html > index.html
```

For another site, substitute its counter IDs **and** update domain metadata: canonical/`og:url`, social image URLs and copy, WebSite/SoftwareSourceCode URLs and IDs, repository/license facts, `robots.txt` sitemap URL and the sole sitemap location. Update the share image/domain wording as appropriate. Root-relative asset paths assume deployment at the domain root. Do not copy Getzilla's identity or schema facts into an unrelated site.

## Deploy and verify

Follow [SERVER-SETUP.md](SERVER-SETUP.md) for assets-first upload, MIME types, local checks and rollback. Keep a downloaded copy of the actual old production HTML before publishing: the repository base differs from the live page, so a Git revert alone is not a production rollback plan. This patch does not change hosting configuration or claim a live deployment.

Focused regression tests:

```bash
python3 -m unittest tests.test_getzilla_landing tests.test_seo_landing_side_project
```

Local tests establish source and behavior contracts. After deployment, check public asset responses and the real browser network panel for analytics; local test stubs or blocked requests do not establish vendor collection or field performance.
