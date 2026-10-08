# Getzilla landing implementation report

Date: 2026-10-07 UTC. Route: `b1693e9cb114`. Change: `20261007-task-b1693e`.

## Status and exact identities

Implementation complete and locally committed in the isolated worktree `/workspace/scratch/d8e33c67341b/getzilla-seo`, branch `codex/getzilla-seo-v111`. Base is `b7aa0a55f3236c578d4365f3f0e58ce5962cf319`.

Product commits:

- `1b9c70a4a622ba1d5c3d1572e292a003c0c3bdf8` — metadata, crawl/identity/local media assets, controls and deployment docs plus regression tests.
- `7c32ea46b99182ff6e76b47a438c5f4522cb16b7` — failing normal-text contrast regression and narrowly adjusted CTA paragraph color.

Only the sole writer's owned product contour and `tests/test_getzilla_landing.py` were staged/committed. Root's untracked engineering change package remains untouched. No factory/runtime/workflow/version/skill edit, remote write, push, PR, deployment or full verification gate was performed by this implementer. Root owns independent reviews, browser/Nu/Lighthouse findings, evidence and final gate.

## Product behavior and choices

Title retains existing positioning (39 characters). Description is concise and identical across ordinary/Open Graph/Twitter metadata. Canonical, `og:url`, WebSite/SoftwareSourceCode URLs and IDs, robots sitemap URL and sole sitemap location agree on `https://getzilla.app/`. The page declares explicit indexing/preview directives, `og:site_name`, truthful `en_US`, real 1200×630 image dimensions and descriptive alt text, and Twitter large-image metadata. JSON-LD contains only the two fact-backed types, current name/canonical/repository/MIT license; serialization uses JSON encoding and escapes `<`, `>` and `&` for safe script embedding. No dates, reviews, addresses or offers were invented.

`favicon.png` rasterizes the unchanged current 32×32 checkmark geometry and original `#18946F` logo color at 96×96. `social-card.png` renders current page wording/checkmark/Onest typography and dark/green geometry at 1200×630. The rendered PNG was visually inspected: no clipping or missing content. It has no external photograph or new claim.

The original Google Fonts CSS was retrieved with a full Chrome user agent after a shortened user agent returned a legacy TTF response. The retained files are the exact Google-hosted variable WOFF2 Latin and symbols subsets, with original filename/hash provenance. The symbols subset is needed for the existing arrow/check-mark glyphs; Latin covers English text and punctuation. CSS declares Onest 400–800, swap, existing system fallbacks and proper original Unicode ranges. Only Latin is preloaded, after the protected analytics head block. The unchanged upstream OFL file is retained. An optional Python fontTools decoding probe could not run because its Brotli extension is absent; no dependency was installed, and the real files rendered successfully in Chromium for the share card. Root's browser tests cover the actual candidate font use.

All eight exact existing Unsplash crop URLs were downloaded directly. Their returned JPEG dimensions match the original 900×600/1200×900 contracts. Each has AVIF/WebP/JPEG variants at 360,720 and its original width, with no upscaling. Each picture retains its original image identity, crop dimensions and exact alt. Sizes express the actual supplied who/problem/result containers; all images remain lazy and gain async decoding. No below-fold image is preloaded. `ASSETS.md` records exact source/license URLs, retrieval date, source and generated hashes/dimensions/bytes; no photographer attribution was invented. Unsplash footer credit remains.

The comparison uses a labeled native button group, `aria-pressed`, associated named result region and mutually exclusive state; After remains the default. The workflow uses one roving tab stop, Left/Right wrap, Home/End, handled-key preventDefault and focused selection. The visible panel is focusable. All workflow panels are readable without JavaScript; JS-only controls stay hidden until initialization. A focus-visible skip link follows the frozen noscript pixel, main is a named focus target, fragment offsets account for the sticky header, safe-area padding is applied, and reduced-motion handling remains. Heading levels are repaired without changing sizes/weights: demo h2 and its side h3 retain their earlier visual declarations.

Action/text green is darkened to `#127A5B` while the logo and original SVG icon colors/geometry remain unchanged. White action labels are 5.30:1 and green on sand 4.61:1. Light-background muted workflow/card labels use existing soft gray 6.41:1 on white. The original amber step label uses existing dark amber. Monospace comments use a lighter muted gray 6.09:1 on the code background. A direct final calculation found the initial CTA paragraph shade at 4.465:1 even after the action green fix; a failing regression was added, then only that paragraph was lightened to `#DCF5EC` to clear 4.5:1. Current visible main copy is frozen by normalized-text SHA-256 `a3d2060727a295dd57806ecb5ce630d28593d8b6f8dc8ce79529a01035ea4b07`. Pricing, H1, section order and demonstration numbers remain existing copy. The nonexistent Trust CI issue template parameter is replaced by an ordinary issue-request URL with a prefilled title.

README and newly added SERVER-SETUP explain exact public inventory, assets-first/HTML-last upload, MIME/caching guidance, full domain/schema/crawl changes for template reuse and retaining actual old production HTML for rollback. No active hosting file or security/header policy is added.

## Frozen analytics evidence

- Protected head block, immediately after charset: `1014`UTF-8 bytes; SHA-256 `c45825f2f9b0117307fe0fbf5c875ef0b9ab15d19e3cfd481045ef91c47fdb04`.
- First-body noscript block: `130`UTF-8 bytes; SHA-256 `3576068d6e4ac30fc0bc8b3cffe297bec5180da34462409ab106ec00d2f4e679`.
- GA reference snippet SHA-256: `a75449dfef9963ff4973fe7c4bf3438d9f6dd9509ae44642afa3f9b689d9ed39`.
- YM reference snippet SHA-256: `7fe4a102fc407eb3e93e42319ba3a4e1e7aaf17084a472b5620a0bf71a974d25`.

Frozen tests validate exact script bytes (therefore attributes/options/order), immediate locations and GA async source. The analytics reference files have no diff. Template substitution reproduces final production HTML byte for byte and only current GA/YM placeholders remain. No consent gate, postponement, new tracking, minification, framing or CSP change.

## Tests: expected before and actual after

Initial TDD run before product edits:11 tests,2 pass,7 expected failures,2 expected missing-file errors. Tracking and template parity already passed. Failures covered missing social/schema/local media, external fonts, heading outline, request URL and executed interface behavior; robots/setup docs were absent. Full output: `/workspace/scratch/d8e33c67341b/audit-live/failing-getzilla-tests.txt`.

Secondary TDD contrast check failed at 4.464976671382634:1 before the CTA paragraph repair. Full output: `/workspace/scratch/d8e33c67341b/audit-live/failing-cta-contrast-test.txt`.

Final focused command:

```text
python3 -m unittest tests.test_getzilla_landing tests.test_seo_landing_side_project -v
Ran 25 tests
OK (skipped=1)
```

All 14 Getzilla landing tests pass. The adjacent existing skill/showcase module contributes11 tests,10pass and1skip for its absent PATH-discoverable local browser dependency; root independently uses the supplied Chromium executable. Final output: `/workspace/scratch/d8e33c67341b/audit-live/focused-getzilla-tests.txt`.

Coverage includes frozen tracking and template; canonical/social/schema/crawl agreement; real icon/share/font assets; exact source photograph provenance and alts; local absolute references and media signatures; copied current main text/Pricing; unique IDs/heading progression/fragment and ARIA targets; no-JS readability; deployment inventory/rollback; normal-text contrast; actual interface JS executed in Node with click/keyboard/focus assertions. The fake DOM is for the small state behavior contract, not a browser/layout claim. Root's independent real-browser matrix validates rendering and native keyboard behavior.

PIL independently decoded and checked dimensions/hashes of all 72 generated AVIF/WebP/JPEG photographs. No corruption or wrong dimensions. `git diff --check` passes. No final full suite or qualifying gate was run here.

## Asset accounting

- 72 photograph variants: 24 AVIF, 24 WebP, 24 JPEG; `3,122,927`bytes.
- 1 share PNG: `225,006`bytes at 1200×630.
- 2 original WOFF2 files: `51,928`bytes total; 1 unchanged OFL license: `4,384`bytes.
- 1 favicon PNG: `1,366`bytes at 96×96.
- Public upload inventory: `80`files, `3,466,694`bytes, including index/robots/sitemap.

Original source crops and media-generation scratch live outside the candidate in audit-live; originals are identified by hashes/URLs in ASSETS.md. Encoding used sharp with concurrency 1 and two concurrent image pipelines, within the allowed media-worker limit. The product has no runtime/build dependencies.

## Remaining concerns and evidence boundaries

Root's browser/Nu/Lighthouse reviews and final gate are pending at this report writing. Root reported baseline external requests encounter `ERR_CERT_AUTHORITY_INVALID` in the packaged Chromium/proxy environment; untrusted raw before/after performance cannot be described as production improvement. This report makes no live deployment, vendor collection, search visibility or field Core Web Vitals claim. Public URL responses, MIME configuration and analytics collection require post-deploy checks using the existing authorized deployment process.

The template has the required two-placeholder parity but domain reuse is intentionally not just counter substitution: documented metadata/schema/discovery updates are necessary. Stable-name share/favicon/crawl files require revalidation; hashed media can be cached immutably after a separate reviewed host configuration decision. No shipping hosting change occurs.

## Rollback

For source rollback, revert these two product commits on an isolated reviewed branch or restore the known reviewed source. For production rollback, restore the saved actual old production HTML first, keep new hashed assets while cached new HTML may still reference them, then restore stable-name favicon/share/crawl files from the deployment backup when applicable. Never treat the repository base as a live-page backup and never remove unrelated public assets.

## Actual changed file inventory

```text
A	side-projects/getzilla-landing/ASSETS.md
M	side-projects/getzilla-landing/README.md
A	side-projects/getzilla-landing/SERVER-SETUP.md
A	side-projects/getzilla-landing/assets/fonts/OFL.txt
A	side-projects/getzilla-landing/assets/fonts/onest-latin-052df7453325.woff2
A	side-projects/getzilla-landing/assets/fonts/onest-symbols-2ec2d45d2ec0.woff2
A	side-projects/getzilla-landing/assets/images/photo-1521737711867-e3b97375f902-360-276541ffc39e.avif
A	side-projects/getzilla-landing/assets/images/photo-1521737711867-e3b97375f902-360-894b4c7324c6.jpg
A	side-projects/getzilla-landing/assets/images/photo-1521737711867-e3b97375f902-360-ac0747ca306c.webp
A	side-projects/getzilla-landing/assets/images/photo-1521737711867-e3b97375f902-720-26a72fee2d0d.webp
A	side-projects/getzilla-landing/assets/images/photo-1521737711867-e3b97375f902-720-8943617c5f6e.avif
A	side-projects/getzilla-landing/assets/images/photo-1521737711867-e3b97375f902-720-978e50e64353.jpg
A	side-projects/getzilla-landing/assets/images/photo-1521737711867-e3b97375f902-900-3aa5d21ca503.jpg
A	side-projects/getzilla-landing/assets/images/photo-1521737711867-e3b97375f902-900-8401dc84a6c5.webp
A	side-projects/getzilla-landing/assets/images/photo-1521737711867-e3b97375f902-900-f45f83f269d6.avif
A	side-projects/getzilla-landing/assets/images/photo-1542831371-29b0f74f9713-360-02ad40cda18f.avif
A	side-projects/getzilla-landing/assets/images/photo-1542831371-29b0f74f9713-360-2c822144024a.jpg
A	side-projects/getzilla-landing/assets/images/photo-1542831371-29b0f74f9713-360-ecdc86db6ccc.webp
A	side-projects/getzilla-landing/assets/images/photo-1542831371-29b0f74f9713-720-4a8aa6d767b5.avif
A	side-projects/getzilla-landing/assets/images/photo-1542831371-29b0f74f9713-720-8817646e3f69.webp
A	side-projects/getzilla-landing/assets/images/photo-1542831371-29b0f74f9713-720-aa62a7b18fc7.jpg
A	side-projects/getzilla-landing/assets/images/photo-1542831371-29b0f74f9713-900-49074c20fe7b.webp
A	side-projects/getzilla-landing/assets/images/photo-1542831371-29b0f74f9713-900-fcd16787a8cf.jpg
A	side-projects/getzilla-landing/assets/images/photo-1542831371-29b0f74f9713-900-fcee1b50f03a.avif
A	side-projects/getzilla-landing/assets/images/photo-1572021335469-31706a17aaef-1200-2e39988963af.avif
A	side-projects/getzilla-landing/assets/images/photo-1572021335469-31706a17aaef-1200-34df25a89186.webp
A	side-projects/getzilla-landing/assets/images/photo-1572021335469-31706a17aaef-1200-54ea62d1b622.jpg
A	side-projects/getzilla-landing/assets/images/photo-1572021335469-31706a17aaef-360-50422956673a.jpg
A	side-projects/getzilla-landing/assets/images/photo-1572021335469-31706a17aaef-360-dd482bb44514.avif
A	side-projects/getzilla-landing/assets/images/photo-1572021335469-31706a17aaef-360-e1a4f010bdb8.webp
A	side-projects/getzilla-landing/assets/images/photo-1572021335469-31706a17aaef-720-1ba81d90d3ea.jpg
A	side-projects/getzilla-landing/assets/images/photo-1572021335469-31706a17aaef-720-415ebdc142df.webp
A	side-projects/getzilla-landing/assets/images/photo-1572021335469-31706a17aaef-720-73f8bce1c2c9.avif
A	side-projects/getzilla-landing/assets/images/photo-1641355527446-232d7f1f2c10-360-4922f0974eae.avif
A	side-projects/getzilla-landing/assets/images/photo-1641355527446-232d7f1f2c10-360-a052a95876b2.jpg
A	side-projects/getzilla-landing/assets/images/photo-1641355527446-232d7f1f2c10-360-da4b4f8ca03d.webp
A	side-projects/getzilla-landing/assets/images/photo-1641355527446-232d7f1f2c10-720-5d5cad38b9ca.avif
A	side-projects/getzilla-landing/assets/images/photo-1641355527446-232d7f1f2c10-720-7116cb0f5081.webp
A	side-projects/getzilla-landing/assets/images/photo-1641355527446-232d7f1f2c10-720-f9e1b7ba9e9a.jpg
A	side-projects/getzilla-landing/assets/images/photo-1641355527446-232d7f1f2c10-900-381bb2468b8c.jpg
A	side-projects/getzilla-landing/assets/images/photo-1641355527446-232d7f1f2c10-900-724589ad2271.avif
A	side-projects/getzilla-landing/assets/images/photo-1641355527446-232d7f1f2c10-900-9ca6a798ff54.webp
A	side-projects/getzilla-landing/assets/images/photo-1685716851721-7e1419f2db18-360-84ed932850ef.webp
A	side-projects/getzilla-landing/assets/images/photo-1685716851721-7e1419f2db18-360-bda8bc213178.jpg
A	side-projects/getzilla-landing/assets/images/photo-1685716851721-7e1419f2db18-360-c8a694e95701.avif
A	side-projects/getzilla-landing/assets/images/photo-1685716851721-7e1419f2db18-720-0eec7ede1fa6.jpg
A	side-projects/getzilla-landing/assets/images/photo-1685716851721-7e1419f2db18-720-109c823eef98.avif
A	side-projects/getzilla-landing/assets/images/photo-1685716851721-7e1419f2db18-720-1fb65eeb7b1b.webp
A	side-projects/getzilla-landing/assets/images/photo-1685716851721-7e1419f2db18-900-815442fc8eea.jpg
A	side-projects/getzilla-landing/assets/images/photo-1685716851721-7e1419f2db18-900-d52974e2c2dc.webp
A	side-projects/getzilla-landing/assets/images/photo-1685716851721-7e1419f2db18-900-df3370f5514c.avif
A	side-projects/getzilla-landing/assets/images/photo-1717667745852-a5bd6876c1de-360-6618631d8dba.jpg
A	side-projects/getzilla-landing/assets/images/photo-1717667745852-a5bd6876c1de-360-723e381adcfc.avif
A	side-projects/getzilla-landing/assets/images/photo-1717667745852-a5bd6876c1de-360-b958b8c86852.webp
A	side-projects/getzilla-landing/assets/images/photo-1717667745852-a5bd6876c1de-720-4e09ddd3210f.jpg
A	side-projects/getzilla-landing/assets/images/photo-1717667745852-a5bd6876c1de-720-973c93354132.avif
A	side-projects/getzilla-landing/assets/images/photo-1717667745852-a5bd6876c1de-720-d110a58035e4.webp
A	side-projects/getzilla-landing/assets/images/photo-1717667745852-a5bd6876c1de-900-0c2c8bcaba60.webp
A	side-projects/getzilla-landing/assets/images/photo-1717667745852-a5bd6876c1de-900-1a3609fa0d1f.avif
A	side-projects/getzilla-landing/assets/images/photo-1717667745852-a5bd6876c1de-900-e49c80f41522.jpg
A	side-projects/getzilla-landing/assets/images/photo-1726649339367-c2577a28881b-360-3af25041bd9d.webp
A	side-projects/getzilla-landing/assets/images/photo-1726649339367-c2577a28881b-360-b19ec7066d48.avif
A	side-projects/getzilla-landing/assets/images/photo-1726649339367-c2577a28881b-360-de64bc2e3c3f.jpg
A	side-projects/getzilla-landing/assets/images/photo-1726649339367-c2577a28881b-720-526f8bd5615a.avif
A	side-projects/getzilla-landing/assets/images/photo-1726649339367-c2577a28881b-720-6d3a14bafdd9.webp
A	side-projects/getzilla-landing/assets/images/photo-1726649339367-c2577a28881b-720-7df3a80f6223.jpg
A	side-projects/getzilla-landing/assets/images/photo-1726649339367-c2577a28881b-900-1dc80bd38d13.jpg
A	side-projects/getzilla-landing/assets/images/photo-1726649339367-c2577a28881b-900-234a1ac9e63f.webp
A	side-projects/getzilla-landing/assets/images/photo-1726649339367-c2577a28881b-900-cbcab1ba43af.avif
A	side-projects/getzilla-landing/assets/images/photo-1773091258432-da61c63abe41-360-7a0d7394496d.avif
A	side-projects/getzilla-landing/assets/images/photo-1773091258432-da61c63abe41-360-c4d6ce75e635.jpg
A	side-projects/getzilla-landing/assets/images/photo-1773091258432-da61c63abe41-360-e55998213e16.webp
A	side-projects/getzilla-landing/assets/images/photo-1773091258432-da61c63abe41-720-085473903617.jpg
A	side-projects/getzilla-landing/assets/images/photo-1773091258432-da61c63abe41-720-ee05c61d0beb.avif
A	side-projects/getzilla-landing/assets/images/photo-1773091258432-da61c63abe41-720-f4ac1efa5b6a.webp
A	side-projects/getzilla-landing/assets/images/photo-1773091258432-da61c63abe41-900-1ac8445b8a77.jpg
A	side-projects/getzilla-landing/assets/images/photo-1773091258432-da61c63abe41-900-ace47befc814.webp
A	side-projects/getzilla-landing/assets/images/photo-1773091258432-da61c63abe41-900-f64ae8ccbec9.avif
A	side-projects/getzilla-landing/assets/images/social-card.png
A	side-projects/getzilla-landing/favicon.png
M	side-projects/getzilla-landing/index.html
A	side-projects/getzilla-landing/robots.txt
A	side-projects/getzilla-landing/sitemap.xml
M	side-projects/getzilla-landing/template/index.template.html
A	tests/test_getzilla_landing.py
```
