# Architecture

The existing static HTML, inline critical CSS and small interaction script remain the deployment architecture. Self-hosted WOFF2 and responsive images are prebuilt repository assets; no production Node/Python process is required. Canonical/social/schema/discovery references use https://getzilla.app/; local assets use the site-root paths. The two-ID template remains a reusable copy and must render byte-identically to production.

The analytics boundary is frozen: charset, GA4 external and inline scripts, Metrika loader/init, then metadata/styles; Metrika noscript remains the first body element. New JSON-LD is non-executable. No code is inserted before the current analytics initialization. Photo and font changes exclude all tracking resources.

A stable raster favicon reuses the existing mark; social imagery reuses existing page design and wording. ASSETS.md records sources/licenses/hashes. Optional LiteSpeed/Apache guidance is inert and excludes CSP, X-Frame-Options, HSTS and broad rewrite changes. Existing production host configuration is not available and must not be overwritten blindly.

The route's API skill is not applicable to this product surface: no producer, consumer, endpoint, auth, event or data contract changes. Full PR verification remains required because this product directory is outside the focused static-landing allow-list.
