# Requirements

Typed authority: change-spec.yaml.

## Acceptance criteria
- AC-001: Production and template retain exact GA4/Metrika blocks, script attributes/order, first-body noscript pixel, IDs and settings. The analytics reference files are unchanged.
- AC-002: The page has valid, consistent canonical/social metadata and parseable, fact-backed JSON-LD. Real local favicon/social resources exist. robots.txt and sitemap.xml agree with the single canonical URL.
- AC-003: The same Onest font and eight existing images are served locally with documented provenance, appropriate responsive candidates, intrinsic dimensions and lazy image loading. Referenced files exist.
- AC-004: The existing demo and step navigation support keyboard operation, correct semantic state, visible focus, sensible headings, skip navigation and reduced motion. Workflow content remains available without JavaScript.
- AC-005: The current merged copy, Pricing, layout and template parity are retained; relevant contrast defects are corrected without redesign.
- AC-006: The static release inventory, upload ordering, real validation results and rollback procedure are documented. No build or runtime dependency is added.

## Failure and edge cases
Check missing files, duplicate IDs, invalid ARIA links, no JavaScript, narrow 320px reflow, keyboard wrapping/Home/End, initial After/Build state, same-origin absolute assets, and template substitution. Do not count simulated vendor responses as real collection. Failed or blocked remote checks remain explicitly reported.

## Governance context
No governance rules, deployed policy, protected branch settings, runtime contracts or API/event schemas change. Existing source-only examples and marketing text are preserved. Upstream third-party exclusions have a user-authorized analytics exception; local font and SVG retention follow fix-existing preservation. No claims about field Core Web Vitals, rich-result eligibility, or guaranteed rankings are introduced.

## Non-functional requirements
Security: preserve analytics and avoid unreviewed CSP/framing changes. Reliability: upload assets before HTML; retain old HTML for rollback. Performance: remove external font/photo dependencies and measure Lighthouse lab results with analytics unchanged. Observability: source hashes, focused regression tests, browser findings, Nu validator output and lab report artifacts.
