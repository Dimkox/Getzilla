# Test plan

## Bounded observations
Before implementation, record failing focused regressions for missing discovery/social assets and invalid controls. Add tests/test_getzilla_landing.py using the existing unittest discovery. Verify frozen analytics hashes/position, template parity, metadata/JSON-LD/discovery consistency, local assets, same image provenance, links/ARIA, content retention and media declarations.

Run the dedicated unittest module and relevant existing SEO-side-project tests. On committed source, run python3 scripts/getzilla_verify.py --mode fast --no-record --test tests.test_getzilla_landing --budget 180 as a bounded observation.

## Browser and external checks
Use the Nu HTML validator and retain JSON; zero HTML errors, with existing analytics informational warnings preserved. Inspect rendered widths 320, 768, 1280 and 1920; keyboard controls and skip link; reduced motion; disabled JavaScript; images/fonts; no overflow. Run Lighthouse 13.4.1 three times with mobile simulated profile and record category medians and exact tool/browser settings. First-load analytics remain present. Separate deterministic initialization tests from vendor network collection; no dashboard success is implied.

Check live robots/sitemap status and source drift before delivery. Production checks after deployment require the exact public release to be deployed; local HTTP success is not a production claim.

## Reviews and final gate
Two route-selected independent reviewers inspect the frozen product and perform bounded relevant mutation probes in private scratch. Coordinator persists complete reports, commits and freezes the report-containing candidate, then runs one final python3 scripts/getzilla_verify.py --mode pr with the measured CPU allocation. Do not change verification scope to hide unrelated baseline failures. Exact-head external GitHub checks and required approvals govern merge separately.
