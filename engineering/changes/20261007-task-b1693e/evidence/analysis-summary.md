# Route analysis synthesis

Route b1693e9cb114; base b7aa0a55f3236c578d4365f3f0e58ce5962cf319. All five selected analysis roles completed read-only inspections before the sole product writer was dispatched. This file is a coordinator synthesis, not a substitute for the later independent review reports.

| Role | Finding and decision |
| --- | --- |
| repo_explorer | Static index/template have no dedicated tests or build. Existing tests target only skill/showcase. Add tests/test_getzilla_landing.py; existing CI discovers it. The focused-static selector does not admit this landing path, so retain full PR gate. Missing Trust CI issue template parameter should be removed without creating unrelated workflow files. |
| task_analyst | Analytics/template parity, one H1 and unique IDs are existing invariants. Repair social metadata/structured data, compare-button semantics, workflow keyboard handling, no-JS hidden content, skip link, heading outline and measured low contrast. Preserve current merged Pricing/content. |
| architect | Keep static inline architecture. Self-host actual Onest bytes and eight source crops with correct sizes. Use actual icon geometry for a96px favicon and current page wording/design for a1200x630 social image. Do not add runtime dependencies. |
| docs_researcher | Google Fonts Onest v11 Latin WOFF2 is https://fonts.gstatic.com/s/onest/v11/gNMKW3F-SZuj7xmf-HY.woff2; actual CSS weights use the same variable file. Retain the full official OFL.txt. Unsplash standard license permits static commercial-page reuse; no API integration is present. Preserve exact image IDs/crops; photographer identities were not established and must not be invented. |
| integration_architect | Head tracking block1014bytes and first-body noscript130bytes exactly match live. Their baseline hashes are in baseline.json. Deploy local dependencies first and index last. Actual live HTML differs from Git base, so retain actual host HTML for rollback. Keep hosting snippets inert; CSP/framing changes could affect replay. |

## Source references
- Upstream skill/spec: https://github.com/aleksandr-alhoff/seo-landing/tree/1aa908f96a09e2e93fd1839ac51b02d362e7a8ef
- Onest license: https://github.com/google/fonts/blob/main/ofl/onest/OFL.txt
- Google Fonts CSS API: https://developers.google.com/fonts/docs/css2
- Unsplash license and terms: https://unsplash.com/license ; https://unsplash.com/terms
- Yandex CSP/replay requirements: https://yandex.ru/support/metrica/en/code/install-counter-csp ; https://yandex.com/support/metrica/en/behavior/web-forms
- LiteSpeed Apache compatibility: https://docs.litespeedtech.com/lsws/configuration/

## Baseline evidence
Nu validator produced three errors: malformed favicon data URL; selected tab without a panel; h1-to-h3 heading jump. Its analytics type/trailing-slash messages are informational and must remain rather than change protected tracking bytes. Live robots.txt, sitemap.xml and favicon.ico each returned404. Existing data-URI favicon is separately present but invalid as written. Source/live drift consists of the already merged Pricing section/nav/styles and corresponding CTA-band spacing.

## Bounded rulings
Analytics preservation overrides incompatible generation-only requirements. Current merged site copy supersedes older chat marketing positioning for this patch. Onest and existing SVG icons stay because this is fix-existing work. No translation URLs, invented FAQ/rating/price facts, or legal entity claims are created. No dynamic API/event contract exists to change; the route's repository-wide API inference does not expand scope.

## Tool environment observations
The container has eight effective CPU cores and four model slots. Each exec command has its own network namespace, so local HTTP server and browser/test process must start within the same command; separate persisted servers are unreachable. Playwright's packaged browser download produced malformed archives; Chromium153.0.8010.0 from the pinned standard npm package @sparticuz/chromium153.0.0 was decoded into private task scratch, without changing product dependencies or sandbox/network controls. Remote requests use the provided network proxy. These are validation-environment facts, not site defects.
