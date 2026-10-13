Result: INCOMPLETE for “all databases”. Public checks confirm two affected build-pin CVEs. Paid and private provider coverage remains NOT RUN. This report approves no dirty source candidate.

| Provider | Observed scope | Result and limit |
|---|---|---|
| OSV API | Fresh union of47 exact PyPI versions: original scanner26, omitted build/tool pins, resolved Trust CI/runner40 | HTTP200,47results. setuptools75.8.0 has4 alias records representing CVE-2025-47273 and CVE-2026-59890. Other pairs had zero records. OSV aggregation is not independent upstream coverage. |
| GitHub Advisory API | Same47 pairs; reviewed, unreviewed and malware modes; authenticated existing gh access; pagination |2reviewed advisories, both setuptools75.8.0. Zero unreviewed/malware. No credential values read. |
| Snyk public |26 original exact-version pages plus setuptools75.8.0 and both found advisories | Public pages confirm both findings. Original26pages show no advisory-ID references. Remaining union versions not scanned through Snyk engine. No paid/authenticated Snyk scan. |
| NVD | One setuptools keyword query,5records; analyzed CPE ranges inspected | Confirms setuptools <78.1.1 and <83.0.0. No exhaustive47-package CPE mapping. Keyword absence never treated as PASS. Awaiting-analysis records and missing CPEs remain limits. |
| CVE.org / official CVEListV5 | Official CVEProject raw CNA JSON for the two found CVEs | Both PUBLISHED. Affected setuptools ranges independently match75.8.0. CVE records are identifiers/advisories, not an exhaustive package resolver. |
| CISA KEV | Full feed1739entries; feed date2026-10-08T20:09:18.9833Z | Neither found CVE is listed. This is known-exploitation coverage only; no safety inference. |
| GitLab public GLAD |42union package names:16HTTP200 index pages,26HTTP404.124linked public advisory pages fetched successfully | Bounded prose range evaluation makes132package/version comparisons. Only the two known setuptools findings match. Four pages state Affected versions None and are separately crosschecked.404pages, index pagination/completeness and private GLAD/GLAM coverage remain limits. This is not the full licensed database. |
| Sonatype Guide / OSS Index | Official migration/PAT docs; one unauthenticated GET for setuptools75.8.0 component report | HTTP401. No PAT/account credential available in named env presence checks. NOT RUN for exact inventory. Do not bypass auth or interpret401as clean. |
| Safety | Official authentication/API-key docs; public data.safetycli.com landing page | Landing HTTP200 is not database access. No Safety API key/CLI access established. Paid/authenticated scan NOT RUN. |
| Flashpoint VulnDB | Official login/subscription pages | Login page HTTP200, no authorized database session/API key established. Paid database NOT RUN. |
| Vulners | Official private endpoint API-key docs; one public CVE page | Public page HTTP403. No API key presence. Package/CPE engine and private/archive feeds NOT RUN. |
| Other commercial/private/vendor databases | No defined inventory of every database or authorized access | NOT RUN. No claim of universal coverage. No subscription purchased. |

Findings:
- HIGH per GitHub: factory and delivery build-system setuptools75.8.0 matches CVE-2025-47273 / GHSA-5rjg-fvgr-3xxf (<78.1.1). Snyk rates this advisory MEDIUM6.8; the severity difference is disclosed. https://github.com/advisories/GHSA-5rjg-fvgr-3xxf
- MEDIUM: same build pin matches CVE-2026-59890 / GHSA-h35f-9h28-mq5c (<83.0.0). macOS Unicode filesystem behavior is a stated exposure condition. https://github.com/advisories/GHSA-h35f-9h28-mq5c
- The historical scanner ignored build-system.requires. Writer received the exact findings. Source repairs and scanner expansion are pending independent review. No proof of exploitation or deployed exposure was claimed.

Source identity and boundaries:
Inventory source main540c12f93e798c2f483455a5086ab0018ac3216e. Source candidate4bf48f5832bac54d08b9666a2354703ce2a03e9d has active writer changes. Original inventory manifests and scanner bytes were confirmed identical before the writer's dependency repair. Trust CI/runner resolution: uv0.11.12, Python3.12.3, Linuxx86_64, explicit public PyPI, no install or build. Graphs are current resolutions, not deployed SBOMs. OS/image layers, wheel-bundled native libraries, other platforms/Python versions, dynamic build requirements and current deployed state remain unscanned. No source changes, code uploads, secrets, private keys or production writes occurred.
reviewed-tree-modified: no
Mutation: skipped; this follow-up is provider metadata analysis, not a code approval.

Evidence and exact commands:
- provider-union-inventory.json:47pairs. provider-union-osv-gh.json: complete OSV/GH requests and responses; gh api --paginate --slurp with exact affects=package@version list.
- provider-public-probes.py; command python3 -B .getzilla/runtime/reviews/20261012-codex/provider-public-probes.py. provider-public-evidence.json:45requests with URLs/status/errors; raw files provider-*.raw include full CISAfeed and CVEListJSON. Env credential presence only: SNYK_TOKEN, SAFETY_API_KEY, SONATYPE_TOKEN, SONATYPE_API_TOKEN, OSS_INDEX_TOKEN, VULNERS_API_KEY, VULNDB_API_KEY all false. Values were never printed/read from files.
- gitlab-advisory-probe.py; command python3 -B .getzilla/runtime/reviews/20261012-codex/gitlab-advisory-probe.py. provider-gitlab-paths.json / provider-gitlab-advisory-metadata.json preserve124URLs, affected prose and source links. Raw advisory HTML is saved.
- gitlab-range-check.py; command python3 -B .getzilla/runtime/reviews/20261012-codex/gitlab-range-check.py. provider-gitlab-range-results.json preserves132comparisons, ranges, two matches and four unparsed records. Parser supports only stated before/start-before/up-to intervals and never treats unknown prose as clean.
- provider-auth-feasibility.json: exact Sonatype401, Vulners403, Safety landing200, VulnDB login200 observations. No retry or auth bypass was attempted.
- advisory-coverage-security-report.md and transitive-resolution/ preserve preceding graph resolution, original inventory audit and raw results.

Provider access contracts:
GitHub https://docs.github.com/en/rest/security-advisories/global-advisories
Sonatype https://help.sonatype.com/en/using-guide-personal-access-tokens-with-oss-index-api-integrations.html
Safety https://docs.safetycli.com/safety-docs/safety-cli/scanning-for-vulnerable-and-malicious-packages/available-commands-and-inputs
Vulners https://docs.vulners.com/docs/api/
VulnDB https://vulndb.flashpoint.io/users/sign_in
GitLab editions https://docs.gitlab.com/user/application_security/gitlab_advisory_database/
Paid access requires the owner's existing account entitlement and approved authentication. A public provider page never substitutes for a licensed inventory scan.

GitLab unparsed-page crosscheck: all four GHSA records were retrieved through gh api advisories/<id>. None is withdrawn. GitLab public affected prose is None, so those pages remain inconclusive in the GitLab range parser. GitHub exact-version union checks are separate evidence. Full source metadata is in provider-gitlab-unparsed-gh-crosscheck.json. No additional confirmed affected pin was found.
