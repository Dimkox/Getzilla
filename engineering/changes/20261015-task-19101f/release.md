# Release and audit status

Default rollout is auto/shadow. Enabling blocking requires a pinned compatible image,
working dependency closure, actual SDK smoke and project review. No global blocking default.
No release or deployed-image change is part of this local implementation.

Security data updated separately on 2026-10-15: OSV PyPI, npm, Go, crates.io, Packagist,
RubyGems; Trivy vulnerability DBv2 and misconfiguration bundle.
Self-audit of base7cf4f65 covered38 pinned entries across5 manifests and found0 known CVEs.
Trivy reported0 vulnerability findings and0 secrets, one HIGH DS-0002 root-user image finding,
and four LOW DS-0026 missing health checks. This is not a claim that Getzilla has no security risk.
Loose-file license scan found six MIT records and one OFL-1.1 font record classified UNKNOWN.
Dependency license coverage is incomplete; no owner denylist was supplied or invented.
SPDX3.29.0 catalogs were read:740 licenses and86 exceptions. Local persistence was blocked
by the earlier hook circuit and is not reported as installed. Raw scan data stays outside Git.

Latest fetched main:7cf4f65dd2ba9bb1390dc84c6185ba0f104255c8, mergePR81 SECURITY.md.
Prior merge:bf44834, PR79 command-hook/scanner fixes. No open PR was present at inspection.
Independent reviews, local final gate and exact-head public Actions remain required.
