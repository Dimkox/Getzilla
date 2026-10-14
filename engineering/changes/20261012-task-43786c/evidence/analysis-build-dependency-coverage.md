# Build dependency coverage

Read-only analysis of the dirty candidate under route 43786cadd549; base 540c12f93e798c2f483455a5086ab0018ac3216e. No tests ran. This is design evidence, not independent approval of the repair.

- Confirmed source gap: `_pairs_from_pyproject` reads project dependencies and optional groups but omits build-system.requires. Factory and delivery currently pin setuptools75.8.0; trust-ci already pins84.0.0. The two CVE classifications come from the security analysis; this report does not independently establish advisory fixed ranges.
- Add build-system exact pins to the existing PyPI dependency collector. Keep name normalization, manifest provenance, deduplication, exclusions and offline/online scanner paths unchanged. Build dependencies execute during package creation, so they belong in the dependency audit even when runtime dependencies are empty.
- Validate build-system as a table and requires as a list of strings. Reject malformed shapes through VulnerabilityError rather than silently dropping them or stringifying objects. A missing build-system is valid. Keep the existing exact-pin scope: ranges and direct URLs are not invented resolved versions. Disclose that transitive, unresolved and dynamic backend requirements remain outside this collector.
- Align factory/delivery pins with existing trust-ci84.0.0 only after security evidence confirms both advisory ranges exclude that version. No deployed Trust CI policy, service or environment changes are part of this repair. Packaging backend remains setuptools.build_meta; Python minimum remains3.11.

Acceptance: a build-only pyproject yields the expected PyPI pin and source manifest; mixed project/optional/build requirements retain all exact pins; duplicates collapse only within the same manifest; all three real pyprojects expose setuptools84.0.0 after repair. Null, string, numeric and mixed-list requires shapes fail closed; absent build table stays valid. Offline advisory fixtures detect the old vulnerable version and do not match the verified fixed version, with HIGH/MEDIUM severity preserved. A mutant removing build-system collection must fail its regression. Scanner failure or missing advisory source remains a gap, never a vulnerability-free PASS.

Compatibility: build factory/delivery wheels in private scratch using the new backend. Check entry points and factory resource files are retained. Use offline cached dependencies where available; do not fetch secrets or deploy. Include the parser and backend pins in full PR scope, fresh independent reviews and exact-head gates; this executable change cannot use docs-focused admission.

Recovery: revert parser and pin changes together through a reviewed PR only when security permits; do not routinely restore a known vulnerable backend. A packaging incompatibility can instead use a separately verified non-vulnerable pin. Keep provider activation, runtime authority and trust boundaries unchanged.

reviewed-tree-modified: no
