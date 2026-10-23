# Read-only analysis

Route: 5311cdded150. HEAD/base: 8a02bab3d3e2a4e4cf8e023068a9652cbb89a5be. Tree: d728995aa1153ab52e88e3d8d82dedbe37d0e0aa.

PR127 merged at ea481a9e3b1a9185b9e7137a933fdcf7c6eb9dac on 2026-10-22, final head865c26e26ba0c78828cc01475002e4ec9539150c. Its override applies only to that PR.
Deferred: disposable PostgreSQL exit, clean-HEAD smoke, test/security/release reviews. Historical reports bind ccfe4a40. decisions.md records system-Python selection. mistakes.md records the old certifi inventory mismatch missed by the narrow test set.
Run committed smoke, bounded controls, all selected reviews, save complete reports, freeze and final full PR verification. Source changes invalidate evidence.
Current route selects code/test/security but not release. Keep the historical release obligation explicit; do not spawn an unselected reviewer. This successor publishes no release.
Live protection requires linux/windows from Actions App15368 and resolved conversations.
Issue122 defers six Low negative-test gaps: local verifier, role/date validation, matrix URL schemes, attestation identity and provider-cache independence. Issue134 defers updater/fsx Low findings, including EU updates omitted from planned_changes. Keep Low work separate.
Sources: https://github.com/Dimkox/Getzilla/pull/127 ; https://github.com/Dimkox/Getzilla/issues/122 ; https://github.com/Dimkox/Getzilla/issues/134 .
No tests or writes. reviewed-tree-modified: no
