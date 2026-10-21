Read-only repository analysis — 2026-10-21 — route d834158878e0.

Source: e158ddc7263a55f5308944c5a426eb1e9f1a4327; tree: 9a7fb672e44de0d3d87e37a70fa4861d37681ce6. Root: /home/pall/projects/liqvera/.getzilla/runtime/getzilla-dispositions. HEAD equals origin/main; nearest published tag is v2.3.0. Git status showed only the new untracked change package. Worktrees were inventoried without cleanup. Discovery used lightweight reads only; no tests, network, source edits or live operations ran. Assigned discovery capacity was at most one CPU.

Existing integration

- .getzilla/getzilla/verification.py:1257 implements _git_diff_check. It runs worktree, index and every admitted committed comparison range. It preserves labeled Git stdout/stderr and fails for any nonzero command or range-selection finding. Exceptions must retain all ranges and raw diagnostics.
- verification.py:1323 implements _secret_scan. It currently emits one finding per rule/file with pattern.search, with no match position or digest. Rules are private-key, aws-access-key and generic-secret. The generic rule also matches public token constants. An exception at rule/file level would be unsafe: one approved address could hide a second real secret in that file.
- CheckResult and its to_dict method already carry details, stdout and stderr. Preserve raw findings there and add explicit disposition identity/status; derive the final check outcome only from remaining undispositioned findings and validation errors. Do not delete raw findings or convert the mandatory check to skip.
- .getzilla/getzilla/quality_gates.py:12 requires secret-scan and git-diff-check for PR admission. No new skip exemption or weaker mandatory-check list is needed. Existing source-stability/fingerprint and receipt logic must continue to qualify the exact tree, including the consumer disposition file and its evidence.
- No existing narrow reviewed disposition mechanism was found in these two check paths. This report recommends an optional closed-format policy, not an existing supported configuration.

Minimal implementation surface

1. Change .getzilla/getzilla/verification.py at the two existing checks. Enumerate each generic match, attach stable rule/path/content/match identity without printing its value, and apply validated dispositions after retaining the raw finding. Parse Git diagnostics conservatively: only the exact reviewed Markdown new-blank-line-at-EOF finding may qualify. Unknown diagnostics, other whitespace, process failures, unsafe names and range errors remain failures.
2. Add one small helper, for example .getzilla/getzilla/verification_dispositions.py, to validate and apply an optional tracked consumer policy. Use a closed schema, bounded regular-file reads, canonical repository-relative paths and exact SHA-256 identities. Missing policy keeps current behavior. Malformed, duplicate, stale, unused, unknown-kind or unsafe entries fail closed; symlinks, traversal, absolute paths and executable evidence are rejected.
3. Add focused tests/test_verification_dispositions.py and integration cases in tests/test_verification_doctor.py. Existing secret detection and divergent-range tests must remain intact. Extend tests/test_manifest_package.py to prove that the helper and any inert example/documentation are shipped.
4. Add brief policy documentation and, if useful, an inert example under .getzilla/templates. Do not ship Liqvera-specific approvals as Getzilla defaults. Keep the actual two-address/one-EOF consumer policy in the Liqvera audit source tree, with review provenance and hash bindings. An implementation choice is .getzilla/config/verification-dispositions.json; final naming belongs to the implementation owner.

Disposition constraints

- Bind every entry to exact check, rule/kind, canonical path and full file SHA-256. Bind generic matches additionally to position and match/value digest so multiple findings cannot collapse into one approval. A changed byte or moved/added match must require fresh review.
- Public-address eligibility must be explicit and narrow: the two reviewed 0x-prefixed, 40-hex-digit public MUSD contract addresses. Do not allow arbitrary generic credentials, 64-digit private-key-shaped values, private-key headers, AWS keys, path globs, whole-directory ignores or unchecked regex exclusions. Never exempt the private-key or aws-access-key rules.
- The EOF disposition must name an immutable regular nonexecutable Markdown file, exact bytes and the single EOF rule. Keep its historical origin/review provenance. It must not cover trailing spaces elsewhere, added content, executable code, another path or an arbitrary failed git command.
- Store reason and independently reviewed evidence path/digest with the policy. A free-form reviewed_by string is not independent review or execution authority. Preserve the usual exact-source review and receipt workflow; the disposition file is source, not a saved-report-only delta.
- Do not log matched secret values. Raw diagnostics can retain rule/path/position/digest and Git output; public evidence should explain the reviewed false positive without weakening genuine-secret handling.

Meaningful tests

- Valid exact public-address dispositions yield pass while preserving two raw findings and their disposition records; one additional genuine secret in either file still fails.
- Missing policy preserves the old failure; stale file or match hash, duplicate entries, unused entries, unknown fields/kinds/rules, malformed hashes, missing/changed review evidence, symlink policy/target/evidence, traversal and absolute paths fail.
- Private-key and AWS-key findings always fail, even with a forged matching policy. A non-address generic credential and private-key-shaped hexadecimal value cannot qualify.
- The reviewed Markdown EOF warning can qualify while its raw Git output remains visible. Other whitespace in the same or another file, changed historical bytes, executable Markdown, staged/worktree changes and mixed accepted/unaccepted warnings still fail.
- Preserve route and PR-target range coverage, invalid/ambiguous-base failures and Git errors. Reuse tests/test_verification_doctor.py:687, :828, :856, :880 and :931 rather than replacing range logic.
- Verify JSON serialization, final check status and unchanged mandatory quality admission. Change the policy/evidence after verification and confirm normal source fingerprint/receipt invalidation.
- Package and installed/external consumer tests must show that the new helper is available and that no active consumer approvals leak into a release archive or unrelated installation.

Packaging and commands

.getzilla/getzilla/manifest.py discovers eligible files and excludes runtime state and secret paths. scripts/package_stack.py snapshots clean committed source and uses that manifest. scripts/install_into.py manages the whole .getzilla directory, so a helper/template there normally needs no individual managed-file entry. A new top-level schema or CLI would need its own MANAGED_FILES entry; avoid adding those unless needed. Do not weaken manifest exclusions to carry policy evidence. Existing tests/test_manifest_package.py:265 provides the tooling/template inclusion-test pattern.

Bounded implementation checks, before review: python3 -m unittest tests.test_verification_dispositions tests.test_verification_doctor tests.test_quality_gates tests.test_manifest_package. The new module name is proposed. Use the controller's measured worker allocation for broader runs; do not allocate 26 workers to this read-only analysis.

After the selected independent reports are complete, saved and committed, freeze the candidate and run one qualifying gate from the Getzilla worktree: GETZILLA_TEST_WORKERS=26 python3 scripts/getzilla_verify.py --mode pr --full-scope --keep-going --json. Use 26 only if the controller still assigns the full measured capacity. Set online OSV or a current offline database explicitly as appropriate; preserve all raw results. Then record passing exact-source review receipts for code_review, test_review, security_review and release_review using scripts/getzilla_review.py with --reviewed-commit <exact-full-sha>, and run python3 scripts/getzilla_status.py. Exit zero alone is insufficient: status must report zero evidence gaps.

Run the corresponding single final qualifying gate from the frozen Liqvera audit checkout with the newly pinned external Getzilla script, preserving Liqvera's original comparison base, full scope, native product checks and supplemental lock/image security coverage. Apply only the three approved hash-bound dispositions there. Do not rewrite immutable Markdown to satisfy lint. Do not use a previous candidate's receipts. The normal Getzilla Makefile verify target is python3 scripts/getzilla_verify.py --mode pr; explicit full-scope/JSON above preserves the audit requirements.

Packaging verification when a package is produced: python3 scripts/package_stack.py --output <task-owned-runtime-release.zip>; verify its manifest/extracted package with the existing manifest/package tests and scripts/verify_manifest.py where MANIFEST.sha256 exists. Packaging writes a local artifact and is separate from publication. No package or publication was performed by this analysis.
