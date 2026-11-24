# Docs, Low findings and release acceptance

Route e2e30c9f2878. Candidate6dd06ff5b96692a01812fbac6252fd08f6169f91; base540c12f93e798c2f483455a5086ab0018ac3216e. Static read-only analysis of supplied issue snapshot/comments and actual source. No tests, provider calls, credentials or candidate edits. reviewed-tree-modified: no.

## Issue63 clause map

1. Installer verification: already implemented. README/QUICKSTART use pinned published tag, published SHA256 and conditional execution; tests/test_structure.py binds installer instructions/digests. Keep shipped installer bytes unchanged. Third-party agent installer examples are a separate supply-chain scope.
2. Signature failure/digest reset: alleged exact troubleshooting instruction was not found in current QUICKSTART/reference/rollout. Add explicit stop/preserve evidence/investigate guidance; never refresh trusted holdout digests to make a failed signature pass. Any legitimate deployed policy/holdout rotation remains a separately authorized operator action.
3. Reviewer independence: AGENTS, canonical reviewer TOML, delivery/verification skills already require independent read-only review, candidate identity and private mutation scratch. Add short residual-risk statement: another agent using the same model can share correlated mistakes; workflow configuration is not OS isolation.
4. Threat model: trust-ci/README Trust boundary already separates trusted server state/images/keys from malicious PR bytes/local receipts. Add explicit compromised-agent/insider cases and public Actions limitation to current reference; source tests cannot certify their own external authority.
5. Ed25519 custody: trust-ci/README identifies CI signing private key only in worker and human public store only in API; AGENTS forbids human private-key access. Rotation/custodian procedure remains undocumented in current reference. Document operator roles, revoke/replace public identities and fresh policy/exact-head checks without key values or commands that access private keys. Actual deployed custody/rotation acceptance is human/operator-only and unobserved.
6. Bad-main recovery: existing L5 runbooks cover provider/SQLite recovery, not a concise repository incident response. Add stop release/deploy, retain SHA/logs, reviewed revert PR, fresh exact-head checks; deployed rollback needs exact target grant and operator-owned recovery proof. No force reset or automatic replay.
7. Test metrics: .coveragerc fail_under74 is source truth. Historical issue72 comment records1559Core and2skips on89b131e, not current candidate counts. Document exact dated test evidence and scratch mutation reports; never claim current PASS/count without final run.
8. SBOM/dependencies/version: reference lists optional Syft; toolchain lock/model and runtime pins exist. Add bounded policy: optional SBOM means not generated/verified by default; pin/security-update scope, source-vs-release distinction and immutable exact merged artifact provenance. No new service/tool required.
9. Autonomy glossary: distinguish milestonesM0–M8 from permission levelsL0–L5. Reference currently documents bounded M8 L1 local reads/tests, L2 ceiling; no general deployedL5 proof. Add compact milestone mapping from DARK_FACTORY_ROADMAP, preserve empiricalM7/M9 limitations.
10. File map: README current canonical/generated map already exists. Bind docs to .grok configuration/agents, .agents canonical skills, generated .grok/skills plus qwen/claude/gemini mirrors, codex/github shared canonical skills. No machine-specific consumer paths.

Minimal doc repair surfaces: docs/REFERENCE.md for security/operation/glossary section; QUICKSTART troubleshooting pointer; trust-ci/README.md operator-custody/rotation boundary if needed. Root README only pointers/current identity. Binding tests in tests/test_structure.py should check meaningful invariants, not prose duplication.

## Issue73 complete accumulated items (body plus three comments)

- Ancestry isolation STILL MISSING: tests/test_review_source.py::test_rejects_nonancestor edits source.py after orphan checkout. Use identical-tree unrelated commit; require ancestry-specific denial and mutant kill.
- Frozen-state doc mismatch: reference at589 has correct reviewing rule but older numbered workflow must be reconciled with it. Remove any ready transition after freeze; update public/private CI wording in that same sequence.
- Unsafe selected metadata fallback STILL MASKED: test_micro_unsafe_selected_metadata_does_not_fall_back uses package report from fixture. Use committed conventional engineering/reviews/code-review.md on micro route so report-location rejection cannot hide safe-read error discrimination. Assert intended reason and kill error-fallback mutant.
- Current/installed Codex launcher denial STILL WEAK: test_installed_codex_launcher_checks_native_cmd asserts permissionDecision deny only. Assert intended command/policy classification; empty normalized command must fail the regression for the intended reason, not unrelated root denial.
- Workdir propagation STILL MASKED: test_codex_cmd_respects_command_workdir uses push plus generic deny. Supply discriminating root/grant fixture and expected root reason; removing workdir must alter outcome. Direct field-preservation test alone is insufficient end-to-end.
- OSV endpoints STILL need independent edge assertions: architecture/system.yaml declares EDGE-SCANNER-OSV-QUERY and EDGE-SCANNER-OSV-MIRROR-DOWNLOAD, both from NODE-LOCAL-VULNERABILITY-SCANNER. Assert each destination/contract separately in architecture regression so either single-edge deletion fails. Do not claim runtime enforced host allowlist. Existing HTTPS-family/ownership checks are insufficient.

These are current test-strength/doc gaps, not observed runtime bypasses. One scoped repair should cover all six Low items. Issue61 is closed by74; do not reopen it.

## Issue72 evidence and missing human decisions

Supplied comments record PR74 merged05f85f12b72b3a897c45c24e172fac8317120b7c, treeea0e67c678c90764196dadce09910954d6be0371; local immutable tag v2.2.1 resolves to those same identities. Published timestamp2026-10-09T03:47:35Z and ZIPdigest0eb872f02f96f246965004637c2c1d6b32cadb988b6c84513a55b251f7fefc68 are recorded publication evidence. Comments separately record640installed-file hashes/doctor/parity/overwrite refusal. These remain historical exact-source observations, not current all-issues verification or live production proof.

Missing human-only inputs: exact target environment/repository and autonomous business task; scoped production deploy/external mutation authority if task needs them; authentication/2FA where required; signed security approvals outside agent environment if external policy demands them. Success/error signal criteria, target-specific recovery procedure and actual acceptance must then be recorded against the installed exact source. Owner all-issues scope permits source repairs; it supplies no unspecified production target or deploy authority. Source/release portion can complete while production acceptance remains explicit NO-GO/unproved.

Additional current prose defect: reference88 still calls predecessor v2.1.1 the published release outside a historical section. Refresh together with pendingrelease2.2.2 current identity; preserve historical records/asset hashes.

Commands: supplied JSON body/comment extraction; rg/sed source/tests/runbooks; git rev-parse HEAD and v2.2.1 commit/tree. No full gate or new completion claim.
