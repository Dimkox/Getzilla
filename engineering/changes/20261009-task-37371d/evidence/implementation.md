# Issue72 bounded source implementation

Source repair for issue61 and current Getzilla handoff. Base 5d5b45f42f8a9f2bc0303b4d16b5d4e54caad5b9; branch readiness/72-production-20261009; route 37371d21accb. No production, deployed policy, provider, daemon, push or publication effects.

Root cause: PASS review receipts identified the recorder's HEAD, not the source the independent reviewer inspected. The core now requires an exact reviewed commit for PASS, derives reviewed/frozen tree identities, requires ancestry and a clean committed candidate, and permits only six conventional independent report filenames directly under active evidence. Git mode 100644, safe regular filesystem entries and UTF-8 Markdown are required. Source, dirty/untracked/staged files, deletion/rename, unsafe prior entries, symlinks, executable evidence, analysis/index/checkpoint files and arbitrary report locations deny. CLI requires --reviewed-commit; failure observations need no fake reviewed identity. validate_evidence and status rederive the entire source binding and reject missing/legacy/mismatched fields. Existing atomic publication and spec/architecture/governance binding remain.

Local receipts remain mutable workflow evidence, not authenticated reviewer identity, external attestation or merge authority. A consistent local record cannot prove a real independent reviewer executed its claims; selected independent reports and exact-head external gates remain required.

Current source is 2.2.1 candidate. Published Getzilla v2.2.0 remains immutable at 5d5b45f / tree 0f6fa49 with zero assets, observed through release API. Predecessor identity, v2.1.1 publication and M8 continuation are archived without changed facts. START_HERE/PROJECT_STATE now point to issue72 and native harness execution. Current docs follow conditional L5 and one final PR verifier. Explicit owner overrides of local workflow rules must be recorded and remain UNVERIFIED until deferred checks run. No check was waived.

Official lifecycle reached reviewing before review. Tracked state remains frozen there. Actual final receipts, zero status gaps and exact-head PR gates record completion without a post-freeze ready mutation; workflow-ruling.md records the bounded decision. Existing Windows PR step now includes the new review-source module; pins, permissions and triggers are unchanged. Git executable-mode refusal is tested independently of POSIX chmod. Native Windows qualification remains pending external CI.

RED before implementation: taskset -c 0-11 python3 -m unittest tests.test_review_source -q. Initial 8 tests failed: missing reviewed identity was accepted (one assertion failure); the new reviewed_commit API was absent (21 subtest errors). This exposed the actual admission gap before repair.

Bounded GREEN observations (no qualifying PR receipt):
- taskset -c 0-3 python3 -m unittest tests.test_review_source tests.test_change_receipts tests.test_package_status tests.test_hooks tests.test_verifier_recovery -q: 152 tests PASS 140.532s. This run preceded the additional portable Git-mode test, covered below.
- taskset -c 4-7 python3 -m unittest tests.test_project_state tests.test_structure tests.test_harnesses tests.test_workflow_sources tests.test_repo_router -q: 136 tests PASS 4.571s.
- taskset -c 8-11 python3 -m unittest tests.test_manifest_package tests.test_installer -q: 98 tests PASS 50.837s.
- taskset -c 8-11 python3 -m unittest tests.test_review_source tests.test_structure tests.test_ci_gate -q: 70 tests PASS 8.702s, including portable Git-mode refusal and Windows step binding.
- python3 -m ruff check <all changed Python source/test paths>: PASS.
- git diff --check: PASS.
- python3 scripts/getzilla_harness.py --write: regenerated only canonical changed skill copies.

Three serial unittest processes at most ran concurrently on disjoint CPU 0-3/4-7/8-11 allocations; total test workers stayed below 4. No full PR verifier ran. A clean committed-HEAD named fast observation follows this implementation commit and is returned out-of-band; it creates no receipt. Independent selected reviews, report freeze, one final full PR verifier and exact-head external checks still remain.

Recovery: revert the isolated source commit through a new reviewed change; never reuse stale receipts. Legacy PASS receipts now deliberately become evidence gaps. Re-run independent review on actual repaired source, save only conventional reports, freeze and collect fresh final local/external evidence. Do not retag or rebuild an immutable published release.

## PR74 repair batch

The equipped final verifier on frozen HEAD `75ff49d90546f2b89ad20cdc5f9e2a240f573914`, tree `e1fc7e6e69ab7f4a62701bded221d15c96583de4`, actually failed: three test failures, 1550 passes, two skips and 3007 passed subtests. Windows job 113643763773 reported the same two installer-document subfailures. Factory checks were unexecuted after fail-fast refusal. Observed coverage 81.37% exceeded the unchanged 74% threshold, but the failed invocation does not qualify coverage. No separate coverage defect or PASS is claimed.

Private 0700 archive scratch `/home/pall/getzilla-session/writer-repair-ogk5ggnb` reproduced both installer errors with the exact named contract test before candidate repair. It also reproduced the rename-guard failure, which identified a new negative test's literal obsolete script name. Candidate stayed unchanged until the coordinator confirmed the verifier terminal.

Repair: install commands now bind to tracked `published_release.tag`, exact tag-object schema and observed release installer digests, independently of source VERSION. Tests compare current unchanged installer bytes to those published digests and retain every original fail-stop/check-before-execution assertion. A no-Git-history fixture advances only source VERSION, then rejects malformed repository/tag/commit/digest records and changed installer bytes. No network or historical Git object is required. `test_project_state` pins the immutable published digests. README/QUICKSTART and both installers remain byte-identical. The rename guard stays unchanged; the handoff test now positively asserts the current Getzilla command. PROJECT_STATE records actual PR74 and pending fresh review/gates.

Historical candidate artifact smoke is preserved in `analysis-artifact-75ff49d.md`: two archives of that old frozen source had SHA256 `b32e88a7add6914f57125d333511de6931d7002476e0882e70c41e9b94c9bd99`; manifest, 629-entry fresh installation, doctor and no-overwrite passed. This evidence is candidate-only and does not qualify repaired/merged source or production readiness.

Bounded repair GREEN: `taskset -c 16-19 python3 -m unittest tests.test_getzilla_identity tests.test_project_state tests.test_install_scripts.InstallScriptContractTests tests.test_structure tests.test_ci_gate -q`: 91 tests PASS in 3.664 s. Ruff passed changed tests. Full PR verification remains after fresh independent reviews. Existing four reports describe the old reviewed candidate and are not new PASS evidence.

Future installer changes require new source/publication provenance; never rewrite immutable published digests merely to make a changed unpublished installer pass. A published-tag update must track an actual qualified publication, not an advancing candidate VERSION.

Full ported-list repair observation: `taskset -c 16-19 python3 -m unittest tests.test_fsx tests.test_install_scripts tests.test_workflow_sources tests.test_ci_gate tests.test_review_source -q`: 68 tests PASS in 21.881 s, with two platform skips on Linux. This is not native Windows qualification. Linux PR74 CI also terminated with the same three old-candidate failures; no additional external defect was reported. Changed-test Ruff and `git diff --check` PASS.


## PR74 supported-consumer compatibility repair

Source `9ea7c523304da5a747d3663bf278641a36bf04f7` was archived to private mode0700 scratch `/home/pall/getzilla-session/writer-compat-fx5fi1g2`. Before repair, three named regressions produced one failure and two errors: `tests.test_review_source.ReviewSourceTests.test_micro_route_without_package_admits_global_reports_and_consumption`, `test_active_package_accepts_documented_global_review_location`, and `tests.test_harnesses.HarnessTests.test_grok_skills_are_rendered_from_the_canonical_sources`. Actual consumer `tests.test_installer.InstallerTests.test_installed_grok_skills_equal_canonical_sources` separately failed against that old scratch. Logs: `/home/pall/getzilla-session/compat-red.log` and `compat-installed-red.log`.

The coordinator cancelled verifier99160 after confirmed compatibility findings: terminal exit130, cancelled/incomplete status, no PASS. Its reviewed candidate remained unchanged; repairs began after child cleanup and terminal confirmation. Existing saved reviews are historical until replaced.

Renderer ownership now includes exactly `.grok/skills`, copied from canonical `.agents/skills`; Grok hooks/agents remain canonical. All skill files are regenerated. Tests cover canonical parity, installed consumer parity, drift repair and retired-file removal without changing hooks/agents. Review admission accepts only six conventional flat report names under `engineering/reviews/` or a valid selected package evidence directory. Low-risk micro routes may lack a package; standard/high-risk routes may not. Present malformed/null/unsafe metadata never falls back. Missing-file detection checks the original FileNotFoundError cause of the descriptor-safe reader; other errors remain failures. Source identity, ancestry, clean-tree, regular-mode, UTF8, role whitelist, A/M-only delta and receipt rederivation remain mandatory. These local receipts confer no merge authority.

Bounded GREEN: `taskset -c 16-19 python3 -m unittest tests.test_review_source tests.test_harnesses tests.test_installer.InstallerTests.test_installed_grok_skills_equal_canonical_sources -q`:49 tests in15.479s. No full verifier or fresh independent PASS is claimed. Recovery is reverting this candidate via a new reviewed repair; no deployed state changed.

Additional controls: identity and existing change-receipt controls passed (33 tests); the first new retirement fixture failed because its synthetic agent omitted required developer_instructions. Replacing that invalid fixture with the existing canonical general_implementer TOML retained preservation assertions; the corrected named retirement test PASS in0.028s. Ruff, generated-harness drift command and git diff --check PASS.
