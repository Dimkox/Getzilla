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
