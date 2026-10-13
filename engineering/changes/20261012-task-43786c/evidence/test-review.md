PASS — no blocking test finding.

- Fresh controls pass: 46 payload/advisory/circuit-breaker tests, 109 structure/state/workflow/router tests, and the changed manifest release-identity test.
- Eight scoped critical mutants are killed. They cover missing build dependencies, wrong worktree hook selection, a planted hook-only subdirectory, fail-open denial, conflicting and malformed native commands, missing native mapping, and missing retry records.
- Existing Low gaps remain in issue #73. A denial-only launcher assertion can accept an unrelated denial. The workdir denial test lacks a granted discriminating fixture. This review adds no evidence to increase their severity. Direct normalization assertions cover copied command/workdir fields.
- The diff adds no external mutation path. Denial ledgers are local workflow writes. Tests use sensitive strings only as hook inputs. They do not execute those commands.

Source: /home/pall/projects/getzilla/.getzilla/runtime/worktrees/fix-codex-cmd-20261011.
Route: 43786cadd549; selected role: test_reviewer.
Comparison base: 540c12f93e798c2f483455a5086ab0018ac3216e.
HEAD before/after: 34bee4d1f10125e4e44e9835fc931595ff9f03a2.
Git tree before/after: f95ae47fca84b309b2386815b65c7008beb53fdf.
Fingerprint before/after: a7e378d0df851e1ff64c78fca8e6c6225eb4073ff4431ea01d5e9f6ed071eb9f.
Staged/unstaged/untracked before/after: empty.
reviewed-tree-modified: no

Scratch: /home/pall/projects/getzilla/.getzilla/runtime/reviews/20261012-codex/test-34bee4d/snapshot.
Parent and scratch are reviewer-owned, non-sticky, mode 0700. Clone command: `git clone --quiet --shared --no-hardlinks /home/pall/projects/getzilla/.getzilla/runtime/worktrees/fix-codex-cmd-20261011 /home/pall/projects/getzilla/.getzilla/runtime/reviews/20261012-codex/test-34bee4d/snapshot`. Clean source inventory needs no dirty overlay. Initial and restored scratch fingerprints equal source. Tests and artifacts stay outside candidate. Private TMPDIR is the sibling test-34bee4d/tmp. No secrets or production state were read.
Capacity discovery: lscpu reports 14 cores/28 online logical CPUs; nproc=22, nproc --all=28, affinity=0,1,8-27. Actual cgroup is user.slice/user-1000.slice/session-2050.scope; applicable quotas are unlimited; cpuset=0-27. Child-only `taskset -c 0-27 nproc` returns 28. Assigned CPUs 6-11; at most two serial test processes overlapped, below four-worker allocation.

Fresh executable claims:
- `taskset -c 6-11 env PYTHONDONTWRITEBYTECODE=1 TMPDIR=/home/pall/projects/getzilla/.getzilla/runtime/reviews/20261012-codex/test-34bee4d/tmp python3 -m unittest tests.test_structure tests.test_project_state tests.test_workflow_sources tests.test_repo_router`: exit 0; 109 tests, 5.359s, OK.
- Same prefix with `tests.test_manifest_package.PackageTests.test_published_zip_matches_immutable_release_record_and_embedded_manifest`: exit 0; one test, 0.002s, OK. This checks stored source identity, not a live download or fresh publication.
- Mutation runner: `python3 -B /home/pall/projects/getzilla/.getzilla/runtime/reviews/20261012-codex/test-34bee4d/run.py`. Its exact per-test commands follow. Each runs in scratch with PYTHONDONTWRITEBYTECODE=1 and private TMPDIR. Scratch bytes are restored between variants.

- baseline: Unmodified module baseline.
  Command: `taskset -c 6-11 python3 -m unittest tests.test_harness_hook_payloads tests.test_known_vulns tests.test_pre_tool_circuit_breaker`
  Output: exit 0; Ran 46 tests in 19.768s; OK. Outcome: baseline PASS.
- omit-build-system: Remove requirements.extend(build_requires).
  Command: `taskset -c 6-11 python3 -m unittest tests.test_known_vulns.CollectTests.test_build_only_backend_pin_is_collected tests.test_known_vulns.CollectTests.test_current_backend_pins_are_in_the_audit_inventory tests.test_known_vulns.OfflineTests.test_build_backend_advisories_detect_old_pin_and_exclude_fixed_pin`
  Output: exit 1; Missing build-only/backend inventory and old-backend advisories; FAILED (failures=3).. Outcome: killed.
- outermost-hook: Use (*e,*reversed(d.parents),d) in generator and generated configurations.
  Command: `taskset -c 6-11 python3 -m unittest tests.test_harness_hook_payloads.GeneratedHookCommandTests.test_nested_real_worktree_uses_its_own_route_and_denial_state`
  Output: exit 1; AssertionError: Posix[84 chars]ee4d/snapshot') != Posix[84 chars]ee4d/tmp/getzilla-test-lyjgkle0/project/.getzi[58 chars].py'); Ran 1 test in 0.520s; FAILED (failures=1). Outcome: killed.
- hook-only-subdir: Remove (q/'.getzilla').is_dir() marker requirement in generator and generated configurations.
  Command: `taskset -c 6-11 python3 -m unittest tests.test_harness_hook_payloads.GeneratedHookCommandTests.test_a_hook_planted_in_a_subdirectory_is_never_run`
  Output: exit 1; KeyError: 'hookSpecificOutput'; Ran 1 test in 0.106s; FAILED (errors=1). Outcome: killed.
- denial-fails-open: Change _deny final permission from False to True.
  Command: `taskset -c 6-11 python3 -m unittest tests.test_pre_tool_circuit_breaker.DenialCircuitBreakerTest.test_validation_denial_survives_root_and_ledger_failures`
  Output: exit 1; AssertionError: 'allow' != 'deny'; Ran 1 test in 0.152s; FAILED (failures=1). Outcome: killed.
- conflict-bypass: Disable alias mismatch validation.
  Command: `taskset -c 6-11 python3 -m unittest tests.test_harness_hook_payloads.HarnessHookPayloadTests.test_codex_conflicting_and_malformed_commands_are_denied`
  Output: exit 1; AssertionError: 'allow' != 'deny'; Ran 1 test in 1.822s; FAILED (failures=1). Outcome: killed.
- type-bypass: Disable native cmd type/non-empty validation.
  Command: `taskset -c 6-11 python3 -m unittest tests.test_harness_hook_payloads.HarnessHookPayloadTests.test_codex_conflicting_and_malformed_commands_are_denied`
  Output: exit 1; AssertionError: 'allow' != 'deny'; AssertionError: 'allow' != 'deny'; AssertionError: 'allow' != 'deny'; Ran 1 test in 2.133s; FAILED (failures=4). Outcome: killed.
- drop-native-mapping: Delete mapped command assignment.
  Command: `taskset -c 6-11 python3 -m unittest tests.test_harness_hook_payloads.HarnessHookPayloadTests.test_installed_codex_launcher_checks_native_cmd`
  Output: exit 1; KeyError: 'hookSpecificOutput'; Ran 1 test in 2.154s; FAILED (errors=1). Outcome: killed.
- skip-denial-ledger: Replace _record_denial call with constant counts (1,1).
  Command: `taskset -c 6-11 python3 -m unittest tests.test_pre_tool_circuit_breaker.DenialCircuitBreakerTest.test_native_validation_denials_record_exact_and_objective_retries`
  Output: exit 1; AssertionError: 'exact tool invocation was denied again' not found in 'exec_command cmd must be a non-empty string.'; Ran 1 test in 0.284s; FAILED (failures=1). Outcome: killed.

Fresh baseline includes installed/current Codex launcher routing, real nested worktree own-route and own-denial state, explicit environment-root override, planted-subdirectory rejection, malformed build requires, manifest provenance/deduplication, and fixed-versus-old synthetic advisory records. Mutation tests assert exact hook source identity for the nested worktree, so an unrelated denial cannot satisfy that routing test. No scoped mutant survived. No blanket mutation score is claimed.

Unexecuted claims and limits: full PR verifier and external exact-head checks belong to the coordinator and were not run. Backend wheel-build compatibility evidence was read, not independently rebuilt. Real advisory providers and commercial databases were not queried; synthetic offline records test matching, not database completeness. Version/state tests check consistency, not live release facts. Scanner support remains exact pinned requirements; ranges and arbitrary requirement syntax remain outside this repair. Full package suite, factory/PostgreSQL integration and non-POSIX launcher execution were not run. Absence of new external double writes is static review with no executable probe. Env-root trust and a planted directory with a full .getzilla marker remain inherited trust assumptions, not newly established claims. Prior cde/660 review outcomes are historical only and are not used as current test runs.

Recommendation: PASS scoped independent test review of exact HEAD 34bee4d1f10125e4e44e9835fc931595ff9f03a2. Retain Low follow-ups in issue #73. Require the frozen candidate final local gate and exact-head external checks before merge.
