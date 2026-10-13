# Source identity RED/GREEN evidence

Route: 65799e00561a. Base/HEAD before edits: 540c12f93e798c2f483455a5086ab0018ac3216e. The existing current identity bindings were updated first; no new tests or behavior changes were added.

## RED: identity alignment before product edits

```sh
env -u GETZILLA_TEST_WORKERS taskset -c 0,1 python3 -m unittest tests.test_structure.StructureTests.test_version_identity_matches_readme tests.test_project_state.ProjectStateTests.test_getzilla_current_identity_and_release_continuation tests.test_manifest_package.PackageTests.test_published_zip_matches_immutable_release_record_and_embedded_manifest
```

Exit code: 1. Exact output:

```text
FFF
======================================================================
FAIL: test_version_identity_matches_readme (tests.test_structure.StructureTests.test_version_identity_matches_readme)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/home/pall/.local/share/getzilla-worktrees/release-2.2.2/tests/test_structure.py", line 420, in test_version_identity_matches_readme
    self.assertEqual(version, "2.2.2")
AssertionError: '2.2.1' != '2.2.2'
- 2.2.1
?     ^
+ 2.2.2
?     ^


======================================================================
FAIL: test_getzilla_current_identity_and_release_continuation (tests.test_project_state.ProjectStateTests.test_getzilla_current_identity_and_release_continuation)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/home/pall/.local/share/getzilla-worktrees/release-2.2.2/tests/test_project_state.py", line 223, in test_getzilla_current_identity_and_release_continuation
    self.assertEqual(published['tag'], 'v2.2.1')
AssertionError: 'v2.2.0' != 'v2.2.1'
- v2.2.0
?      ^
+ v2.2.1
?      ^


======================================================================
FAIL: test_published_zip_matches_immutable_release_record_and_embedded_manifest (tests.test_manifest_package.PackageTests.test_published_zip_matches_immutable_release_record_and_embedded_manifest)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/home/pall/.local/share/getzilla-worktrees/release-2.2.2/tests/test_manifest_package.py", line 1421, in test_published_zip_matches_immutable_release_record_and_embedded_manifest
    self.assertEqual(candidate_version, '2.2.2')
AssertionError: '2.2.1' != '2.2.2'
- 2.2.1
?     ^
+ 2.2.2
?     ^


----------------------------------------------------------------------
Ran 3 tests in 0.006s

FAILED (failures=3)
```

These are expected metadata mismatches, not a runtime behavior regression. VERSION and current publication facts still had their old values for this run.


## Resumed bindings — 2026-10-12

The existing 15-file dirty release candidate was preserved. No files in the frozen command repair or paused docs19c contour were edited. New `test_release_handoff_keeps_history_and_production_authority_separate` reproduced RED before corrections; `/tmp/getzilla-release-docs-red.log` contains the missing predecessor historical-field binding. Corrected START_HERE PR238 to historical_v2_1_1_published_release, package2.0.18 to prior_published_releases, and both M8 inbound links to the version-neutral docs/REFERENCE heading. Added dated v2.2.1 publication separately; old changelog source notes remain unchanged. Added publication_observation_20261012 for exact PR74/head/run/unsigned-tag/asset observations, explicitly not current verification; immutable published_release fields were not rewritten.

Removed routine pending owner steering in favor of conditional L5 exact grants and real green gates. Exact production target/task authority remains unresolved. The command repair is pending, not delivered. The first 120-test bounded run passed119 and found an existing missing observed_main_sha in REFERENCE current-state prose. Added the actual dated540c comparison base and explicit instruction to refresh only after the repair's actual merge. The two affected binding tests passed0.005s; final complete controls are retained in /tmp/getzilla-release-docs-final-green.log.

Command: `taskset -c 24-27 python3 -m unittest tests.test_structure tests.test_project_state tests.test_manifest_package tests.test_install_scripts.InstallScriptContractTests -q`. This is bounded dirty-candidate observation only, not committed smoke, qualifying verification or fresh release acceptance. Ruff, git diff --check and unchanged harness drift pass. Direct structural comparisons confirm the complete old v2.2.0 published record and every old continuation field are preserved. No published asset rebuild, runtime behavior, provider, trust policy or production effect occurred. Hold uncommitted until actual command-repair integration and fresh base binding; no ready transition or source freeze.
