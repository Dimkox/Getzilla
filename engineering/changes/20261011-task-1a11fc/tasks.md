# Implementation plan

Goal: isolate the controller scope override without weakening full verification.
Architecture: the existing shared child-test environment is the only production boundary changed. Parent scope selection remains unchanged.
Tech stack: Python stdlib, unittest, current pytest/coverage engines.
Spec: change-spec.yaml.

Dependencies: route-permitted analyses before implementation; a single general_implementer owns product writes; independent code/test reviews follow a clean committed candidate; the final gate follows persisted reports. Verified capacity is 28 CPUs; Core uses 12 workers. No independent writers share this worktree.

- [x] Add a real child-process regression that fails on inherited full-scope control and verifies parent preservation.
- [x] Run the new regression and save RED output before production edits.
- [x] Filter only FORCE_FULL_VARIABLE in python_test_runner._environment.
- [x] Run the new regression and nearby runner/scope modules; save GREEN output and commit the repair.
- [ ] Run bounded quality-gate smoke, complete independent reviews, persist reports and freeze.
- [ ] Run full PR verification with OSV/OpenGrep and bind fresh receipts.
- [ ] Deliver through the PR exact-head checks and rebuild/verify two local archives.

Review focus: parent operator override retained; unset overrides behave normally; ordinary variables/capability retained; all child runner engines use the shared boundary; explicit test-owned overrides still work. Tests must exercise observable child behavior rather than mock assertions.
