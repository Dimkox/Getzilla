# Implementation observations

Source base: 8a02bab3d3e2a4e4cf8e023068a9652cbb89a5be.
Single owner: integration_implementer.

Regression first failed for both missing controller APIs. After a three-line callable guard in _host_supported, the regression passed. It verifies rejected preflight, UNSUPPORTED_HOST and no process/state/log creation.

Bounded controls used system Python3.12 through scripts/getzilla_par.py -j 8:
- factory.tests.test_linux_process_adapter: 14 passed in 7.487s.
- factory.tests.test_offline_release_builder: 7 passed in 0.365s.
- Parallel wall time: 7.8s.
- git diff --check: passed.

Raw logs: .getzilla/runtime/par/20261023T065749-3620095/001.log and 002.log; summary.json.
Only source/test files changed. No dependency, wheel inventory, signal or identity semantics changed.
These observations create no verification receipt. Full gate and independent reviews remain pending.

The nested-worktree hook required canonical exact-path grants before the source/test edits. Grant e53b870cb14fb21b covered only those two paths. No production authority was created.
