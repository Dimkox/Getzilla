# Read-only analysis

Route: 5311cdded150. HEAD/base: 8a02bab3d3e2a4e4cf8e023068a9652cbb89a5be. Tree: d728995aa1153ab52e88e3d8d82dedbe37d0e0aa.

uv python find and uv python find --system select managed CPython3.11 without os.pidfd_open. Fresh pydoc checks confirm system Python3.12.3 provides both required pidfd APIs.
Explicit UV_PYTHON=/usr/bin/python3.12 UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never selection returns /usr/bin/python3. Also set UV_LOCKED=1.
run_disposable_exit.py inherits environment, creates a temporary uv environment, nonce-bound PostgreSQL container and random loopback port, then runs restart preflight, Factory discovery and restart/reconciliation. Preserve process ownership checks.
validate_committed_inventory requires exact derive_inventory(factory/uv.lock) equality. Test: factory.tests.test_offline_release_builder.OfflineReleaseBuilderTests.test_committed_inventory_is_exactly_derived_from_uv_lock.
Bounded control: system Python unittest for that inventory test and factory.tests.test_linux_process_adapter. Final gate uses supported environment and measured CPU allocation. Do not use repository-sandbox to skip PostgreSQL.
No Factory suite, PostgreSQL operation, Docker operation or install ran. Capabilities are fresh; prior tests are historical. reviewed-tree-modified: no

