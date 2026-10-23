# Read-only analysis

Route: 5311cdded150. HEAD/base: 8a02bab3d3e2a4e4cf8e023068a9652cbb89a5be. Tree: d728995aa1153ab52e88e3d8d82dedbe37d0e0aa.

Current inventory matches factory/uv.lock SHA256 8be006c54e43f790bdc6ae1412a60f3efbbcd98be5e527cf699da4f36d2041a8 and contains certifi2026.10.19/pypdf6.21.2. The old dc3d66bc inventory contains pypdf6.19.0.
Historical f6df5325 evidence separates inventory drift and missing managed-Python pidfd APIs. Its 20-test pass is historical only. Fresh pydoc checks confirm system Python3.12.3 provides os.pidfd_open and signal.pidfd_send_signal.
_host_supported checks the host and child Python but omits controller APIs used by stop. A controller can pass preflight, start a child and fail cleanup. Refuse before process creation using existing UNSUPPORTED_HOST behavior. Test each missing API and no spawn. Preserve identity checks and bounded cleanup; no PID-only fallback.
Use the four documented UV variables for new controls and final full gate. Require actual PostgreSQL execution. Rollback is a source revert. No schema, dependency, production-state or public-contract change.
No files changed or heavy tests ran. reviewed-tree-modified: no

