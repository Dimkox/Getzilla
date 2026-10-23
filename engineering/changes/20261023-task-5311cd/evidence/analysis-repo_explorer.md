# Read-only analysis

Route: 5311cdded150. HEAD/base: 8a02bab3d3e2a4e4cf8e023068a9652cbb89a5be. Tree: d728995aa1153ab52e88e3d8d82dedbe37d0e0aa.

No missing product repair remains in local dc3d66bceac4568442344e1b6ebba00fed63046a or f6df5325417829e362bcb526ac934705cfbd4192.
dc3d66bc changes the runtime wheel inventory and ten workflow/prose files. Its certifi 2026.10.19 update is already in main through ab3791a11604feac7184ce351b0fc068098afefb, plus pypdf 6.21.2. Inventory lock_sha256 equals actual factory/uv.lock: 8be006c54e43f790bdc6ae1412a60f3efbbcd98be5e527cf699da4f36d2041a8. Do not restore the older inventory.
f6df5325 changes three workflow files only and records a blocked smoke.
Offline builder, Linux process adapter and their tests are unchanged from dc3d66bc. Minimum controls: seven offline builder tests, thirteen process adapter tests and tests.test_quality_gates. The full verifier invokes factory/tests/run_disposable_exit.py.
Historical records prescribe system Python3.12 and explicit UV_PYTHON, UV_NO_MANAGED_PYTHON=1, UV_PYTHON_DOWNLOADS=never, UV_LOCKED=1. Historical results are not current verification.
No tests or mutations ran. reviewed-tree-modified: no
