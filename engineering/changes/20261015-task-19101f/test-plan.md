# Test plan

P0: reject malformed policy, unknown IDs, symlink/path escapes and incomplete scope.
P0: missing configuration/backend and abnormal tool exits must not pass.
P0: block/shadow projection must preserve mandatory quality rules.
P0: output, time and cancellation bounds must terminate the owned execution.
P0: source snapshots exclude unrelated private files and bind their content digest.
P1: each adapter validates argv, diagnostic schema and exit status.
P1: host28/affinity22 gives22; host28/child26 gives26; explicit28 gives26; quota4 gives4.
P1: consumer installation retains all shared modules and public/private CI selection.

Focused commands:
- python3 -m unittest tests.test_lqg_core tests.test_lqg_eslint tests.test_lqg_kotlin tests.test_lqg_dart tests.test_lqg_swift
- python3 -m unittest tests.test_python_test_runner
- python3 -m unittest tests.test_quality_gates tests.test_ci_gate tests.test_installer tests.test_manifest_package
- ruff check .getzilla/getzilla/language_quality .getzilla/getzilla/cpu_budget.py tests/test_lqg_core.py

Actual observations: the combined focused command above passed277 tests in103.791seconds.
It covered adapters/core, the full Python runner module, quality gates, CI, installer and manifest.
The later registry execution/source-mutation fixture passed separately. Capacity12 tests passed.
The runner initially found an obsolete fallback2 assertion; its repair and focused rerun passed.
Local Node container smoke passed: source read-only, uid nonzero, loopback-only network,
ambient test variable absent. The fixture explicitly admits only the known Node image.
An unapproved image is refused before any subprocess. This is sandbox proof, not SDK qualification.
Real ESLint/Kotlin/Dart/Swift tool matrix is NOT_RUN. SDK downloads were not attempted.
Performance baseline is unavailable. No p50/p95 target or cache performance is claimed.
Final controls/reviews/receipts remain separate and must bind the committed candidate.
