# Test plan

P0: malformed policy and unknown types fail closed. Custom configuration and policy-only
changes force full scope. FIFO/symlink inputs cannot block or escape the snapshot.
P0: operator image ownership/mode/schema checks run before container execution.
Timeout/cancellation, closed output pipes and cleanup failure never become PASS.
P0: shadow observations cannot block. Blocking never reads/writes cache, and cached
provenance cannot create admission PASS even with a forged reported status/hash.
P1: cache invalidates every key dimension; rejects malformed, expired, oversized,
unsafe-permission, symlink/hardlink/FIFO entries; evicts within fixed limits.
P1: doctor preflight, installed documentation, unchanged CI split/workflow bytes and
receipt-publication failure preserve existing behavior.
P1: all seven adapters run through the real registry with deterministic fixture outputs.
P1: CPU reserve is applied once and caps explicit as well as automatic requests.

New regression modules: tests.test_lqg_repair, tests.test_lqg_cache,
tests.test_lqg_integration, tests.test_lqg_benchmark.
Existing controls: all four adapter modules, tests.test_lqg_core,
tests.test_python_test_runner, tests.test_quality_gates, tests.test_ci_gate,
tests.test_workflow_sources, tests.test_installer, tests.test_manifest_package,
tests.test_toolchain and tests.test_verification_doctor.DoctorTests.

Observed RED: 3 scope/FIFO failures and 4 malformed-type errors; then 25 tests GREEN.
Cache RED: missing module and expected CACHED_UNVERIFIED; then 33 tests GREEN.
Extra RED found closed-pipe cancellation and wrong historical evidence linkage; repaired.
Doctor/payload RED: no doctor items and missing installed documentation; repaired.
Fixture RED: missing harness/timing fields; repaired.
The combined focused run passed 207 tests in54.909s. Installer/manifest/toolchain/doctor
controls passed 116 tests in63.164s. After strengthening byte-limit assertions, the
8 cache tests passed again in0.109s. These are 323 distinct focused tests, not a final
PR receipt. Committed-HEAD smoke is run after the repair commit and reported separately.

Synthetic command: python3 scripts/benchmark_lqg.py --samples 5 --concurrency 2.
Raw evidence lives in evidence/synthetic-benchmarks.json with source bytes digest.
It measures 20 scenarios, five cold and warm samples each, plus two concurrent fixtures.
No real SDK, container startup or external CI target is qualified. SDK smoke is NOT_RUN;
external CI baseline is unavailable. Earlier Node container isolation smoke is separate.

The historical 277-test run and reviews apply to the pre-repair tree only. Both historical
reviews remain FAIL. Fresh reviews and final receipt must bind the new frozen candidate.
