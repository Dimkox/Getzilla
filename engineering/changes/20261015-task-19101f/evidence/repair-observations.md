# LQG repair observations — 2026-10-15

These are implementation observations. They are not independent review, local qualifying
receipts or external CI authority. The reviewed historical candidate remains FAIL.

Comparison base: 7cf4f65dd2ba9bb1390dc84c6185ba0f104255c8.
Pre-repair HEAD: 2abea74537edd4980be6c0239b4fb2fe57de3181.
Historical Git tree: 86892a3d091660b541991f7f2d57e9c1330437bd.
Working branch: feat/language-quality-gates-20261015.
One integration writer uses the original canonical lqg-20261015 worktree. Local
route19101f3e5e0d remains recorded; current coordinator routes permit code/test review.
The security/release obligations of the stale local route remain a disclosed gap.

## Regression evidence

- `python3 -m unittest tests.test_lqg_repair -v`: RED with three scope/FIFO failures
  and four malformed-type errors. After repair, repair plus core passed 25 tests.
- New cache tests first failed for the missing module and missing CACHED_UNVERIFIED.
  Cache plus core plus repair then passed 33 tests.
- Two further regressions exposed closed-pipe cancellation and a wrong historical
  evidence link. Both failed before the fix and passed after it.
- Integration tests first failed for missing doctor items and a missing consumer guide.
  Core, repair, cache and integration then passed 38 tests.
- Fixture tests failed before the helper/timing implementation. Both later passed.
- The final combined runtime group below passed 207 tests in 54.909 seconds.
- The installation/doctor group below passed 116 tests in 63.164 seconds.
- After adding assertions that force byte-budget eviction independently of the entry
  count, `python3 -m unittest tests.test_lqg_cache` passed all eight tests in 0.109 seconds.
  This last run repeats members of the 323 distinct focused tests; it does not add eight.
- Ruff on all changed LQG runtime, doctor, tests, fixtures and scripts passed.
  Typed specification validation with `--gate --json` passed, with 9/9 acceptance
  criteria mapped and no errors. `git diff --check` passed.

```text
python3 -m unittest tests.test_lqg_core tests.test_lqg_eslint tests.test_lqg_kotlin tests.test_lqg_dart tests.test_lqg_swift tests.test_lqg_repair tests.test_lqg_cache tests.test_lqg_integration tests.test_lqg_benchmark tests.test_python_test_runner tests.test_quality_gates tests.test_ci_gate tests.test_workflow_sources
python3 -m unittest tests.test_installer tests.test_manifest_package tests.test_toolchain tests.test_verification_doctor.DoctorTests
python3 scripts/benchmark_lqg.py --samples 5 --concurrency 2
```

The source snapshot changed after the historical reviews. Their complete reports are
preserved in historical-code-review-2abea745.md and historical-test-review-2abea745.md.
Neither report was changed to PASS. No reviewer mutation claim is made by this owner.

## Synthetic measurements

[Raw samples](synthetic-benchmarks.json) bind the measured implementation, fixture and
benchmark bytes to SHA-256 `6494984d205ac0990375c2f476c5798c57e1e0e35c02881bb0e1fc6b41461995`.
The source was dirty over 2abea745 when measured; it is not represented as a clean
committed run. Later documentation/test-assertion changes do not change those measured
runtime/fixture/benchmark bytes.

The command completed 20 cases, five cold and five warm samples per case, plus two
concurrent isolated fixtures. Allocation was six CPUs from the host reserve budget:
28 logical, reserve two, currently available22, unlimited observed quota, effective6.
The separate hook owner has six; the total remains below26.

Selected changed-scope median wall times, milliseconds:

| Synthetic fixture | Empty Getzilla cache | Unverified cache hit |
| --- | ---: | ---: |
| Small JavaScript, untyped | 72.935 | 58.122 |
| Small TypeScript, typed syntax | 73.387 | 61.560 |
| Medium JavaScript, 150 files | 321.441 | 188.342 |
| TypeScript monorepo, four packages | 1207.844 | 472.808 |
| Kotlin | 89.274 | 68.506 |
| Dart | 87.398 | 72.087 |
| Flutter | 98.028 | 75.398 |
| Swift | 98.231 | 74.419 |
| Mixed language monorepo | 1605.939 | 601.618 |
| Python only | 37.996 | 39.252 |

Full-scope raw samples and p95 values are in the JSON. Two concurrent fixtures took
131.764 ms wall time including fixture setup and performed two fresh injected runs.
Memory values are Python tracemalloc peaks, not RSS or container RAM. Cold means
empty Getzilla cache, not a cold operating-system cache.

The fixture executor is injected test code. Real Git discovery, hashing, scope, argv,
normalization, evidence and cache run; installed SDKs, typed analysis, container startup
and external CI queues do not. Warm status is CACHED_UNVERIFIED and never admission PASS.
These measurements do not qualify rollout latency targets or external CI overhead.
No package install, SDK download or LLM call occurred.

## Limits and next gate

Actual ESLint/Kotlin/Dart/Swift SDK smoke and macOS runner qualification remain NOT_RUN
because those prepared runtimes are unavailable. The earlier Node container isolation
smoke is historical and proves isolation only. Gradle admission remains unsupported
without a structured report contract. Dependency closure must exist in the approved
pinned image; host node_modules and .dart_tool are not copied.

The installed payload includes docs/LANGUAGE_QUALITY_GATES.md and its consumer link.
Doctor preflight executes no consumer tool. Public/private CI selection is unchanged.
Blocking bypasses the cache entirely; untrusted cache content cannot create a fresh
result, receipt or admission, even if its payload hash is recomputed.

After the clean repair commit, run the bounded no-record quality-gate control.
Then obtain fresh independent code/test reviews on that exact candidate, preserve their
reports, and run the one final qualifying PR gate. No full PR gate, branch push, merge,
deployed policy change or release is claimed here.
