BLOCKED: the short non-Git TMPDIR corrects the reproduced Git-context and Chrome socket failures, but the native runner still exposes an import-priority defect in hook bootstrap. This follow-up supersedes any inference that TMPDIR alone is sufficient for the full gate. No source, tests, assertions or candidate state were changed.

Candidate before/after: `/home/pall/projects/liqvera/.getzilla/runtime/getzilla-dispositions`, HEAD `4cf2abf21753e61383e3d89be593e0fb815afc7f`, tree `947e9f362d4f0bc862e8bf12455c8e4b1862e850`, empty Git status. `failed-before.json`, `failed-after.json`, `residual-before.json` and `residual-after.json` retain matching identities. All selected test file hashes remained equal; ten additional import-related source files also hash to their pinned Git blobs in `source-provenance-bindings.json`.

reviewed-tree-modified: no

The original gate summary contains 36 `FAILED` and six `SUBFAILED` records. These map to exactly 38 unique parent node IDs; deduplication preserves every failed subtest by running its parent. `failed-selection.json` binds all 42 original lines, their source report SHA-256 and the complete selected node list.

| Bounded execution, CPUs 0–3 | Result |
| --- | --- |
| All 38 failed parents, short TMPDIR, unchanged native runner environment, four xdist workers | 33 passed; five parents failed, reported as seven failures including two subtests; 38 passing subtests; 15.83 s |
| The five residual parents alone, same native environment | Seven failure records; 28 passing subtests; 4.85 s |
| Same five parents and command, removing only candidate `/.getzilla` from inherited `PYTHONPATH` | Five passed; 30 passing subtests; 4.31 s |

The residual parents are both `HookDegradedTests` cases for broken policy/helper imports, both `DegradedFailClosedTests` cases, and `EnforcementReportTests.test_self_test_proves_the_policy_runs`. Their deliberately broken fixture libraries are ignored: degradation events are absent, protected `rm -rf build` is allowed, and enforcement incorrectly reports a healthy policy. The command is supplied only as a synthetic hook-classification payload; it is never executed.

The exact cause is import ordering. `.getzilla/getzilla/python_test_runner.py:320` exports the original candidate's `.getzilla` directory in `PYTHONPATH`. `.grok/hooks/pre_tool_use.py:89–96` appends the fixture's `.getzilla` directory. `_lib.py:18–19` only puts its owning `STACK` first when it is absent; because the fixture path was already appended, it remains behind the inherited healthy candidate package.

An independent invocation of the unchanged fixture hook under Python `-v` confirms this mechanism. With native PYTHONPATH, the trace loads the original candidate's `getzilla/policy.py`, returns `allow` for the protected payload, and records no fixture degradation event. Removing only that one inherited path loads the deliberately broken fixture policy, returns `deny`, and records a degradation event. The same fixture and payload were used for both runs. `provenance.json` and both complete `provenance-*.stdout/.stderr` files retain the source paths and outcomes.

Smallest demonstrated environment change: remove the original candidate `.getzilla` entry from child PYTHONPATH. This is a diagnostic control, not an approved full-gate workaround: the native runner recreates that entry internally, so simply unsetting caller PYTHONPATH does not repair the gate. A narrow source repair for the sole implementation owner is to make hook bootstrap prioritize its own `STACK` even when the path already exists later in `sys.path`. This preserves local policy ownership under inherited paths and keeps the native test environment intact. No repair was applied or validated in this review.

Regression design sent to the implementation owner: launch the real fixture hook with PYTHONPATH pointing to another healthy Getzilla package; break the fixture's `policy.py` and, separately, `fsx.py`; require local import provenance, `HOOK_DEGRADED`, refusal of protected actions, and allowance of ordinary reads. Preserve the existing enforcement self-test failure assertion. Keep the competing inherited package in the regression so the original code fails it.

Commands, from `/home/pall/projects/liqvera`:

```sh
env PYTHONDONTWRITEBYTECODE=1 taskset -c 0-3 .getzilla/runtime/completion/getzilla-gate-venv/bin/python -B .getzilla/runtime/completion/getzilla-gate-environment-diagnosis/failed_cases.py
env PYTHONDONTWRITEBYTECODE=1 taskset -c 0-3 .getzilla/runtime/completion/getzilla-gate-venv/bin/python -B .getzilla/runtime/completion/getzilla-gate-environment-diagnosis/residual_imports.py tests
env PYTHONDONTWRITEBYTECODE=1 taskset -c 0-3 .getzilla/runtime/completion/getzilla-gate-venv/bin/python -B .getzilla/runtime/completion/getzilla-gate-environment-diagnosis/residual_imports.py provenance
```

All evidence is under `completion/getzilla-gate-environment-diagnosis/`. `failed-tests-command.json` records the exact expanded argv, cwd and native environment builder; `failed-tests.stdout` retains all 12,952 bytes, with empty stderr and external JUnit output. `residual-results.json` records both exact paired commands and environment paths; their full output is retained separately. These executions use the frozen runner's `_pytest_command(4, 'worksteal')` and `_environment`, with selected nodes and no subset-inappropriate coverage plugin/threshold. They do not represent full-gate acceptance. The initial paired-environment report remains byte-exact at SHA-256 `555fed1bf20647ef0e43a7f599ea1182084befa7c9a18e6c1e8ef17ac6d000a2`.

Limits: no full-suite/full-gate rerun, coverage certification, new receipt, deployment, publication, live mutation, payment or grant access. Remaining full-gate checks and load-sensitive behavior require fresh verification after the source repair; the prior full gate remains failed.
