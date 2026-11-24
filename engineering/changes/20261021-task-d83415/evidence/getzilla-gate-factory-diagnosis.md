# Factory gate diagnosis

Route d834158878e0; candidate 4cf2abf21753e61383e3d89be593e0fb815afc7f. No candidate source edits, receipts, production actions or dependency changes. All results below are diagnostic observations, not a qualifying gate.

## Decision

Retain the 720-second factory suite limit. The full diagnostic completed 1,040 tests in 518.958 seconds; total runner time was 530.498 seconds. It failed with one assertion failure, 11 errors and six skips. Increasing the limit would not resolve those failures.

Use a short, private, non-Git TMPDIR under `/home/pall` and set `UV_PYTHON=/home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-gate-venv/bin/python`. The supported-interpreter control proves that this selects base `/usr/bin/python3.12`, version 3.12.3, with a working `os.pidfd_open`. All six previously failing adapter/installer parent cases then pass in 5.596 seconds, without skips or source changes.

## Full-run evidence

The coordinator authorized one bounded full diagnostic on CPUs 8–15. An exact private copy of `factory/tests/run_disposable_exit.py` changes only `_FULL_SUITE_TIMEOUT_SECONDS = 720` to `1200`. It runs the original main from the candidate source directory with the original preflight, full unittest discovery, restart logic and uniquely bound disposable-container cleanup. The increased diagnostic limit was not reached. The candidate remained clean at the same HEAD before and after the run.

Scratch `/home/pall/.gz-fdiag-f588fmwt` is UID 1000 mode 0700. Its nonsymlink ancestors are root-owned `/` and `/home` mode 0755, and UID 1000 `/home/pall` mode 0750. Git discovery from it exits 128. The launcher retains the qualifying launcher's CA/proxy environment and dedicated outer interpreter, without exposing private environment values.

`getzilla-gate-factory-diagnosis-full.json` records original/copy SHA-256, source/tree identities, exact argv, environment names, CPU allocation, monotonic start/end and output hashes. `.copy.diff` proves the sole private-copy change. `.stdout` and `.stderr` are full, unsliced private logs. `.progress.jsonl` records individual completion timestamps. `.analysis.json` records all error bindings, timing intervals and cleanup verification. The outer launcher's 1,900-second safety bound allows the unchanged preflight/restart budgets and was not reached.

The original runner's final restart probe did not run after unittest returned nonzero. Do not treat the preflight PASS as completed restart/reconciliation acceptance.

## Failure bindings

1. Nine error records arise from six Linux adapter/installer test parents: managed uv CPython 3.11.15 lacks `os.pidfd_open`. The full tracebacks identify `~/.local/share/uv/python/cpython-3.11.15-linux-x86_64-gnu`. `factory/runtime/linux_process_adapter.py:296` raises AttributeError during stop, including repeated cleanup errors. The installer test additionally expects HEALTH_FAILED but receives RECONCILIATION_REQUIRED. The outer gate interpreter being Python 3.12 does not force `uv run --project factory python` to select it.
2. `test_committed_inventory_is_exactly_derived_from_uv_lock` raises WHEEL_INVENTORY_DRIFT. `factory/runtime/runtime-wheels-linux-x86_64-cpython312.json` records lock hash `546b59e943616b6e114cd34fdf0a2d24d0ffde05598e11af447530c69d320900`; current `factory/uv.lock` hashes to `38152455cec25094f51b2c1f1c5e3cf69b4ea04257f05278b1bf1ac824fd5515`. The only derived wheel-entry change is certifi 2026.7.22 to 2026.10.19, with its filename and digest. `getzilla-gate-factory-diagnosis-inventory-drift.json` records both entries. The implementation owner can regenerate this file using existing `build_offline_release.derive_inventory`; no source change was made here.
3. `test_cancel_and_fresh_recovery_race_is_bounded_and_single_terminal` fails at `factory/tests/test_execution_persistence_postgres.py:5676`. The cause is `psycopg.errors.LockNotAvailable: canceling statement due to lock timeout`, while locking a tuple in `capacity_counters`, wrapped as StoreUnavailable by `factory/src/getzilla_factory/store.py:1342` through `claim_execution_recovery`. The test holds cancellation at an advisory barrier, starts recovery, then releases the barrier after 0.1 seconds. This establishes the refused lock, not a complete explanation of the contention. Five unchanged observations under the supported interpreter subsequently pass, as recorded below; no DB source repair is justified.

The six skips comprise one fresh-cluster migration test requiring FACTORY_FRESH_CLUSTER_DATABASE_URL and five PDF-worker tests whose version probe requires stale pypdf 6.18.1 while the factory dependency pins 6.19.0. The PDF mismatch also affects the runtime guard, as detailed below. No skipped case is a fresh pass or a launcher-added exclusion.

## Supported-interpreter proof

`getzilla-gate-factory-diagnosis-supported-launcher.py` sets UV_PYTHON to the dedicated gate interpreter and UV_PROJECT_ENVIRONMENT to a private diagnostic venv. Before testing, it asserts Python 3.12, exact resolved base executable equality with the dedicated interpreter, callable os.pidfd_open, and successful open/close of a pidfd for itself. The resulting venv reports base `/usr/bin/python3.12`, version 3.12.3.

All six selected parents execute and pass: concurrent managers; fixed child identity/health/shutdown; install/update/reconcile/remove/purge; stale boot records; child forked by TERM handler; resistant descendants. Evidence is in `getzilla-gate-factory-diagnosis-supported.json`, its preflight logs and complete stdout/stderr. Total control time including interpreter setup is 6.108 seconds. Candidate HEAD and status remain unchanged in that control.

## Timing and the original cutoff

The named UDS test passes under original nested TMPDIR in 4.005 seconds, with a valid 97-byte socket path. It also passes under short scratch. In the full diagnostic it passes in 4.005 seconds, completing at 507.906 seconds. The original 720-second whole-process timeout happened while this test name was displayed; that did not identify a hung UDS test.

Completion intervals attribute approximately 241.562 seconds to test_postgres_integration and 188.559 seconds to test_execution_persistence_postgres, including adjacent setup/output overhead. The slowest completed case takes 49.576 seconds to construct/release 101 database execution lifecycles. Further slow cases take 30.546, 27.535, 20.537 and 13.283 seconds. These are measured workloads, not inferred sleeps.

Static inventory finds 1,027 test-method definitions in 72 files; actual discovery executes 1,040 cases. Literal Python sleep sites sum to 2.405 seconds if each runs once, which is not a runtime bound because loops and branches differ. Clearly unconditional successful-path sleeps contribute 1.7 seconds; one deliberate transaction-timeout test adds about one second. Static waits alone cannot justify a larger suite budget. No causal claim is made for why the original full run was slower: its earlier timings were truncated, and these runs are not a controlled single-variable comparison.

## Supported-interpreter database race observations

The coordinator authorized five unchanged observations of `test_cancel_and_fresh_recovery_race_is_bounded_and_single_terminal` before any database source change. A private diagnostic wrapper imports the original disposable runner/main and replaces only the full unittest selection with five copies of the named test. It keeps the original fresh-container setup, preflight, guards, timeout constants, per-test fixture/reset, final restart probe and bound cleanup. This is repeated measurement, not retry-until-pass; every outcome contributes to the result.

With UV_PYTHON pinned to the verified 3.12 interpreter, all five observations pass in 6.312 seconds, with no skipped case or assertion change. The complete runner exits 0 in 48.460 seconds. Its preflight and final actual restart/reconciliation probes pass. The original main returned successfully through its ID/name/image/nonce-bound cleanup. An independent labelled-container inventory contains eight retained containers, all created October 2–13, before this October 21 run; none belongs to this diagnostic. The selected run did not emit its exact container ID, so no independent exact-ID inspect is claimed. No process remains under `/home/pall/.gz-race-4u3sbm0c`. Candidate source was clean at 4cf2abf when the control ended. Full logs, source/wrapper hashes and cleanup results are retained in `getzilla-gate-factory-diagnosis-race*`.

Source inspection confirms the contract: recovery timeout 3.0 reserves two seconds for connection and sets lock_timeout 500ms plus statement/transaction timeouts 1000ms. `execution_recovery_context` calls `capacity_lock_run` before locking task/run/allocation/manifest rows. `capacity_lock_run` locks the relevant capacity-counter rows in sorted scope order. The original test intentionally holds cancellation at an advisory trigger barrier, then releases it after recovery starts. A real lock refusal propagates as StoreUnavailable; the broader recovery loop handles unavailable claims without consuming fresh discovery progress.

The earlier full-run lock refusal has not reproduced under this supported isolated control. No SQL/application fix, weaker assertion, lock-limit increase or test retry is justified by these observations. A corrected full qualifying gate must still exercise the race in suite context; these five passes do not replace that gate or prove that interpreter selection alone caused the earlier refusal.

## PDF pin consistency and inventory handoff

The supported Python 3.12 environment contains pypdf 6.19.0, matching `factory/pyproject.toml`, `factory/uv.lock` and the wheel inventory. However, `factory/src/getzilla_factory/resources/landing_pdf_worker.py:24` accepts only 6.18.1 and emits `pdf_parser_unavailable` for the declared dependency. `factory/src/getzilla_factory/landing_media.py:21` advertises the same stale version. `factory/tests/test_landing_pdf_worker.py:34` probes 6.18.1, so its five parser-present tests skip while the unavailable-parser test passes. This is an actual runtime mismatch, not merely an obsolete test message.

The minimal active consistency repair is to align the worker guard, runtime version metadata, test probe and decorator messages with declared 6.19.0. Preserve resource limits, isolation, content identity and negative behavior. `PDF_DECODER_DIGEST` is derived from worker bytes. The eight objects under `factory/contracts/jsonschema/landing-backend-capability.v1.schema.json` properties.profile.enum are enforced exact facts, not examples: regenerate those existing entries from `HttpLandingProfile.for_provider(profile_id, available=True).to_facts()`, preserving membership and order. `test_profile_facts_keep_the_backend_capability_contract_shape` checks that equality. The old test comment notes the object-enum comparator restriction; coordinate the metadata change with the implementation owner's comparator repair. No dedicated schema-generation command was found. `getzilla-gate-factory-diagnosis-pdf-pin.json` binds these facts to original 4cf source hashes.

Wheel inventory regeneration, for the implementation owner from repository root under supported Python 3.12:

```python
import json
import sys
from pathlib import Path
sys.path.insert(0, "factory/runtime")
from build_offline_release import derive_inventory
Path("factory/runtime/runtime-wheels-linux-x86_64-cpython312.json").write_text(
    json.dumps(derive_inventory(Path("factory/uv.lock")), indent=2, sort_keys=True) + "\n"
)
```

The exact expected wheel change is certifi-2026.7.22-py3-none-any.whl, SHA-256 `62f22742b58a1a33014a2b6b706588a8d7e2a88ae7bd1a6ebe8c992928483775`, to certifi-2026.10.19-py3-none-any.whl, SHA-256 `42d35340cc5b9ba78e818ddbff0c5b1c2b779de448a340fd1b989f5fa8670e1b`, plus the lock hash already recorded above. No other wheel-entry changes were observed. No regeneration or application source edit was performed by this analyst.

## Cleanup

The original runner removed its exact disposable container `adaptive-factory-exit-5119e412985e`; a read-only inspect confirms absence. Missing pidfd support left five synthetic test processes. With explicit coordinator authorization, each exact PID was rebound through system Python 3.12 pidfd_open after UID, start-tick, cwd and executable checks; SIGTERM through that pidfd confirmed exit. No other process or container was touched. `getzilla-gate-factory-diagnosis-full.fixture-cleanup.json` records every identity/result. Final inspection finds no process beneath either diagnostic scratch subtree; `getzilla-gate-factory-diagnosis-cleanup-final.json` records this and container absence.

Remaining work belongs to the implementation owner/coordinator: correct the launcher interpreter selection, reconcile the wheel inventory and active PDF pin consistency, and run a fresh required gate with the retained 720-second limit. Preserve the original database assertions and guard limits. No full successful gate or zero-gap acceptance is claimed by this report.

All probes are complete. No live process depends on the original 4cf worktree; it was released to the coordinator for integration. Original diagnostic provenance remains bound to 4cf even if the shared worktree advances.
