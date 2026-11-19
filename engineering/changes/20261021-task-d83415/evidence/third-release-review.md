# Getzilla R3 release review

Verdict: **PASS in release scope**. No additional blocking release finding in the inspected security, duplicate-write and test scope. This does not establish overall completion or merge eligibility. The final full local gate and required exact-head external CI remain **NOT_RUN**.

## Source and isolation

- Route `d834158878e0`; change `20261021-task-d83415`.
- Candidate `/home/pall/projects/liqvera/.getzilla/runtime/getzilla-dispositions`.
- Before/after HEAD `4c4cd124b2e382d3c6d8b19e2efe2c8fb45219ae`.
- Before/after Git tree `3dd0c14d38b13e618a736735d5eefb830295cf32`; status clean at both checks, including untracked files.
- Comparison base `e158ddc7263a55f5308944c5a426eb1e9f1a4327` remains the actual merge base with observed local `origin/main` at `e42398ddaa41e662e921d7af68ab87b1e28e3554`.
- Private scratch `/home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-r3-release-review`, mode `0700`, under owned non-sticky parents without group/world write access. `git archive` and scratch-only indexing reproduced the exact candidate tree. Tests used only CPUs 16–17 and scratch `tmp` as `TMPDIR`.

reviewed-tree-modified: no

I inspected the actual R3 repair and complete changed-path inventory, retained review/control evidence, updated reference, delivery/rollback instructions, and verifier/package integration. Prior unchanged integration findings were rechecked against the successor. No candidate files were generated or changed.

## Findings

- **Security and default policy:** No additional release blocker found. The repair requires the entire preceding context to be ASCII, including comments and strings. It also rejects unknown code characters and legacy HTML comments. The fresh regression run covers mixed Unicode/ASCII whitespace, Unicode comment terminators, unsupported syntax, and positive/negative form-feed and vertical-tab cases using exact scanner occurrence bindings. The reference explicitly documents conservative refusal, including harmless preceding Unicode, and calls this an eligibility check rather than a language parser. Existing strict absence, invalid/stale policy, distinct occurrences, genuine-secret and Git-layer cases still pass. The helper is installer-managed; the consumer policy is absent and outside installer ownership. No active policy ships by default.
- **Output consumers and duplicate writes:** No blocking change. The repair leaves the schema version, raw/effective severity, original Git exit/output retention and native status aggregation unchanged. Native quality admission uses check status. The reference explains how other consumers should interpret dispositions and preserves the boundary between local review evidence and authenticated authority. The added checks inspect local source and Git state; they add no external-write path. No live mutation or receipt publication was performed by this review.
- **Evidence preservation:** All four first-round report hashes and all five second-round report hashes match their respective bindings. The latter includes both the superseded security PASS and revised FAIL. Both earlier release reports remain byte-for-byte equal to my original files. The bindings retain `request_changes` and `NOT_RUN`, and state history records the repair cycles. All 13 second-repair payload hashes and sizes match. Their retained outputs substantiate 28 focused tests/193 passing subtests, two killed writer mutants, two real Liqvera matches disposed, the refused dirty-head preflight, and the later clean 29-test observation. Those are recorded writer controls, not new executions by this reviewer. The dedicated environment record describes preparation and does not claim a gate pass.
- **Delivery and recovery:** No blocking release issue. Removing consumer policy restores strict failures; feature-code rollback needs no migration or service action. Historical Liqvera evidence remains unchanged. Delivery is PR-only after selected reviews, a report-only freeze and the required exact-head gates. No new tag or release artifact is required. The observed upstream workflow contains Linux, Windows and macOS jobs. Required checks and their results must be observed on the final PR head; this report does not assume only Linux/Windows or assert that any external check passed. Pin the verified tool commit for the separate Liqvera successor audit.

## Fresh bounded execution

Working directory: scratch `snapshot`. Environment: `TMPDIR=/home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-r3-release-review/tmp`, `PYTHONDONTWRITEBYTECODE=1`.

```text
taskset -c 16,17 /home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-gate-venv/bin/python -B -m unittest -v tests.test_verification_dispositions tests.test_manifest_package.ManifestTests.test_disposition_helper_ships_without_target_review_policy
```

Observed: **29 tests in 43.989 seconds, OK, exit 0**. The longer duration is this run's actual result; the earlier 6.463-second observation is separate. Scratch `bounded-tests.log` and `bounded-tests.json` retain complete output and exact arguments. The tests cover the repaired context cases, strict defaults, raw/effective reporting, source fingerprint changes, real Git-layer fixtures and manifest inclusion. A read-only AST check confirmed helper ownership and policy exclusion. `git diff --check e158ddc7263a55f5308944c5a426eb1e9f1a4327 HEAD` exited 0. Candidate and scratch stayed clean; `identity-before.json` and `identity-after.json` bind this review.

Mutation probes were not performed by this release reviewer; selected code/test reviewers own independent critical mutation review. No mutant outcome is claimed as my execution. Not run here: full repository suite, full qualifying verifier, new package/install round trip, Windows/macOS execution, arbitrary external report consumers, complete receipt lifecycle, external CI or live operations. Other selected reviews and both final gates must qualify the frozen successor before merge. Any source repair requires fresh review.
