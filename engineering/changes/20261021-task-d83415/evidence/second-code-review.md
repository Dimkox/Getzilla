# Independent code review — disposition repair, round 2

Review status: **FAIL — one remaining security blocker.** This review is complete. Final qualifying gate: **NOT_RUN**.

Reviewer: `/root/code_reviewer`. Route: `d834158878e0`. Scope: security, duplicate external writes and tests. The candidate was not edited.

## Identity and isolation

- Candidate: `/home/pall/projects/liqvera/.getzilla/runtime/getzilla-dispositions`.
- Actual base: `e158ddc7263a55f5308944c5a426eb1e9f1a4327`.
- Before/after HEAD: `98ff57375f95cc93e5f3cc785a8105f23743d0a3`.
- Before/after tree: `52ffc8f3b4e8acec6c0f618cf062d388e84b6782`.
- Before/after status: clean, including untracked files. All 33 changed-file SHA-256 values match.
- Before observation: `2026-10-21T13:49:08.076511+00:00`; after: `2026-10-21T13:51:34.522837+00:00`.
- Private scratch: `/home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-r2-code-review`, mode `0700`.

reviewed-tree-modified: no

Canonical ancestors were checked for current-user ownership, no sticky bit and no group/other write permission. A fresh `git archive --format=tar HEAD` was extracted into `scratch/snapshot`. Scratch-only `git init -q`, `git add -f .` and `git write-tree` reproduced the exact candidate tree. After both mutations were restored, `git diff --exit-code` returned zero and `git write-tree` still matched. Candidate status, HEAD, tree and changed-file hashes were checked again.

Tests, temporary repositories and logs stayed outside the candidate. `TMPDIR` was inside scratch. All probe subprocesses had CPU affinity `0-5`; a child check confirmed six CPUs. Mutations were serialized because they edit the same scratch helper. No secret, live service, external write or deployment was accessed. The complete base-to-HEAD diff, repaired controls, route and reviewing state were inspected. Only the helper's context parser, its tests and documentation changed in executable review scope since the previous review; the core verification integration is unchanged.

## Finding

1. **Blocking, medium — mixed Unicode/ASCII whitespace defeats the member-context rejection.** At `.getzilla/getzilla/verification_dispositions.py:124`, the prefix walk treats non-ASCII whitespace as a significant character and replaces the preceding member-access dot in `previous`. A following ASCII space satisfies the immediate boundary check. The final punctuation check then permits the occurrence.

   Three complete, syntactically valid JavaScript member-assignment fixtures used U+00A0, U+FEFF or U+2028 followed by an ASCII space between the member dot and `token`. Each supplied the actual scanner match location/hash and exact file/evidence hashes. All three incorrectly returned `pass`, `1 disposed`, `0 unresolved`. Node parsed every complete program successfully without executing it. These are member assignments, not the documented standalone token context.

   The focused suite still passes all 24 tests. It tests a non-ASCII character immediately before `token`, but misses a non-ASCII separator earlier in a mixed whitespace sequence. Keep the prefix grammar conservative: reject unsupported code-prefix characters instead of allowing them to erase member context. Add real scanner-bound regressions for mixed whitespace. This does not require or justify a claim of full JavaScript parsing. The coordinator received this blocker; the sole writer must repair it in a separate candidate.

## Closure of the earlier finding

The original review applied to HEAD `9e29128aed4abea3dbe50d7f797aecbb26ff17d9`, tree `eb9006a8a0e0b861a101b15d6094ddb6df228f96`. Its failure and mutation observations remain historical.

Fresh probes on this successor confirm that the original four credential-prefix cases now fail closed: U+200C, U+200D, a combining mark and a Unicode escape ending in `}`. The corrected committed tests use actual scanner suffix locations and match hashes. Removing the context guard now causes 26 assertion failures, unlike the earlier surviving mutant. Ordinary standalone declarations/object fields, Unicode inside a completed comment, and Unicode inside a completed string still pass. This is closure of those specific cases, not of the remaining mixed-whitespace defect.

The strict JSON/path/hash loader, complete finding enumeration, Git-layer binding and source-stability code were reviewed again in the actual diff. The fresh 24-test run covers their existing regressions. No duplicate external-write path is added: the helper reads source/Git data and classifies findings. Repeated independent scans produced identical results and unchanged fixture Git status.

## Fresh checks and mutations

Working directory: `/home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-r2-code-review/snapshot`. Environment: `PATH=/usr/bin:/bin`, `TMPDIR=/home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-r2-code-review/tmp`, `PYTHONDONTWRITEBYTECODE=1`, `GETZILLA_SERIAL=1`.

| Claim | Exact command | Observed result |
| --- | --- | --- |
| Committed disposition regressions | `taskset -c 0-5 python3 -B -m unittest -v tests.test_verification_dispositions` | Exit 0; 24 tests pass in 2.787 seconds. |
| Original closure, legitimate context, mixed whitespace and repeatability | `taskset -c 0-5 python3 -B /home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-r2-code-review/context-probes.py` | Four positive contexts pass; four original negative contexts reject; three mixed-whitespace member cases falsely pass. All 11 complete programs parse in Node. Repeated results/statuses are unchanged. |
| Fresh bounded source mutations | `taskset -c 0-5 python3 -B /home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-r2-code-review/run-mutations.py` | Both mutants killed; all scratch source restored. |

The context script calls `node -e 'new Function(process.argv[1]);'` with each synthetic program to check syntax only. It does not execute the program. The script is a diagnostic collector and exits zero; the three expected/actual mismatches are failures, not passing acceptance. Only public-shaped synthetic values are used.

Both mutants run this exact command:

```text
taskset -c 0-5 python3 -B -m unittest -v tests.test_verification_dispositions.DispositionTests.test_address_shape_does_not_admit_credential_names_or_opaque_values tests.test_verification_dispositions.DispositionTests.test_real_scanner_suffix_never_disposes_unicode_or_escaped_credentials
```

| Mutant | Change | Classification and result |
| --- | --- | --- |
| M1 | Remove `_standalone_context(text, match.start())` from token admission | **Killed.** Exit 1; two test methods produce 26 assertion failures. |
| M2 | Replace the final member-punctuation rejection with unconditional `True` | **Killed.** Exit 1; two test methods produce six assertion failures. |

No executed mutant survived or was inconclusive. The bounded mutation success does not override the independent failure in the unmodified implementation. Exact replacements, argument arrays and logs are in `mutation-results.json` and the named `.log` files.

## Limits and evidence

The full Getzilla gate, broad repository suites, package/install round trips, external CI, Windows behavior, exhaustive language parsing, resource-limit stress and filesystem-race testing were not run. The coordinator's controls at `4998635d41c3b41028c56df456459b9bfa3e463e`, including the real Liqvera matches, were inspected as separate evidence and are not relabelled as this review's execution. This review makes no claim of complete JavaScript syntax recognition or real-world public identity verification for future policy entries.

Scratch evidence: `source-before.json`, `source-after.json`, `source.diff`, `ancestry-before.txt`, `worktrees-before.txt`, `capacity.txt`, `baseline-results.json`, `baseline.log`, `context-results.json`, `context-probes.py`, `mutation-results.json` and mutation logs. The candidate remains clean and unchanged. The full report is outside it. A repaired successor needs fresh review before the reports are frozen and the final qualifying gate runs.
