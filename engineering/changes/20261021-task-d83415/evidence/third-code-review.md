# Independent code review — R3

**PASS within the reviewed scope. No remaining blocker found.** Scope: security, duplicate external writes and tests. Reviewer: `/root/code_reviewer`; route: `d834158878e0`. Final qualifying gate: **NOT_RUN**.

**Binding.** Candidate `/home/pall/projects/liqvera/.getzilla/runtime/getzilla-dispositions`; actual base `e158ddc7263a55f5308944c5a426eb1e9f1a4327`, independently confirmed as the merge base with fetched origin/main. Before and after HEAD: `4c4cd124b2e382d3c6d8b19e2efe2c8fb45219ae`; tree: `3dd0c14d38b13e618a736735d5eefb830295cf32`. Status stayed clean, including untracked files; all 42 changed-file hashes match. Observations: 14:09:33–14:14:44 UTC on 2026-10-21.

reviewed-tree-modified: no

**Isolation.** Fresh scratch `/home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-r3-code-review` has mode `0700`, under verified canonical, owned, non-sticky ancestors without group/other write permission. A Git archive reproduced the exact candidate tree in `snapshot/`; scratch-only `git write-tree` matched before and after mutations, and final `git diff --exit-code` returned zero. TMPDIR stayed in scratch. Probes used CPUs `0-5`, at most six; mutations were serial because they edit the same scratch file. No candidate artifacts, secrets, live actions or source fixes were involved.

**Assessment.** The actual diff and repaired controls were inspected without inheriting earlier verdicts. Whole-prefix ASCII validation, including comments/strings, closes the reproduced Unicode context gaps. The supported code alphabet rejects ambiguous constructs; ordinary ASCII declarations/object fields remain eligible. This is a conservative eligibility check, not a JavaScript parser. Correct scanner locations and match hashes are used in the new tests. Existing hash/path/schema validation, Git-layer binding, complete finding retention and source-stability regressions remain covered by the fresh focused suite. No external-write path is introduced; repeated independent scans produced equal results and unchanged fixture status.

Fresh independent probes cover 21 complete synthetic programs: six eligible contexts and 15 rejected contexts, including all earlier identifier and mixed-whitespace failures, hidden Unicode comment terminators, legacy HTML comments, and FF/VT declarations/member access. Every expectation passed. Node parsed each program without executing it. Earlier failures on `9e29128`/tree `eb9006a8` and `98ff573`/tree `52ffc8f3`, plus implementation controls on `209a80b` and `a8c8a15`, remain separately identified historical evidence.

## Executed commands and mutation results

Exact command aliases and environment used below:

```sh
review_python=/home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-gate-venv/bin/python
review_scratch=/home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-r3-code-review
review_tests=tests.test_verification_dispositions.DispositionTests
cd "$review_scratch/snapshot"
export PATH=/usr/bin:/bin TMPDIR="$review_scratch/tmp" PYTHONDONTWRITEBYTECODE=1 GETZILLA_SERIAL=1
```

| Claim/probe | Exact command | Observed result |
| --- | --- | --- |
| Disposition regressions | `taskset -c 0-5 "$review_python" -B -m unittest -v tests.test_verification_dispositions` | Exit 0; 28 tests pass, 5.233 s. |
| Packaging boundary | `taskset -c 0-5 "$review_python" -B -m unittest -v tests.test_manifest_package.ManifestTests.test_disposition_helper_ships_without_target_review_policy` | Exit 0; one test passes, 2.508 s. |
| Independent contexts and repeatability | `taskset -c 0-5 "$review_python" -B "$review_scratch/context-probes.py"` | Exit 0; all 21 expectations and syntax/repeatability assertions pass. |
| M1: remove the complete-prefix ASCII check | `taskset -c 0-5 "$review_python" -B -m unittest -v "$review_tests.test_non_ascii_comment_and_string_prefixes_are_conservatively_refused"` | **Killed:** exit 1, eight assertion failures. |
| M2: remove the supported-code alphabet check | `taskset -c 0-5 "$review_python" -B -m unittest -v "$review_tests.test_unsupported_ascii_constructs_cannot_manufacture_standalone_context"` | **Killed:** exit 1, five assertion failures. |

Both mutants were restored in `finally` blocks. No executed mutant survived or was inconclusive. An initial command combining the first two test targets reached the reviewer's 45-second timeout: **inconclusive, not pass**. Partial output was not retained by that first driver. Both targets then passed separately without source changes; the timeout did not recur and its cause is unestablished. It is recorded in `initial-combined-timeout.json`.

**Limits.** No full gate, broad suite, external CI, full installer round trip, fresh Liqvera adoption run, exhaustive language parsing/resource stress or filesystem-race campaign ran here. Supplied real-Liqvera controls were inspected as other evidence, not relabelled as this review's execution. Unsupported prefixes intentionally remain blocking. This report does not create a verification receipt or deployment authority.

Complete bindings, commands and logs are in the scratch `source-before.json`, `source-after.json`, `source.diff`, `focused-result.json`, `package-result.json`, `contexts-result.json`, `context-results.json`, `mutation-results.json` and named logs. The final gate remains pending until all current reports are persisted and frozen.
