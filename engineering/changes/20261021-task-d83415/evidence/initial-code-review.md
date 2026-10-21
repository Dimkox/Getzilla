# Independent code review: verification dispositions

Review status: **FAIL — one security blocker.** Review execution is complete. The final qualifying gate is **NOT_RUN**.

Reviewer: `/root/code_reviewer`. Route: `d834158878e0`. Scope: security, duplicate external writes and tests. No source fixes were made.

## Source and isolation

- Candidate: `/home/pall/projects/liqvera/.getzilla/runtime/getzilla-dispositions`.
- Base: `e158ddc7263a55f5308944c5a426eb1e9f1a4327`.
- Before/after HEAD: `9e29128aed4abea3dbe50d7f797aecbb26ff17d9`.
- Before/after Git tree: `eb9006a8a0e0b861a101b15d6094ddb6df228f96`.
- Before/after status: clean, including untracked files. Hashes of all 26 changed files match.
- Private scratch: `/home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-code-review`, mode `0700`.
- Exact snapshot: the scratch `snapshot/` directory. `git archive --format=tar HEAD`, followed by scratch-only `git init -q`, `git add -f .` and `git write-tree`, reproduced the candidate tree before probes. All mutations were restored. Final `git diff --exit-code` returned zero and `git write-tree` reproduced the same tree.

reviewed-tree-modified: no

The scratch ancestors were checked for canonical paths, current-user ownership, no sticky bit and no group/other write permission. `TMPDIR` was inside scratch. All tests and their subprocesses used affinity `0-5`, at most six CPUs. A child affinity check reported six CPUs and `0-5`. Mutation runs were serialized because they replace the same scratch source files. No artifact-producing command ran in the candidate. No secret, private configuration or live service was accessed. There was no deployment, external mutation or publication.

AGENTS, README, START_HERE, PROJECT_STATE, actual diff, active change package and selected workflow skills were read. Getzilla uses `architecture/system.yaml` and PROJECT_STATE instead of Liqvera's `docs/architecture.md` and `handoff.md`. Worktrees and existing main/tag ancestry were recorded without cleanup or remote writes. The coordinator's startup-capacity record was inspected. The role-specific read-only instruction takes precedence over startup commands that would write candidate runtime state.

## Finding

1. **Blocking, medium — the standalone-token boundary admits credential-name suffixes.** In `.getzilla/getzilla/verification_dispositions.py:82`, `public_token()` treats every preceding character outside `[\w$.-]` as a safe boundary. Python's `\w` does not cover all JavaScript identifier continuation characters. An identifier that contains U+200C, U+200D or a combining mark before the suffix `token` is therefore admitted. A JavaScript Unicode escape ending in `}` before that suffix is also admitted. All four synthetic cases produced `pass`, `1 disposed`, `0 unresolved` with correctly bound file/hash/location/evidence. Node confirmed that all four are valid identifiers. They are credential names, not the documented standalone lowercase `token` field.

   The committed credential-name test does not protect this guard: it gives the full prefixed assignment's hash and column 1, while the broad scanner matches the suffix at a later column. It rejects that entry on locator/hash mismatch even if the boundary guard is removed. Removing the entire boundary guard leaves all 22 committed tests passing. An independent test using the actual suffix location/hash catches that removal.

   Have the sole writer reject identifier continuations and escape-derived suffixes conservatively. Add negative tests with valid scanner locations and match hashes for ASCII, Unicode and escaped credential prefixes. Preserve the legitimate standalone token case. The coordinator has accepted this finding and will request a new review after a separate repair; this report remains bound to the original failing candidate.

## Security and write assessment

The rest of the inspected design remains narrow: duplicate JSON keys and unknown fields fail; hashes bind complete raw source and separate review evidence; every configured entry is validated; tracked regular paths exclude symlinks, hidden index flags and runtime evidence; per-match scanning preserves unresolved findings; whitespace classification uses the actual worktree/index/HEAD bytes and retains raw command output and exit codes. The focused tests and mutations below support those specific boundaries. A hash is not authenticated review authority, as the documentation correctly states.

No duplicate external-write path is introduced. The new helper reads files and Git objects and classifies observations. Independent repeat calls to both checks produced identical results and unchanged fixture Git status. This supports repeatability of these local checks, not a claim about deployments or external services.

## Executed checks

All commands below ran from the scratch `snapshot/` directory. Their common environment was `TMPDIR=/home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-code-review/tmp`, `PYTHONDONTWRITEBYTECODE=1`, `GETZILLA_SERIAL=1`; subprocess tests used `PATH=/usr/bin:/bin`. Exact argument arrays and logs are retained in the scratch artifacts.

| Claim | Exact command | Observed result |
| --- | --- | --- |
| Committed disposition regressions pass on the unmodified candidate | `taskset -c 0-5 python3 -B -m unittest -v tests.test_verification_dispositions` | Exit 0; 22 tests pass. Repeated after restoring mutations: 22 pass. |
| Helper ships without shipping target review policy | `taskset -c 0-5 python3 -B -m unittest -v tests.test_manifest_package.ManifestTests.test_disposition_helper_ships_without_target_review_policy` | Exit 0; one test passes. |
| Correctly located credential prefixes are rejected; repeated checks do not change source | `taskset -c 0-5 python3 -B /home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-code-review/independent-probes.py` | Plain token passes and ASCII credential fails as intended. Four Unicode/escape credential cases falsely pass. Repeated secret/whitespace results are equal; all fixture statuses stay unchanged. The script exits 0 as a diagnostic collector; the recorded expected/actual mismatches are failures, not passes. |
| Independent ASCII suffix rejection oracle | `taskset -c 0-5 python3 -B /home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-code-review/independent-probes.py --ascii-only` | Baseline exits 0; removing the boundary makes the oracle exit 1. |
| The problematic names are valid JavaScript identifiers | `taskset -c 0-5 node /home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-code-review/identifier-syntax.cjs` | Exit 0; all four synthetic names compile and return the harmless fixture value. |

The independent probes use only synthetic public-shaped values. No real credential or private key is involved. They do not establish the real-world public identity of any future disposition target.

## Bounded mutation probes

Driver: `taskset -c 0-5 python3 -B /home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-code-review/run-mutations.py`.

All replacements occur only in the verified scratch snapshot and are restored in `finally` blocks. For M1–M4, the command is `taskset -c 0-5 python3 -B -m unittest -v` followed by the exact qualified test names below. Full commands, replacement strings and outcomes are in `mutation-results.json`.

| Mutant | Exact selected tests / probe | Result |
| --- | --- | --- |
| M1: disable duplicate JSON-key rejection | `tests.test_verification_dispositions.DispositionTests.test_malformed_duplicate_key_version_and_size_fail_without_findings` | **Killed.** Exit 1; duplicate-key case fails. |
| M2: retain only the first match per secret rule | `tests.test_verification_dispositions.DispositionTests.test_one_disposition_never_suppresses_second_match_on_same_line` and `tests.test_verification_dispositions.DispositionTests.test_two_occurrences_require_two_location_bindings` | **Killed.** Exit 1; both tests fail. |
| M3: use worktree bytes for every Git layer | `tests.test_verification_dispositions.DispositionTests.test_current_worktree_hash_cannot_dispose_a_different_head_blob` and `tests.test_verification_dispositions.DispositionTests.test_staged_and_worktree_eof_are_bound_to_their_own_bytes` | **Killed.** Exit 1; both tests fail. |
| M4: return before source-stability checks | `tests.test_verification_dispositions.DispositionTests.test_evidence_mutation_during_scan_fails_closed` | **Killed.** Exit 1; the test fails. |
| M5: remove the token-name boundary | Full `tests.test_verification_dispositions` module, then independent `--ascii-only` oracle | **Survived committed suite:** 22 pass. **Killed independently:** oracle exits 1. This coverage gap is part of the blocker above. |

No executed mutant was inconclusive. These are bounded behavior probes, not an exhaustive mutation score. The restored candidate's passing 22-test run does not override the independent parser failure.

## Limits and evidence

Unexecuted here: the final Getzilla gate, broad repository suites, full packaging/install round trips, Liqvera end-to-end adoption, external exact-head CI, Windows filesystem behavior, exhaustive malformed-input/resource-limit stress and adversarial filesystem races. Static review of those surfaces is not fresh execution evidence. No active disposition policy is added by this diff, and no future entry's historical or public identity was authenticated by these synthetic probes.

Evidence under the scratch root: `source-before.json`, `source-after.json`, `source.diff`, `ancestry-before.txt`, `worktrees-before.txt`, `capacity.txt`, `independent-results.json`, `mutation-results.json`, `final-control-results.json`, and named `.log` files. `source-before.json` and `source-after.json` preserve exact changed-file SHA-256 bindings. The full report is outside the candidate. A repaired successor needs fresh exact-source review before reports are frozen and the final gate runs.
