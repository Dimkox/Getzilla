# Code review — PASS with one Low test finding

Scope: security, duplicate external writes, and tests. No blocking defect found.

- **Low:** `test_rejects_nonancestor` changes source on its orphan branch. The source-delta guard masks removal of the ancestry guard. Add an unrelated commit with the same tree to isolate ancestry. Current code rejects this case correctly.
- No external mutation path was added. Duplicate external writes do not apply.
- The fixture helper commits all prepared changes. It therefore proves committed-candidate admission, not dirty-candidate rejection. Dedicated dirty, staged, and untracked tests retain that coverage.

Source identity before and after:

- HEAD: `c6bbfa86b3d3177b0b66993ceaf3f092b6e6cbfa`
- Tree: `9950552a6d088e518ea5db688659808ce271e4b7`
- Fingerprint: `7fc6376f1514f3be3cc0cca905b6fe65d9d857c5a7af15dba87cf849dfa4a0ad`
- Candidate status: clean.
- reviewed-tree-modified: no

Scratch: `/home/pall/getzilla-session/code-review-ee7lw94a`, mode `0700`, under owner-controlled non-sticky parent `/home/pall/getzilla-session`, mode `0700`. `git clone --quiet --no-hardlinks /home/pall/getzilla-session/Getzilla <scratch>/repo` and checkout of the exact HEAD reproduced the candidate HEAD/tree with clean status. All tests and mutations ran there.

Executed controls used `PYTHONDONTWRITEBYTECODE=1 TMPDIR=<scratch>/tmp taskset -c 0-3` and one test process:

```text
python3 -m unittest tests.test_review_source -q
14 tests; OK.

python3 -m unittest \
 tests.test_package_status.PackageStatusTests.test_status_rejects_legacy_and_forged_review_source_receipts \
 tests.test_package_status.PackageStatusTests.test_stop_does_not_hide_incomplete_package_behind_current_receipts \
 tests.test_hooks.HookTests.test_stop_allows_current_evidence -q
3 tests; OK.
```

An earlier command named a nonexistent package-status test. It produced one loader error. The corrected command above passed.

Mutation probes edited scratch files, ran the named test, then restored the original bytes:

| Mutation | Command/probe | Result |
|---|---|---|
| Replace ancestry condition with `if False` | `python3 -m unittest tests.test_review_source.ReviewSourceTests.test_rejects_nonancestor -q` | **Survived**: existing test passed; Low finding above. |
| Remove report-path allowlist condition | `python3 -m unittest tests.test_review_source.ReviewSourceTests.test_rejects_source_delta_and_dirty_or_untracked_candidate -q` | **Killed**: committed source delta was admitted; assertion failed. |
| Disable consumption binding check | `python3 -m unittest tests.test_review_source.ReviewSourceTests.test_consumption_rejects_missing_and_forged_binding -q` | **Killed**: all four missing/forged-binding subtests failed. |

Independent ancestry probe: create an unrelated identical-tree commit with `git commit-tree <tree> -m 'unrelated identical tree'`, then call `review_source_binding(root, unrelated_commit, report)` in a fresh subprocess. Original code exited `1` with “reviewed commit is not an ancestor.” The ancestry mutant exited `0` and admitted it. This probe **kills** that mutant.

Limits: no Windows execution, full-suite run, production activation, external CI, or concurrent filesystem-race probe. Static inspection of path safety, bounded Git calls, receipt publication, and external-write absence is not executable proof. Final exact-head verification and external checks remain pending.
