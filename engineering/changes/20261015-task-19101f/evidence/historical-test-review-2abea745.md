# Independent test review: 2abea745

Reviewer: /root/lqg_test_review. Recommendation: **FAIL**. Static review found two Medium defects. Independent executable review is **inconclusive**.

- **Medium — configuration changes can skip blocking checks.** `core.py:208` does not classify an arbitrary configured filename or `.getzilla/config/policy.json` as a configuration change. With no changed source file, the registry can return `SKIPPED_BY_POLICY`. Existing scope tests cover a lockfile. Add registry tests for custom-config and policy-only changes.
- **Medium — a special input file can block verification.** `core.py:265` opens an input before checking its file type. A FIFO can block before the sandbox timeout starts. Existing input tests cover access times and directory symlinks. Add a bounded FIFO regression.
- **Critical coverage remains incomplete.** Tests do not exercise operator-registry ownership, permissions, symlinks or malformed schema. They also omit container cleanup failure and cancellation during execution. The current cancellation test stops before process creation. Add these cases before claiming those boundaries are verified.

Also test non-string tool drivers and sandbox engines. Static inspection shows set membership can raise `TypeError` outside `load_policy`'s error handling. This path was not executed.

Source identity:

- Repository: `/home/pall/projects/getzilla/.getzilla/runtime/worktrees/lqg-20261015`
- Base: `7cf4f65dd2ba9bb1390dc84c6185ba0f104255c8`
- HEAD before/after: `2abea74537edd4980be6c0239b4fb2fe57de3181`
- Git tree fingerprint before/after: `86892a3d091660b541991f7f2d57e9c1330437bd`
- `git status --porcelain=v1 --untracked-files=all`: empty before and after.
- reviewed-tree-modified: no

Scratch: `/home/pall/.cache/getzilla-lqg-test-review.r2Mh7THU`. Its parent and the scratch directory are owned by `pall`, mode `0700`, and non-sticky.

Executed setup commands:

```text
mktemp -d /home/pall/.cache/getzilla-lqg-test-review.XXXXXXXX
git archive --format=tar --output=/home/pall/.cache/getzilla-lqg-test-review.r2Mh7THU/candidate.tar 2abea74537edd4980be6c0239b4fb2fe57de3181
git rev-parse HEAD HEAD^{tree}
git status --porcelain=v1 --untracked-files=all
```

The commands succeeded. Archive extraction and snapshot verification did not run. The hook rejected `apply_patch` creation of the scratch helper with: "Write outside repository root is blocked." Probe setup stopped.

No independent tests or mutants ran. Scope fallback, special-file rejection, operator admission, snapshot confinement, cleanup, resource limits and blocking-result projection remain **unexecuted**. Their mutation outcomes are **inconclusive**; none is reported killed or survived. Non-critical adapter portions: `mutation: skipped (non-critical)`.

The owner reports 277 focused tests, 98 later LQG tests, a committed-HEAD control and Node sandbox smoke passing. These are supplied observations, not independent results from this review. Real SDK smoke, cache/performance qualification and final PR verification remain pending. No new duplicate external-write path was found by static inspection. The documented route mismatch remains unresolved.
