# Independent code review: 2abea745

Reviewer: /root/lqg_code_review. Recommendation: **FAIL**. Two Medium findings require repair.

- **Medium — Configuration changes can skip blocking checks.** `core.py:208` recognizes fixed configuration names only. A change confined to a configured `rules.json` or `.getzilla/config/policy.json` can select no source files. Lines 352–354 return `SKIPPED_BY_POLICY`, and line 422 omits the blocking check. Include resolved configuration and policy paths in scope invalidation. Add regression tests for both cases.
- **Medium — A source FIFO can hang verification.** `core.py:265` opens the input before checking its file type. A tracked source replaced with a FIFO can block before the sandbox timeout starts. Open without blocking, validate the descriptor as a regular file, then read. Add a bounded FIFO regression test.

Source identity:

- Candidate: `/home/pall/projects/getzilla/.getzilla/runtime/worktrees/lqg-20261015`
- Base: `7cf4f65dd2ba9bb1390dc84c6185ba0f104255c8`
- HEAD before/after: `2abea74537edd4980be6c0239b4fb2fe57de3181`
- Tree fingerprint before/after: `86892a3d091660b541991f7f2d57e9c1330437bd`
- `git rev-parse HEAD HEAD^{tree}` returned those identities.
- `git status --porcelain=v1 --untracked-files=all` returned no changes.
- `git diff --exit-code 2abea74537edd4980be6c0239b4fb2fe57de3181 --` exited 0.
- reviewed-tree-modified: no

Mutation evidence: **NOT_RUN / inconclusive**. Scratch path `/home/pall/projects/getzilla/.getzilla/runtime/lqg-code-review-2abea745` was not created. These exact commands were denied:

```text
mkdir -m 700 /home/pall/projects/getzilla/.getzilla/runtime/lqg-code-review-2abea745
```

Observed: hook required an exact protected-path grant.

```text
python3 scripts/getzilla_approve.py protected-path --action protected-path-write --resource .getzilla/runtime/lqg-code-review-2abea745 --resource .getzilla/runtime/lqg-code-review-bootstrap.py --source explicit-user-consent --ttl 120 --reason 'Delegated independent reviewer scratch only; exact private snapshot and bounded probes; no candidate writes'
```

Observed: `ambiguous-command-root`. The circuit breaker stopped further attempts.

Operator-image admission, credential exclusion, network isolation, cleanup, configuration invalidation and FIFO handling received no executable probes. No mutants ran. Static findings above remain unexecuted.

No duplicate external-write defect was found by static inspection. SDK qualification, installer completeness and runtime cleanup remain unverified by this reviewer. Documentation correctly labels cache reuse, SDK smoke and latency benchmarks as pending. No PASS receipt is justified.
