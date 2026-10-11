# Evidence

Store human-readable review reports here. Machine receipts live under `.getzilla/runtime/receipts/` and are bound to the current repository fingerprint.

`state.json` holds canonical local checkpoints and explicit evidence accounting. A `not_run` reason explains unfinished work; a recorded result is self-reported and does not satisfy a passing receipt. Checkpoints are observations in this worktree, and become available to another clone only when separately committed and published.

New-package and first-implementation observations are appended below by the lifecycle commands. A pending README mirror is surfaced in status and can be retried with the same explicit lifecycle command; state and README publication is not a two-file atomic transaction.

Code and test review reports perform bounded, change-relevant mutation probes in a reviewer-owned private scratch copy outside the reviewed worktree. Keep the reviewed candidate read-only; use scratch below a trusted non-sticky parent with mode `0700`. Reproduce the exact candidate (HEAD and relevant staged, unstaged, and untracked changes), record its HEAD and tree fingerprint before/after, and treat unsafe or mismatched snapshots and changed fingerprints as stale/inconclusive. Reviewer read-only configuration is not an OS-enforced isolation boundary.

Delivery order: 1. bounded local checks; 2. independent reviews of one committed candidate; 3. save the complete review reports; 4. commit and freeze the candidate; 5. one final qualifying `python3 scripts/getzilla_verify.py --mode pr`.

Reviewers return the complete report to the coordinator out-of-band and do not write into the candidate worktree. After all reviews finish, the coordinator saves all reports here, then commits and freezes the candidate. The frozen candidate tree must equal the tree the reviewers saw except for the saved report files: before the final gate, `git diff --name-only <reviewed-commit> HEAD` lists only those reports; any other difference makes every review stale. Record fresh fingerprint-bound receipts for the tree containing those reports only after the final gate passes. Any change after review invalidates all receipts: repeat the independent reviews on the new tree, save the new reports, commit and freeze again, and run a new final gate. Never reuse evidence from another tree.

Each report must include:

- source identity: HEAD and candidate tree fingerprint;
- scratch path and `reviewed-tree-modified: no`;
- each claim probed, exact command, concise observed output, and mutant outcome (`killed`, `survived`, or `inconclusive`);
- claims not executed and why; static claims without executable probes are unexecuted;
- surviving mutants as findings or explicit limitations (no blanket mutation-score threshold unless a scoped policy requires it).

<!-- checkpoint:initial -->
## Initial checkpoint

Local observation only; not verification or publication evidence.

```json
{
  "kind": "initial",
  "change_id": "20261011-task-1a11fc",
  "route_id": "1a11fc0a8f4b",
  "observed_at": "2026-10-11T00:51:13+00:00",
  "branch": "fix/verify-control-env-20261011",
  "head": "05f85f12b72b3a897c45c24e172fac8317120b7c",
  "detached": false,
  "git_available": true,
  "git_findings": [],
  "dirty_product_state": "clean",
  "dirty_product_paths": [],
  "note": "draft; implementation not started"
}
```

Initial evidence accounting (current records are in `state.json`):

```json
{
  "schema_version": 1,
  "obligations": [
    {
      "id": "verification",
      "kind": "receipt",
      "receipt_kind": "verification",
      "status": "not_run",
      "reason": "implementation not started"
    },
    {
      "id": "code_review",
      "kind": "receipt",
      "receipt_kind": "code_review",
      "status": "not_run",
      "reason": "implementation not started"
    },
    {
      "id": "test_review",
      "kind": "receipt",
      "receipt_kind": "test_review",
      "status": "not_run",
      "reason": "implementation not started"
    }
  ]
}
```

<!-- checkpoint:implementation -->
## Implementation checkpoint

Local observation only; not verification or publication evidence.

```json
{
  "kind": "implementation",
  "change_id": "20261011-task-1a11fc",
  "route_id": "1a11fc0a8f4b",
  "observed_at": "2026-10-11T00:53:02+00:00",
  "branch": "fix/verify-control-env-20261011",
  "head": "05f85f12b72b3a897c45c24e172fac8317120b7c",
  "detached": false,
  "git_available": true,
  "git_findings": [],
  "dirty_product_state": "clean",
  "dirty_product_paths": [],
  "note": "implementation started; preserve work before handoff"
}
```
