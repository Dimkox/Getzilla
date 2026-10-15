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
  "change_id": "20261015-task-19101f",
  "route_id": "19101f3e5e0d",
  "observed_at": "2026-10-15T06:57:29+00:00",
  "branch": "feat/language-quality-gates-20261015",
  "head": "7cf4f65dd2ba9bb1390dc84c6185ba0f104255c8",
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
    },
    {
      "id": "security_review",
      "kind": "receipt",
      "receipt_kind": "security_review",
      "status": "not_run",
      "reason": "implementation not started"
    },
    {
      "id": "release_review",
      "kind": "receipt",
      "receipt_kind": "release_review",
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
  "change_id": "20261015-task-19101f",
  "route_id": "19101f3e5e0d",
  "observed_at": "2026-10-15T07:56:32+00:00",
  "branch": "feat/language-quality-gates-20261015",
  "head": "ad9a5a3fef511997162870386b19dd2fd905adce",
  "detached": false,
  "git_available": true,
  "git_findings": [],
  "dirty_product_state": "dirty",
  "dirty_product_paths": [
    ".getzilla/getzilla/cpu_budget.py",
    ".getzilla/getzilla/language_quality/core.py",
    ".getzilla/getzilla/language_quality/sandbox.py",
    ".getzilla/getzilla/python_test_runner.py",
    ".getzilla/getzilla/verification.py",
    ".getzilla/templates/consumer-AGENTS.md.tmpl",
    "AGENTS.md",
    "START_HERE.md",
    "decisions.md",
    "docs/LANGUAGE_QUALITY_GATES.md",
    "docs/REFERENCE.md",
    "mistakes.md",
    "tests/test_lqg_core.py",
    "tests/test_python_test_runner.py"
  ],
  "note": "implementation started; preserve work before handoff"
}
```
