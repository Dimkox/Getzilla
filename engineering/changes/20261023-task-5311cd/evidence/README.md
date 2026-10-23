# Evidence

Base and initial HEAD: 8a02bab3d3e2a4e4cf8e023068a9652cbb89a5be.
Initial tree: d728995aa1153ab52e88e3d8d82dedbe37d0e0aa.
Initial product inventory: clean; staged and unstaged empty; only new workflow packages untracked.

The coordinator first paraphrased the task with production/migration terms. This created an out-of-scope route. It was cancelled before implementation and archived under canonical runtime scratch. The exact user text produced route 5311cdded150 with no human gates and the same selected agents as the initial route.

Analysis reports and startup capacity are observations. They are not review receipts. Current verification remains UNVERIFIED until the frozen-candidate gate and external checks pass.

<!-- checkpoint:initial -->
## Initial checkpoint

Local observation only; not verification or publication evidence.

```json
{
  "branch": "fix/pr127-validation-20261023",
  "change_id": "20261023-task-5311cd",
  "detached": false,
  "dirty_product_paths": [],
  "dirty_product_state": "clean",
  "git_available": true,
  "git_findings": [],
  "head": "8a02bab3d3e2a4e4cf8e023068a9652cbb89a5be",
  "kind": "initial",
  "note": "draft; implementation not started",
  "observed_at": "2026-10-23T06:52:03+00:00",
  "route_id": "5311cdded150"
}
```

Initial evidence accounting (current records are in `state.json`):

```json
{
  "obligations": [
    {
      "id": "verification",
      "kind": "receipt",
      "reason": "implementation not started",
      "receipt_kind": "verification",
      "status": "not_run"
    },
    {
      "id": "code_review",
      "kind": "receipt",
      "reason": "implementation not started",
      "receipt_kind": "code_review",
      "status": "not_run"
    },
    {
      "id": "test_review",
      "kind": "receipt",
      "reason": "implementation not started",
      "receipt_kind": "test_review",
      "status": "not_run"
    },
    {
      "id": "security_review",
      "kind": "receipt",
      "reason": "implementation not started",
      "receipt_kind": "security_review",
      "status": "not_run"
    }
  ],
  "schema_version": 1
}
```

<!-- checkpoint:implementation -->
## Implementation checkpoint

Local observation only; not verification or publication evidence.

```json
{
  "kind": "implementation",
  "change_id": "20261023-task-5311cd",
  "route_id": "5311cdded150",
  "observed_at": "2026-10-23T06:58:15+00:00",
  "branch": "fix/pr127-validation-20261023",
  "head": "8a02bab3d3e2a4e4cf8e023068a9652cbb89a5be",
  "detached": false,
  "git_available": true,
  "git_findings": [
    "uncommitted_product_zero_ahead"
  ],
  "dirty_product_state": "dirty",
  "dirty_product_paths": [
    "factory/runtime/linux_process_adapter.py",
    "factory/tests/test_linux_process_adapter.py",
    "mistakes.md"
  ],
  "note": "implementation started; preserve work before handoff"
}
```
