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

## Delivery boundary and admission observations

The first frozen candidate193c547 received a required release-review escalation before heavy tests. Runtime routing adopted only the reviewers/evidence selected by router.escalate_route. The next candidatea5c598e reached the range whitespace check and found extra EOF lines in four newly added analysis reports. Both results are failures, not passing gates. Raw reports are under canonical runtime scratch/pr127-final.

The source repair is unchanged. This repair batch normalizes the four reports, records effective review scope and refreshes all selected reviews before a new freeze.

Push is BLOCKED by the tool-denial circuit breaker. The first native exec push lost its workdir at the harness bridge; the hook checked the canonical checkout. Explicit cd then failed cross-root before grant lookup. No push occurred. Open a new session with /home/pall/projects/getzilla/.getzilla/runtime/worktrees/pr127-followup as the actual workspace root. Refresh the exact branch grant, push the frozen candidate, open a successor PR and require exact-head linux/windows CI plus resolved threads. Never retry around the root boundary in this session.

The Low archived-install regression gap was added to issue122:
https://github.com/Dimkox/Getzilla/issues/122#issuecomment-6359615975
