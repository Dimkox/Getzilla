# Evidence index

- startup-capacity.json: measured host/process/cgroup capacity before routing and heavy work.
- baseline.json: exact source revision, captured live URL, analytics hashes and observed Pricing drift.
- analysis reports: independent route-selected findings, persisted by the coordinator.
- Implementation, focused observations, browser/HTML/lab reports and final gate results are recorded as they run. A missing check is not a pass; the final local gate and external merge authority remain separate.

<!-- checkpoint:initial -->
## Initial checkpoint

Local observation only; not verification or publication evidence.

```json
{
  "branch": "codex/getzilla-seo-v111",
  "change_id": "20261007-task-b1693e",
  "detached": false,
  "dirty_product_paths": [],
  "dirty_product_state": "clean",
  "git_available": true,
  "git_findings": [],
  "head": "b7aa0a55f3236c578d4365f3f0e58ce5962cf319",
  "kind": "initial",
  "note": "draft; implementation not started",
  "observed_at": "2026-10-07T11:20:01+00:00",
  "route_id": "b1693e9cb114"
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
  "change_id": "20261007-task-b1693e",
  "route_id": "b1693e9cb114",
  "observed_at": "2026-10-07T11:42:45+00:00",
  "branch": "codex/getzilla-seo-v111",
  "head": "7c32ea46b99182ff6e76b47a438c5f4522cb16b7",
  "detached": false,
  "git_available": true,
  "git_findings": [],
  "dirty_product_state": "clean",
  "dirty_product_paths": [],
  "note": "implementation started; preserve work before handoff"
}
```

## Final identity correction

The original full gate exposed the inherited migration-note branding defect, diagnosed and repaired in identity-diagnosis.md and identity-repair-report.md. Current page hash and archive are recorded in upload-archive.json; current Nu and bounded mobile observations are nu-local-final.json and identity-note-320.json. Previous reports remain historical at their documented source identities. See review-resolution.md for the exact one-question exception and API transport/exact-head verification requirements.
