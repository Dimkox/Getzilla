# Offline continuation journal (issue235 T3)

This slice preserves local attempt and budget records. It does not dispatch requests. All six startup adapters remain unqualified. Issue235 stays open for native adapters, checkpoints, effect reconciliation, fencing and current permission checks.

The API lives in `.getzilla/getzilla/model_continuation_state.py`:

- `create_chain(root, Binding, Usage, TaskBudget)` records the original attempt as candidate zero. The ordered policy list includes this original model. Original request/cost usage and task deadline must be supplied; unknown usage fails.
- `inspect_chain(root, binding)` reads a matching chain. Missing or corrupt state is an error, not a fresh budget.
- `record_terminal(root, binding, generation, event_id, category)` records a closed normalized category. Terminal inference state leaves tool effects unknown.
- `reserve_next(root, binding, expected_revision, event_id, Usage)` returns `adapter_not_qualified` in production. Tests patch the private boundary only to exercise persistence. Every result has `dispatch_permitted:false`, including test reservations.
- `cancel_chain(root, binding, expected_revision)` stops further reservation and retains all expenditure. Cancellation can reduce activity after policy revocation.

Bindings include chain/task/owner/route/session IDs and workspace/source/checkpoint digests. They are trusted caller references, not proof of live source or native provenance. T4/T5 must verify that provenance before any real adapter exists. IDs and category codes are bounded; raw prompts, errors and credentials are not accepted.

## Budget and crash behavior

The stricter task or policy cap applies. Each task ID can have only one chain in a repository, even if a caller changes chain ID. Original usage counts; attempts use candidates in order without reuse. Requests can reserve more than one call for a bounded attempt. There is no hidden retry allowance, cost refund, expiration, pruning or automatic recovery API.

Policy JSON preserves exact decimal money. USD ceilings round down to integer micros; reservations and observed original charges round up. Positive sub-micro ceilings fail. Usage/task money accepts decimal strings, Decimal or integers, never binary floats. Time is conservatively floored to whole seconds. Absolute deadlines and last observation time survive restart. Backward clock observations stop admission. Disabling or materially changing policy stops new reservation; caps are never enlarged in place.

Committed reservations remain `reserved_unknown` after crashes. They cannot be sent or replayed from this journal. Duplicate events return a prior result only when their complete normalized content matches; conflicting IDs and stale generations/revisions fail. A provider request ID is not an idempotency guarantee. Future native adapters must prove stop/fence, checkpoint completeness, effect reconciliation, destination authorization and retry accounting before continuation.

## Storage support

The protected store is `.getzilla/runtime/model-continuation/`: one stable kernel lock and one bounded 512KiB journal, at most64chains and256events per chain. Full capacity refuses new work without dropping active records. The store is owner-only. Reads reject nonregular files, symlinks, hardlinks, executable/shared-mode files, duplicate keys and inconsistent data. Checksums detect corruption, not hostile rewrites by an already-authorized same-user process.

Pinned directory handles and file identity checks detect directory/lock replacement. Publication flushes file data, atomically replaces the journal, then flushes its directory. A failure after replacement is ambiguous and yields an error; the caller must inspect and reconcile, never resend. Failed first publication can leave a lock with no journal; this deliberately needs investigation instead of silently resetting a ledger.

Admission requires POSIX directory fsync and stable filesystem locking. Unsupported filesystems fail closed on primitive errors. Windows admission is explicitly unsupported because this repository has no directory-fsync implementation there. Local process/crash fixtures do not establish hardware power-loss guarantees on every filesystem.

This store has no relationship to Factory PostgreSQL budget grants or PR239 progress TTL/recovery. It never issues either grant and never clears blocked checks. Existing native status and installer override rules remain unchanged.

## Recovery and rollback

Disable the policy to stop reservation. Preserve the journal and unknown outcomes. Revert source through a reviewed PR if needed; never delete a ledger to regain attempts or money. No live dispatch path exists to roll back in T3.

## Controlled local fixture

`getzilla.controlled_fixture.run` exercises only a synthetic two-model Codex session. It requires a pinned local Docker image and an exact Codex 0.165.0 binary. The image is not downloaded. The host copies the fixture script and binary into a new local image and verifies both hashes inside that image before use. The inspected execution container has no bind mounts. It uses `network=none`, read-only root, a non-root user, dropped capabilities and bounded resources. It receives no host journal, credentials or user input. This assumes the local Docker daemon and pinned base image are trusted.

The host stores fixture accounting separately in `.getzilla/runtime/model-continuation-fixture/`, using the same protected T3 storage primitives. A fixed fixture policy must name `local_fixture/synthetic` candidates `fixture-a` and `fixture-b`. The host records the original usage and consumes its one-shot send state before starting the container. It accepts the next turn only after a correlated terminal 429 with no native retry or observed tool effects, and after recording the next reservation against the same budget. It records success only after the container exits and cleanup succeeds.

Restarting the same task never sends an unknown or completed attempt again. An ambiguous send or cleanup remains unknown and requires investigation. Each result retains `dispatch_permitted:false`. The fixture journal records synthetic facts only; its domain, its messages and its claim cannot qualify a live adapter or prove a live process is fenced. It does not implement ordinary Getzilla startup switching or qualify any of the six clients.

To exercise the optional isolated fixture on a machine with the pinned local image and binary, run `GETZILLA_RUN_CODEX_FIXTURE=1 python3 -m unittest tests.test_controlled_fixture` with the installed Codex on `PATH`. The regular unit suite skips this opt-in test. No provider call is required. If the exact local dependencies are missing, the fixture fails closed. Rollback is a reviewed source revert; preserve the fixture journal rather than deleting it to reset a budget.
