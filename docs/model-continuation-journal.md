# Offline continuation journal (issue235 T3)

This slice preserves local attempt and budget records. Direct model dispatch remains disabled. All six startup adapters remain unqualified. Issue235 stays open for native adapters, checkpoints, effect reconciliation, fencing and current permission checks.

The API lives in `.getzilla/getzilla/model_continuation_state.py`:

- `create_chain(root, Binding, Usage, TaskBudget)` records the original attempt as candidate zero. The ordered policy list includes this original model. Original request/cost usage and task deadline must be supplied; unknown usage fails.
- `inspect_chain(root, binding)` reads a matching chain. Missing or corrupt state is an error, not a fresh budget.
- `record_terminal(root, binding, generation, event_id, category)` records a closed normalized category. Terminal inference state leaves tool effects unknown.
- `reserve_next(root, binding, expected_revision, event_id, Usage)` returns `adapter_not_qualified` in production. Tests patch the private boundary only to exercise persistence. Every result has `dispatch_permitted:false`, including test reservations.
- `cancel_chain(root, binding, expected_revision)` stops further reservation and retains all expenditure. Cancellation can reduce activity after policy revocation.

Bindings include chain/task/owner/route/session IDs and workspace/source/checkpoint digests. They are trusted caller references, not proof of live source or native provenance. Native continuation must verify that provenance. IDs and category codes are bounded; raw prompts, errors and credentials are not accepted.

## Budget and crash behavior

The stricter task or policy cap applies. Each task ID can have only one chain in a repository, even if a caller changes chain ID. Original usage counts; attempts use candidates in order without reuse. Requests can reserve more than one call for a bounded attempt. There is no hidden retry allowance, cost refund, automatic record expiry, pruning or automatic recovery API.

Policy JSON preserves exact decimal money. USD ceilings round down to integer micros; reservations and observed original charges round up. Positive sub-micro ceilings fail. Usage/task money accepts decimal strings, Decimal or integers, never binary floats. Time is conservatively floored to whole seconds. Absolute deadlines and last observation time survive restart. Backward clock observations stop admission. Disabling or materially changing policy stops new reservation; caps are never enlarged in place.

Committed reservations remain `reserved_unknown` after crashes. They cannot be sent or replayed from this journal. Duplicate events return a prior result only when their complete normalized content matches; conflicting IDs and stale generations/revisions fail. A provider request ID is not an idempotency guarantee. Future native adapters must prove stop/fence, checkpoint completeness, effect reconciliation, destination authorization and retry accounting before continuation.

## Storage support

The protected store is `.getzilla/runtime/model-continuation/`: one stable kernel lock and one bounded 512KiB journal, at most64chains and256events per chain. Full capacity refuses new work without dropping active records. The store is owner-only. Reads reject nonregular files, symlinks, hardlinks, executable/shared-mode files, duplicate keys and inconsistent data. Checksums detect corruption, not hostile rewrites by an already-authorized same-user process.

Pinned directory handles and file identity checks detect directory/lock replacement. Publication flushes file data, atomically replaces the journal, then flushes its directory. A failure after replacement is ambiguous and yields an error; the caller must inspect and reconcile, never resend. Failed first publication can leave a lock with no journal; this deliberately needs investigation instead of silently resetting a ledger.

Admission requires POSIX directory fsync and stable filesystem locking. Unsupported filesystems fail closed on primitive errors. Windows admission is explicitly unsupported because this repository has no directory-fsync implementation there. Local process/crash fixtures do not establish hardware power-loss guarantees on every filesystem.

This store has no relationship to Factory PostgreSQL budget grants or PR239 progress TTL/recovery. It never issues either grant and never clears blocked checks. Existing native status and installer override rules remain unchanged.

## Recovery and rollback

Disable the policy to stop reservation. Preserve the journal and unknown outcomes. Revert source through a reviewed PR if needed; never delete a ledger to regain attempts or money.

## Direct model-only OpenAI request

The optional `getzilla.openai_model_request` API prepares a text-only Responses request for accounting. Dispatch refuses before consuming a claim or accessing the network because data admission is not established. The journal stores no credential or prompt. This API is not connected to native Getzilla startup or automatic model continuation.

The caller must supply a versioned contract containing the exact model, account reference, full input token ceiling, output token ceiling, byte limit, price ceilings, rate revision and expiry. The operator must confirm that the input ceiling covers the model's complete input context, including framing, and that both prices cover every applicable charge. These are operator assertions: byte length is not a token count, and the adapter does not verify current provider prices or account ownership. The configured ceiling is not a provider-enforced spending limit. See the [OpenAI token guide](https://developers.openai.com/api/docs/guides/token-counting) and [pricing](https://developers.openai.com/api/docs/pricing).

T3 reserves the full configured input and output ceilings, rounds the charge up to micros and applies the stricter task or policy cap. A live-model-only record binds the contract and request digest to the first policy candidate. A consumed accounting claim is never reissued. This accounting claim does not authorize data transfer. The API does not record terminal outcomes or reserve another candidate. It cannot resume a native coding session, reconcile tool effects, or prove a process fence. Credential/account matching and data authorization remain unfinished.

## Controlled local fixture

`getzilla.controlled_fixture.run` exercises only a synthetic two-model Codex session. It requires a pinned local Docker image and an exact Codex 0.165.0 binary. The image is not downloaded. The host copies the fixture script and binary into a new local image and verifies both hashes inside that image before use. The inspected execution container has no bind mounts. It uses `network=none`, read-only root, a non-root user, dropped capabilities and bounded resources. It receives no host journal, credentials or user input. This assumes the local Docker daemon and pinned base image are trusted.

The host stores fixture accounting separately in `.getzilla/runtime/model-continuation-fixture/`, using the same protected T3 storage primitives. A fixed fixture policy must name `local_fixture/synthetic` candidates `fixture-a` and `fixture-b`. The host records the original usage and consumes its one-shot send state before starting the container. It accepts the next turn only after a correlated terminal 429 with no native retry or observed tool effects, and after recording the next reservation against the same budget. Before recording success it verifies the exact owned container has exited, checks its isolation again, and removes the owned resources. This stopped-container observation is local to the fixture. It does not reconcile external effects or fence a live attempt before a model switch.

Restarting the same task never sends an unknown or completed attempt again. An ambiguous send or cleanup remains unknown and requires investigation. Each result retains `dispatch_permitted:false`. The fixture journal records synthetic facts only; its domain, its messages and its claim cannot qualify a live adapter or prove a live process is fenced. It does not implement ordinary Getzilla startup switching or qualify any of the six clients.

`getzilla.controlled_fixture.run_fenced` is a separate synthetic path. It runs A and B in different isolated containers, with two coordinator-owned volumes for the synthetic Codex session and workspace. It checks that A has exited and that the complete bounded workspace content and modes match its pre-A state before recording a versioned fixture fence and checkpoint in T3. It then reserves and consumes B against the same budget, checks the checkpoint again and resumes the same synthetic thread. The container has no external network and no host bind mounts. The host trusts its Docker daemon and exclusively owned synthetic volumes.

On restart, a recorded fence can resume B only after the host revalidates the owned stopped container, image, volume identity, policy, budget and checkpoint. An extra or missing owned container, changed or unreadable checkpoint, consumed send, or unconfirmed A outcome stops recovery. A completed record returns its prior outcome without a new send. Volumes remain available for investigation after an unknown outcome; their names are derived from the project root and journal binding. Fixture evidence cannot qualify a live adapter, reconcile external writes, or establish safety for a real workspace.

The fenced fixture also gates each synthetic inference request through its host. The host accepts only the expected fixture model, local Responses path, streaming mode and function-tool descriptors. Before it allows the local synthetic response, T3 consumes the one request already reserved for that attempt. A duplicate, changed policy, invalid request or unknown outcome gets no second allowance. The request event stores only its version and generation; it stores no prompt or credential. Earlier fixture readers that do not recognize this versioned event fail closed. This gate does not forward to a real provider and does not authorize live network access.

To exercise the optional isolated fixture on a machine with the pinned local image and binary, run `GETZILLA_RUN_CODEX_FIXTURE=1 python3 -m unittest tests.test_controlled_fixture` with the installed Codex on `PATH`. The regular unit suite skips this opt-in test. No provider call is required. If the exact local dependencies are missing, the fixture fails closed. Rollback is a reviewed source revert; preserve the fixture journal rather than deleting it to reset a budget.

The experimental `fixture_model_rotation_v1` domain is stored only in the fixture journal. It supports versioned terminal accounting and the next configured model under the same budget. It records only bounded classifications and request digests. Synthetic responses never update or authorize the live journal. Billing, authentication, malformed output and lost responses never switch. Retry-After remains pending until its deadline. On restart, an unknown send is not repeated; a completed attempt returns its status without storing or reconstructing the response text. The fixture coordinator is disabled outside controlled tests. Direct dispatch remains disabled until exact data and account admission is implemented. These APIs do not qualify native CLI continuation.
