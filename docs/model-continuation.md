# Model continuation: policy, journal and Codex protocol

Issue [235](https://github.com/Dimkox/Getzilla/issues/235) remains open. This slice loads policy, classifies normalized failures and reports status. It makes no model requests, scans no credentials and changes no native user defaults. No adapter is qualified. A configured policy cannot start continuation.

Run `getzilla status --model-continuation --harness codex` (or `grok`, `qwen`, `claude`, `gemini`, `copilot`). Normal `getzilla status` also includes this status. Without an explicit harness, the CLI reports `unknown`.

## Shared policy

The project file `.getzilla/config/model-continuation.json` ships with `{"schema_version":1,"enabled":false}`. Missing, invalid, disabled and configured states stay distinct. Status never prints candidate identities, paths or parse errors.

An enabled policy requires an ordered `candidates` list of unique `{provider, account_ref, model}` objects and a `bounds` object with all four fields: `max_attempts`, `max_requests`, `deadline_seconds`, `max_cost_usd`. There is no default spend allowance. Supply explicit positive finite limits. Attempts and requests must be integers; attempts cannot exceed candidate count and requests cannot be fewer than attempts. Limits cannot exceed 1,000,000,000; candidate count is 1–64. A disabled policy may retain the same validated chain and bounds.

References are non-secret identifiers of 1–128 ASCII letters, digits, dots, underscores, hyphens or slashes, starting with a letter or digit. Model identifiers also allow colons for provider variants such as `:free`; provider and account references do not. URLs, `..`, `//`, credentials and extra fields are not accepted. An account reference is a name, not a credential. The regular file is limited to 16 KiB. Duplicate keys, symlinks, nonregular files, boolean numbers and nonfinite numbers are rejected. This file is configuration, not a grant or data-transfer approval.

The installer treats this file as managed content. Preserve a consumer override with the existing `.getzilla/AGBP_SYNC.json` `kept_local` and matching `kept_local_sha256` mechanism before an update. The installer does not automatically preserve edits to arbitrary managed configuration. This slice does not change that contract.

## Startup and classification

| Harness | Hook fixture output | Native runtime qualification |
| --- | --- | --- |
| Grok, Qwen, Claude, Codex, Gemini | Existing `hookSpecificOutput` SessionStart context | Unqualified |
| Copilot | Top-level `additionalContext` | Unqualified |

The [Copilot hook reference](https://docs.github.com/en/copilot/reference/hooks-reference#sessionstart--sessionstart), checked on 2026-10-29, specifies the top-level startup context. Generated launchers identify the harness. Payload tests prove serialization and policy selection, not that a specific native version displays the note. Disabled hooks and bare modes cannot report startup status; use the explicit CLI. Hooks remain advisory.

`classify_failure` accepts only schema-1 normalized events with `origin:model` and a category. Trusted adapters must establish attempt identity and terminal-event provenance before calling it. An untrusted mapping with those fields establishes neither. Eligible categories are `rate_limit`, `quota_exhausted`, `provider_unavailable`, `inference_transport_failure`, `generation_failure` and `inference_deadline`. Authentication and billing need user action. All other categories stop, including tool/test failures, safety, cancellation, context overflow and task-budget exhaustion. Extra fields, such as a native retry signal, stop until an adapter normalizes a terminal event.

Eligibility never authorizes dispatch. The offline journal retains attempt, request and cost limits across restarts. A new Codex JSON-lines boundary owns a bounded process, initializes the app-server protocol and correlates turn events with the journal. Unknown event provenance is recorded as unknown, not as a trusted model failure. It never sends a successor turn. Local fake-peer tests do not qualify a native client. Confirmed checkpoints, tool-effect reconciliation, generation fencing, authorization, destination checks and qualified adapters remain required. Do not infer provider-switch support from native model selection.

## Codex synthetic compatibility evidence

An isolated Codex 0.165.0 app-server used a synthetic loopback provider. A failed model A turn with typed HTTP 429 was followed by a model B turn in the same thread. The probe started the second turn itself; it did not use Getzilla dispatch authority. The client still advertised five built-in tools. This proves protocol behavior only, not safe tool fencing or live adapter qualification. The reproducible fixture is `tests/fixtures/codex_loopback_probe.py`; run it only in a disposable container with no external network and no host credentials. Normal lifecycle notifications and the exact typed 429 shape are recognized as observations. Unknown events, mismatched turn identities and conflicting errors fail closed. Journal provenance remains unknown and no successor dispatch is allowed.

### Reproduce the isolated fixture inputs

The old bare image ID `a0f57064…` is historical and is not reconstructed by
retagging another image. The current fixture uses the declared offline recipe
`tests/fixtures/codex-fixture.Dockerfile` and its digest-bound JSON contract.
Prepare the official `python@sha256:623674a14ef93d052bb9b0de4dbf5f28eb578a35263838941cc8aa43213c1487`
base for Linux/amd64 separately. Missing or substituted local base metadata
refuses before building; the fixture never pulls it automatically.

The contract names the official Codex 0.165.0 Linux musl archive and its archive
digest. Verify downloaded archive bytes before extraction, then verify the
executable SHA256 `c06a67fd8ac76508dc78bd99ce20c9f317b8d568beda59485f3f4134df9962d5`.
An archive digest does not substitute for the executable digest. Select this
binary through that test invocation's PATH; do not change the normal Codex
installation. Other versions are unqualified by this fixture.

With the base cached, the fixture uses the explicit local Docker socket and
the default local builder with `--pull=false --network=none`.
It uses an empty private Docker config and HOME for each invocation. It keeps that
directory alive until its Docker clients exit, then removes it. Saved host
contexts and credential configuration do not enter the client environment.
If an attached client cannot be reaped, the fixture raises
`client_cleanup_unconfirmed` and retains its config/HOME. The exception's
`cleanup_context` is an in-memory ownership handle with the exact created
process objects. Its `reconcile(handle.processes)` method checks termination
without sending signals or replaying work, and removes only the original
directory after its identity still matches. Foreign or changed process
identities, replaced directories and links refuse cleanup. Losing the handle
does not trigger deleting garbage collection or authorize cleanup by PID/path.
Process crashes can still require recorded, task-owned investigation cleanup.
All three executable-input readers share nonblocking, no-follow regular-file
admission, a 512 MiB limit, bounded streaming hashes and source-identity checks
before and after reading. FIFOs, links, empty or oversized files and changes
during a read refuse before Docker allocation.
The private build context contains only the declared binary, fixed script, Dockerfile and contract;
the Dockerfile has no RUN instruction or package installation. A fresh owner
label changes each ephemeral image's identity. The real observed ID, owner,
base and contract binding are checked, followed by actual in-image Python
version and all input hashes. No mutable tag or caller-supplied image is trusted.
Record those identities for each qualification row; matching input recipes do
not make run-specific owner-labelled images byte-identical.

Use the existing opt-in `GETZILLA_RUN_CODEX_FIXTURE=1` tests in
`tests.test_controlled_fixture`. Allocate two measured CPUs to the daemon-created
containers with `GETZILLA_FIXTURE_CPUSET` or a two-CPU host affinity from which
the fixture selects its pair. Unknown or unavailable CPU sets refuse. Every
native container is network-none, root-filesystem read-only, UID 65534, with all
capabilities dropped, no-new-privileges, 64 PIDs, 512 MiB and two CPUs. Fenced
state/work mounts are newly owned named volumes; no host credentials, project
binds or Docker socket enter them. The sole UID 0 helper has only CHOWN, accepts
one fixed initialization program and changes only the two empty, label-verified
owned volume roots. It performs no recursive changes. Controlled workspace
fault injection runs as UID 65534.

Retain actual outcomes and owned-resource cleanup readback. Unknown outcomes
preserve their journal and investigation resources; do not reset consumed sends
or treat replay as a fresh qualification. Synthetic provider responses, models,
429s, usage and budgets remain synthetic. These tests cannot qualify live
authentication, model inference, provider/account switching, other five clients,
production trusted pins or independent security authority. Issue 235 remains
open until its separately required live boundaries are qualified.

## Recovery

Set `enabled:false` to disable requested continuation. No dispatch exists in this slice. Revert the source change through a reviewed PR to remove passive reporting; preserve consumer configuration and native user settings.
