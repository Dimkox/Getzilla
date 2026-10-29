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

## Recovery

Set `enabled:false` to disable requested continuation. No dispatch exists in this slice. Revert the source change through a reviewed PR to remove passive reporting; preserve consumer configuration and native user settings.
