# Offline agent replay

`getzilla evals` checks approved recorded outputs with executable assertions.
It makes no network calls and needs no provider SDK. It reads only the local files you select and never calls a model. Select and approve incident cases through the existing
review process in [issue #154](https://github.com/Dimkox/Getzilla/issues/154).
A passing replay qualifies the recorded examples only. It does not qualify a
model or grant merge, release or external-write authority.

Run the shipped synthetic control:

```bash
getzilla evals run \
  --manifest tests/fixtures/agent-evals/v1/manifest.json \
  --outputs tests/fixtures/agent-evals/v1/outputs-control.json --json
```

Use `python3 scripts/getzilla_evals.py` when the `getzilla` launcher is absent.
Place the global `--root <project>` option before `run` or `accept`. All file
arguments use paths relative to that root. Input files must be regular files.
Links, parent traversal and absolute paths are refused. JSON rejects duplicate
keys, non-finite numbers, nesting beyond 64 levels and unknown fields.

## Version 1 inputs

The complete [example manifest](../tests/fixtures/agent-evals/v1/manifest.json)
pins the suite, dataset ID/version, adapter/grader/comparator versions, protocol,
case IDs and raw case-file SHA-256 hashes. Its `identities` object records the
model, prompt, tool, index, config and exact source commit/tree. These are declared
experiment identities. The report also hashes the manifest, recording and actual
runner module. Use immutable identities for real approved recordings. The shipped
outputs are handwritten synthetic controls, with the source snapshot at which
they were defined. They are not evidence of actual model execution.

Each [case](../tests/fixtures/agent-evals/v1/case.json) has `schema_version: 1`,
`id`, a bounded incident/source label, `input`, a nonempty `assertions` list, and
optional descriptive `signals`. Every assertion has an ID, operation and a JSON
path. Paths are arrays of object keys or nonnegative array indices. An empty path
selects the complete output.

| Operation | Check |
| --- | --- |
| `equals` | Canonical JSON equality to `expected`; `true` differs from `1` |
| `contains` | String at `path` contains the string `expected` |
| `not_contains` | String at `path` excludes the string `expected` |
| `exists` | `path` exists; this operation has no `expected` field |

A missing path fails. A prose note is invalid. An unknown operation or unavailable
adapter/grader version is unsupported. `length` and `reported_confidence` signals
are descriptive. They never change correctness. Reported confidence is a value
from the recording; it is not a probability of correctness. Out-of-range numeric
telemetry is invalid. Numeric bounds are checked before float conversion.

A [recording](../tests/fixtures/agent-evals/v1/outputs-control.json) has
`schema_version: 1` and `outputs`. Every entry binds `case_id`, `case_sha256` and
`output`. It may include `latency_ms` and `usage` with `input_tokens` and
`output_tokens`. Missing optional telemetry remains unknown. The report gives
latency and usage coverage without creating another cost store. See
[observability #152](https://github.com/Dimkox/Getzilla/issues/152) and
[economics #200](https://github.com/Dimkox/Getzilla/issues/200).

Each case returns `pass`, `fail`, `invalid`, `timeout`, `not_run` or `unsupported`,
with a reason code and assertion verdicts. Zero cases, duplicate IDs, missing
outputs, invalid schema and exhausted budgets cannot pass. Limits are 1 MiB per
input file, 100 cases, 32 assertions per case, 16 path components, and a 60-second
maximum replay budget (`--timeout`, default 10 seconds). The complete JSON export, including baseline comparison, stays within
512 KiB. If evidence exceeds that limit, the result is invalid with
`report_size_limit`; comparison is inconclusive. Oversized successful results are not exported. Assertions run in process through a fixed operation list;
there is no shell, code evaluation or user regex. Regular-file reads and fixed
operations are bounded; this is not a sandbox for executing external adapters.

JSON exports omit input, output and assertion values. They carry hashes,
per-case verdicts and descriptive numeric signals. Use safe case IDs and incident
labels: these labels are intentionally included in reports. Run IDs, timestamps
and measured time stay outside `canonical` and `result_digest`. The same files
and runner produce the same canonical verdicts and digest.

## Baseline comparison and acceptance

Baseline transactions require POSIX descriptor-relative file operations. Other
platforms return `baseline_descriptor_unsupported` and keep offline replay
available. Create a trusted baseline parent directory first. Missing parents
are refused and are never created by replay or acceptance. Then explicitly accept
a passing run:

```bash
getzilla evals accept \
  --manifest tests/fixtures/agent-evals/v1/manifest.json \
  --outputs tests/fixtures/agent-evals/v1/outputs-control.json \
  --baseline .getzilla/runtime/synthetic-eval-baseline.json \
  --reason "Accept synthetic control" --scope "Offline example only"
getzilla evals run \
  --manifest tests/fixtures/agent-evals/v1/manifest.json \
  --outputs tests/fixtures/agent-evals/v1/outputs-mutant.json \
  --baseline .getzilla/runtime/synthetic-eval-baseline.json --json
```

The second command exits 1 and names `must-deny` as the regressed assertion.
`run` never updates the baseline. A missing baseline gives `baseline_missing`
and exits 1. A valid comparison requires the same declared cohort, assertions,
dataset, protocol, adapter and grader/comparator contract. The protocol's
`variables` list names identity fields that may change, such as model, prompt,
tool, index or source. Both identities and paired results remain in the report.
An undeclared identity change or changed cohort/grader is `incomparable`.
An incomplete or unsupported run is `inconclusive`. Replay uses one fixed
recording per case; it makes no statistical significance claim. Stochastic
inference, repeats and noise estimation require a separate explicit adapter and
budget. Version 1 accepts only `repetitions: 1`.

`accept` reruns the supplied files and refuses any nonpassing run. It appends
reason, scope, timestamp and the previous acceptance digest to a hash-linked
history. Atomic replacement and an exclusive sibling lock serialize acceptance. Baseline
reads, lock/temp creation, replacement and cleanup use held parent descriptors.
The runner holds and validates every ancestor before and after operations; a
changed directory name or destination identity causes refusal. It never reopens
the selected parent by path during a baseline transaction.
Corrupt history is refused. All previous entries remain. Each baseline file
holds at most 32 acceptances; at the limit, select a new baseline path and retain
the old file. A process crash can leave `<baseline>.lock`; inspect the stopped
process before removing that stale lock. History hashes detect accidental edits;
local files are not signed attestations or merge authority.

## Existing verifier integration

Projects can add `.getzilla-evals.json`:

```json
{
  "schema_version": 1,
  "suites": [{
    "id": "approved-incidents",
    "manifest": "evals/manifest.json",
    "outputs": "evals/recorded-outputs.json",
    "baseline": "evals/accepted-baseline.json",
    "modes": ["pr", "release"]
  }]
}
```

The existing `getzilla verify` command runs these suites in the selected modes.
Each suite needs both a passing replay and a passing baseline comparison.
Missing, invalid, unsupported or regressed evidence fails that check. At most 16
suites may be configured. Without this file, the verifier performs no agent eval
work. Its other checks, review rules and exact-head external checks still apply.
Standalone `evals run` supplies evidence only; it is not a second verifier.
