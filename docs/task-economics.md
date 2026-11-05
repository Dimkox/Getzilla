# Task economics calculation contract

`getzilla.route_metrics` contains a standard-library-only calculator for supplied
economic facts. It does not collect facts, authenticate a customer, grant access,
accept work, change a budget, import a bill or execute a model.

The protected `read_report(request, handle=...)` entry currently returns the
fixed `protected_read_unavailable` result. A role label, same UID, private-FD
token or public Python DTO cannot activate it. Actual #150 source/destination
authority,#151 minimization/transform/release and #159's frozen source-cut adapter
are still required. The existing report CLI/journal dispatcher are unchanged by
this calculation slice. No new CLI economics option is claimed here.

## API and source ownership

- `validate_economics_payload(dict) -> dict` returns an owned validated payload.
  `decode_economics_payload(bytes)` also rejects duplicate keys, nonfinite JSON,
  invalid UTF-8 and transport overflow. Refusal is fixed
  `EconomicsError("invalid_economics_payload")`, without rejected data.
- `parse_report_query(dict) -> ReportQuery` and `decode_report_query(bytes)`
  return an immutable normalized request. Unknown fields and effects such as
  paths, imports, SQL, shell, URLs, roles, source grades and destinations refuse
  with `invalid_report_query` before source access.
- `compute_economics(EconomicsInput, ReportQuery) -> ReportResult` is an
  ephemeral arithmetic seam. Its public Python input does **not** prove source
  admission or coverage. A future genuine host must derive it from authorized
  retained facts. Every computed result says `calculation_only: true`.
- `render_report_json(result)` and `render_report_text(result)` render that
  same immutable result. Unknown remains null/unknown. Exact reduced rational
  values avoid floating-point arithmetic or rounding individual allocations.

The closed contracts are [payload](../schemas/economics-payload.v4.schema.json),
[query](../schemas/economics-query.schema.json) and
[result](../schemas/economics-result.schema.json). Runtime semantic validation
is required in addition to JSON Schema.

The payload is the allocated 17-variant `economics_observation` family. Its inner
discriminator remains `candidate_kind`. It has no generic attributes or authority
labels. Native coverage and economic observations are different v4 kinds.
#159 owns the one existing journal, native capture/proof/coverage and CLI paths;
#153 owns original admission/settlement; #152 owns actual measurement provenance.
There is no second journal, outcome store or persistent task/PR mapping here.

## Arithmetic input is not a read handle

`EconomicsInput` has exactly these Python fields:

| Field | Meaning |
|---|---|
| `observations` | List of `{row, delivery}` pairs from an already admitted cut. This calculator checks the frozen v4 economics envelope and delivery-v2 syntax/hash, not filesystem custody, actual fsync, owner acknowledgement or enterprise permission. |
| `bindings` | Host-derived original effect records: the five OperationRef fields plus `task`, `head`, `outcome`. They bind the subject/effect independently of the observer/import task. |
| `selections` | Host-derived `{task, selected_at, selection_event_digest}` records for the original selected cohort. A task-ID query declares a cohort; it does not assert window selection. |
| `census` | The externally established task cohort, or null when unknown. A supplied list or hash does not qualify itself. |
| `gaps` | Missing/unqualified/censored history from the actual source adapter. Absence of gaps cannot be inferred from a readable private file or payload label. |
| `source_cut_digest` | The host's source-bound cut reference, including the applicable source/proof/coverage/policy/sanitizer versions. It is a reference, not permission. |

The observer is the actual native observer/import operation. It may differ from
the cost's original task. The calculator never assigns cost to the observer by
default. A Core native original claim maps to one physical managed effect under
its immutable original subject/producer binding. Multiple usage/billing facts
may describe that effect. A failed spawn is not a new measured effect. Factory
groupings require their actual domain/source proof and are not coerced to this
native #153 rule.

Actual host admission must happen before constructing these inputs. Registered-
host v4 syntax is not admitted by a local OS handle. `read_report` remains
unavailable even if a caller constructs a syntactically valid cut or handle-like
object. No arbitrary callback or sink replaces that boundary.

## Definitions

The knowledge cutoff keeps `at < as_of`, `captured_at < as_of` and the parsed
six-fraction delivery bound `delivered_by <= as_of`. Occurrence/capture use
strict UTC seconds in v4. Old service dates cannot backdate an import. Native
delivery proves local availability by its stated time, not a global clock,
first visibility or customer acceptance.

Conflicts are reconciled across the eligible supplied cut **before** cohort or
accounting filters. Exact event replay is idempotent. Changed event/source-fact,
physical-operation, original-claim or billing-line identities quarantine their
versions. Local/provider usage for one physical operation is coalesced, not
summed twice. Confirmed charges and tariff estimates remain separate bases;
reservations and opaque micro-units are never converted into observed spend.

Selected task lifetime includes every supplied related attempt/head through the
cutoff, including failed/cancelled attempts before selection. `cohort_period_spend`
uses the same selected tasks and the separate accounting interval.
`scope_period_spend` concerns the supplied authorized cut, not all repository
work. A bounded/declared native cohort is not a repository-wide census. An
aggregate crossing an accounting or rate boundary without segments is unknown;
the calculator does not invent prorating.

Each physical operation is allocated once. Shares have distinct task refs and
sum to at most 1,000,000 ppm. Remainder is unallocated. It does not silently become
the original task's cost. Missing related costs and unallocated task shares
retain labeled known subtotals while full values remain null. Retry/repair and
supersession cycles, missing parents and ambiguous branches censor history.

Rates are supplied dated rational facts with units, currency, source and cache
policy. No current tariff or historical cache multiplier is built in. Inclusive
input/output buckets are not billed twice. With one inclusive output rate,
reasoning is already in output; with a distinct reasoning rate, subtract that
component before pricing the remaining output. Different cache modes/configs
require distinct operations/writes. Unknown semantics leaves derived costs
unknown. The current currency profile admits USD/EUR/GBP/JPY/CAD/AUD/CHF/CNY;
each observation supplies its scale explicitly. Unknown or unsupported currency
never becomes USD. Other currencies need an explicit reviewed profile extension.

FX applies only through selected explicit dated facts and retains original
currency totals. Missing/overlapping rates remain unknown. Credits are positive
source amounts adjusting a referenced matching charge; they are not negative
token usage. Human time, CPU, GPU, elapsed, energy and CI runner time retain
their different units. Neither missing billing nor runner minutes means free
local work or a known monetary rate.

Ended, completed, merged and accepted are independent. A pass, grant, session
end or merge does not create acceptance. Explicit decisions and their qualified
supersession lineage are needed; late revocation creates a new cut and does not
rewrite an old result. Missing dispositions/census produce an unknown denominator.
A qualified known zero accepted count produces an undefined, null ratio.

For one currency and money basis:

- `accepted_task_mean` divides accepted tasks' lifetime spend by accepted tasks.
- `cohort_spend_per_accepted` divides the selected cohort's lifetime spend by
  that same count. It includes rejected/abandoned work in its numerator.
- `rejected_abandoned_share` divides those tasks' spend by cohort spend.
- `unsuccessful_attempt_share` separately measures failed/cancelled-attempt
  spend inside accepted tasks against accepted-task lifetime spend.

Ratios retain explicit numerator/denominator/cohort definitions and units.
Unknown components do not become a full cost-per-accepted figure. Native
source-qualified outcomes/census remain #159's responsibility; fixture decisions
are not real acceptance.

## Result and limits

The definition is `task-economics-v1`; a future accepted formula change must
change its version. Snapshot identity binds normalized query, eligible fact/
delivery bytes, original effect mappings, selections/census/gaps, cut reference
and definition. Exact replay/order changes do not alter it. A mismatched requested
snapshot returns fixed unavailable; this API creates no snapshot cache/ledger.

Only requested views populate their sections. Unrequested lifetime/friction
sections remain empty/null; groups explicitly name lifetime versus accounting
period. Source refs are safe identifiers, never raw provider/customer/account
values. Actual #150#151 output minimization and current release authorization are
still mandatory; a calculated digest is not their substitute.

The current structural ceilings are 64 KiB query, 8 KiB v4 row, 4,096 observations,
8 MiB row bytes, 4,096 effect bindings, 256 selections/tasks, 16 shares/FX/cache refs,
two group dimensions/256 total output groups and 1 MiB result/text. Each money row
can retain 8,192 contributing event/proof references; global references can retain
those plus the source cut. These derived ceilings remain subject to the byte limit.
Result decoding also intersects the existing 20,000-node bound; individual inputs are bounded by
depth 10/4,096 nodes. Result rational strings are bounded to 100 digits. Exhaustion
returns unavailable, not truncated complete totals. Cooperative wall/CPU stop
ceilings are 2 seconds each; these do not promise OS scheduling latency. Every
native/source/dependency limit can lower these ceilings.

Real small/max admitted wall/CPU/RSS/read/output measurements remain release
evidence. Structural bounds are not a measured transient-RSS guarantee. Actual
host memory/resource enforcement and the full protected-read benchmark are
unimplemented until the native#150/#151/159 composition exists.

## Mandatory integration work

This source slice does not close issue200. Still required: reviewed sequential
#159 journal/CLI/read adapter integration; real #153/#152 usage/export producers and
native source/coverage/outcome mappings; actual ##150 authority and#151 sanitizer/
lineage/release across Core/Factory/native profiles; real bounded benchmarks;
finite native #277 calculation/resource/export reconciliation; and actual matched
normal/long cache workload evidence. Unsupported backend cache counters remain
unknown and leave that acceptance open. Synthetic scenarios do not pass it.
Provider login/export or paid-run consent is needed only when the authorized
real stage requires it. The missing integrations are engineering work.

The #138 projection uses explicit human decisions/durations and review-for-push
facts. Grants are not human decisions. Commit/fast-path/evidence/defect census
is not supplied by this slice, so those fields stay null. It creates no second
metrics ledger and claims no measured process improvement.
