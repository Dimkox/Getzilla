# Protected native-local economics

`getzilla report --economics-query-stdin --json` reads a bounded typed query from stdin. Run it from the actual project root in the current route owner's existing session. The same snapshot produces the JSON report and its text view. The command does not import observations, call providers/models, reconcile an account or change task outcomes. It rejects combinations with import, trace, sprint and alternate period arguments.

The query is the existing `ReportQuery`: authorized root scope digest, `as_of`, explicit task cohort or selection interval, separate accounting interval, named views/groupings, money bases, FX/cache-pair references and optional snapshot reference. It accepts no SQL, shell, caller source facts, role, principal or grant. A foreign scope/task cannot expand the native root cut.

## Current authority and source cut

This narrow profile uses the existing `NativeAccessBroker`. Actual OS-owned CWD, the current canonical route/session owner, current source HEAD/tree, existing Read policy, owned no-follow source resources and final source revalidation are mandatory. It is not an enterprise ACL or private-egress capability. Without a live nonserializable native reader handle, `route_metrics.read_report` remains closed. Constructing a query, DTO or a result with a claimed qualification cannot authorize it.

The reader freezes the existing journal, canonical routes/census and existing execution registry under task-transition → execution → nonblocking journal read locks. It uses existing native canonical delivery acknowledgements; caller-written proof labels are not imported. It retains full source hashes, route/census identities, source metadata and the current owner/policy binding. Source/authority changes before admission refuse the result. A missing registry is recorded as missing; it is never initialized by the calculation. Lock guards remain the existing lock mechanism, not a new ledger.

Limits remain bounded: at most120 canonical routes,4096 journal rows,8MiB aggregate captured bytes and the existing calculator's2-second wall/CPU budget. Native access requests and final local emission have separate2-second cooperative deadlines; the local reader context lasts at most15 seconds and accepts at most8 requests. Existing native I/O and source-budget bounds are retained. Oversized, malformed, truncated or foreign input cannot become a complete report. No count, depth or byte bound is widened.

## Actual resource producer and unknowns

The actual enrolled native child-reap path now adds one closed v4 `local_usage` observation to the existing canonical publication/journal. It records only the already measured monotonic child elapsed time. Its stable physical identity is the actual unique native claim. The original claim and finish events, the canonical operation key and real journal delivery acknowledgement bind the observation. Replays do not publish another usage fact. The reader independently recomputes that exact projection from admitted source events before using it.

The producer does not infer an attempt ID, CPU/GPU/energy/RSS, provider usage, tariff, money, CI/human time or acceptance. Those fields remain unknown. The legacy native path has no actual attempt identity, so its report retains `history_gap`. Period attribution stays unknown when no exact service interval was observed. Existing execution-registry bytes are in the cut; unlinked registry history is disclosed, not guessed into an operation.

The reader calls the existing `compute_economics`; it creates no second journal, subtotal reducer or accepted-task ledger. A qualified native-local **PARTIAL** result means the protected read was admitted, not that all costs are known. Full monetary values and acceptance denominators remain `null` when unknown. A labelled known subtotal is not a full cost. Merge, completion, pass, grant or session end never creates human acceptance.

Only the new source-owned native elapsed producer is admitted in this initial economic source profile. Provider charges, tariffs, human attestations and other economic DTO variants still need their own actual registered producer/authority integration. Their syntax alone is not enough. The pure calculator keeps its existing calculation-only contract and limitations; the protected wrapper separately records actual native read qualification and source coverage.

## Output and experiment consumption

The protected wrapper contains the canonical calculation, source snapshot, coverage, purpose and `private_egress_authorized: false`. Its live host-issued identity is checked before local output. Output uses the fixed stdout renderer; no caller callback, network model sink or arbitrary export destination is accepted. Stored or copied result dictionaries do not retain a reader capability.

`review_experiment` can consume this canonical protected reader with its live dedicated purpose handle. It does not sum costs again. Partial economics remain incomplete; supplied pair assignments and human outcomes do not become native acceptance. The comparative human experiment remains **NOT_RUN**. No experiment decision or savings claim follows from a local resource observation.

## Evidence and remaining work

Controls exercise a real managed local child, native journal publication and replay, a real report CLI process, current scope/session checks, stale-source refusal, conflicting and duplicate deliveries, truncated input, caller DTO refusal and canonical experiment consumption. Synthetic calculator fixtures still test tariffs, cache categories, currencies, revocation and arithmetic; they are not invoices or measured provider spend.

Actual provider reconciliation, human-acceptance authority, complete cross-attempt identity, full history/coverage and a real comparative human experiment remain unavailable. Largest-dataset resource measurements must be read with their recorded fixture/provenance and observed refusal status; no unavailable measurement is zero. This is a protected-reader/known-local-resource implementation slice, not full issue200 or release acceptance.
