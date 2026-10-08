# Architecture — Queue provenance analysis converges on list-append loops

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Current behavior

`_mutate_call` models `xs.append(v)` as a new `("number", len)` entry. Each abstract loop
iteration adds one index (an infinite ascending chain), so `_loop` raises after
`loop_limit`. `_join_envs` charges `1 + len(entries)` for every name at every merge point,
including names whose value did not change.

## Proposed behavior

- After `_LOOP_WIDENING_DELAY` (2) exact iterations, `widen_sequence` collapses any
  sequence that gained indexes into an unbounded sequence. The element summary is
  `_aggregate` of all elements. The length is unknown: a `("length", "unbounded")` marker
  for ordinary summaries, or a non-ordinary default. As a result, negative indexes,
  unpacking and concatenation stay conservative (`UNKNOWN_QUEUE`). The loop state is
  compared after widening, because pre-loop entries re-enter through the zero-iteration
  path on every join and would otherwise oscillate.
- Appending/extending ordinary values to an ordinary sequence of unknown length leaves it
  unchanged. Concatenating two ordinary sequences of unknown length yields an ordinary
  unbounded sequence. Any queue content still yields `UNKNOWN_QUEUE`.
- `_join_envs` skips the join (and its charge) when both bindings are identical.

## Components and boundaries

Only `.getzilla/getzilla/queue_provenance.py`. `architecture_fitness.py` and the limits
are unchanged.

## Data flow

Unchanged: fitness → `analyze_queue_tree` → signals/derived names/uncertain.

## API and event contracts

`analyze_queue_tree` signature and result type are unchanged.

## Governance context

Canonical governance JSON under `governance/` remains separately reviewed authority. Any rule, example, debt, or digest named here is non-authoritative context until the verifier rederives current governance evidence.

- Applicable rule IDs: FIT-BOUNDED-WORKER-JOBS.
- Applicable canonical example IDs/versions: none.
- Open or overdue debt IDs: none.
- Expected governance handoff or receipt impact: none.

## Bitrix-specific impact

- Modules/events/agents/components affected: none.
- Cache and managed cache impact: none.
- Installation/update/uninstall impact: none.
- Core modification: forbidden unless explicitly approved.

## Decisions

Widening instead of raising `loop_limit`: no finite loop limit converges an ascending
chain (verified: still failing with unlimited value/statement budgets). Not charging
identity joins instead of raising `value_limit`: those charges constructed no value, and
the comparison costs no more than the uncharged environment copy in `_fork`.

## Risks and mitigations

- Missing a queue appended in or after a loop: covered by tests asserting a semantic-call
  signal or uncertainty.
- Unbounded work from uncharged comparisons: merges are bounded by the statement limit and
  names by the AST node limit, the same bound the `_fork` copies already rely on.
