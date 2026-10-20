# Cost guard: paid and unbounded operations

An agent that writes "generate until it looks good" against a paid API can spend real money in
minutes. Getzilla treats that as risky work with three static checks. Nothing is called, imported
or executed.

## 1. The prompt

The router reads the task with the risk vocabulary (`docs/risk-terms.md`). A **paid provider**
(OpenAI, OpenRouter, Kling, Midjourney, ...) or an **automation platform** (n8n, Zapier, Make)
together with **repetition** (variants, batches, "until it works", schedules) is a cost signal:

- the route is at least `medium`, with the reason `COST_SIGNAL:...`;
- the route declares the human gate `paid_run_approval`;
- the route context tells the agent to write a budget contract and test the limit.

A single call ("ask OpenAI one question") is not a signal on its own; the diff check still sees it.

## 2. The diff

`verify` reads the files changed from the comparison base to HEAD (`.getzilla/config/cost-providers.json`
lists providers):

| Finding | Meaning |
|---|---|
| `PAID_CALL` | a call into a paid SDK, a provider host or a paid n8n node (informational) |
| `UNBOUNDED_PAID_LOOP` | that call sits in a `while` loop with no counter, `itertools.count()`, a helper called from such a loop, or an n8n cycle through a paid node with no counter (`$runIndex`, a batch node) |
| `UNBOUNDED_RETRY` | the call is under `@retry` without `stop=` or `backoff.on_exception` without `max_tries`/`max_time` |
| `SCHEDULED_PAID_CALL` | the paid call is in a module that schedules work (`schedule`, APScheduler, Celery beat, croniter, rq-scheduler, huey); the contract must set `max_scheduled_runs_per_day`, otherwise `pr`/`release` fail with `COST_SCHEDULE_UNBOUNDED` |
| `UNANALYSED_PAID_CALL` | another language mentions a provider host; loops there are not analysed |

## 3. The budget contract

When there is a signal or a finding, the active change package needs `cost-contract.json`
(`schemas/cost-contract-v1.schema.json`):

```json
{
  "schema_version": "cost-contract-v1",
  "provider": "Kling via n8n",
  "max_calls": 20,
  "max_spend_usd_cents": 1500,
  "stop_condition": "stop after MAX_CALLS generations or the first accepted video",
  "alert": "email the owner when spend passes 10 USD",
  "limit_symbol": "MAX_CALLS"
}
```

`limit_symbol` must appear in the paid code and in at least one test. In `pr`/`release` mode the
`cost-guard` check fails on `UNBOUNDED_PAID_LOOP`, `UNBOUNDED_RETRY`, `COST_CONTRACT_MISSING`,
`COST_CONTRACT_INVALID` and `COST_BOUND_UNTESTED`. In `fast` mode it only warns. A contract on
paper does not excuse an unbounded loop in code. Spend is in integer cents because Getzilla
records are canonical JSON without floats. The contract is part of the gate's approval scope:
changing it invalidates earlier approvals.

## 4. The first live run

While the route declares `paid_run_approval`, the PreToolUse policy blocks a live run:
`n8n execute*`, a network client (`curl`, `wget`, `Invoke-WebRequest`, ...) to a provider host,
or an interpreter running a file `verify` flagged. Reading or searching such code is not a run.
A human approves one exact resource:

```text
getzilla gate decide paid_run_approval approved --actor <your name> --action paid-run --resource n8n --reason "one supervised run"
```

Tests never make live paid calls.
