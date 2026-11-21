# Expert procedure and review capacity experiment — contract v1

Actual comparative experiment: **NOT_RUN**. No live participants, paid sessions, payments, savings or product qualification are established. Expert approval and owner launch approval: **NOT_OBTAINED**. This is a bounded manual protocol and dry-run checker for issue #358.

## Procedure v1: small documentation corrections

Proposed class: one bounded correction to existing non-executable user documentation, with a stable original requirement and one accepting engineer. Exclude security, privacy, permissions, release/integrity instructions, executable examples that change behavior, code/configuration, customer confidential data, and changes that require a different task class. The owner must validate class coverage before launch.

Historical sources identified by issue #358 are the accepted handoff audit in PR #293 (`docs/adlc-handoffs.md`) and recorded-output regression runner in PR #333 (`docs/agent-evals.md`). These are source candidates, not experimental tasks or proof that this procedure passed expert review. Verify accepted source snapshots and their applicability before freezing the protocol. Do not use experimental tasks as extraction sources.

1. The author records source snapshots, original scope, effective requirement version, pending/rejected additions and current route. Use the existing continuity and readiness contracts. Missing obligations stop admission.
2. The protocol owner freezes a concise input brief, author steps, exclusions, mandatory review/check plan, human stop owner and procedure version. Another engineer reviews the procedure independently and rehearses it without implicit author knowledge. Record approval against that exact version. Changed versions invalidate approval.
3. Assign a reviewer and reserve measured review minutes before starting. Use the manual preflight below. The route's current `review_plan` remains mandatory. Worker slots are not reviewer capacity.
4. The author makes the correction in the existing task/worktree. Stop on ambiguity, new scope, missing authorization, missing source evidence or a budget/retry stop from `task_budget`. Ask the named human to resolve it. This procedure grants no new permissions.
5. Run the canonical selected checks and independent reviews for the exact committed candidate. Reconcile obligations at handoff and before acceptance. Passing a test, offline replay, technical baseline, or opening a PR is not human acceptance.
6. The accepting engineer records a candidate-bound decision and requirement version. Keep revoked, reopened, rejected and abandoned results. Observe defects through the common predeclared window. Record measured preparation, specification, review and correction time through the existing economics sources.

Procedure preparation and maintenance are first-experiment costs. Record them separately and include them in full economics; do not amortize them against hypothetical future use.

## Manual review admission

`getzilla.review_experiment.review_admission` checks a supplied complete snapshot, at most 60 seconds old, for the named reviewer. Configure positive available minutes and a WIP limit before launch. It counts active work, waiting for review, review and rework. Only explicit terminal states leave the count. Missing/unknown states, duplicate task IDs, stale views, no review minutes or an exhausted limit deny admission.

A positive result is only a manual preflight. It is not a reservation, authorization or task transition. Serialize the admission decision with the current canonical task assignment, re-read current state, reserve the review time in the existing workflow and apply current `review_plan` and `task_budget` checks. Do not store another queue or replace the lifecycle. When full, finish review/corrections for submitted work before admitting a new task. Waiting duration is not measured human working time.

## Pre-launch comparable cohort

`validate_protocol` bounds a version-1 supplied protocol to 64 KiB, four pairs/eight distinct tasks, a task class, independent accepted-work source references, exact procedure/expert approval version, reserved reviewer time, configurable WIP, canonical budget reference, selection/scope/check/tool/model versions, schedule and randomization record. Freeze it before assignment. Eight/four are the explicit initial contract, not proof of statistical power. A later sample design requires a new version.

Each pair has a documented comparability basis, one control, one experiment and recorded execution order. Randomly assign within pairs before starting; retain the seed/assignment record and source snapshot. The checker verifies the recorded structure, not the randomness or truth of the supplied references. The owner must verify these facts before launch. Do not substitute unsuccessful tasks.

Control uses the actual current process, including existing AI tools and all mandatory checks. Experiment adds only this procedure and manual review admission. Record selection/exclusion criteria, eligible class share of the original backlog, common acceptance criteria, budgets, concurrency, model/tool versions and a preallocated review schedule. Account for shared-queue effects, order and reviewer learning. Inseparable confounding prevents a causal claim. This evaluates the whole package, not either component independently.

## Economics and observation

Reuse #200 through `route_metrics.read_report`; do not accept caller-supplied cost totals or build a second ledger. The current protected reader fails closed pending its qualified integration. `assess_experiment` preserves its response and reports economics unavailable. It never converts current merge-only `observed_cost`, elapsed time, grant counts or offline evaluator output into full cost or human acceptance.

Before launch, prove the canonical economics census covers every assigned task and attempt: failed, terminated, rework and prior SHAs as well as successful attempts. Include measured author/expert preparation and maintenance, specification, review and correction time, actual rates/currencies and required cost categories. Keep unknown categories explicit. Full ledger-reading coverage does not prove full cost coverage. Prevent double counting through canonical operation/attempt identity reconciliation. Use acceptance, including revocation, at a common `as_of`.

The primary metric is full cohort spend per independently accepted result, including unsuccessful assigned tasks and all procedure costs. Zero accepted results leaves this ratio undefined; incurred costs remain. Incomplete sums are subtotals. Retain pair reports and canonical query/snapshot references. Additional metrics are accepted tasks per fixed period, first-submission acceptance, measured manual minutes, lead/wait/rework durations, lost requirements and defects over the same window.

`assess_experiment` retains all eight assignments; missing, stale, self-authored, unknown or malformed outcomes remain unknown. Its counts are supplied assertions, never verified acceptance. It cannot return a positive qualification because no independent acceptance/economics binding exists in this module. This is deliberate. An adapter must be reviewed separately before observed production decisions can be automated. No paid-run runner or second verifier is introduced.

## Predeclared observed decision rules

Before launch, the owner and accepting engineer must approve the exact protocol, useful savings threshold, absolute budget, quality/data completeness thresholds, stop owner and common defect window. Numeric protocol fields are proposed values until that approval is recorded.

- **No-go before launch:** missing independent sources/approval, comparable baseline, operational checks, accounting census, budget or reserved reviewer time. Do not start a paid or customer run.
- **Stop:** canonical budget/retry stop, quality/obligation regression, missing authorization or exhausted review capacity. Keep all incurred costs and assignments. `assess_experiment` reports `stop` for supplied failed mandatory checks or excess defects; this does not replace the canonical stop authority.
- **Indeterminate/revise:** missing or unknown outcomes, incomplete full costs/human time, missing independent acceptance, incomplete observation window, changed inputs or confounded scheduling. Never report savings from a subtotal.
- **Discuss a broader experiment:** only after the named independent human verifies complete R1–R5 evidence at the same `as_of`, all required acceptance/quality criteria, no lost obligations, full spend within the approved limit, and full cohort cost-per-accepted improvement at least the predeclared threshold. Preserve their decision and canonical report references. Four pairs supply only a preliminary signal. This does not authorize automation or promises of universal savings.

The repository checker returns `NOT_RUN`, `indeterminate` or `stop`. It never issues the final human decision or expands authority. Current report status is NOT_RUN; all comparative results, real human cost, observed savings and external validity remain unmeasured.

## Offline checks

Run `taskset -c 2 python3 -m unittest discover -s tests -p test_review_experiment.py`. Synthetic fixtures test fail-closed protocol, stale/self/unknown evidence, waiting/rework WIP, failure retention and no false qualification. They are not experimental evidence. Current review plans, recorded-output evaluator, canonical task budgets and protected economics remain independent required systems.
