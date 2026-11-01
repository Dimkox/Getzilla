# ADLC handoffs in an Autonomous Backlog Sprint

This map connects the fourteen phases in the [ADLC course](https://www.dobryakov.com/courses/adlc/index.html) to existing Getzilla contracts. The course supplies the phase names. The repository mapping, gaps and priorities below are engineering conclusions for [GH155](https://github.com/Dimkox/Getzilla/issues/155).

**Audit identity:** 68 files, 1,721,220 bytes at commit `84f3279558b74c068f0715b102b3b9c80c363d53`, tree `8cc8e9691d0eff179deb801445858ae8e9f5bc79`. A subsequent blob and SHA-256 comparison found all 68 files unchanged at `0d803e5f29d8447a4de85f6193a60216771b6192`. The later comparison does not rerun historical tests. Changes after those snapshots need their own delta review.

## Decision and scope

Reuse route selection, typed change criteria, workflow graphs, independent review, verification, Factory execution and release contracts as the handoff path. Fill missing provenance, continuity, effect-boundary and acceptance evidence through existing issues. No additional orchestrator, state machine or authoritative ledger is needed.

Ideation, discovery and marketing are outside this sprint scope. Approved discovery outputs can enter the requirements phase. Formation and governance apply across the included phases.

The existing Core lifecycle is draft → scoped → approved → implementing → verifying → reviewing → ready → released → archived, with correction, blocked and cancelled branches. Factory execution states remain separate. The state graph is defined in [change.py at the audited commit](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/.getzilla/getzilla/change.py). A lifecycle label is not proof of execution, acceptance or permission.

## Phase, producer and consumer map

Owner names below are roles, not authenticated human decisions. The selected writer owns the isolated source candidate. Reviewers remain independent.

| Phase | Producer → consumer | Existing handoff and state | Stop condition | Evidence gap |
|---|---|---|---|---|
| 1. Ideation | Outside sprint → brief owner | Approved idea may become input; no new state | Scope remains excluded | No ideation outcome claimed |
| 2. Discovery | Outside sprint → requirements owner | Accepted discovery findings may enter a brief | Unapproved findings cannot silently change scope | No discovery service claimed |
| 3. Marketing | Outside sprint → publication owner | Separately authorized commercial work | Sprint delivery grants do not authorize a campaign | No marketing execution claimed |
| 4. Requirements | Task analyst and brief owner → architect and writer | Brief, requirements, typed objective/AC/INV/FORBID, source fingerprints; draft → scoped → approved | Invalid spec/reference, unresolved conflicting scope or unknown authority blocks affected work | Origin/version/owner/conflict decisions are incomplete |
| 5. Architecture | Architect/domain architect → writer and reviewers | Machine model, rules, ADR, architecture and drift evidence; same change/source | Incompatible contracts, invalid references or relevant model drift | Decision-to-source and contradiction trace needs coverage |
| 6. Formation | Router and native coordinator → selected roles | Allowed agents, one writer, review plan, measured capacity and actual lifecycle IDs | Unselected role, stale identity or exhausted worker capacity | Role label alone does not identify a principal |
| 7. Planning | Analyst and architect → writer | Tasks, source manifest, bounded task graph, convergence, test/rollback plans; approved → implementing | Missing dependency, cycle, uncovered criterion or conflicting concurrent write | Long-running task continuity and empirical forecast remain separate work |
| 8. Implementation | Selected writer/task lease owner → verifier | Isolated diff, task/run packet, checkpoint, reservation/usage, result envelope; implementing ↔ blocked | Stale fence, revoked scope, exhausted cap or unknown prior external outcome | Each real adapter still needs qualification |
| 9. Code review | Independent code/specialist reviewer → writer and coordinator | Exact-source findings, resolutions and bound receipts; reviewing → ready or correction | Missing/stale review or unresolved blocking finding | A mapped test or author analysis is not an executed independent review |
| 10. Testing | Writer and verifier → reviewers/coordinator | Criterion mapping, exact command/result, scope and source digest; verifying → reviewing or correction | Required failure, unsupported check or missing evidence | Cross-client continuation and real local/media work require experiments |
| 11. Release | Release reviewer and authorized coordinator → recipient/operator | Candidate/published identity, package hashes, rollback, exact external checks; ready → released → archived | Wrong source/artifact, missing checks or current action scope | Release does not prove deployment health or task acceptance |
| 12. Operations | Scoped operator and execution owner → incident/budget owners | Existing task/run/lease, outbox/recovery, stop/cancel and usage observations | Fence/cap/kill stop, ambiguous provider outcome, forbidden audience | No proof that every adapter emits complete trace/cost evidence |
| 13. Maintenance | Finding/incident owner → analyst and brief owner | Deduplicated issue, decisions, mistakes and revised criteria → next scoped change | Never rewrite historical PASS to hide a failure | Accepted/rejected/revoked outcomes and calibrated forecast need real records |
| 14. Governance | Policy/rights/budget/publication owners → each effect executor | Existing route/change/task/session/source/grant identities across phases | Unknown, expired, revoked or mismatched authority blocks the affected effect | Local gate flags do not establish end-to-end enforcement |

## Existing artifacts and their limits

### Requirements and architecture

[spec.py](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/.getzilla/getzilla/spec.py), the [change schema](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/schemas/change-spec.schema.json) and [source_provenance.py](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/.getzilla/getzilla/source_provenance.py) provide bounded typed requirements and source references. A criterion-to-test mapping names intended evidence; it does not execute the test or accept the task.

[architecture.py](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/.getzilla/getzilla/architecture.py), the [machine model](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/architecture/system.yaml), [rules](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/architecture/rules.yaml) and [workflow-source ADR](../engineering/adr/0001-workflow-source-version-contract.md) govern structure. Requirement origin, conflict decisions and semantic source identity remain explicit follow-ups. A path or directory name cannot replace the identity of reviewed bytes.

### Formation, planning and implementation

[router.py](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/.getzilla/getzilla/router.py), [review_plan.py](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/.getzilla/getzilla/review_plan.py) and [agent_lifecycle.py](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/.getzilla/getzilla/agent_lifecycle.py) select and bind roles. Actual native identities and generations must be observed. When unavailable, mark them unavailable.

[workflow_artifacts.py](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/.getzilla/getzilla/workflow_artifacts.py) validates bounded source/task/convergence graphs. Imported complete/ready labels remain advisory. [Session progress](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/.getzilla/getzilla/session_progress.py), [model continuation](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/.getzilla/getzilla/model_continuation.py) and [continuation state](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/.getzilla/getzilla/model_continuation_state.py) are distinct from proving that a client resumed the intended logical task.

[Factory service](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/factory/src/getzilla_factory/service.py), [store](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/factory/src/getzilla_factory/store.py) and [state](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/factory/src/getzilla_factory/state.py) govern task/run ownership and budgets. Their existence is not proof that every future adapter uses them. A default-off registry is not a live provider integration.

### Review, verification and release

[Receipts](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/.getzilla/getzilla/receipts.py), [verification](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/.getzilla/getzilla/verification.py), [scope selection](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/.getzilla/getzilla/verification_scope.py) and [quality gates](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/.getzilla/getzilla/quality_gates.py) bind local evidence to source. An audit of these files does not prove a current PR passed them. Skipped checks remain skipped.

[Release state](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/.getzilla/getzilla/release_state.py), [deployment preparation](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/.getzilla/getzilla/deploy.py) and [packaging](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/scripts/package_stack.py) distinguish candidate, publication and operational actions. Required external checks apply to the exact PR head. Production health and owner acceptance need their own evidence.

### Operations, maintenance and governance

[Recovery](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/factory/src/getzilla_factory/recovery.py), [result brokerage](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/factory/src/getzilla_factory/result_broker.py) and [metrics_journal.py](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/.getzilla/getzilla/metrics_journal.py) supply existing observations. Unknown external outcomes require reconciliation before another potentially charged submission. A reservation is not a charge, elapsed time is not human work, and missing cost is not zero.

[Decisions](../engineering/decisions.md) and [mistakes](../engineering/mistakes.md) feed findings back to requirements. Preserve historical evidence, deduplicate the issue, revise criteria and open the next scoped change. Release, merge, passed tests and accepted tasks are different facts.

[Human gates](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/.getzilla/getzilla/human_gates.py) describe local workflow evidence. Generic transitions do not universally stop on every open gate. A paid-run gate has a specific enforcement path; protected effects also need current [policy](https://github.com/Dimkox/Getzilla/blob/84f3279558b74c068f0715b102b3b9c80c363d53/.getzilla/getzilla/policy.py), scoped grants and required external checks. Future media must enforce rights, permitted audience, exact assets and spend/publication authority at its actual adapter boundary.

## Minimum handoff

Carry the existing repository/change/route/logical-task/session identity; exact source commit/tree, specification and artifact digests; producer/consumer roles; criterion IDs; command/result evidence; unresolved decisions; stop reason; and resume preconditions. Add continuation chain/checkpoint or Factory run/fence/operation identity where relevant. Carry remaining budget without creating another budget store.

Human decisions require principal evidence, exact scope, version, expiry and current revocation checks. Unknown values stay unknown. Narrative completion, imported progress and deterministic planning keys cannot become acceptance, test receipts or release/publication grants.

## Prioritized existing follow-ups

| Order | Concrete work and acceptance | Existing issues |
|---|---|---|
| 1 — continuity and source | Preserve one logical task through continuation and scope changes; bind actual reviewed source; qualify positive and negative cases independently. Work in progress at the audit snapshot is not credited as delivered. | [GH246](https://github.com/Dimkox/Getzilla/issues/246), [GH252](https://github.com/Dimkox/Getzilla/issues/252), [GH235](https://github.com/Dimkox/Getzilla/issues/235), [GH240](https://github.com/Dimkox/Getzilla/issues/240) |
| 2 — protected effects | Demonstrate cross-scope/revoked/expired access, unapproved audience, unknown provider outcome and aggregate cap exhaustion stop the affected action. | [GH150](https://github.com/Dimkox/Getzilla/issues/150), [GH151](https://github.com/Dimkox/Getzilla/issues/151), [GH153](https://github.com/Dimkox/Getzilla/issues/153), [GH162](https://github.com/Dimkox/Getzilla/issues/162) |
| 3 — reconstruction and economics | Reconstruct task → policy → tool/model → approval → source → test/CI → acceptance from existing evidence; measure privacy and overhead; expose missing costs. | [GH152](https://github.com/Dimkox/Getzilla/issues/152), [GH200](https://github.com/Dimkox/Getzilla/issues/200) |
| 4 — requirement decisions | Record origin/version/owner/conflict decisions; changed inputs invalidate relevant acceptance. | [GH158](https://github.com/Dimkox/Getzilla/issues/158), [GH160](https://github.com/Dimkox/Getzilla/issues/160) |
| 5 — empirical delivery | Build a reproducible real-event reporting window and calibrated uncertainty; never label fixtures as delivery history. | [GH159](https://github.com/Dimkox/Getzilla/issues/159), [GH200](https://github.com/Dimkox/Getzilla/issues/200), [GH277](https://github.com/Dimkox/Getzilla/issues/277) |
| 6 — media design/module seam | Review the [media design](media-production.md) and its restricted case evidence; qualify optional integration in a later scope. | [GH165](https://github.com/Dimkox/Getzilla/issues/165), [GH166](https://github.com/Dimkox/Getzilla/issues/166) |

GH164 remains excluded Future. This map introduces no queue, worker or replacement orchestration. It is a pinned audit and handoff design, not proof of live adapter coverage, a current release or a real 14-day sprint.
