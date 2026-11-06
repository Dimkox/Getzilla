# ADR-146: Compliance Foundation

Status: proposed design, awaiting independent review. Scope: [issue #146](https://github.com/Dimkox/Getzilla/issues/146), all seven acceptance criteria. This change supplies documentation and a data schema only. It installs no engine, jurisdiction rules, service, policy pack or gate. It provides neither legal advice nor regulatory certification.

The companion [Enterprise operating model](enterprise-operating-model.md) addresses [issue #157](https://github.com/Dimkox/Getzilla/issues/157): proposed control ownership, approvals, expiring exceptions, incidents and review reporting. It reuses this Foundation and its schema; it adds no policy engine or operational authority.

## Existing mechanisms and integration audit

The audit baseline is accepted commit `352d62450afea5821346a99cf47ebe8565717d42`. The following are current source behavior, not findings that a law applies to a customer.

| Existing path and entry point | Current behavior | Proposed reuse and limit |
|---|---|---|
| [.getzilla/getzilla/eu_ai_act.py](../.getzilla/getzilla/eu_ai_act.py), `enabled`, `draft_class`, `evaluate` | Optional EU component; explicit installed matrix plus opt-in record; purpose-based draft classification; declared provider/deployer roles; date, evidence and review checks. Technical decisions are pass/review/block. | Preserve this adapter and its existing opt-in semantics. Its pass is not a general applicability or legal-compliance result. No automatic migration to a new pack. |
| [docs/eu-ai-act.md](eu-ai-act.md) and [.getzilla/compliance/eu-ai-act/obligations.json](../.getzilla/compliance/eu-ai-act/obligations.json) | Document the current component and its project-authored obligation matrix. Matrix source-review metadata and named confirmations are data, not authenticated legal-review identities. | Import only explicitly mapped engineering evidence. This audit does not validate the matrix's legal accuracy, completeness or dates. |
| [.getzilla/getzilla/compliance_scaffold.py](../.getzilla/getzilla/compliance_scaffold.py), `scaffold`; [scripts/getzilla_compliance.py](../scripts/getzilla_compliance.py) | Copies an optional transparency adapter for a registered system. This is not a jurisdiction resolver. | Keep scaffolding separate from applicability, authority and legal interpretation. No scaffold action is added here. |
| [.getzilla/getzilla/continuity.py](../.getzilla/getzilla/continuity.py), `submit`, `ack_scope`, `context_binding`; [.getzilla/getzilla/router.py](../.getzilla/getzilla/router.py) | Existing task identity, scope, owner epoch and typed requirements. | Intake references a versioned facts snapshot under the same task; do not create a compliance task-identity system. |
| [.getzilla/getzilla/review_plan.py](../.getzilla/getzilla/review_plan.py), `assess`; [.getzilla/getzilla/diff_risk.py](../.getzilla/getzilla/diff_risk.py); [.getzilla/getzilla/policy.py](../.getzilla/getzilla/policy.py), `evaluate_pre_tool` | Source-bound review selection and existing operation/control-plane guards. | Attach advisory findings to the existing plan/package. A pack cannot grant a tool action, lower a review requirement or override a guard. |
| [.getzilla/getzilla/verification.py](../.getzilla/getzilla/verification.py), `_eu_ai_act_check`; [scripts/getzilla_audit_bundle.py](../scripts/getzilla_audit_bundle.py), `_compliance`, `ci_check` | Optional EU verification and source-bound audit output. CI audit labels its authority as evidence-only. | Reuse tests, exact PR/CI source identities and audit references; do not turn execution success into legal approval. |
| [.getzilla/getzilla/receipts.py](../.getzilla/getzilla/receipts.py), `write_receipt`; [scripts/getzilla_review.py](../scripts/getzilla_review.py) | Reviews bind the inspected source and context. | Reference the original report/hash/scope. A report for another tree, purpose or policy version is historical, not a fresh review. |
| [.getzilla/getzilla/ci_evidence.py](../.getzilla/getzilla/ci_evidence.py), `export_evidence`, `export_local_evidence` | Narrow source-bound CI/local evidence exports; local grants are not exported as authority. | Keep large evidence outside Git. Reuse hashes and controlled artifact references, not copied evidence blobs or duplicate agent calls. |
| [.getzilla/getzilla/state.py](../.getzilla/getzilla/state.py), `add_approval`, `has_valid_approval` | Scoped local delegated grants. | Local grants are not legal-review approval, customer identity or external merge authority. |
| [trust-ci/src/adaptive_trust_ci/api.py](../trust-ci/src/adaptive_trust_ci/api.py), `submit_approval`; [signing.py](../trust-ci/src/adaptive_trust_ci/signing.py), `verify_approval` | A separate server policy validates human-signed approval scope, source binding, freshness and replay constraints. | Reuse this trust boundary where applicable. A future legal-review scope needs an operator-approved verifier/policy extension; it does not exist merely because a pack names a reviewer. No keys or trust-store changes are part of this proposal. |
| [.getzilla/getzilla/metrics_journal.py](../.getzilla/getzilla/metrics_journal.py) and [.getzilla/getzilla/cost_guard.py](../.getzilla/getzilla/cost_guard.py) | Existing bounded observations and cost checks. | Record only supported bounded aggregate measurements. No second decision journal, generic telemetry attributes or legal authority ledger. |

No generic multi-jurisdiction resolver or trusted legal-review adapter is established by these paths. Existing EU engineering checks remain unchanged.

## Decision and alternatives

Propose an optional, pluggable Compliance Foundation that reads pinned declarative packs and existing evidence references. Keep the evaluator separate from the Core operation guard and reuse existing task, review, evidence and approval boundaries.

Alternatives considered:

- Add jurisdiction branches directly to the EU evaluator: smaller initial patch, but couples unrelated update cycles and makes an EU pass easy to mistake for wider coverage.
- Create a separate compliance service, authority store and evidence journal: independent deployment, but duplicates identity, grants and provenance and adds maintenance and latency.
- Use optional adapters over the existing boundaries: selected design proposal. It permits isolated pack updates and a non-blocking pilot without claiming that legal coverage or runtime integration already exists.

There is no automatic pack discovery, network fetch, model call, jurisdiction selection by IP, or enabling configuration in this change. EU, US federal/state/local, UK and China are candidate research areas, not shipped or complete rule coverage.

## Proposed contracts

[compliance-policy-pack-v1.schema.json](../schemas/compliance-policy-pack-v1.schema.json) defines closed Draft 2020-12 data objects. It includes stable rule IDs, pack/rule versions, jurisdiction hierarchy, primary source citations and content digests, effective intervals, applicability conditions, evidence requirements, severity, accountable owner and review metadata. The four outcome names are fixed. The v1 pack mode is advisory.

The schema validates shape, not legal interpretation, calendar ordering, authentic reviewer identity, source authenticity or applicability. `reviewed`, `owner_ref`, a digest and a matching schema are assertions to verify, never capabilities. No actual jurisdiction pack is supplied. Future semantic validation must reject duplicate rule IDs, unknown source references, invalid date ordering, unsupported predicates and ambiguous supersession before evaluating anything.

Proposed interfaces, not implemented APIs:

- `collect_facts(task_context, authorized_system_ref) -> ProductUseFactsV1`: use the existing authenticated/task boundary; return fact values, unknowns, evidence references and a snapshot digest.
- `evaluate(facts, pinned_packs, evidence_index, as_of) -> ApplicabilityReportV1`: a bounded deterministic adapter with no I/O, model calls or execution of pack code.
- `attach_report(existing_change, report_ref)`: use the existing package/audit mechanism; report references retain their original source and permission scope.

Facts cover the product/system boundary, intended purpose, market offered into, deployment jurisdiction, provider/deployer or other declared roles, actual use, affected population/location and relevant placement/use dates. Structured purpose/use codes require reviewed provenance; an NLP guess is not a confirmed fact. Each record distinguishes platform and customer facts. Missing values remain unknown. IP, locale or time zone may prompt a question, but never establish legal jurisdiction or a negative decision.

Conditions are a bounded conjunction of named fact membership predicates. Packs contain no Python, SQL, scripts, arbitrary expression strings or remote callbacks. Customer-supplied facts and pack bytes remain subject to existing tenant/project access and source/destination policy. A caller role, UID, task ID, pack digest or JSON reviewer reference does not authenticate a customer or authorize disclosure.

## Applicability and responsibility

Applicability is separate from evidence sufficiency and from permission to release or execute.

| Outcome | Proposed meaning |
|---|---|
| `applicable` | A fresh, reviewed rule and complete, sourced facts establish the rule's predicates at the evaluation time. Required evidence can still be missing. This is not “compliant.” |
| `not_applicable` | A complete reviewed context establishes a specific false predicate, or the rule is outside its effective interval. Record the reason and reevaluation boundary. This excludes only that rule/version/context. |
| `uncertain` | Facts, coverage, evidence access or evaluation capability are insufficient, or a work/deadline bound is exceeded. Do not convert an empty result into a negative decision. |
| `needs_legal_review` | Rule interpretation, legal source freshness, jurisdiction conflicts, exemptions or reviewer qualification require a human decision. A stale or unauthenticated review cannot produce a negative clearance. |

Core fact completeness and valid rule/source review are prerequisites even when a condition appears false. Evaluate each relevant jurisdiction independently. Unknown jurisdiction coverage, no matching pack or zero evaluated rules is `uncertain`, not universal non-applicability. Disabled execution has a separate operational status and creates no legal result. Missing technical evidence is reported separately as incomplete; it never becomes a compliance pass. Legal ambiguity escalates to legal review rather than being “resolved” by severity sorting or a model.

| Responsibility | Platform/operator | Customer/system owner |
|---|---|---|
| System boundary and facts | Describe Getzilla's actual orchestration, data handling and offered functionality. | Confirm the customer's product, deployment, purpose, actual use, affected people and role(s). |
| Policy sources | Maintain pinned source provenance, schema compatibility, update alerts and honest coverage limits. | Arrange jurisdiction-specific legal assessment and approve application of a pack to its system. |
| Evidence | Preserve source/run/hash/context bindings and access controls; expose missing or stale evidence. | Supply authorized system-specific evidence and confirm its relevance. |
| Human acceptance | Verify identity/scope through an existing trusted boundary; never fabricate legal qualification. | Select qualified reviewers and accountable owners; retain actual decisions and scope. |

The platform can itself have obligations; customer duties do not automatically transfer to it, and its technical artifacts do not discharge customer duties. These are design responsibility assignments, not an assessment of either party's legal status.

## Evidence, human review and freshness

Reference existing tests, PRs, CI runs, audit bundles and independent reviews by repository/source tree, exact artifact hash, originating run and context. Also bind system/facts digest, pack version and bytes, rule IDs, evaluation time and reviewer scope. Preserve evidence type: test execution, author assertion and human review are not interchangeable. The same immutable evidence may satisfy several compatible requirements; deduplicate collection by the existing source/run/artifact identity, not by assuming matching filenames prove relevance.

Keep evidence content in existing controlled runtime/CI storage. Git holds only schemas, reviewed pack metadata when later authorized, and concise documentation. Opaque artifact IDs can still be sensitive. Enforce current tenant/project access on resolution and export; never treat a hash or stored reference as permission. Retention and deletion follow the existing evidence owner and customer policy, including derivative reports/caches; pack configuration cannot extend those permissions or invent a new retention authority.

Proposed update lifecycle: draft source acquisition → independent technical/source comparison → qualified legal interpretation → exact version/digest review → explicit advisory promotion → observation → optional later enforcement decision. Pack author and accepting reviewer must be distinct for promotion. A future trusted adapter must validate the actual reviewer and authorized scope, source/pack/facts bindings, expiry and revocation through the existing authority. It must refuse unsupported approval scopes. Current dated confirmation fields and local grants do not supply this adapter.

Sources need an official publication locator, retrieved bytes/version, digest, retrieval time and next-review deadline. A URL alone is not proof. Source changes, revocation, a passed review deadline or new effective date invalidate affected cached results and require reevaluation. A clock that cannot establish these bounds yields `uncertain`. A source check by automation is labelled automation, not human legal review. Legal-review evidence expiry and source-check freshness are separate clocks.

Rule versions are immutable. Fixes produce a new pack version/digest with explicit supersession; old decisions retain their old bindings. Use half-open effective intervals, with boundary/time-zone interpretation reviewed explicitly. Do not infer legal priority from a newer timestamp, a higher severity or a parent jurisdiction ID. Conflicting concurrent duties, overlapping unreviewed versions or an unclear effective date produce `needs_legal_review`. There is no silent fallback to stale cached rules.

## Integration, budgets and rollout

All figures below are proposed pilot limits, not measurements or legal review intervals mandated by law.

| Stage | Proposed bound and failure behavior |
|---|---|
| Intake/planning | At most 64 KiB of authorized structured facts. Cached advisory lookup target p95 ≤25 ms. No synchronous legal-source network call. Missing facts generate an explicit evidence task, not an account or Core-work blockade. |
| Local evaluation | One original 250 ms monotonic deadline; at most 20 selected packs, 200 total rules, 128 sources, 256 evidence references and 4 MiB aggregate pack bytes. Refuse overflow before partial coverage can be presented as complete; return `uncertain` with a coverage reason. |
| Cache | At most 16 entries / 8 MiB in the existing disposable evidence contour; lifetime ≤5 minutes and never beyond source review, human review, permission or effective-date boundaries. Key includes source/pack bytes, facts/evidence scope, current permission revision and evaluation interval. Current permission is rechecked at release. Unknown revision means no reusable result. |
| Tokens/network | Default 0 model calls, 0 tokens, 0 paid calls and no source fetch on the task path. No duplicate analysis agent per rule. Optional future drafting must use the existing exact scoped cost/budget policy and still cannot attest legal review. |
| Maintenance | Initial planning estimate: 2–4 engineering hours per pack per month for source comparison, fixtures and release work. Qualified legal-review time/cost remains unknown and separately scheduled. Pilot at most two packs; stop expanding when the measured maintenance budget is exceeded. |
| Measurement | Before promotion, publish hardware/limits and 10 cold plus 50 warm public-fixture runs; include p50/p95, deadline failures, rule counts, RAM, artifact bytes, token/call totals and maintenance time. A missed target does not become an assumed pass. |

Phase 0 is this design and independent schema/source review. Phase 1 is an explicit Enterprise advisory pilot with synthetic fixtures; Core and the existing EU opt-in gate retain their behavior. Task intake, planning and PR/CI may attach observations through existing package/audit paths. Phase 2 permits reviewed opt-in real packs and a qualified human-review adapter after separate design approval. Phase 3 may propose selected enforcement only after measured evidence, exact owner/customer consent and existing gate policy review. No unknown result silently enables delivery, and no new advisory outage blocks unrelated Core work. Rollback disables the optional adapter and retains historical observations; it cannot waive any already-required gate or retrospectively erase evidence.

## Draft work packages and test strategy

These are design work packages, not opened or approved implementation issues. Propose separate implementation tickets only after independent review of this ADR and schema.

| Future phase | Proposed interfaces/owners to reuse | Required tests before that phase can qualify |
|---|---|---|
| A. Closed pack parsing | Existing schema/contract validation, package and source-reading helpers; new adapter only after approval. | Unknown fields/operators, duplicate IDs, dangling source refs, invalid ordering and pack/aggregate bounds refuse; no dynamic code or hidden network. |
| B. Facts and applicability | Existing task/context and authenticated system owner; pure `evaluate` contract above. | Same purpose in different roles/use/markets; missing facts; IP-only hints; absent pack; zero rules; reversed jurisdiction order; platform/customer same IDs remain separate. Unknowns never yield blanket negative clearance. |
| C. Temporal/conflict semantics | Existing evidence bindings plus immutable pack/facts versions. | Day before/at/after effective start and end; concurrent versions; source or review expiry; future dates and clock uncertainty; conflicting jurisdictions; ambiguous priority requires legal review. |
| D. Evidence and human review | Existing receipts/audit bundle and actual trusted approval verifier. | Missing test/CI/artifact, wrong source/facts/pack hash, stale/revoked review, unsupported scope and replay cannot qualify acceptance. Repeat collection reuses the same evidence reference; a report assertion cannot sign itself. |
| E. Advisory integration | Existing intake/plan/PR/CI paths and optional module lifecycle. | Opt-out adds no model/network call; timeout/overflow stays visible; existing EU gate unaffected; replay does not create duplicate tasks or reports; no cross-project resolution/export; retention removes report/cache derivatives through their existing owner. |
| F. Measured promotion | Existing budgets, review plan and exact-source external delivery checks. | Cold/warm timing/resource and maintenance cohort above; rollback; stale artifact import remains historical; independent legal/source review is missing until actually supplied. |

Implementation is outside this issue. The tests above are future acceptance tests, not executed engine or native-authority evidence. Current artifact checks cover only schema structure, synthetic values, local references and this planning scope.

## Acceptance and references

AC1: audited paths above. AC2: this proposed ADR and [versioned schema](../schemas/compliance-policy-pack-v1.schema.json); independent review remains pending. AC3: applicability/responsibility tables. AC4: evidence and review lifecycle. AC5: explicit limits and absence of certification. AC6: budgets/non-blocking rollout. AC7: draft work packages only; no implementation issue is opened by this change.

The issue's [course reference](https://www.dobryakov.com/courses/ai-compliance/09-beyond-eu-us-uk.html) is background, not a rule source or legal authority. [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12/json-schema-core) is the primary data-format reference. Actual legal packs will require independently verified official publications and amendments; no current legal obligation, effective date or jurisdiction-wide coverage is asserted in this proposal.
