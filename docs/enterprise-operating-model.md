# Enterprise operating model: ownership, exceptions and evidence

Status: proposed planning artifact for [issue #157](https://github.com/Dimkox/Getzilla/issues/157). No owner appointments, active enterprise controls, response service or legal approvals are established here. Independent design review is pending. The [Compliance Foundation ADR](compliance-foundation.md) and its [versioned policy-pack schema](../schemas/compliance-policy-pack-v1.schema.json) remain the single proposed applicability/policy contract. All seven #146 criteria remain mandatory.

This model separates engineering evidence from legal interpretation and certification. A passing test, signed CI attestation, source digest or named reviewer does not establish legal compliance. This document supplies no jurisdiction rules, runtime engine, role backend, activation, security approval or deployment.

## Existing mechanisms and their limits

The source baseline is accepted `352d62450afea5821346a99cf47ebe8565717d42`. These mechanisms already exist; the operating procedures below are proposals.

| Existing mechanism | Reuse and current limit |
|---|---|
| [Governance rules](../governance/rules/index.json), [debt](../governance/debt/index.json) and [.getzilla/getzilla/governance.py](../.getzilla/getzilla/governance.py) | Reuse evidence, owner, lifecycle, expiry and repayment references. `_has_external_rule_authority` currently returns false: records cannot acquire exact-record authority merely by setting an approval or active field. Rule expiry is optional in the existing schema; the mandatory exception expiry below is a design requirement, not shipped enforcement. |
| [Canonical examples](../governance/canonical-examples/index.json), `validate_example_deviation` in the same module | Reuse the narrow justification, criterion and current evidence checks where applicable. This is not a general exception permission. |
| [Local grants](../.getzilla/getzilla/state.py), [review receipts](../.getzilla/getzilla/receipts.py) and [review entry point](../scripts/getzilla_review.py) | Preserve the original action/source/context/expiry bindings. Local delegation and a reviewer label do not establish human identity, legal qualification or merge authority. |
| [Verification dispositions](../.getzilla/getzilla/verification_dispositions.py) | Reuse source-bound classifications where supported. These records explicitly are not authenticated approvals. |
| [Trust CI approval API](../trust-ci/src/adaptive_trust_ci/api.py) and [signature verifier](../trust-ci/src/adaptive_trust_ci/signing.py) | Keep existing server policy, exact source/scope, expiry, revocation and replay checks. Human signing keys stay outside the agent environment. A proposed legal or exception scope does not create an accepted verifier scope. |
| [Incident archive](../engineering/incidents/README.md), [engineering lessons](../engineering/mistakes.md), existing task packages and tracker | Reuse incident provenance, task identity and follow-up evidence. An archive is not a live incident queue, pager or response service. No new incident backend or duplicate decision journal is proposed. |

## Proposed responsibility and approval model

These are responsibilities to assign through the existing authorized operator/customer process. All appointments and contact routes are **unassigned** until recorded and verified there. A role name, UID, SID, task handle or JSON field is not customer identity or authority.

| Proposed role | Responsibility | Approval boundary |
|---|---|---|
| Platform control owner | Maintain the platform control, evidence references, source freshness, due dates and remediation task. | May propose a change; cannot accept their own independent review. |
| Customer/system owner | Confirm product, purpose, deployment, actual use and system-specific evidence within their actual authority. | Cannot grant platform operations or other customers' access. Customer duties do not silently transfer to the platform. |
| Independent engineering reviewer | Check the exact implementation/design, source bindings, test scope and explicit unknowns. | Engineering acceptance only; does not certify legal compliance or replace required external checks. |
| Release acceptor/operator | Use the existing exact-source review, CI, policy and delegated operation boundaries. | No exception can waive branch protection or supply a missing signed human approval. |
| Incident coordinator | Track acknowledgement, containment decisions, actual responders and recovery evidence. | Acts only within existing delegated operation scope; the title grants no new access. |
| Qualified legal reviewer | Interpret relevant law and confirm a scoped, dated legal assessment when needed. | Qualification, identity and acceptance require an actual supported trusted boundary. That adapter is not provided by this plan. |

The platform owner and customer owner must agree the actual responsibility split before an Enterprise pilot. Missing appointments, delegation or review capability remain visible unknowns. An agent can draft evidence and proposals; it cannot appoint an approver, sign a human decision or attest that a customer accepted responsibility.

## Proposed exception lifecycle

An exception is a specific temporary treatment of one control in one context. It is not permission to ignore policy. Reuse an existing task and, where their contracts fit, its governance/debt records; do not create a parallel exception database or approval ledger. If the existing mechanism cannot represent or authenticate the required scope, leave the exception pending and the affected operation unavailable.

The request must identify the control/rule and version, repository/system, task/operation, actual audience, source HEAD/context and supporting evidence. Record the reason, risk, compensating controls, proposed owner and approver references, start and expiry in UTC, revocation conditions, validation plan and repayment/renewal task. Reference authorized evidence; do not copy secrets or private content into public issues. Missing evidence is unknown, not an implicit waiver.

Proposed flow: request → independent risk/evidence review → acceptance by the actual supported authority → bounded use → expiry/revocation → verified closure. Author and independent accepting reviewer must differ. Current governance records alone cannot complete the authority step. The design default is seven days, with a maximum of thirty days per acceptance; these are proposed operating limits, not law or current runtime guarantees. Shorter existing authority/policy limits prevail.

No automatic renewal is allowed. Renewal requires a new current-scope review before expiry and retains the old decision as history. Expired, revoked, wrong-source, wrong-audience, unsupported or clock-uncertain exceptions cannot authorize the affected action. Recheck current authority at use through its existing boundary; a copied receipt or cached approval is not sufficient. Do not block unrelated Core work merely because an optional Enterprise proposal is unavailable.

Exceptions cannot bypass data access boundaries, required external CI, human Trust CI signing, existing payment/operation permissions or a required security approval. They cannot authorize use of a human key by an agent. This document creates no signed scope and changes no trust store.

## Proposed incident escalation and recovery

Use existing authorized operator channels and a source-bound task/incident record. This plan sends no notifications and supplies no paging integration. Record detection time, reporter evidence type, affected systems/source, scope, actual owner/acknowledgement, containment actions, recovery criteria and links to follow-up work. Restrict evidence and audiences through the current owner policy; opaque references can also be sensitive.

1. Triage an observed impact or control failure. Preserve bounded evidence and distinguish an observation from an inference.
2. Ask the actual operator to contain the affected operation using existing authorized controls. Do not invent a kill switch, revoke credentials or change production from a role label.
3. Escalate through the agreed operator/customer contact route. Proposed targets are immediate triage for suspected ongoing severe impact, same working day for other material failures, and the next scheduled review for minor findings. These are planning targets, not staffed response SLAs. Unconfirmed impact and missing acknowledgement stay unknown.
4. Recover only after the responsible authority accepts current evidence through the existing release/operation boundary. Record residual risk and any separately authorized, unexpired exception.
5. Add a provenance-preserving incident entry and lessons, then propose the control/policy change through ordinary independent review. Preserve the original observation and decision history.

If the owner, contact route or authority is missing, record that gap and keep the affected protected operation unavailable. An agent does not invent an acknowledgement, contact a third party or certify recovery. Incident participation does not extend access or evidence retention rights.

## Proposed cadence, evidence report and budget

| Trigger or interval | Proposed work and owner |
|---|---|
| Weekly | Control owner checks open exceptions, upcoming expiry, unassigned responsibilities and overdue remediation. |
| Monthly | Control owner compares evidence freshness, incident follow-ups and source changes; independent reviewer checks material changes. |
| Quarterly | Platform/customer owners review the responsibility split, delegated scopes, contact routes and policy-pack maintenance capacity. Qualified legal review is separately arranged where required. |
| Event-driven | Revisit affected decisions after a source/policy change, effective-date boundary, changed purpose/use, permission revocation, incident or reviewer expiry. Do not wait for a meeting or reset an existing review deadline. |

These intervals are proposals. They do not extend the Foundation's source/evidence deadlines or the existing EU component's separate review rules. Stale, missing, inaccessible or revoked evidence remains explicitly incomplete; an elapsed review date cannot silently produce acceptance.

Attach a concise report to the existing change/audit path. Reference the exact repository/HEAD/tree, originating run, context, artifact hashes, system/facts and pack versions, control scope, actual appointment/approval status, exception expiry, incident status, coverage/unknowns and next review. Preserve original tests, AI/author observations, independent engineering reviews and human/legal decisions as distinct evidence types. The report is evidence, not a capability, certificate or declaration that all controls operated.

Resolve/export references only under current project/customer permissions. Retention and deletion use the existing evidence owner and customer policy, including derivatives; this model adds no storage authority or second journal. Large artifacts stay outside Git. A restricted report must not become public because its reference is opaque.

Reuse the [Foundation's budgets and non-blocking rollout](compliance-foundation.md#integration-budgets-and-rollout). Proposed coordination overhead is at most two engineering hours per pilot month in addition to its per-pack estimate; legal review and incident response effort remain unknown and separately scheduled. Default task-path overhead remains zero model calls, zero tokens and zero paid calls; no synchronous meeting or network source lookup is added. Record actual maintenance time before expansion. Exceeding the proposed budget pauses optional expansion and triggers review; it does not waive an existing control.

## Business assumptions and phased adoption

C1: the planning assumption permits free local use by staff, contractors and client developers, including internal copies; a centrally operated service is a paid offering. This proposes no billing service or new licence terms. The public [LICENSE](../LICENSE) remains unchanged.

C2: use official source links with provenance; controlled internal mirrors may support availability only if they preserve the original identity, version, hash and access scope. A mirror is not a new legal authority. C3: the company/legal identity is **нет пока — not yet specified**. Do not infer it from contributors, domains or repository ownership.

Phase 0 is independent review of #146 and this #157 design. Only after that review may a later authorized backlog assign real owners, confirm the current authority path, define a scoped advisory pilot and exercise expiry, missing-owner, incident and stale-evidence scenarios. A later phase would require actual staffing/delegation, measured maintenance, supported approval contracts and evidence of an incident exercise before claiming operation. No implementation issues are opened by this document. No runtime capability, legal rule coverage or certification is delivered by a draft or its schema.

## References and scope

The cited [AI Governance course](https://www.dobryakov.com/courses/ai-governance/index.html) and its [operating-model chapter](https://www.dobryakov.com/courses/ai-governance/10-operating-model.html) are background on ownership, lifecycle and review. They are not legal sources, evidence that a control operates, or authority to activate one. This proposal makes no legal or standards-conformance claim. The existing #146 ADR owns applicability outcomes and jurisdiction policy-pack design; this document only describes proposed human responsibilities and operating procedures around that contract.
