# Trust CI signed command evidence for EU AI Act audit

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

Change ID: `20261021-task-466751`
Created: 2026-10-21T13:12:34+00:00
Risk: high
Complexity: high-risk
Domains: ai, api, security

## Problem

Implement the Trust CI producer half of EU AI Act phase2 from PR120: optional signed command argv from the actual executed policy, API attestation compatibility and replay, and an opt-in EU audit example policy for the Core read-only audit command. Security boundary stays independent. Trust CI source and tests only; no deployed policy, keys, infrastructure or production changes.

## Outcome

An enabled repository can receive explicit v2 signed evidence of the exact audit command. Default repositories keep their current policy identity and v1 payload shape.

## Scope

### In scope

- Add strict optional command evidence in Trust CI policy, models and runner.
- Add tests, an opt-in command fragment and reader-first rollout guidance.
- Record source scope, observations and integration prerequisites in this package.

### Out of scope

- No Core, engineering contract, schema or architecture-rule edits in this branch.
- No deployed policy, store migration, API migration, keys, external mutation or production activation.

## Constraints

- Backward compatibility: omit false flags and absent argv. Keep the v1 contract exact and replay old envelopes unchanged. V2 readers ship first.
- Data/privacy: command arguments become signed durable evidence and must contain no secrets.
- Performance: no new service or dependency. Tests use at most six workers.
- Operational: Core/schema must merge first. Production approval remains pending.

## Source authority and identities

The owner asked to finish the EU AI Act phase-2 plan from PR #120 under Getzilla. This authorizes the source implementation described here. The coordinator recorded this source-only scope after the six route-selected analyses. It does not authorize production actions or provide a human security signature.

Route: `4667515abad1`. Branch: `feat/eu-ai-act-trustci-20261021`. Initial HEAD and trusted comparison base: `e158ddc7263a55f5308944c5a426eb1e9f1a4327`. Initial staged and unstaged tracked inventories were empty. The only untracked inventory was this change package.

Product inventory: `trust-ci/src/adaptive_trust_ci/policy.py`, `models.py`, `runner.py`; `trust-ci/tests/test_policy.py`, `test_runner.py`, `test_signing.py`, `test_api.py`; `trust-ci/config/eu-ai-act-audit.command.example.json`; `trust-ci/README.md`. Source preparation can proceed independently. Rebase on merged Core before integration tests, review and final qualification.
