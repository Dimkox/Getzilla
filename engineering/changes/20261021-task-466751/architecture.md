# Architecture — Trust CI signed command evidence for EU AI Act audit

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Current behavior

The baseline command results omit argv. Policies have no opt-in flag. Stored attestations preserve the signed payload exactly. Core's closed v1 schema rejects new command-result keys. `FIT-SIGNED-PAYLOAD-EXACT` forbids extending that signed v1 contract.

## Proposed behavior

Append `CommandSpec.attest_argv: bool = False` and `CommandResult.argv: tuple[str, ...] | None = None`. Omit false and None on serialization. Strictly reject non-boolean policy flags. In `_run_command`, stamp the selected policy argv with `dataclasses.replace` and clear untrusted executor argv when the command does not opt in.

Emit an explicit v2 attestation when any selected repository or holdout command opts in, including early synthetic failures. All other profiles emit v1. Accept only integer versions 1 and 2. V2 validates optional argv as 1 to 128 nonempty strings with at most 4096 characters each. Require both metadata keys in v2 and allow a null spec digest. Preserve paired-optional metadata and exact raw envelope replay for v1.

## Components and boundaries

Change only Trust CI source and tests. Keep signing, storage, API and sandbox behavior. Synthetic checks keep argv absent. Core/schema readers ship first. No deployed policy changes occur here.

## Data flow

Selected policy command → executor → runner stamps policy argv → signed result → unchanged envelope storage/API/replay. For any profile with an opted-in command, refuse `TRUST_CI_*` in all command environments and in `allowed_environment` before execution.

## API and event contracts

The added command-result argv is optional in a separate v2 contract. Core owns that contract. The v1 contract stays exact. Existing envelopes remain valid. V1-only validators reject v2, so upgrade consumers first. Do not reconstruct or enrich old envelopes. A signed v1 envelope with raw argv stays v1 and cannot qualify EU audit authority.

## Governance context

Canonical governance JSON under `governance/` remains separately reviewed authority. Any rule, example, debt, or digest named here is non-authoritative context until the verifier rederives current governance evidence.

- Applicable rule IDs: FIT-TRUST-CI-SEPARATION and FIT-LOCAL-CANNOT-DEFINE-TRUST-CI.
- Applicable canonical example IDs/versions: existing Trust CI policy and signing patterns.
- Open or overdue debt IDs: none introduced.
- Expected governance handoff or receipt impact: normal route reviews and exact-head gates after Core integration.

## Decisions

Ruling: keep the audit in an opt-in fragment because enabling it globally would fail repositories without EU configuration. Ruling: omit false policy flags because a serialized default would change legacy policy epochs. Ruling: reject reserved identity overrides only for opted-in profiles because broad rejection would alter unrelated legacy behavior.

Superseded ruling: add optional argv under signed v1. Architecture fitness rejected that extension. The approved correction uses a separate v2 schema and strict dual reader while default profiles keep v1 emission. No fitness rule is changed or bypassed.

## Risks and mitigations

Arguments may expose secrets; operators must keep them out of attested commands. Signed invocation proves exact-source audit execution and its status, not legal conformity or regenerated bundle bytes. Old validators require a reader-first rollout. Core integration remains required before review freeze.
