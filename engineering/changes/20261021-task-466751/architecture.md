# Architecture — Trust CI signed command evidence for EU AI Act audit

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Current behavior

Command results omit argv. Policies have no opt-in flag. Stored attestations preserve the signed payload exactly. Core's closed schema currently rejects new command-result keys.

## Proposed behavior

Append `CommandSpec.attest_argv: bool = False` and `CommandResult.argv: tuple[str, ...] | None = None`. Omit false and None on serialization. Strictly reject non-boolean policy flags. In `_run_command`, stamp the selected policy argv with `dataclasses.replace` and clear untrusted executor argv when the command does not opt in.

## Components and boundaries

Change only Trust CI source and tests. Keep signing, storage, API and sandbox behavior. Synthetic checks keep argv absent. Core/schema readers ship first. No deployed policy changes occur here.

## Data flow

Selected policy command → executor → runner stamps policy argv → signed result → unchanged envelope storage/API/replay. For any profile with an opted-in command, refuse `TRUST_CI_*` in all command environments and in `allowed_environment` before execution.

## API and event contracts

The added command-result argv is optional. Core owns the contract update. Existing envelopes remain valid. Old closed validators reject new argv, so upgrade consumers first. Do not reconstruct or enrich old envelopes.

## Governance context

Canonical governance JSON under `governance/` remains separately reviewed authority. Any rule, example, debt, or digest named here is non-authoritative context until the verifier rederives current governance evidence.

- Applicable rule IDs: FIT-TRUST-CI-SEPARATION and FIT-LOCAL-CANNOT-DEFINE-TRUST-CI.
- Applicable canonical example IDs/versions: existing Trust CI policy and signing patterns.
- Open or overdue debt IDs: none introduced.
- Expected governance handoff or receipt impact: normal route reviews and exact-head gates after Core integration.

## Decisions

Ruling: keep the audit in an opt-in fragment because enabling it globally would fail repositories without EU configuration. Ruling: omit false policy flags because a serialized default would change legacy policy epochs. Ruling: reject reserved identity overrides only for opted-in profiles because broad rejection would alter unrelated legacy behavior.

## Risks and mitigations

Arguments may expose secrets; operators must keep them out of attested commands. Signed invocation proves exact-source audit execution and its status, not legal conformity or regenerated bundle bytes. Old validators require a reader-first rollout. Core integration remains required before review freeze.
