# Selected analysis synthesis

Source: `e158ddc7263a55f5308944c5a426eb1e9f1a4327`. Route: `4667515abad1`. The coordinator completed six independent read-only analyses before writer dispatch. These are analysis facts, not test or review PASS evidence.

- repo_explorer: runner-side stamping needs policy, models and runner changes only. Keep exact stored-envelope replay and synthetic checks unchanged.
- task_analyst: finish PR #120 phase 2 through the existing optional layer. Source-only authority does not authorize production actions.
- architect: Core/schema first, producer second. Add trailing strict boolean opt-in and optional result argv. Omit false and None to preserve legacy identity.
- docs_researcher: old closed validators reject argv. Upgrade readers first. Arguments become durable evidence and must contain no secrets. Source examples are not deployed activation.
- ai_architect: run a real enabled/disabled audit after Core integration. Signed argv alone cannot prove an audit that silently skipped EU rules. This feature does not prove tenant filtering, deletion, model evaluations or legal conformity.
- integration_architect: use exact `python3 scripts/getzilla_audit_bundle.py --ci-check` argv. No placeholder expansion. Protect `TRUST_CI_*` identity values in opted-in profiles. Keep status, exit code, output digest and replay behavior.

Core and Trust CI use separate isolated worktrees. This branch may prepare source independently. Final integration, review and gates wait for the merged Core consumer/schema changes.

## Explicit v2 ruling

The initial optional-v1 design is superseded. Core fitness correctly rejected extension of the exact signed v1 contract under `FIT-SIGNED-PAYLOAD-EXACT`. The architect approved a separate v2 contract and dual reader. Trust CI emits v2 when any selected repository or holdout command opts into argv evidence. Default profiles still emit v1. Parsing accepts only integer versions 1 and 2. V2 argv, when present, contains 1 to 128 nonempty strings, each at most 4096 characters. V2 permits a null spec digest. Preserve v1 raw payload and metadata-presence handling; raw argv in a v1 envelope never upgrades it to EU audit authority. Disable opt-in to return future emissions to v1, while retaining the dual reader for existing v2 envelopes.

The architect also requires both `spec_digest` and `criterion_coverage` keys in v2. A null digest is valid. Only v1 retains paired-optional metadata. V2 parsing checks presence before defaults and sets metadata presence to true.
