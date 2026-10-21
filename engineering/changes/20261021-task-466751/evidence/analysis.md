# Selected analysis synthesis

Source: `e158ddc7263a55f5308944c5a426eb1e9f1a4327`. Route: `4667515abad1`. The coordinator completed six independent read-only analyses before writer dispatch. These are analysis facts, not test or review PASS evidence.

- repo_explorer: runner-side stamping needs policy, models and runner changes only. Keep exact stored-envelope replay and synthetic checks unchanged.
- task_analyst: finish PR #120 phase 2 through the existing optional layer. Source-only authority does not authorize production actions.
- architect: Core/schema first, producer second. Add trailing strict boolean opt-in and optional result argv. Omit false and None to preserve legacy identity.
- docs_researcher: old closed validators reject argv. Upgrade readers first. Arguments become durable evidence and must contain no secrets. Source examples are not deployed activation.
- ai_architect: run a real enabled/disabled audit after Core integration. Signed argv alone cannot prove an audit that silently skipped EU rules. This feature does not prove tenant filtering, deletion, model evaluations or legal conformity.
- integration_architect: use exact `python3 scripts/getzilla_audit_bundle.py --ci-check` argv. No placeholder expansion. Protect `TRUST_CI_*` identity values in opted-in profiles. Keep status, exit code, output digest and replay behavior.

Core and Trust CI use separate isolated worktrees. This branch may prepare source independently. Final integration, review and gates wait for the merged Core consumer/schema changes.
