# Security and operator handoff

Getzilla source is a 2.2.2 release candidate. Published v2.2.1 stays immutable.
Read [the current reference](../../docs/REFERENCE.md) and [the engineering contract](../../AGENTS.md).

## Threats and authority

Treat PR files, agent output and local receipts as untrusted inputs.
The threats include a malicious PR, a compromised agent and an insider who can change source.
A local test cannot certify its own external merge authority.
Public Getzilla uses exact-head GitHub Actions linux/windows checks.
Private consumers use the independent Trust CI service and its deployed policy.
Trust CI keeps its policy, holdout, images, durable state and trust stores outside the PR domain.
An insider with control of that trusted service remains a risk.
Repository source changes cannot prove that deployed controls still hold.

## Key ownership and rotation

Human security approvers keep their Ed25519 private keys on human-controlled machines.
Agents must never read, create, request or simulate those keys or signed approvals.
The Trust CI API operator owns the server-mounted human public-key store.
The CI worker operator owns the CI attestation signing key.
Keep signing material outside source, PR runners, logs and agent workspaces.
Read [the Trust CI boundary](../../trust-ci/README.md) for service roles.

For rotation, assign the operator and human approver before maintenance.
Revoke the old public identity and replace it through the operator-owned trust-store process.
Bind the new identity and policy epoch to fresh exact-head checks and required approvals.
Retain public identity, scope, time and revocation evidence. Never record private values.
Use a separate exact maintenance authorization for deployed trust material.
Actual deployed custody and rotation acceptance: NOT_RUN in this source task.

## Failed verification and bad main

Stop the pipeline on signature, policy or holdout digest mismatch.
Preserve the exact source SHA, expected public identity and safe error logs.
Compare the artifact, deployed policy epoch and approved holdout provenance.
Do not refresh trusted digests to make a failed check pass.
A legitimate policy or holdout change needs separate operator authorization and fresh evidence.

If bad source reached main, stop release and deployment.
Preserve the affected SHA, failure signal and safe logs.
Prepare a revert on an isolated branch and deliver it through a reviewed PR.
Require fresh checks on its exact head. Never force-reset the shared branch.
For an affected installation, record the exact target and last accepted artifact.
Use separately authorized rollback or forward recovery. Check its success and error signals.
Do not replay external writes without reconciliation and idempotency evidence.
Production recovery exercise: NOT_RUN in this source task.

## Review and test evidence

The author cannot approve its own work.
Reviewers inspect the actual diff and surrounding source with read-only candidate access.
Critical paths need bounded mutation probes in private scratch outside the candidate.
Reports record the source identity, commands, killed or surviving mutants and untouched candidate.
Another agent using the same model can share the author's mistakes.
Workflow read-only settings do not provide OS isolation.

The Core coverage floor is `74%` in [`.coveragerc`](../../.coveragerc).
Its measured scope is `.getzilla/getzilla` and `scripts`; test and runtime files are omitted.
It is not full factory or Trust CI coverage.
Issue72 recorded 1559 Core tests and 2 skips at `89b131e7b20afeafc02bf859131e449fa618c702`.
That is historical evidence, not this candidate's test count or PASS.
Read the final exact-source verifier report for current counts, scope and skipped checks.
Mutation reports live in the active `engineering/changes/<id>/evidence/` package or `engineering/reviews/`.
Count only executed probes. A surviving mutant is a finding or stated limit.
Current combined all-issues qualifying run: NOT_RUN in this leaf.

## Dependencies, SBOM and release policy

Use the checked-in toolchain lock and installer profile facts in [the reference](../../docs/REFERENCE.md).
Pin dependencies and review security updates through an isolated PR.
Run the applicable scanner and tests on the final candidate.
Syft is optional. An SBOM is not generated or verified by default.
If produced, bind its tool version, dependency scope and digest to the exact release artifact.
Do not infer completeness from an optional tool entry.
Source VERSION identifies a candidate. A published tag identifies an immutable release.
Use the exact merged tested source for packaging, tag and release operations.
Keep existing published ZIPs, sidecars and installer hashes unchanged.
Verify the tag-pinned installer hash before execution as shown in [QUICKSTART](../../QUICKSTART.md).
A release or installation does not prove provider activation or production task acceptance.

## Milestones and permissions

M0–M8 are delivery milestones. L0–L5 are permission levels.
They are different scales. Read [the roadmap](../../DARK_FACTORY_ROADMAP.md) for exact acceptance scope.

| Milestone | Source responsibility |
| --- | --- |
| M0 | Independent live merge authority |
| M1 | Typed business specification |
| M2 | Executable architecture model |
| M3 | Controlled learning and debt governance |
| M4 | Durable task queue and resource limits |
| M5 | Background implementation environment |
| M6 | Agent loop and independent semantic validation |
| M7 | Automated PR lifecycle and empirical qualification |
| M8 | Bounded owner autonomy and accepted product evidence |

One accepted Liqvera case supports the bounded owner M8 policy.
Per-clone activation begins with L1 local reads/tests and an L2 ceiling.
It gives no general production or external-write authority.
Empirical M7 and general signed-environment M9 qualification remain separate.
Owner L5 repository consent is conditional on exact-head checks, independent review and resolved threads.
It does not establish a live generic L5 deployment or authorize unspecified production effects.

## Canonical file map

| Path | Role |
| --- | --- |
| `.grok` | Canonical harness configuration, agents and hooks; generated skill mirror |
| `.agents/skills` | Canonical project skills |
| `.getzilla/getzilla` | Local routing, policy and verification runtime source |
| `.claude` | Generated Claude configuration |
| `.codex` | Generated Codex configuration |
| `.gemini` | Generated Gemini configuration |
| `.qwen` | Generated Qwen configuration |
| `.github` | Generated Copilot configuration and public CI workflow |
| `architecture/system.yaml` | Reviewed architecture model |
| `architecture/rules.yaml` | Architecture rules |
| `architecture/generated/` | Generated views |

Regenerate harness mirrors with `scripts/getzilla_harness.py --write` after canonical changes.
Do not edit generated copies as the source of truth.
