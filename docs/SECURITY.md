# Security model

This page answers the external handoff review in #63. Everything here describes the current code and documentation. Where a guarantee is weaker than it sounds, the limitation is named.

## What Getzilla defends against

| Threat | Defence | Limitation |
|---|---|---|
| A coding agent that misreads a task, takes a shortcut or is prompt-injected | Local hooks (`.grok/hooks/pre_tool_use.py` and the generated copies) deny destructive commands, secret reads, control-plane writes, pushes, merges and publication without an exact delegated grant. | Hooks are a local guardrail, not a sandbox. An agent that runs outside the hooks (another tool or another shell) is not checked. |
| A malicious or careless pull request | Merge needs a pull request and the external exact-head check: GitHub Actions for public repositories, Trust CI for private ones. Local receipts and grants are never merge authority. | Branch protection is configured by the owner on GitHub; Getzilla cannot enforce it from inside the repository. |
| A compromised agent that forges evidence | Receipts are bound to the exact tree fingerprint. New review receipts bind the exact reviewed commit/tree and runtime report-content hash (`review_source.py`); source or report changes make them stale. Historical tracked receipts retain their legacy report-only-delta validation. Trust CI signs attestations with a key the agent never reads. | Local evidence lives on the same machine as the agent; only the external check is independent of it. |
| An insider with repository write access | Trust CI runs a holdout bundle that a pull request cannot modify, verifies its digest before checkout, and needs human-signed approvals for protected actions. | A person who controls the Trust CI host, its keys or the GitHub App can bypass it. |
| A tampered installer | The README commands download the installer from a release tag and compare its SHA-256 with the published digest before running it. The test suite binds that digest to the installer bytes. | The digest is only as trustworthy as the README you read it from. |

## Keys

No key material is stored in this repository.

- **CI attestation key (Ed25519).** Generated on the CI server or in a secret manager with `adaptive-trust-ci keygen`. It is mounted only into the Trust CI worker. Its public key is published for offline attestation checks.
- **GitHub App key (RSA).** It is mounted only into the worker. The App gets only Checks: read and write, Contents: read, and Pull requests: read.
- **Human approval keys (Ed25519).** Generated on the owner's workstation, never on the CI server or in an agent workspace. Only the public key and its `key_id` go into the server-side `runtime/trust-store.json`.
- **Rotation.** Trust store schema 2 gives each key a `not_before` and a `revoked_at`. To rotate, add the new public key with `not_before`, move signing to it, then set `revoked_at` on the old key. `adaptive-trust-ci trust-store-validate --trust-store <file>` checks the key lifecycle, revocation and scopes. Signatures from a revoked key are rejected from `revoked_at` on.

See [trust-ci/README.md](../trust-ci/README.md) for the setup commands.

## When a check fails

- **The holdout digest does not match, or an attestation fails to verify.** Stop the pipeline; never update the digest or the trust store to make the check pass. Find out which bytes changed and why. Regenerating a holdout digest is a deliberate owner action on the CI host, recorded with its reason. It is not a troubleshooting step.
- **Bad code is already on `main`.** Revert it through a pull request; `main` is never rewritten. If the bad commit was released, publish a new patch release that contains the revert; tags are never moved. A release tag always points at the exact merged commit (AGENTS.md, "Local delegated grants"). Every production-facing change must carry rollback or forward-recovery steps and observable success and failure signals (AGENTS.md, "Development discipline").

## Reviewer independence

Reviews follow `.agents/skills/getzilla-delivery/SKILL.md` and AGENTS.md:

- each selected reviewer works on the same committed candidate and records its commit and tree hash;
- the candidate stays read-only; required mutation probes cover critical code: security, policy/permissions, authentication, money or external writes, and deletion. Other reviews state `mutation: skipped (non-critical)`;
- when probes run, they use a private copy outside the candidate, below a mode `0700` parent. The report lists every claim probed, the exact commands, the observed output, and each mutant as killed, survived or inconclusive; static claims without a probe count as unexecuted;
- source or report-content changes after review invalidate the bound receipts. Saving ignored runtime evidence does not require a source or freeze commit.

**Limitation:** the reviewers are usually the same model family as the author. Isolation, read-only access, their own probes and mutants reduce shared blind spots; they do not remove them. The external exact-head check is the independent gate.

## Tests and dependencies

- **Test suite.** `python3 -m pytest -n <workers> tests`; around 2,200 tests at the time of writing. Coverage gate: `fail_under = 74` in `.coveragerc`. Mutation evidence is required for critical-code reviews (AGENTS.md, "Reviewer mutation evidence"); other reviews record the non-critical skip. This is not a blanket mutation-score threshold.
- **Dependencies.**
  - Runtime pins are exact. Trust CI installs from hashed lockfiles (`trust-ci/requirements*.txt`, `--require-hashes`).
  - The known-vulnerabilities check scans every lockfile and pinned manifest against OSV, from an offline mirror or online.
  - A Syft SBOM is optional (see the tool table in [REFERENCE.md](REFERENCE.md)). No SBOM is published with releases yet.
- **Versions and releases.** Semantic versions are tagged `vMAJOR.MINOR.PATCH` on the exact merged commit, and published as GitHub Releases.

## Glossary: levels and milestones

- **L5 autonomy** (AGENTS.md, "L5 autonomy"): the agent runs the whole loop itself (plan, change, tests, independent review, pull request) within exact delegated grants. Merge, tag and release of the project's own repository happen only under the owner's standing L5 consent and the external check. The lower levels are not defined as a separate scale.
- **M0–M9** are delivery milestones recorded in `PROJECT_STATE.json` and `docs/REFERENCE.md` (for example "M0 Live Trust Authority" or "M8 owner policy"). They are not autonomy levels.
