---
name: getzilla-delivery
description: Use for every routed software-development task. Reads the active route, dispatches only selected agents, enforces one write owner, and closes the task with fingerprint-bound verification and independent review evidence.
---

# Getzilla Delivery Controller

## Inputs

Read `.getzilla/runtime/active-route.json`. It contains:

- intent, domains, risk, and complexity;
- required workflow skills;
- parallel read-only analysis agents;
- exactly one write agent or no write agent;
- independent review agents;
- quality profiles, human gates, and evidence kinds.

Do not substitute your own generic workflow when a route exists.

## 1. Establish the run

1. Run `python scripts/getzilla_status.py`.
2. Load every skill named in `workflow_skills`.
3. For `standard` and `high-risk` work, create a durable change package:

```bash
python scripts/getzilla_change.py start
```

4. Use the change package for scope, requirements, architecture, tests, decisions, release, rollback, and human approval evidence.

Micro changes may stay in chat if they are genuinely bounded, but still require verification and selected reviews.

## 2. Parallel analysis

Dispatch all `analysis_agents` whose work is independent. Give each agent:

- route ID and task;
- exact repository root;
- active change path when available;
- one narrow question;
- a report destination under `<change>/evidence/analysis-<agent>.md`.

Wait for all reports. Synthesize facts, conflicts, and unresolved decisions. Do not ask the user for facts recoverable from the repository.

Dispatch every `analysis_agents` entry in one wave. The route already caps that list (default 10); do not spawn extra names to fill the cap. Keep exactly one write owner.

## 3. Scope and design gate

Write or update the change brief, acceptance criteria, architecture, risk, and test plan.

When `human_gates` contains `scope_and_design_approval`, present the decision and stop before implementation. For ordinary low/medium-risk tasks without a named gate, proceed after recording a bounded design.

Transition durable changes:

```bash
python scripts/getzilla_change.py transition <change-id> scoped --reason "scope and acceptance criteria written"
python scripts/getzilla_change.py transition <change-id> approved --reason "approved or no named human gate"
```

## 4. Single-owner implementation

Dispatch only the route's `write_agent`.

The write agent must:

1. Read the change package and analysis reports.
2. Add a failing test or characterization test.
3. Implement the smallest coherent vertical change.
4. Run focused checks.
5. Return changed files, commands, results, residual risk, rollout, and rollback notes.

Do not spawn a second write agent for the same route. Review fixes return to the same write owner.

## 5. Bounded observations

Delivery order: 1. bounded local checks; 2. independent reviews of one committed candidate; 3. save the complete review reports; 4. commit and freeze the candidate; 5. one final qualifying `python3 scripts/getzilla_verify.py --mode pr`.

Run change-relevant checks during implementation and repair. On a clean committed HEAD, a named smoke may use the contract's `--mode fast --no-record --test tests.test_module --budget 180` form. These observations create no verification receipt or scope admission; do not run a preliminary full qualifying gate before reviews.

Record exact commands, comparison base/HEAD and outcomes. A failing check returns to the write owner. Do not manufacture an active route, shorten the comparison range or record passing evidence against a failing or stale tree.

## 6. Independent review

Dispatch all route `review_agents` in parallel. Each reviews the same committed candidate from its own perspective and records its commit and tree hash (`git rev-parse HEAD HEAD^{tree}`) and returns the complete report to the coordinator out-of-band; reviewers must not write into the candidate worktree.

Code and test reviewers perform bounded, change-relevant mutation probes in a reviewer-owned private scratch copy outside the reviewed worktree. The candidate stays read-only: do not edit or restore it, or generate artifacts there. Scratch must be below a trusted non-sticky parent with mode `0700` and reproduce the exact candidate snapshot, including relevant staged, unstaged, and untracked changes. Record HEAD and candidate tree fingerprint before and after review; unsafe scratch, mismatched snapshot, or changed candidate makes the review inconclusive/stale. Read-only reviewer configuration and prompts are workflow requirements, not OS-enforced filesystem isolation.

Reports list source identity, scratch path, literal `reviewed-tree-modified: no`, each claim probed, exact commands and concise observed output, and each mutant as killed/survived/inconclusive. List unexecuted claims and why; static claims without executable probes are unexecuted. Survivors are findings or explicit limitations; do not apply an unstated blanket mutation-score threshold. After all reviews finish, the coordinator persists the returned reports under the change evidence directory. Persist these reports before the final qualifying gate below; do not claim that an implementation-time observation qualifies the changed candidate.

## 7. Final verification and receipts

After all selected independent reports are complete and persisted, commit and freeze the candidate. The frozen candidate tree must equal the tree the reviewers saw except for the saved report files: before the final gate, `git diff --name-only <reviewed-commit> HEAD` lists only those reports; any other difference makes every review stale. Run one final qualifying local PR gate on that exact candidate using the measured CPU allocation:

```bash
python3 scripts/getzilla_verify.py --mode pr
```

The existing fail-closed selector, not a route label or the agent's assertion, determines admissible verification scope inside the run. Record the exact base/head, changed-path digest, profile/reason and all skipped checks. A skip is not a pass; historical component evidence is not fresh verification.

For a positively established product change confined to `side-projects/seo-landings/**` plus one explicitly named focused landing test in one landing directory, preserve the separate explicit focused contract:

```bash
python3 scripts/getzilla_verify.py --mode focused-static-seo-landing
```

The active `engineering/changes/<id>/` package is workflow evidence, not product scope. Mixed or unknown paths, multiple landing directories, missing/ambiguous tests, invalid/incomplete route or range inventory, and runtime, contracts, Trust CI, packages, architecture, workflow/configuration, SEO-skill or showcase changes require the PR path. This instruction creates no additional fast path or permission to downgrade scope.

For every genuinely passing independent report, after the qualifying gate succeeds, record its exact evidence kind with fresh fingerprint-bound receipts that cover the persisted reports and final tree:

```bash
python scripts/getzilla_review.py code_review --status pass --report engineering/changes/<id>/evidence/code-review.md
python scripts/getzilla_review.py test_review --status pass --report engineering/changes/<id>/evidence/test-review.md
```

Use `bitrix_review`, `security_review`, `data_review`, and `release_review` when requested. If review or verification cannot execute, record `NOT_RUN` or `BLOCKED` with the reason; do not fabricate a passing receipt or substitute self-review for an independent reviewer. Any change after review invalidates all receipts: repeat the independent reviews on the new tree, save the new reports, commit and freeze again, and run a new final gate. Never reuse evidence from another tree.

## 8. Close

Run `python scripts/getzilla_status.py`. Completion requires zero evidence gaps. For durable changes, transition to `ready` after verification and review.

Do not deploy, publish, merge, or perform external writes as part of closure. Those are separate, explicitly approved actions. The last mile is `python3 scripts/getzilla_deploy.py`; humans own the printed commands.
