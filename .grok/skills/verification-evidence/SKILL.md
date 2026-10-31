---
name: verification-evidence
description: Use whenever tests, review, CI evidence, or completion claims must be checked and bound to the current repository state.
---

# Verification and evidence

Follow `.agents/skills/getzilla-delivery/SKILL.md`. Run bounded controls, commit source, reconcile the route, collect selected independent reviews, save reports outside Git, then run one final qualifying local gate. A complete clean low-risk diff of at most 50 added plus deleted code lines may use the light lane with one ordinary code review and any configured or explicitly retained additional reviews; unknown or sensitive inventories retain full gates. Use `--mode fast` for measured light admission, `--mode pr` for full delivery or its existing qualifying scope selector, and `--mode release` for release work. Fast can still run full test discovery; named `--no-record --test` smoke is only an observation. Full CI and external exact-head merge checks remain required.

Save new state, startup, analyses and reports under `.getzilla/runtime`. New packages use `.getzilla/runtime/changes/<id>/`; package-free reviews use `.getzilla/runtime/reviews/<route-id>/`. Do not create report-only or workflow freeze commits. At most one concise summary per change may be tracked. Preserve historical tracked packages and their existing source bindings.

PASS review receipts require `--reviewed-commit <exact-full-sha>`, clean source, a conventional non-executable regular Markdown report, exact HEAD/tree identity, route/change identity and a report-content hash. Recheck these at consumption. A new commit or report edit requires fresh evidence. Runtime state updates alone do not change the reviewed source. Record NOT_RUN/BLOCKED and the reason when a check cannot run; never invent a PASS.

Reviewers work read-only and return concise reports out-of-band. Mutation probes are required only for critical code: security checks, policy and permission parsers, authentication, money or external-write paths, and data deletion. For other changes state `mutation: skipped (non-critical)`. Every review requires clean committed source and records exact HEAD/tree and tree fingerprint before/after, clean-source observations, `reviewed-tree-modified: no`, exact commands, outcomes and unexecuted claims, even when mutation is skipped. Return dirty candidates to their writer. Bound applicable probes to private scratch below the canonical project's `.getzilla/runtime`, with a trusted non-sticky parent and mode 0700. Create the snapshot from the exact reviewed commit; staged, unstaged and untracked changes are not copied. When probes run, report the scratch path and mutant results. A changed candidate or incomplete snapshot makes the review stale.

`python3 scripts/getzilla_evidence.py --output .getzilla/runtime/exports/<id>.zip` exports bounded local observations with hashes for separate PR attachment. It excludes grants and keys and never activates imported receipts. CI artifacts contain only that runner's actual evidence, exact source provenance and CI state, retained for 30 days. CI explicitly labels workstation reviews/analyses unavailable.

Completion needs zero `getzilla_status.py` gaps and the external checks on the exact PR head. Local evidence and an owner override do not replace branch protection, exact production/external grants or human-signed security approval.

Reviewers return the complete report to the coordinator out-of-band. After all reviews finish, save reports outside Git and run one final qualifying gate. Use one canonical project root. Put private scratch outside the reviewed candidate and outside the reviewed worktree, beneath that root's `.getzilla/runtime`. Record HEAD and tree fingerprint before/after, scratch path, `reviewed-tree-modified: no`, exact commands and observed output. Report killed, survived and inconclusive mutants and all unexecuted claims. Read-only configuration is not an OS-enforced isolation boundary.
