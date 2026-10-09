---
name: verification-evidence
description: Use whenever tests, review, CI evidence, or completion claims must be checked and bound to the current repository state.
---

# Verification and Evidence

Delivery order: 1. bounded local checks; 2. independent reviews of one committed candidate; 3. save the complete review reports; 4. commit and freeze the candidate; 5. one final qualifying `python3 scripts/getzilla_verify.py --mode pr`.

During implementation run only bounded checks; they create no receipt. Dispatch every review agent selected by the route. Each inspects the same committed candidate and returns the complete report to the coordinator out-of-band. After all reviews finish, the coordinator saves all reports in the change package, then commits and freezes the candidate. The frozen candidate tree must equal the tree the reviewers saw except for the saved report files: before the final gate, `git diff --name-only <reviewed-commit> HEAD` lists only those reports; any other difference makes every review stale. Then run the final gate once. Verification receipts include a repository fingerprint. Record passing reports with `scripts/getzilla_review.py` only after that final gate passes. Any change after review invalidates all receipts: repeat the independent reviews on the new tree, save the new reports, commit and freeze again, and run a new final gate. Never reuse evidence from another tree. Completion requires zero gaps in `python scripts/getzilla_status.py`.

Code and test reviewers run bounded, change-relevant mutation probes only in a reviewer-owned private scratch copy outside the reviewed worktree. Keep the candidate unchanged; scratch must be below a trusted non-sticky parent with mode `0700` and reproduce the exact candidate, including relevant staged, unstaged, and untracked changes. Bind the report to HEAD and candidate tree fingerprint before/after. Unsafe scratch, an incomplete snapshot, or a changed fingerprint makes the result inconclusive/stale. Configured read-only mode is not an OS-enforced isolation boundary. Reports include scratch path, literal `reviewed-tree-modified: no`, executed claims, exact commands and concise output, killed/survived/inconclusive mutants, and unexecuted claims with reasons.

Never claim a command passed unless its current result is available. Never reuse review evidence from a different tree.

PASS review receipts require `--reviewed-commit <exact-full-sha>`. The CLI and core require a clean committed candidate and recheck ancestry plus a delta limited to non-executable regular Markdown files in `engineering/reviews/` or the valid active change evidence directory. Deleted, renamed, executable, symlinked and unknown-path reports do not qualify. Missing legacy or forged source bindings are evidence gaps. Failure observations need no reviewed identity.

## Manual override

An explicit owner override of a local workflow rule is acceptable. Record the exact rule, scope, reason, deferred checks and follow-up validation in the change package. Label the result UNVERIFIED until those checks run. Never create a fake PASS receipt, review or external attestation. This does not grant authority to bypass exact-head external checks, branch protection or the human private-key boundary.


Freeze tracked workflow state at `reviewing` before independent review. Do not transition tracked state to `ready` after freeze: that changes reviewed source and stales the reports. Fresh final receipts, zero status gaps and exact-head external PR results record completion. The old prepare-only command printer's ready prerequisite grants no authority and does not restrict separately authorized exact L5 operations. A full lifecycle-state redesign is a later task.

Saved report-only deltas use exactly `code-review.md`, `test-review.md`, `bitrix-review.md`, `security-review.md`, `data-review.md` or `release-review.md` directly under `engineering/reviews/` or the valid active change evidence directory. Low-risk micro routes may use `engineering/reviews/` without a durable package; other routes require their selected package. Malformed or unsafe selected package metadata fails closed. Analysis, README/index, checkpoint and arbitrary custom Markdown files are source changes, not saved review reports.
