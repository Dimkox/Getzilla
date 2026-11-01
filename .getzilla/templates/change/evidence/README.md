# Evidence

Store human-readable review reports here. Machine receipts live under `.getzilla/runtime/receipts/` and are bound to the current repository fingerprint.

`state.json` holds canonical local checkpoints and explicit evidence accounting. A `not_run` reason explains unfinished work; a recorded result is self-reported and does not satisfy a passing receipt. Checkpoints are observations in this worktree, and become available to another clone only when separately exported and attached.

New-package and first-implementation observations are appended below by the lifecycle commands. A pending README mirror is surfaced in status and can be retried with the same explicit lifecycle command; state and README publication is not a two-file atomic transaction.

Every review requires a clean committed candidate; return dirty candidates to their writer. Record the exact reviewed HEAD and tree fingerprint before/after, and keep the reviewed candidate read-only. Mutation probes are required only for critical code: security checks, policy and permission parsers, authentication, money or external-write paths, and data deletion. For other changes state `mutation: skipped (non-critical)`. Perform applicable bounded, change-relevant probes in a reviewer-owned private scratch copy outside the reviewed worktree, below a trusted non-sticky parent with mode `0700`. Make the copy with `getzilla cleanup snapshot <commit>`, using the exact full reviewed SHA. Snapshots contain committed content only; staged, unstaged and untracked changes are not copied. Treat unsafe or mismatched snapshots and changed fingerprints as stale/inconclusive. Remove the copy with `getzilla cleanup snapshot --remove <path>` when the report is returned. Reviewer read-only configuration is not an OS-enforced isolation boundary.

Delivery order: bounded checks, commit source, independent reviews, save reports outside Git, then one final qualifying local gate. Record receipts only after the final gate passes.

Reviewers return the complete report to the coordinator out-of-band. After all reviews finish, the coordinator saves reports here without changing the source commit. Runtime report receipts bind exact reviewed HEAD/tree, route/logical-task/authority-epoch, context revision, package/spec/requirements and the hash of the actual report bytes. A new source commit, edited report, amendment, handoff or changed scope document makes prior receipts stale. Runtime status alone does not change source. Never reuse evidence from another tree or task context.

Each report must include:

- exact reviewed HEAD/tree and candidate tree fingerprint before/after, with clean-source observations;
- `reviewed-tree-modified: no` for every review, plus the scratch path when probes run;
- exactly one standalone `reviewed-context-digest: <64 lowercase hex>` line from the context actually inspected, matching the later `--reviewed-context` argument; never relabel an old report;
- exact commands executed and concise observed output; when probes run, also each claim probed and mutant outcome (`killed`, `survived`, or `inconclusive`);
- claims not executed and why; static claims without executable probes are unexecuted;
- surviving mutants as findings or explicit limitations (no blanket mutation-score threshold unless a scoped policy requires it).

New evidence belongs to this ignored runtime package. Preserve exact source identity and commands. Do not commit reports or freeze workflow state. Export a bounded archive with scripts/getzilla_evidence.py for PR attachment; CI artifacts contain only actual CI-run evidence and expire after 30 days.
