# Rollback — GZ-HOOK-ROOT-001

Trigger rollback if quoted data becomes code, a sensitive cross-root action passes, or an interpreter/write guard regresses.

Before installation, discard the candidate through the normal branch workflow. After source delivery, revert the repair commit through a new isolated PR or apply a bounded forward fix. Regenerate harness files with `python3 scripts/getzilla_harness.py --write` and run the quoting, root, authority, shell-target and circuit-breaker regressions. Require independent review and fresh exact-head gates.

No data, deployment or live hook changes occur in this task. No ledger reset is needed. Prior published artifacts remain immutable.
