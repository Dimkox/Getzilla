# Test plan

1. Reproduce missing-controller-capability acceptance with a regression.
2. Run bounded Linux process and offline inventory controls.
3. Commit source and workflow state. Run named quality-gates smoke on clean HEAD.
4. Run selected independent code, test, security and release reviews in parallel. Review the successor diff and PR127 audit boundaries. Critical process ownership changes need bounded private mutation probes.
5. Persist complete reports, commit and freeze.
6. Run python3 scripts/getzilla_verify.py --mode pr --full-scope with supported system Python and 26 workers. Require actual factory-postgres-exit execution.
7. Record current source-bound receipts and require exact-head public Actions before merge.

Historical passing checks do not qualify this candidate. Keep every skipped check explicit. Do not use repository-sandbox to replace PostgreSQL execution.
