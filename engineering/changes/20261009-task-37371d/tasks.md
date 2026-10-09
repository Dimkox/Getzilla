# Implementation plan

Goal: close actual workflow blockers for issue72 by deadline05:00UTC, without inventing a production target.
Architecture: reviewer source binding at receipt boundary and consumption; truthful Getzilla current handoff. Stack: Python standard library, Git, existing Getzilla tooling. Spec: change-spec.yaml.

Constraints: single selected general_implementer writer; no dependencies/services/provider activation; all historical bytes preserved; no live production mutation. Review focus: unsafe revisions, report path escapes, uncommitted source, legacy receipts, Windows path handling.

- [ ] Task1: Add failing tests to tests/test_change_receipts.py proving CLI/core pass can no longer certify source not reviewed. Cover ancestor/equality and report-only success, source/dirty/unsafe failures, legacy consumption. Run red tests first.
- [ ] Implement focused source validator in receipts.py or a small adjacent module and safe CLI argument --reviewed-commit. Preserve receipt publication and fields. Update affected positive fixtures to supply real Git reviewer commits; do not weaken security assertions. Run bounded regressions.
- [ ] Task2: Update START_HERE.md, PROJECT_STATE.json, README.md, QUICKSTART.md and docs/REFERENCE.md current fields/L5/one gate. Preserve historical predecessor objects. Update only coupled binding tests. Refresh delivery/evidence skills and CLI command examples for reviewed identity and standing L5 repository actions. Regenerate harness only if managed source requires it, and include relevant parity tests.
- [ ] Commit candidate; bounded named smoke; independent code/test/security/release reviews. Repair findings through same writer, repeat controls/reviews, persist reports and freeze.
- [ ] Final verifier and exact-head external checks. Exact delegated branch/PR transport and conditional L5 merge. Release successor only on exact merged tested source; do not retag v2.2.0.

Routine scope decisions use owner standing L5 consent and explicit latest instruction to execute the goal. This does not approve a production deployment or security trust-store change.
