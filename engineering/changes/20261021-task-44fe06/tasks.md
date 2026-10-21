# Tasks

- [x] Record approved source scope, typed criteria, architecture and rollout boundary.
- [x] Add and observe failing regression tests.
- [x] Implement Core, v2 schema, adapters, installer and docs. Preserve v1 bytes.
- [x] Run fresh focused checks after scoped recovery:151 passed,1 skipped,156 subtests passed; architecture, spec, governance, Ruff and Bandit passed.
- [x] Record the implementation and bounded controls for source state reviewing.
- [x] Historical named smoke passed on source 5e8b873 with no receipt.
- [x] Coordinator collected all four first-wave reports in 4abde00; code/security review found three Medium defects.
- [x] Rebase onto actual main e42398d and implement one repair batch after red regressions.
- [x] Preserve the repair checkpoint and rebase onto actual main a103b373 after PR123/PR124. Retain both groups of prose changes and lean-install behavior.
- [x] Historical bounded controls on checkpoint585edde8 at basea103:212 passed,1 skipped,199 subtests; architecture/spec/governance/Ruff/Bandit passed.
- [x] Rebase onto actual main287e64 after PR125 without conflicts. Confirm EU product/test bytes match585edde8; retain its bounded observations without repeating unchanged tests.
- [x] Prepare repaired source state reviewing and record actual controls.
- [ ] Run the named committed-HEAD smoke and send the exact source identity to the coordinator.
- [ ] Coordinator collects four fresh independent reviews.
- [ ] Coordinator freezes reports and runs final local PR gate and external exact-head checks.

Trust CI producer and example policy are a separate successor. No extra write agent shares this candidate.

Final qualification is UNVERIFIED. First-wave controls and reports are historical after rebase/repair.
No fresh independent review, final local gate, push or external exact-head check ran for this repair.
