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
- [x] Historical named smoke passed on61827791 in0.101s with stable source and no receipt.
- [x] Coordinator saved four wave2 FAIL reports inb23baf3. Two Medium findings remain; six Low gaps stay in issue122.
- [x] Add failing wave2 regressions and implement captured opt-in plus bounded receipt-ignore compatibility. Focused48tests and67subtests passed.
- [x] Complete wave2 architecture/spec/governance controls and prepare state reviewing. Ruff/Bandit also passed; V1/util/reports stay unchanged.
- [ ] Run the named committed-HEAD smoke and send the exact repaired source identity to the coordinator.
- [ ] Coordinator collects four fresh independent reviews after the second repair.
- [ ] Coordinator freezes reports and runs final local PR gate and external exact-head checks.

Trust CI producer and example policy are a separate successor. No extra write agent shares this candidate.

Final qualification is UNVERIFIED. Prior controls and both report waves are historical after repair.
No fresh independent review, final local gate, push or external exact-head check ran for this repair.
