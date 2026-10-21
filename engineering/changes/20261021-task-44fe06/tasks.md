# Tasks

- [x] Record approved source scope, typed criteria, architecture and rollout boundary.
- [x] Add and observe failing regression tests.
- [x] Implement Core, v2 schema, adapters, installer and docs. Preserve v1 bytes.
- [x] Run fresh focused checks after scoped recovery:151 passed,1 skipped,156 subtests passed; architecture, spec, governance, Ruff and Bandit passed.
- [x] Record the implementation and bounded controls for source state reviewing.
- [ ] Run the named committed-HEAD smoke after the reviewing commit and report its exact result to the coordinator.
- [ ] Coordinator collects independent reviews.
- [ ] Coordinator freezes reports and runs final local PR gate and external exact-head checks.

Trust CI producer and example policy are a separate successor. No extra write agent shares this candidate.

Final qualification is UNVERIFIED. Fresh controls cover the final v2 metadata change.
No independent review, final local gate, push or external exact-head check ran for this candidate.
