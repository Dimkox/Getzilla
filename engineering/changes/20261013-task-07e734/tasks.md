# Tasks — Fix Getzilla issue #42: commit complete Trust CI transitive and build dependency locks with hashes; bind existing Dockerfiles and public CI installation consumers to locked profiles; ensure vulnerability inventory includes them. Use existing uv tooling, pinned versions and supported Python targets. No actual image builds, dependency installation, deployed policy edits or key reads. Isolated source leaf, bounded lock/consumer tests only; one final parent gate after all issues.

- [x] Freeze runtime/test/runner/build profiles and supported marker contract.
- [x] Add missing-lock/consumer RED and drift/closure regressions.
- [x] Implement frozen lock exports and all four Docker/public CI consumers.
- [ ] Run selected quality profile.
- [ ] Complete independent reviews.
- [ ] Bind evidence to the final tree fingerprint.

Bounded source controls pass. Selected full quality profiles, independent reviews and final fingerprint receipts are explicitly deferred to the parent integration under the owner override. Leaf source is UNVERIFIED integration transport, not local completion or release authority.
