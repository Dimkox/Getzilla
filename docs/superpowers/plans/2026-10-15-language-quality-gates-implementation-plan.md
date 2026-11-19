# GZ-LQG-001 implementation plan

Design: [contract](../specs/2026-10-15-language-quality-gates-design.md).
Change: engineering/changes/20261015-task-19101f.
Base: 7cf4f65dd2ba9bb1390dc84c6185ba0f104255c8.

1. Freeze the shared ABI and durable scope.
2. Build four adapter contours in isolated worktrees. One owner integrates them.
3. Build the shared policy, package discovery, conservative scope, sandbox,
   bounded shadow cache, evidence and verification/doctor integration.
4. Add regression tests before behavior. Cover malformed policy, custom config
   and project policy changes, FIFO/symlink inputs, operator image admission,
   cleanup failures, running cancellation and cached-observation provenance.
5. Verify public/private CI selection, consumer runtime/documentation payload,
   policy-off rollback and all seven adapters with synthetic fixtures.
6. Record reproducible cold/warm, changed/full, typed/untyped and monorepo timings.
   Keep SDK/container performance and external CI latency claims separate.
7. Commit candidate. Run bounded committed-HEAD controls. Obtain allowed code/test
   reviews. Persist reports, freeze, then run the qualifying PR gate.
8. Deliver through a PR with required exact-head external checks.

CPU budget is max(1, total host logical CPUs - 2), then actual affinity/cpuset
and minimum ancestor quota. The resumed host observation is 28 logical CPUs and
a verified child capacity of 26. This repair owner has 6 CPUs; the separate hook
owner has 6. Combined allocation is 12, below 26. Route and agent-slot caps remain
separate. LQG executes tools serially inside each verification.

- [x] Inspect latest base and owner source plans.
- [x] Specify and integrate seven pure CLI adapters.
- [x] Implement shared policy, scope, isolated execution, CPU budget and evidence.
- [x] Repair both findings from the historical 2abea745 FAIL reviews.
- [x] Add bounded clone-local shadow cache with explicit CACHED_UNVERIFIED results.
- [x] Add doctor preflight, public/private CI regression and installed documentation.
- [x] Exercise JS/TS, Kotlin, Dart, Flutter, Swift, mixed and Python-only fixtures.
- [x] Run reproducible synthetic benchmark; save raw samples and measured source digest.
- [ ] Run independent reviews of the repaired committed candidate.
- [ ] Freeze reports and pass the final local and exact-head external gates.
- [ ] Qualify real SDK/macOS runners and representative external CI latency.

Remaining environment limits: no qualified ESLint/JDK/Kotlin/Dart/Flutter/Swift
image matrix or macOS runner was available. Real SDK smoke remains NOT_RUN.
External CI latency baseline is unavailable. Synthetic measurements do not prove
the 5%/10% rollout targets. Gradle execution cannot yield PASS without a structured
report; approved CLI paths remain available. No cache reuse is allowed for blocking
admission. Auto-fix, AI remediation and default blocking are separate future scope.

Current result: UNVERIFIED pending fresh reviews and final gates. Historical FAIL
reports stay FAIL. The old local route and current coordinator route differ;
the package records that gap without invented review receipts.
