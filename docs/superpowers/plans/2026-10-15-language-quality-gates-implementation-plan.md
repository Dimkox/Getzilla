# GZ-LQG-001 implementation plan

Design: [contract](../specs/2026-10-15-language-quality-gates-design.md).
Change: engineering/changes/20261015-task-19101f.
Base: 7cf4f65dd2ba9bb1390dc84c6185ba0f104255c8.

1. Commit ABI bootstrap and durable plan.
2. Run core and four language writers in separate worktrees.
3. Core owns shared policy/discovery/scope/sandbox/evidence and verification.py.
   Language owners own only adapters/eslint.py, kotlin.py, dart.py, swift.py
   and their tests/test_lqg_<language>.py. No overlapping mutable candidate.
4. Add tests before behavior. Cover malformed policy, unsafe paths, full fallback,
   missing tools, bounded output, timeout/cancellation and shadow/blocking admission.
5. One integrator takes the four commits. Check consumer installation and focused
   regressions. Record actual SDK smoke availability and rollback evidence.
6. Commit candidate. Run bounded committed-HEAD controls. Obtain route-selected
   independent reviews. Store reports, freeze, then run the final PR gate.
7. Deliver through PR with required exact-head external checks.

Resumed measured capacity: 26 allowed logical CPUs, no finite cgroup quota.
Default CPU budget is max(1, host logical CPU count - 2), capped by allowed
online CPUs and the minimum finite ancestor quota. This host has 28 logical CPUs. Core gets
four test workers; each adapter gets at most two. Route analysis cap is 10,
platform child slots 12. Integration writes are serialized.

- [x] Base and contracts inspected.
- [x] Consolidated design and ABI specified.
- [x] Core and adapters implemented and integrated.
- [x] Focused tests, install and rollback checks complete.
- [ ] Real smoke and performance limitations recorded.
- [ ] Independent review and final/external gates complete.

Current result: UNVERIFIED.

Implemented first rollout: seven CLI adapters, shared execution/evidence, CPU reserve,
and verifier integration. Persistent cache, representative performance qualification,
Gradle structured reports and real SDK matrix remain pending. They are not marked done.
