# Tasks — Trust CI signed command evidence for EU AI Act audit

- [x] Freeze contracts and expected behavior after six selected analyses.
- [x] Add failing tests and API/legacy characterization.
- [x] Prepare the smallest producer change with focused tests.
- [x] Prepare real signed integration on immutable Core candidate; keep it UNVERIFIED.
- [ ] Rebase on merged Core/schema and execute real signed audit integration.
- [ ] Run selected quality profile.
- [ ] Complete independent reviews.
- [ ] Bind evidence to the final tree fingerprint.

## Dependencies and limits

One writer owns this branch and worktree. Core has a separate writer and worktree. Local capacity is 26 verified CPUs; reserve is two. The coordinator assigns workers for each wave. Integration preparation uses six workers on CPUs 18-23 while Core reviews use CPUs 0-17. Independent reads may run in parallel. Writes and RED/GREEN steps stay ordered. Final review and qualification wait for actual merged Core integration.
