# Scratch pip fixture used the CI runner interpreter

Date: 2026-10-29. Scope: [PR #231](https://github.com/Dimkox/Getzilla/pull/231), issue #232.

The Linux CI run at `a3c18ca9c2b5e5d684f3fb1da368e29e76588b77` failed one of 2,599 Core tests. The scratch pip fixture used `sys.executable` as its install interpreter. Local Python lived under `/usr`, but Actions Python lived under `/opt/hostedtoolcache`. The policy correctly refused that unsupported install path.

The fixture now uses `/usr/bin/python3` metadata and does not execute it. A regression changes the runner path to the Actions layout and checks that the supported fixture still passes. Keep the test runner path separate from the policy input path. Do not widen a security rule to repair an invalid test fixture.

The regression failed before repair and passed afterward. Fresh exact-commit CI remains required before merge.
