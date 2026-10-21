# Release plan — Trust CI signed command evidence for EU AI Act audit

## Deployment

Source-only delivery through an isolated PR after Core/schema merge. No production deployment is authorized. The production gate remains pending.

## Feature flags / staged rollout

Install Core/schema consumers first. Add the audit command fragment only to an explicitly EU-enabled repository profile. `attest_argv: true` changes that profile's policy epoch. Keep default example profiles unchanged.

## Metrics and alerts

Observe signed argv, command status, exit code and existing output digest. A missing/disabled EU opt-in must fail the audit. Old envelopes stay valid but cannot qualify EU evidence.

## Go/no-go criteria

Require real signed Core integration, focused tests, committed controls, all selected independent reviews, final local verification and external exact-head checks. Source examples do not activate deployed policy or establish release readiness.
