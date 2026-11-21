# Release plan — Trust CI signed command evidence for EU AI Act audit

## Deployment

Source-only delivery through an isolated PR after Core/schema merge. No production deployment is authorized. The production gate remains pending.

## Feature flags / staged rollout

Install Core consumers and the separate v2 schema first. Add the audit command fragment only to an explicitly EU-enabled repository profile. `attest_argv: true` changes that profile's policy epoch and emits v2. Keep default example profiles and v1 emission unchanged.

## Metrics and alerts

Observe signed version, argv, command status, exit code and existing output digest. A missing/disabled EU opt-in must fail the audit. Old v1 envelopes stay valid but cannot qualify EU evidence, even if raw argv appears in the payload.

## Go/no-go criteria

Require real signed Core integration, focused tests, committed controls, all selected independent reviews, final local verification and external exact-head checks. Source examples do not activate deployed policy or establish release readiness.
