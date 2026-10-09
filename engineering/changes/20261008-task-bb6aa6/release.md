# Release plan — Cursor rules as a harness target

## Deployment

Source-only change; ships with the next Getzilla release.

## Feature flags / staged rollout

None.

## Metrics and alerts

None.

## Go/no-go criteria

`getzilla_verify.py --mode pr` passes; a live Cursor check confirms scoped rules attach.
