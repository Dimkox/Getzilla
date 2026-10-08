# Release plan — Declare the jsonschema CLI as a factory test dependency

## Deployment

Source-only change; ships with the next Getzilla release.

## Feature flags / staged rollout

None.

## Metrics and alerts

None.

## Go/no-go criteria

The tests named in the test plan pass in `getzilla_verify.py --mode pr`.
