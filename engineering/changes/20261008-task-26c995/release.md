# Release plan — Refuse missing bandit and OpenGrep binaries in pr/release gates

## Deployment

Source-only change; ships with the next Getzilla release.

## Feature flags / staged rollout

None.

## Metrics and alerts

None.

## Go/no-go criteria

The tests named in the test plan pass in `getzilla_verify.py --mode pr`.
