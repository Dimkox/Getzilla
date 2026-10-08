# Release plan — Queue provenance analysis converges on list-append loops

## Deployment

Ships with the next Getzilla release (2.2.0 CHANGELOG bullet). Consumers get it via the updater.

## Feature flags / staged rollout

None.

## Metrics and alerts

None.

## Go/no-go criteria

`getzilla_verify.py --mode pr` passes architecture fitness.
