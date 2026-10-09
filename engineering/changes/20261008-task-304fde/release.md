# Release plan — Verify the OpenGrep binary digest at run time and quarantine unverified binaries (#39)

## Deployment

Ships with the next Getzilla release; no migration.

## Feature flags / staged rollout

None.

## Metrics and alerts

The opengrep verify stage summary names the digest mismatch.

## Go/no-go criteria

Final verifier stages owned by this change pass; independent reviews and the exact-head CI check succeed.
