# Release plan — Pin and checksum third-party tool downloads in the updater

## Deployment

Ships with the next Getzilla source release; takes effect on the next `scripts/getzilla_update.py` run.

## Feature flags / staged rollout

None.

## Metrics and alerts

`--status` shows `tool:opengrep` ok with `sha256 verified` or fail with the mismatching digest.

## Go/no-go criteria

Final verifier stages owned by this change pass; independent reviews and the exact-head CI check succeed.
