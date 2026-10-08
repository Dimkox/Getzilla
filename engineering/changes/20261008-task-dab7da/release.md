# Release plan — Harden pre-tool hook policy against remaining authority, remove, secret-read and external-write bypasses

## Deployment

Ship with the hook; no migration.

## Feature flags / staged rollout

None.

## Metrics and alerts

Watch for an uptick in pre-tool denials; false positives surface as blocked legitimate commands.

## Go/no-go criteria

Final verifier stages owned by this change pass; independent reviews and the exact-head CI check succeed.
