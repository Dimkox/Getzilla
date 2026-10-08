# Release plan — Close hook policy bypasses (secret reads, merge/push/publish spellings, rm -rf /)

## Deployment

Ships with the next Getzilla source release; consumers receive it via `scripts/install_into.py`.

## Feature flags / staged rollout

None; policy-only change.

## Metrics and alerts

Hook deny reasons (`Reading secret material is blocked`, `Production action ...`, `rm -r of /...`) in the tool-denial ledger.

## Go/no-go criteria

Final verifier stages owned by this change pass; independent reviews and the exact-head CI check succeed.
