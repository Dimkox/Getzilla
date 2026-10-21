# Rollback plan — Trust CI signed command evidence for EU AI Act audit

## Trigger conditions

Unexpected default policy epoch changes, invalid replay, unsupported consumer schema or false audit qualification.

## Application rollback

1. Stop new argv emission in the affected profile under separately approved deployment authority.
2. Keep upgraded consumers until all new envelopes no longer require them.
3. Revert producer source if needed. Never rewrite signed envelopes.

## Data recovery / forward-fix

No migration or backfill. Preserve every stored envelope. A profile change creates a fresh policy identity and requires fresh exact-head checks.

## Verification after rollback

Run default identity and legacy replay tests. Confirm no new command argv is emitted and no old envelope gained metadata.
