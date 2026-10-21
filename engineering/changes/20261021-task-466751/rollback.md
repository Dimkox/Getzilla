# Rollback plan — Trust CI signed command evidence for EU AI Act audit

## Trigger conditions

Unexpected default policy epoch changes, invalid replay, unsupported consumer schema or false audit qualification.

## Application rollback

1. Disable argv opt-in in the affected profile under separately approved deployment authority. Future emissions return to v1.
2. Keep dual readers for stored v2 envelopes. Stop new v2 emission before any consumer rollback.
3. Revert producer source if needed. Never rewrite signed envelopes.

## Data recovery / forward-fix

No migration or backfill. Preserve every stored envelope. A profile change creates a fresh policy identity and requires fresh exact-head checks.

## Verification after rollback

Run default identity and legacy replay tests. Confirm future envelopes use v1 without argv and no old envelope gained metadata. Confirm stored v2 envelopes still verify with the retained dual reader.
