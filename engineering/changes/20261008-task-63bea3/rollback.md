# Rollback plan — Refuse unchecked pinned dependencies in pr/release gates

## Trigger conditions

The change misbehaves in verification.

## Application rollback

Revert the fix commit.

## Data recovery / forward-fix

No data is involved.

## Verification after rollback

tests/test_known_vulns.py.
