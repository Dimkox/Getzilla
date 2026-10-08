# Rollback plan — Show package and advisory in known-vulnerabilities details

## Trigger conditions

The change misbehaves in verification.

## Application rollback

Revert the fix commit.

## Data recovery / forward-fix

No data is involved.

## Verification after rollback

tests/test_known_vulns.py.
