# Rollback plan — Queue provenance analysis converges on list-append loops

## Trigger conditions

Fitness misses queue provenance that it reported before.

## Application rollback

Revert the fix commit. Fitness then fails closed again (unsupported).

## Data recovery / forward-fix

No data. Forward-fix by tightening widening.

## Verification after rollback

tests/test_architecture_fitness.py.
