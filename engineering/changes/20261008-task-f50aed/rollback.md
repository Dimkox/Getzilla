# Rollback plan — Close hook policy bypasses (secret reads, merge/push/publish spellings, rm -rf /)

## Trigger conditions

Legitimate workflows blocked by a false positive that cannot be rephrased.

## Application rollback

Revert the `fix(hooks)` commit; the regression test commit then fails and documents the reopened bypass.

## Data recovery / forward-fix

No data. Prefer a forward fix that narrows the specific false positive.

## Verification after rollback

`python -m unittest tests.test_policy tests.test_hooks`.
