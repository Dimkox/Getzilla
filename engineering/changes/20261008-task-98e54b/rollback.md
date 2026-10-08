# Rollback plan — Reject wildcard resources in delegated grants

## Trigger conditions

An exact-resource workflow is refused incorrectly.

## Application rollback

Revert the `fix(approve)` commit; the regression test commit then fails and documents the reopened issue.

## Data recovery / forward-fix

No data; approvals are short-lived runtime state.

## Verification after rollback

`python -m unittest tests.test_policy tests.test_protected_write`.
