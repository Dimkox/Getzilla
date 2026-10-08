# Rollback plan — Harden pre-tool hook policy against remaining authority, remove, secret-read and external-write bypasses

## Trigger conditions

A legitimate workflow is blocked or the hook regresses performance.

## Application rollback

Revert the `fix` commit; the regression test commit then fails and documents the reopened issue.

## Data recovery / forward-fix

None; policy is stateless.

## Verification after rollback

`python -m pytest tests/test_policy_hardening.py`.
