# Rollback plan — Skip real-process adapter tests on unsupported hosts

## Trigger conditions

The change misbehaves in verification.

## Application rollback

Revert the fix commit.

## Data recovery / forward-fix

No data is involved.

## Verification after rollback

factory/tests/test_linux_process_adapter.py.
