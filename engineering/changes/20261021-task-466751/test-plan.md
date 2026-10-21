# Test plan — Trust CI signed command evidence for EU AI Act audit

## Risk-based scenarios

| Priority | Scenario | Evidence |
| --- | --- | --- |
| P0 | Actual argv beats forged executor metadata on success and failure | Runner tests |
| P0 | Reserved identity overrides fail only in opted-in policies | Policy tests |
| P0 | Signed argv tamper fails; stored envelopes replay exactly | Signing, runner and API tests |
| P0 | V2 requires bounded argv and both metadata keys; version tampering fails | Signing tests |
| P0 | Any selected opt-in emits v2 even before commands execute | Runner tests |
| P1 | Default/false identities stay unchanged; only selected profiles change | Policy tests |
| P1 | Synthetic results omit argv; example fragment stays opt-in | Runner and policy tests |

## Automated checks

- Unit: add regression tests first, observe failures, then implement.
- Integration: run Trust CI policy, runner, signing and API tests with six workers.
- Contract: preserve signed v1 JSON and raw replay. Validate explicit v2 version, argv bounds and metadata. Roll out dual readers first.
- E2E: after rebasing on merged Core, execute real enabled, disabled and absent audit input and verify signed output. Pending dependency.
- Static analysis: diff checks and focused Python lint.

## Manual checks

- Independent security and code/test review follows committed controls. Coordinator owns review dispatch and final gate. No current PASS claim.
