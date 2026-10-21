# Test plan — Trust CI signed command evidence for EU AI Act audit

## Risk-based scenarios

| Priority | Scenario | Evidence |
| --- | --- | --- |
| P0 | Actual argv beats forged executor metadata on success and failure | Runner tests |
| P0 | Reserved identity overrides fail only in opted-in policies | Policy tests |
| P0 | Signed argv tamper fails; stored envelopes replay exactly | Signing, runner and API tests |
| P0 | V2 requires bounded argv and both metadata keys; version tampering fails | Signing tests |
| P0 | Any selected opt-in emits v2 even before commands execute | Runner tests |
| P0 | Real command, API, stored replay, installed verifier and Core agree | EU audit integration tests |
| P0 | Disabled, absent, skipped, REVIEW and BLOCK cannot gain audit authority | EU audit integration tests |
| P1 | Default/false identities stay unchanged; only selected profiles change | Policy tests |
| P1 | Synthetic results omit argv; example fragment stays opt-in | Runner and policy tests |

## Automated checks

- Unit: add regression tests first, observe failures, then implement.
- Integration: run Trust CI policy, runner, signing and API tests with six workers.
- Contract: preserve signed v1 JSON and raw replay. Validate explicit v2 version, argv bounds and metadata. Roll out dual readers first.
- E2E preparation: run the local-process harness on frozen Core checkpoint `585edde8be99ad2145a389dd86164daf2e2fc1c7`. The consumer and non-editable verifier install use committed source. Exercise real policy argv, production result construction and GitWorkspace checks, signed API envelopes, MemoryStore replay, and the Core consumer. Use only an in-memory test signing key and export its public key. This does not test container isolation or PostgreSQL durability.
- E2E qualification: rebase onto actual merged Core and repeat this integration before final controls and reviews. Frozen-candidate observations do not satisfy that dependency.
- Static analysis: diff checks and focused Python lint.

## Manual checks

- Independent security and code/test review follows committed controls. Coordinator owns review dispatch and final gate. No current PASS claim.
