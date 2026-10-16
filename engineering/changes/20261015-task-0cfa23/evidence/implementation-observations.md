# Implementation observations

Initial product base/HEAD: `7cf4f65dd2ba9bb1390dc84c6185ba0f104255c8`. Branch: `fix/hook-root-20261015`. Route: `0cfa23ed0476`. No staged or unstaged product changes existed at takeover. The draft change package was the only untracked inventory.

The initial RED run had six methods and 13 failing subcases. Two initial assumptions were broader than the old contract: non-sensitive root conflicts remain soft, and safe newline chains are allowed. The regression now uses a sensitive push for the root conflict and retains the old newline controls. The separate dynamic push argument guard still rejects parentheses in those selectors; grant reason data is tested through its normal CLI input.

An intermediate edit removed a splitter constant still imported by `shell_targets`; negative probes caught the resulting soft import fallback. The third consumer now imports the shared command chunk function. No fallback policy was changed.

The first broad guard run passed 183 of 184 tests. Its one failure proved the existing safe newline contract. After preserving that contract, all 184 tests passed in 53.086 s. Denial metadata had its own RED check for the missing field before implementation. The generator completed with no generated diff.

A package/runtime enumeration was stopped after a denied broad scan. Its first denial was hidden by truncated batched output, so an identical retry reached the circuit breaker. A later quoted-alternation search also hit the known parser defect and was stopped. Subsequent reads used exact files and plain commands.

The initial exact test-file grant `5196d825f5961fda` became stale when the coordinator wrote parent observations. The denied edit stopped. The coordinator then recorded fresh exact grant `53f94ca840977c51`, binding `b5df77869e1d0f48d0041f2621b72ae6b8d2d9db91f5479b64663464e6b31c21`, and explicitly resumed only that named write. This changed authorization state. No circuit counter, policy, ledger or live hook was reset.

The final nine focused tests passed in 3.309 s. Ruff passed for the five changed Python files, and `git diff --check` passed. The tracked package state is reviewing before the candidate commit.

The live parent hook remains old. Final PR verification, independent reviews and external exact-head CI are pending. Implementation-time tests are observations, not completion receipts.
