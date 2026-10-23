<!-- Historical source: 01f67873ea17949208f92c83d34d0af38a586779:engineering/mistakes.md; bytes 60:411; sha256 1c1158f16597f11374ebe9d8dcbb203ac4582dfcfda2266af5b2ce410f8e4bac. -->

## 2026-10-02 — Explicit worktree path is required for apply_patch

Root cause: apply_patch resolves repository-relative paths from the controller checkout and
does not inherit an exec_command workdir. Two newly-created PR3d tests briefly landed in the
root checkout; they were immediately removed and recreated under the explicit worktree prefix.



Source: [engineering/mistakes.md:4-9](https://github.com/Dimkox/getzilla/blob/01f67873ea17949208f92c83d34d0af38a586779/engineering/mistakes.md#L4-L9).

Recorded PR references:

- Recorded PR number 3; repository association is not asserted.
