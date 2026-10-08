# Round-2 review response (#36, #37)

Addendum to this change package for the independent round-2 review of the hook-policy
follow-up. Each finding is reproduced as a probe in `tests/test_policy_hardening.py`
(`Review2PosixTests`, `Review2WindowsTests`) and fixed in
`.getzilla/getzilla/_policy_legacy.py` (plus `.getzilla/config/policy.json` for the
credential patterns). Public-repo rule: the probes live in the tests, not in prose here.

## HIGH
- **S59-1 — per-token secret matching unbounded.** `_secret_reference` now ticks the
  shared `_Budget` per token; `shell_secret_reference` caps the scanned command at
  128 KiB and fails closed, and memoizes its verdict per process so the scan runs once
  (`sensitive_action` + `evaluate_pre_tool` reuse it). Perf regression test uses a
  20 000-token argv and asserts a sub-8 s, fail-closed deny.
- **S59-2 — recursive root removal behind wrappers.** `_recursive_remove_of_root`
  scans the whole argv for a delete verb (skipping an inert argv0) rather than a fixed
  wrapper list, so ionice/watch/unbuffer/chrt/flock/busybox/toybox reach main's coverage.

## MED
- **S59-3** grep globs with no path are reads (`glob='.env'`, `'**/server.key'`); a bare
  path walk skips hidden entries to avoid the `path='.'` false positive.
- **S59-4** credential stores added to `DEFAULT_SECRET_READ` *and* `policy.json`
  (`~/.claude`, `~/.codex`, gcloud, `~/.vault-token`, composer, azure, terraform, cargo,
  gem); `gh api -F body=@<cred>` is caught by the same pattern split.
- **S59-5** fish/tcsh/csh/mksh/ash/script execute their payload; `$IFS` word-splitting
  is ambiguous and handled by the policy itself.
- **S59-6** Windows parity: carets, Start-Process/saps, PowerShell web cmdlets,
  robocopy /MIR, Format-Volume/Clear-Disk, recursive Copy-Item/Compress-Archive/
  findstr /s, encoded PowerShell.

## LOW
- **S59-7** package-publish clients published in the deny-by-default set
  (twine/cargo/gem/poetry/bun/helm/crane/oras/skopeo/nerdctl/flit/maturin).
- **S59-8** `ssh` `known_hosts`/`authorized_keys` and `.ssh/config` are not secrets.

## Overlap with #53 (grant binding) — merge order

Both PRs edit `_policy_legacy.py`. The regions are disjoint except the production path:
#53 rewrote production authority to **resource-bound** (`production_targets` +
`has_valid_approval(resource=...)`), while this PR adds `package-publish` as a new
production action. **Merge order: #53 first, then this PR rebased on top.** On the rebase
the `package-publish` action must bind to the publish target in #53's resource model
(the registry/index or artifact ref) rather than the action-level grant used here against
main; the `_production_action` return value is unchanged, only the grant lookup it feeds
moves to the resource-bound form. No other hunks conflict.
