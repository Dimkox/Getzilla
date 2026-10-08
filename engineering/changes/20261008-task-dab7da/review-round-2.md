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

## Delivery and overlap with #53 (grant binding) — merge order

PR #59 was merged at its round-1 head (`655c16a`) before these round-2 commits were
pushed, so they ship as a separate follow-up PR from the same branch; its base is current
`main`, whose tree equals `655c16a`.

#53 has since merged `main` (round-1 #59) into its branch. Either order now works:

- **Recommended: #53 first, then this PR.** Merging `main` into this branch then has a
  single conflict in `_http_write_resource_text`: keep #53's exact
  `github-pr-review:unparsed` return and add this PR's PowerShell web-cmdlet block below it.
  A scratch integration of both heads passes the policy, hook and approval suites
  (149 tests).
- With #53's resource-bound production model, `package-publish` resolves to no resource,
  so no grant can authorize it (fail-closed); modelling the publish target (registry/index
  plus artifact) is a follow-up if granted publishing is wanted.
