# Routing repair design

Source: 4bf48f5832bac54d08b9666a2354703ce2a03e9d. Static read-only inspection; no tests ran.

- Select the nearest installed project from cwd, then its ancestors. Require the project identity directory `.getzilla` and the requested canonical hook. Preserve explicit harness PROJECT_DIR precedence. Do not select a planted `.grok/hooks` directory alone. Existing `test_a_hook_planted_in_a_subdirectory_is_never_run` must remain passing.
- Keep project selection separate from command workdir authorization. A nested real worktree must use its own hook and its own denial ledger. External or conflicting command roots must remain denied.
- Route malformed-input and oversize denials through the same denial helper as policy denials. Give malformed inputs a fixed action class and bounded generic reason; retain normalized input and root context for fingerprints. Do not evaluate malformed commands or import policy as a prerequisite to denying them.
- Resolve ledger context defensively. Catch root, fingerprint, lock and ledger failures inside the deny path. Always emit the original denial. Ledger failure means repeat guidance is unavailable; it never means allow. Avoid letting the outer fail-open exception handler handle an established denial.
- Preserve legacy command-only string/list callers. Native cmd, when present, remains the executed-field authority and must be a nonempty string. Conflicts deny. Preserve all workdir aliases.

Acceptance: run exact generated launchers with nested real outer/inner projects whose hooks emit distinct markers; assert inner selection from inner cwd and descendants, explicit project-dir precedence, and rejection of a planted hook-only subdir. Assert malformed/conflicting/native type and oversize denials create ledger entries, second exact denial gives exact circuit guidance, and a semantic rewrite gives objective guidance. Assert outside/conflicting workdirs deny. Inject ledger and root-context failures and assert deny without a traceback. Retain ordinary safe-command and installed-consumer launcher controls across harness verdict formats. Regenerate canonical owned mirrors and check drift.

Recovery: revert canonical generator/hook changes and all generated mirrors together through a PR. Keep runtime ledgers ignored. Do not alter grants, trust policy or provider settings. Return all failures to the same write owner as one repair batch. Commit repaired source, run bounded controls, obtain all fresh selected independent reviews, save reports and freeze, then run fresh local and external exact-head gates. Old reviews do not qualify repaired source.

reviewed-tree-modified: no
