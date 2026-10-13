# Routing repair analysis

Source: route 43786cadd549; worktree `/home/pall/projects/getzilla/.getzilla/runtime/worktrees/fix-codex-cmd-20261011`; HEAD 4bf48f5832bac54d08b9666a2354703ce2a03e9d. Read-only source inspection. No tests or dangerous command execution. Only this runtime report was written.

## Confirmed findings

- Critical boundary: `harnesses.py:_command` deliberately orders environment roots, then reversed cwd parents, then cwd. A nested independent project loses to the outer project hook. The docstring calls this outermost selection intentional anti-planting protection. A plain nearest hook-file search would remove that protection; select the nearest complete project boundary instead, then its own hook. Preserve explicit supported project-directory semantics and define conflicting environment roots.
- Import chain: launcher inserts the selected hook directory into sys.path, then runpy executes that script. `_lib.py` derives REPO_CANDIDATE from its own hook path and prepends that project's `.getzilla`. `user_prompt_submit.py` imports getzilla.router/state from that stack. `root_from(payload)` uses nearest `.getzilla` via util.find_root, so root state can be written inside the nested project while routing code came from the outer project. That mixes source and state authority. PreToolUse likewise imports outer policy/root helpers but can resolve nested route/grant state. Agent/tool permission decisions therefore need same-root source imports and route state.
- util.find_root already scans cwd then parents for `.getzilla`; launcher uses the opposite order and only tests hook-file existence. Installed consumers also receive generated launchers and can sit below another Getzilla project. Repair belongs in canonical launcher generator; regenerate generated configurations, not copied ad hoc launchers.
- P2 confirmed: pre_tool_use.main emits `_getzilla_input_error` denial before root_context and returns. It never reaches `_record_denial`. Repeated malformed/conflicting native cmd requests remain denied but never get exact-repeat/objective-stop guidance or a ledger entry. This is a retry-control gap, not permission allow. Oversize denial has the same early-return shape; avoid silently changing its security bounds.

## Minimal regression fixtures

1. Real nested project beneath an outer project, with distinct harmless hook/source markers. Invoke generated UserPromptSubmit and PreToolUse from nested root and a deep subdirectory. Assert nested hook, router/policy imports and nested runtime state; outer state unchanged. Include a linked worktree `.git` file boundary.
2. Nested installed consumer using materialize_new below an outer project. Its generated Codex launcher must enforce its own cmd policy and update only its own route/ledger.
3. Retain anti-planting fixture: src/deep/.grok/hooks alone must not replace the project's hook. Require full recognized project boundary, not hook presence alone.
4. Explicit CLAUDE/QWEN/GEMINI project-directory behavior; contradictory/stale values must not silently pick a different policy stack. Cover generated harness verdict shapes after regeneration.
5. Malformed native cmd twice: deny both; second reason includes exact circuit breaker; safe ledger records contain hashes/metadata only. Same reason with changed malformed payload should hit objective circuit breaker. Missing/unrecognized root still denies without exceptions or unsafe ledger writes.

Existing coverage: tests/test_harness_hook_payloads.py test_installed_codex_launcher_checks_native_cmd covers siblings, not nested consumers; test_a_hook_planted_in_a_subdirectory_is_never_run covers a hook-only planting fixture. tests/test_pre_tool_circuit_breaker.py covers ordinary external-write denials, not input-validation denial. Current malformed tests assert only first deny verdict. No existing nested independent-root regression was found.

Evidence commands: rg/sed of harnesses.py, _lib.py, user_prompt_submit.py, pre_tool_use.py, util.py and the two named test modules; git rev-parse HEAD. Static call-chain claims were inspected, not executed. Historical 4bf verification cannot qualify the upcoming repair.
