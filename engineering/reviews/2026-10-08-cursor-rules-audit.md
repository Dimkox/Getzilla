# Cursor rules comparison and bounded implementation

Date: 2026-10-08. Research for PR #55 (first candidate `c0d3d407`, base `be14794d`).
The candidate's separate generator was replaced by a target of the existing harness
renderer; this document describes that design.

## Scope of the comparison

This is a comparison of the previously selected rule sets and representative
modules against Getzilla's engineering contract, delivery skill, harness renderer,
installer ownership and CI configuration. It is not a line-by-line audit of every
upstream file or a security assessment of all Getzilla runtime components.
An existing instruction is classified as guidance, not proof of runtime enforcement.

| Source inspected | Relevant contribution | Getzilla comparison and disposition |
| --- | --- | --- |
| [e-gov/cursor-prompts](https://github.com/e-gov/cursor-prompts) | Common security/integration standards, stack-specific rules and agent instructions | Getzilla already has a contract and domain skills. Add a scoped adapter referencing them; do not import Java/Spring/Nuxt assumptions. Reject `alwaysApply: true` combined with globs. |
| [PatrickJS/awesome-cursorrules](https://github.com/PatrickJS/awesome-cursorrules) | Modular technology/security/review guidance | Add eight original project-specific modules. Do not install a collection of mutually irrelevant stacks or universal line-count rules for functions. |
| [PostHog/posthog-foss](https://github.com/PostHog/posthog-foss/blob/master/AGENTS.md) | Actual commands, generated-file conventions and subsystem context | Reuse Getzilla commands, routes, skills and generated-source ownership. Do not import PostHog's Kea types, architecture or tools. |
| [matank001/cursor-security-rules](https://github.com/matank001/cursor-security-rules) | Language security and dangerous data-flow checklists | Add explicit authorization/tenant negative-test, SQL/argv, SSRF, path-containment and MCP guidance. This adds instructions, not new sanitizers, taint enforcement or a security certification. |
| [Cod3Bende4/universal-ai-rules](https://github.com/Cod3Bende4/universal-ai-rules) | Lifecycle routing, shared sources and editor adapters | Reuse Getzilla's existing lifecycle; keep references lazy and validate adapter budgets. Reject model self-review as a technical gate and unconditional bulk-loading. |
| [steipete/agent-rules](https://github.com/steipete/agent-rules) | Historical agent workflow examples; archived repository | No direct import. Getzilla already has its own workflow and authority model. |
| [jimmypocock/cursor-rules](https://github.com/jimmypocock/cursor-rules/blob/main/.cursor/rules/base.mdc) | Additional candidate with duplicated/incorrect frontmatter | No direct import. Strict descriptor validation prevents duplicate IDs/JSON keys, non-boolean flags and always-plus-globs ambiguity. |

Format reference: [Cursor Rules documentation](https://cursor.com/docs/rules).
Upstream URLs are provenance references inspected during the research, not vendored
or pinned dependencies. All new instruction text and implementation are original;
no external rule library, installer or package is executed or copied.

## Findings and implementation

1. **Missing Cursor adapter.** The tree lacked `.cursor`. Cursor is one more target of
   the existing harness renderer: sources in `.grok/cursor-rules/*.toml` (the same
   TOML shape as `.grok/agents/`), output in `.cursor/rules/getzilla/*.mdc`, written by
   `scripts/getzilla_harness.py --write` and checked by its drift test, including
   stale extra files. Cursor is not registered as a runtime executor (`HARNESSES`).
   Cursor already reads `AGENTS.md` and `.agents/skills/` natively, so the rules stay
   short and point to those files instead of copying them.
2. **Adapter hygiene.** The renderer rejects unknown keys, non-boolean flags, blank
   description/instructions, a scoped rule without globs, an always-applied rule with
   globs, other than one always-applied core, globs Cursor would split or misread
   (comma, brace list, quote, whitespace/newline, absolute, `..`) and rules over 4 KiB
   (core) / 8 KiB (scoped) / 500 lines; TOML rejects duplicate keys and file names make
   rule IDs unique. Writes walk directories by descriptor through `getzilla.fsx` without
   following links and land files with mode 0644 for every generated harness.
   `.cursor/rules` is shared with the user: only files carrying the generated marker are
   Getzilla's. Unmarked files there (and `.cursorrules`, `.cursor/settings.json`, other
   rule folders) are never touched; an unmarked file, a directory or a linked parent
   where an output goes is a `conflict` that blocks every harness write before any file
   changes. `.cursor/**` is protected control plane.
3. **Conflicting delivery sequence.** The delivery skill requested a full gate before
   reviews and another after them; `verification-evidence` and the evidence template
   still said "reruns final verification". All of them now state one order: bounded
   local checks, independent reviews of one committed candidate, saved reports,
   commit/freeze, one final qualifying gate; the frozen tree must equal the reviewed
   tree apart from the saved reports, and any later change invalidates all receipts.
4. **Already specified, not duplicated.** Scope/architecture, one isolated writer,
   independent review, owner-controlled approvals, exact-head evidence, CI
   selection, rollback, context discipline and runtime budgets remain existing
   contracts. No new queue, provider, approval regime or parallel policy system.

`install_into.py` is unchanged: consumers receive the sources with `.grok/`, but not
`.cursor/rules/getzilla/` (adding it to `MANAGED_DIRS` is a separate owner decision).
Verification for this change lives in its change package; live Cursor
behavior (rule attachment by globs) still needs a check in a real Cursor install.

## Mapping of the first candidate's 27 tests

All in `tests/test_harnesses.py` (`CursorRuleTests`) unless noted.

| First candidate test | Now |
| --- | --- |
| committed rules current; core only always-applied | `test_committed_harnesses_match_the_canonical_sources`, `test_committed_rules_use_the_documented_frontmatter` |
| render deterministic and scoped | `test_committed_rules_use_the_documented_frontmatter` |
| missing → write → clean → idempotent; stale detected and repaired; obsolete reported, removed only on write | `test_write_is_world_readable_idempotent_and_removes_stale_rules`, `test_symlinked_output_is_drift_and_is_replaced_not_followed` |
| invalid metadata; duplicate JSON keys; invalid JSON; core/scoped budgets | `test_invalid_rule_sources_are_rejected` (TOML source) |
| custom rules, legacy `.cursorrules`, local settings preserved | `test_user_cursor_files_are_preserved` |
| unowned collision / directory collision block all writes; Cursor conflict prevents other harness rewrites | `test_unowned_file_or_directory_at_an_output_blocks_every_write` |
| symlink components rejected without touching outside | `test_write_never_follows_a_symlinked_directory` |
| output symlink rejected | changed: the link is drift and is replaced, never followed (`test_symlinked_output_is_drift_and_is_replaced_not_followed`) |
| missing target not created | `test_missing_target_is_not_created` |
| CLI read-only check, explicit repair, source error without traceback; harness CLI covers Cursor | `test_cli_checks_read_only_repairs_on_write_and_reports_source_errors` |
| no Cursor execution harness | `test_cursor_is_not_an_execution_harness` |
| install into an existing consumer preserves its contract; missing consumer reference blocks writes | dropped with `--target`: generation targets this repository only and `install_into.py` is unchanged; committed references are checked by `test_rule_references_name_existing_files` |
| three delivery-sequence tests | `tests/test_delivery_sequence.py`; copy equality by the harness drift test |
