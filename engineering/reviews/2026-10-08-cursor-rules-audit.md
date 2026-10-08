# Cursor rules comparison and bounded implementation

Date: 2026-10-08. Status: implementation candidate; **UNVERIFIED transport**.
Initial main: `851499c21a57631084b445dd8c92f89357b6889a`.
Publication base: `be14794d67ba60082d14fce285cee5908b159a4a`, tree
`6582c5e84f16111a38f52bbe471a20f1b0e6c2b2`.

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

1. **Missing Cursor adapter.** The inspected tree lacked `.cursor`; the existing
   renderer supported other editors. Add `.getzilla/cursor-rules.json`, a
   standard-library renderer/checker/installer, eight generated `.mdc` files and
   `scripts/getzilla_cursor.py`. Extend `scripts/getzilla_harness.py` without
   registering Cursor as a runtime executor or adding `.cursor` to a broad
   destructive managed-root list.
2. **Missing adapter hygiene checks.** Validate source shape, duplicate keys/IDs,
   booleans, safe relative references, scope metadata and context-byte/line limits.
   Check missing/stale/obsolete output. Refuse unowned collisions and detected
   symlinks/reparse points before writing; preserve user-owned rules and settings.
3. **Conflicting delivery sequence.** `AGENTS.md` requires bounded observations,
   independent reports, freeze and one final qualifying gate. The delivery skill
   requested a full gate before reviews and another after them. Reconcile that
   instruction sequence, synchronize Qwen/Claude/Gemini copies, and preserve the
   Grok compatibility skill's extra denial circuit breaker. This changes workflow
   guidance, not verifier code or admissible scope.
4. **Already specified, not duplicated.** Scope/architecture, one isolated writer,
   independent review, owner-controlled approvals, exact-head evidence, CI
   selection, rollback, context discipline and runtime budgets remain existing
   contracts. No new queue, provider, approval regime or parallel policy system.

## Implementation plan and acceptance

Use one writer and standard library only. First reproduce missing adapter/CLI
behavior and delivery ordering with tests, then implement the bounded changes.
Acceptance covers deterministic generation, exactly one bounded always-on core,
read-only checks, safe consumer targeting, ownership preservation, failure cases,
CLI integration, generated bytes and synchronized delivery order. Preserve all
unrelated base-tree files. Publish only an isolated draft PR, never merge/release.

The shared `install_into.py` is intentionally unchanged: Cursor installation is a
separate explicit step. `.getzilla` source files already fall inside its managed
directories; installed-module usage is documented in `.cursor/README.md`. This is
not a claim that the complete installed-consumer package was exercised here.

## Observed verification and remaining gates

Local execution used a partial source snapshot with exact Git-blob-checked copies
of relevant existing files and isolated fixtures. Git clone failed because this
environment could not resolve GitHub; GitHub connector reads remained available.
Effective CPU capacity was measured as four workers (five allowed CPUs, quota
four). No independent subagent/reviewer tool was available.

Focused command in that snapshot:

```bash
/usr/bin/python3.13 -m unittest discover -s tests -v
```

Observed result: **27 tests passed** across `test_cursor_rules.py` and
`test_delivery_sequence.py`. This command discovered those two local modules,
**not the complete Getzilla test suite**. Earlier RED runs demonstrated missing
CLI integration and the old delivery-order failures before the corresponding fixes.
The existing harness integration uses the real, unchanged `harnesses.py` with a
minimal isolated hook/skill fixture; it is not a full-repository harness run.

Full repository tests and `getzilla_verify.py --mode pr`: **NOT_RUN**.
Ruff/Bandit: **NOT_RUN** (tools absent; installation failed with DNS errors).
Independent route-selected reviews and qualifying receipts: **NOT_RUN**.
Live Cursor application, Team Rules, Windows/junction acceptance, complete
consumer installation and deployed runtime qualification: **NOT_RUN**.
External CI and merge authority must be read from the exact published PR head;
this document claims neither a successful check nor approval.

No fabricated routes, review signatures or receipts. No production, provider
eligibility, owner human-gate mode, deployed policy, branch protection, secrets,
workflow dispatch, merge or release changes. Rules remain advisory; executable
budgets and security/merge enforcement require their existing runtime mechanisms.
