# Grok shipped skill impact — bot P1

Source HEAD: `9ea7c523304da5a747d3663bf278641a36bf04f7`; tree: `8f7665ea455a6bedef129383adbb4e2224b3ae74`. Read-only static analysis. reviewed-tree-modified: no. No tests, provider calls or external writes.

Result: the actual shipped Grok skill mirror is stale and outside harness drift enforcement.

- Canonical input is `.agents/skills/**`, read recursively by `_skills()` in `.getzilla/getzilla/harnesses.py:155`.
- `render()` at lines228–231 emits every canonical file to `.qwen/skills/**`, `.claude/skills/**` and `.gemini/skills/**`. These three delivery, verification and release copies equal canonical bytes on this source.
- Codex and Copilot consume shared `.agents/skills/**`; no generated skill directory exists for either in render. Cursor receives separate prompt rules from `.grok/cursor-rules/*.toml`, not a mirrored skill tree.
- Grok ships `.grok/skills/**`. Its `getzilla-delivery/SKILL.md`, `verification-evidence/SKILL.md` and `release-readiness/SKILL.md` differ from canonical. Grok delivery lacks required `--reviewed-commit`, keeps tracked transition to `ready` and denies all merge/publication. Verification lacks current receipt binding/frozen-state/report-name rules. Release denies conditional L5 merge.
- `GENERATED_ROOTS` at line16 omits `.grok/skills`. Existing committed-harness parity test calls drift and therefore misses this defect. Structure tests inspect common phrases in Grok and canonical files but do not ensure equality.
- `scripts/install_into.py:22` recursively owns both `.grok` and `.agents`, plus `.qwen`, `.claude`, `.codex`, `.gemini`, `.github/hooks`, `.github/agents` and `.getzilla`. Its descriptor-bound inventory at lines529–557 ships existing bytes. Thus consumers receive stale Grok files even when generated harness checks pass. No installer generation repairs them.

Minimal repair: generate `.grok/skills/<relative>` for every canonical skill file; add ONLY `.grok/skills` to generated ownership. Never add `.grok`: hooks, agent TOML and Cursor rule TOML there remain canonical inputs. Regenerate copies once through the normal generator. Update generator description/source comments to identify Grok skills as generated.

Existing safety paths apply to the narrow new root: drift compares expected bytes and rejects links; write preflights parent conflicts; descriptor-relative `_parent`, `O_NOFOLLOW` temporary writes and unlink delete stale owned entries without following links. Unexpected Grok skill files become managed retired outputs. Canonical hooks/agents stay outside enumeration. Static inspection supports this reuse; no fresh execution claim is made.

Binding regressions: render includes all canonical relative files for Grok, including reference assets; committed parity catches changed Grok delivery bytes; isolated fixture drift finds a stale file and write restores it; retired Grok skill removal leaves canonical `.grok/hooks.json` and `.grok/agents` intact; linked Grok skill parent blocks writes and external target remains unchanged. Existing tests cover analogous generated-root cases. Installer payload/plan regression should assert delivered `.grok/skills/<name>/SKILL.md` equals `.agents/skills/<name>/SKILL.md`, including required `--reviewed-commit` and frozen `reviewing` contract.

Commands: rg path/symbol searches; sed source/test reads; diff of the three Grok skills against canonical; Python byte comparisons of all four mirrors; git rev-parse HEAD HEAD^{tree}. No candidate write. This report is analysis, not independent review or verification evidence.
