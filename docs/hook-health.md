# Hook health and verification claims

## Hooks that fail open

Getzilla's hooks never lock the agent out of its own repair because of their own bugs: if the
policy cannot be imported, reads and ordinary edits are allowed. Protected actions are not: while
the policy is not loaded, the PreToolUse hook still refuses, with the standard library only, a push,
merge, tag, release, `gh api`, package or image publication, `terraform apply/destroy`, recursive
`rm`, and any write into the control plane (`.getzilla/`, `.grok/`, the agent folders, `AGENTS.md`).
A missing control is not taken as permission (#78). None of this is silent. Every time it happens, a `HOOK_DEGRADED` event is appended to
`.getzilla/runtime/hook-events.jsonl` (time, hook, agent, error). This includes the case where
the hook's own helper library cannot load; that path writes with the standard library only.

- The stop gate says how many hook calls failed open since the active route started.
- `verify` records the count in the receipt (`hook_health`). In `pr`/`release` mode a change
  whose effective risk is `high` fails with `HOOKS_DEGRADED_ON_HIGH_RISK`: the policy that should
  have guarded it did not run. Fix the hook error, start a new route and verify again.

Sensitive actions were already denied when policy evaluation fails; that stays fail-closed.

## "All tests pass" needs a receipt

At stop, Getzilla reads the agent's last message (from the hook payload or the transcript).
When it claims that tests or checks passed (phrases from the `verification-claim` entry of the
risk vocabulary, English base plus language packs) and there is no passing verification receipt
for the current tree, the stop gate:

- in `soft` mode (default) adds `unsupported verification claim: ...` to its note;
- in `strict` mode blocks the stop with that reason on Claude Code and Codex, so the agent runs
  verify and reports its real result. Agents without a blocking Stop hook get the warning and a
  `HOOK_DEGRADED` event (`STRICT_BLOCK_UNSUPPORTED:<agent>`). A stop that was already continued
  once by the hook (`stop_hook_active`) is never blocked again.

Strict mode is on when the effective risk (route risk raised by the last recorded diff risk) is
`high`; `GETZILLA_STOP_GATE_MODE=soft|strict` overrides it.
