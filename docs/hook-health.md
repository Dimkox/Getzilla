# Hook health, unfinished work and verification claims

## An unfinished root task continues

For an owned delivery task, the Stop hook checks remaining work independently of the
agent's last answer. A truthful partial report such as "committed, still not deployed"
does not waive an unchecked plan item. The hook reads existing canonical scope gaps,
the selected package's native `tasks.md` checklist and missing/stale required receipts.
It also reports malformed or unsafe selected package inputs as unresolved work.

Claude Code and Codex receive `decision: block` with a continuation reason. That asks
the coordinator to read the retained original task and amendments, then perform the
next available, already authorized step. The hook itself runs no delivery command and
grants no permission. Qwen, Grok and Gemini receive an explicit unfinished-work advisory
under the current adapter capability policy.

Only a matching session owner at a root Stop is eligible. Explicit `SubagentStop`,
`Interrupt`, `SessionEnd` and `StopFailure` events, distinct child identities, foreign or
unbound sessions, and terminal/cancelled tasks cannot be restarted. A root `agent_type`
profile alone does not make a child. A current matching package transition to `blocked`
with a concrete reason permits an honest pause; missing/stale scope, unsafe inputs or
malformed blocker history cannot inherit that waiver. The reason records the owner's
explanation, not independently verified proof of the external obstacle.

Continuation is bounded in two ways. `stop_hook_active` never triggers another block
in the native continued turn. Across calls, at most two requests are issued for the
same remaining-work observation, task and authority epoch. Changed recorded scope or
remaining obligations create a new observation. Exhaustion, or unreadable retry state,
permits a visible unfinished handoff and leaves the task open. Timestamps and another
partial answer do not reset the observation. Retry records live in the existing
`.getzilla/runtime/stop-attempts.json`; they are not completion evidence.

The package inspector exposes `pending_tasks_count` and at most 20 short `pending_tasks`
previews, separately from structural package validity. Native checklist rows support
bulleted and ordered lists, including nested child tasks beneath checked parents.
Checked rows, HTML comments, fenced, quoted, indented-code and inline-code examples do
not create obligations. Code indentation is measured relative to the current list
container, so an ordinary four-space child list remains work. Inline code within a
real task remains part of its description. Reads retain the existing
file, encoding, symlink and size limits and never follow paths named inside a task.

Continuation reasons are escaped data inside the existing passive `system-reminder`
envelope: Codex can submit them as a new prompt without appending user requirements.
Stop never closes a route, marks a task checked, approves an operation or writes a
passing receipt. The control depends on the recorded native plan: imported BMAD status
is not completion authority, and this change does not prove actual delivery to DEV.

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
This setting controls verification claims only; it does not disable the independent
unfinished-delivery check. Cancellation, child and owner boundaries apply to both checks.
