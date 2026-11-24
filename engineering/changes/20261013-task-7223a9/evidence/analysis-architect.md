# core bounded design

Route7223a929fd61; HEAD6dd06ff5b96692a01812fbac6252fd08f6169f91. Read-only design.
- Own architecture_fitness.py, harnesses.py, focused tests, canonical focused-first skill wording and generated mirrors. Parent AI writer owns _lib.py/pre_tool_use.py; coordinate shared test/mirror ownership before integration.
- Issue60: derive relative package identity from exact-side source/package evidence, not longest ownership prefix. Preserve queue reachability and uncertainty. RED relative nonqueue import must pass; real relative queue adapter and escaping/ambiguous imports must remain governed.
- Issue71: compare open ancestor identities to fresh no-follow root walk before each mutation. Detect rename before temp creation and replacement; clean owned temp after failure. Preserve Windows identity behavior. Revalidation is bounded race detection, not atomic OS confinement.
- Launcher PreToolUse must emit the harness-specific DENY for missing guard, nonzero exit or import failure. Do not execute the same hook twice through python3||python after hook execution fails. Interpreter discovery fallback is separate from hook retry. Keep other event output contracts stable; no compatible DENY means block by nonzero exit, never empty allow.
- Tests: nested real project vs planted hook-only directory, explicit root precedence, moved/replaced parent, compatible fail-closed launcher verdict across formats, no double execution, absent interpreter. Classify first and select one final verifier. No leaf full gate.

No candidate edits or tests ran. reviewed-tree-modified: no
