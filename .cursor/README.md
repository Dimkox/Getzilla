# Getzilla rules for Cursor

These are prompt-only project rules, not a new factory execution provider or a
Cursor hooks integration. `AGENTS.md`, the active route and existing external
merge authority remain authoritative. Cursor is intentionally absent from the
runtime `HARNESSES` registry.

## Source and scope

Edit `.getzilla/cursor-rules.json`, then regenerate the managed files. Do not edit
the generated `.mdc` files. Exactly one core rule is always applied; the remaining
seven rules have file scopes. Referenced skills are read when relevant, not
inlined into every rule. The core also requires the security rule for sensitive
operations whose filenames do not match a security glob.

| File | Scope |
| --- | --- |
| `00-core.mdc` | Existing contract, scope, preservation and evidence boundaries |
| `10-security.mdc` | Authentication, secrets, untrusted data and tool boundaries |
| `20-python.mdc` | Repository-specific Python development |
| `30-contracts-data.mdc` | API/events, migrations and integrations |
| `40-tests.mdc` | Regression tests and verification evidence |
| `50-agent-runtime.mdc` | Existing routing, context and runtime-budget contracts |
| `60-frontend.mdc` | UI, accessibility and analytics preservation |
| `70-delivery.mdc` | CI, release preparation and operational boundaries |

The generator limits the core to 4 KiB, each scoped rule to 8 KiB and each rule to
500 lines. These are adapter-byte limits, not limits on Cursor's total context:
`AGENTS.md`, user rules, opened files and loaded skills add their own content.
File scopes select guidance; they are not a security boundary.

## Check and regenerate

From the repository root, a check is read-only (exit 0 clean, 1 drift, 2 invalid
source/target). Only an explicit `--write` modifies files:

```bash
python3 scripts/getzilla_cursor.py
python3 scripts/getzilla_cursor.py --write
```

The existing multi-editor command also checks or regenerates Cursor rules:

```bash
python3 scripts/getzilla_harness.py
python3 scripts/getzilla_harness.py --write
```

It rejects Cursor ownership conflicts before rewriting other harnesses. The
operation is not a transaction across all editors/files; repair a reported
partial I/O failure and rerun the read-only check.

## Install into another repository

Install the Getzilla stack first; the target must already contain its own
`AGENTS.md` and all referenced `.agents/skills/` files. Then run from this source:

```bash
python3 scripts/getzilla_cursor.py --target /path/to/project
python3 scripts/getzilla_cursor.py --target /path/to/project --write
```

The shared installer is unchanged. The `.getzilla` source directory is already
stack-managed, so an installed stack can use the module directly without the
optional wrapper script:

```bash
python3 .getzilla/getzilla/cursor_rules.py
python3 .getzilla/getzilla/cursor_rules.py --write
```

Cursor activation is an explicit installation step, not an automatic change to
consumer settings. Live Cursor/editor behavior and installed-consumer packaging
still require their normal acceptance checks.

## Ownership and limitations

Only marked generated files under `.cursor/rules/getzilla/` are replaced or
retired. Existing `.cursorrules`, user rules, settings and `AGENTS.md` are not
rewritten. An unmarked collision blocks the entire Cursor plan before any write;
resolve it explicitly rather than adding a force flag. Marked obsolete `.mdc`
files are reported by the check and removed only with `--write`.

The tool rejects detected symlinks/reparse points and file/directory collisions
below the selected repository root. Each replacement is atomic, but a multi-file
update is not transactional. Use an isolated single-writer workspace: this tool
is not a sandbox against concurrent hostile filesystem mutation.

Rules do not prove that tests ran, isolate a reviewer, enforce a token budget,
change human-gate mode, approve a merge or provide organization-wide Team Rules.
Those responsibilities stay with existing executable policy and the operator.
See `engineering/reviews/2026-10-08-cursor-rules-audit.md` for the comparison and
verification boundaries of this change.
