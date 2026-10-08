# Queue provenance analysis converges on list-append loops

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

Change ID: `20261008-task-d259e6`
Created: 2026-10-08T14:29:24+00:00
Risk: medium
Complexity: standard
Domains: event, api

## Problem

Since ccaab18 added `import queue` (stdlib, for the threaded pipe pump) to
`.getzilla/getzilla/architecture_diff.py`, the queue provenance analyser runs on it. Any
loop that appends to a list (`chunks.append(chunk)` in `_worktree_blob`) never reaches a
fixpoint and raises `queue loop analysis limit exceeded`. Even without the loop issue,
branch joins charge every unchanged local, which costs 39,495 values against the 4,096
budget. Any change to a module importing `architecture_diff` (for example
`verification.py`) is reported FIT-BOUNDED-WORKER-JOBS unsupported, and architecture
fitness fails with no override.

## Outcome

Architecture fitness analyses such modules within the existing limits. It reports real
queue provenance and stops reporting analyser exhaustion.

## Scope

### In scope

- Sound widening of growing sequences in `_Interpreter._loop`.
- Skipping value charges for bindings that are identical on every merged path.
- Regression tests reproducing both failures on main.

### Out of scope

- Changing `statement_limit`, `value_limit` or `loop_limit`.
- Changing which imports count as queue libraries (stdlib `queue` stays in scope).

## Constraints

- Backward compatibility: all existing fitness tests pass unchanged.
- Data/privacy: none.
- Performance: architecture_diff.py analysis drops from limit failure to 774 values.
- Operational: none.
