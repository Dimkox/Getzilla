# Workflow Artifact Adapters — Upstream Format Amendment (2026-10-06)

This document amends `2026-09-15-workflow-artifact-adapters-upstream-amendment.md`; both amend the
byte-frozen design `2026-08-30-workflow-artifact-adapters-design.md`. Everything the 2026-09-15
amendment accepts, corrects or lists as known-unparsed still holds unless stated below.

## Re-pinned upstream currency (2026-10-06, git reads at exact tags and default-branch heads)

| Component | Previous pin | New pin | Tag commit | Default-branch head checked |
| --- | --- | --- | --- | --- |
| obra/superpowers | v6.3.0 | **v6.4.2** (2026-09-25) | `8ca22dba9a94` | `8ca22dba9a94` (head is the release) |
| bmad-code-org/BMAD-METHOD | v6.12.0 | **v6.12.1** (2026-10-04) | `790dae9c8e2a` | `8f2c13dd0e00` (unreleased, see below) |
| github/spec-kit | v1.0.7 | **v1.1.0** (2026-10-02) | `f1d3a4f8337e` | `2dda047809dd` (no template change after v1.1.0) |

The `workflow_sources` contract pins released semver tags only (`tests/test_workflow_sources.py`),
so a component whose default branch is ahead of its latest release is pinned to that release and
the head is recorded here as an observation.

### github/spec-kit v1.1.0

- Artifact templates (`spec`, `plan`, `tasks`, `checklist`, `constitution`) are byte-identical to
  v1.0.7; task rows, `## Phase N:` headings, roles and the `.specify/` and `specs/` paths are
  unchanged. Characterized by `CurrentUpstreamFormatTests.test_spec_kit_v110_tasks_template_rows_parse_unchanged`
  with byte-verbatim `templates/tasks-template.md:48-54`.
- The only template change is `templates/commands/converge.md`: every existing task enters the
  intent inventory regardless of checkbox state, because "completion claims are not evidence".
  This matches the adapter's existing rule that imported checkboxes are advisory hints only.

### bmad-code-org/BMAD-METHOD v6.12.1

- `bmad-create-epics-and-stories` now writes `status: draft` in the epics document front matter
  and sets `status: final` only when planning validation passes. Both describe the plan, not
  delivered work: neither token is terminal, so neither advances imported tasks (unknown tokens
  were already non-terminal by design). Pinned by
  `CurrentUpstreamFormatTests.test_bmad_v6121_epics_front_matter_status_does_not_advance_imported_work`
  with byte-verbatim front matter from `epics-template.md:1-5` and `done` as the control.
- Story template, `## Epic N:` / `### Story N.M:` headings and `sprint-status.yaml` are unchanged.

### obra/superpowers v6.4.2

- `docs/superpowers/specs/` and `docs/superpowers/plans/` are unchanged.
- Since v6.4.1 two plans with the same basename get separate workspaces under
  `.superpowers/sdd/`, each recording its owning plan in a `plan-path` file; the workspace
  directory no longer has to equal the plan basename. The adapter only requires the
  `.superpowers/sdd/` prefix, which still holds. Pinned by
  `CurrentUpstreamFormatTests.test_superpowers_v64_collision_workspace_evidence_stays_under_sdd_prefix`.
- `executing-plans` (Native mode) uses the same workspace and ledger. `diagnosing-superpowers`
  writes to `~/.superpowers/diagnosing-superpowers/` in the user's home, outside any repository,
  and is not a tracked source.

## Known upcoming: unreleased BMAD default branch

The BMAD default branch after v6.12.1 is the unreleased v7 rewrite (Python package, `skills/` tree,
`Unreleased` changelog section with breaking changes, a `bmad migrate method` path from v6). When it ships, the adapter's BMAD subset
will need a new amendment:

- stories and epics become ticket files with YAML front matter (`id`, `type`, `parent`, `covers`,
  `after`, …) and a plain `# Title` heading instead of `## Epic N:` / `### Story N.M:`;
- story status moves out of the story file into a plan file beside it, and the v6 `epics.md` and
  `sprint-status.yaml` are migrated into that ticket tree (`tickets.toml` plus joined plans);
- documents land in `<type>-<slug>/<type>-<slug>.md` under `output_folder`, inside
  `initiative-<slug>/` when an initiative is active. `output_folder` still defaults to
  `_bmad-output`, so the declared path prefixes keep matching.

Checked against the default-branch `skills/bmad-ticket/assets/` story and epic templates: they
already load as advisory sources and yield no imported tasks or status hints, which is the safe
direction.

## Authority note

Unchanged from 2026-09-15: `source_version` stays free-form, currency is asserted only by the
`workflow_sources` contract, and imported documents never gain route, governance, approval,
receipt or merge authority.
