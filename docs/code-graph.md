# Python code graph and impact (M3 MVP)

`getzilla graph` builds a static graph of the **Python** files of one project and answers
"what may this change affect, and what must still be verified". It never imports, executes or
installs project code.

```text
getzilla graph build  --root DIR [--cache FILE] [--config graph.json]
getzilla graph status --root DIR [--cache FILE]
getzilla graph impact --root DIR [--changed PATH ...]
getzilla graph export --root DIR
```

## Scope and identity

The input is chosen by the ingestion router (`docs/project-ingestion.md`): a Git repository
(tracked and untracked, not ignored files) or a plain folder. `.git`, `.getzilla/index` and
`.getzilla/runtime` are local state and never in scope. A generation is bound to the source
identity (object format, commit, tree, digest of the files in scope), every file's SHA-256, the
config (`package_roots`, `namespace_packages`, limits) and the extractor version; any change makes
`status` report `stale`.

The export (`schemas/code-index-state-v1.schema.json`) carries paths, qualified names, spans,
digests, edges and coverage. It never contains source text, literals or absolute paths.

## What is resolved

- Symbols: functions, async functions, classes and nested qualified names (`A.run.inner`).
- Imports: absolute, relative and aliased imports against the configured package roots.
  `external` (not in scope), `internal`, or `unresolved` with a reason (ambiguous module, a
  directory without `__init__.py` unless `namespace_packages` is on, a name that exists in scope
  outside the package roots, a relative import outside its package).
- Calls: `exact` only for a single, unrebound def/class reached by name, a nested function, or an
  internal `from x import f` / `import x; x.f()`. Rebinding and monkey patching give `candidate`
  with the possible targets; attribute dispatch (`self.m()`, `obj.m()`), reflection (`getattr`,
  `eval`, dynamic imports) and computed callees are `unresolved`. Builtins and external modules
  are `external`.

Syntax or encoding errors make a file `incomplete` with a reason. Other code languages are listed
as `unsupported_language` and the coverage claim becomes `python_files_only`.

## Impact

`impact` follows reverse imports and reverse calls of the old and new generation (so a deleted
target still reaches its dependents). Files with unresolved calls whose name matches an affected
symbol, reflection or dynamic callees, and unresolved internal imports are added with their
dependents. Any incomplete file, unsupported code language in scope, changed file the graph does
not analyse or traversal limit makes the report `complete: false` with
`fallback_scope: configured_project` and `full_test_suite`. `security_checks` and `review` are
always required: an empty affected set never means "nothing to test".

`getzilla.code_graph.architecture_bindings` maps files to `architecture/system.yaml` nodes (most
specific declared path; ties stay unknown) and lists the rules whose paths, node types or trust
domains are touched. Bindings carry the digest of the architecture source and are refused for
another version; the model is only read. `getzilla.code_graph.task_bindings` attaches an impact
report to an existing `workflow/task-graph.json` (validated by `validate_task_graph` and its own
digest) as a separate record; it never edits the task graph or the route and only adds
verification requirements.

## Cache

The cache is `<root>/.getzilla/index/graph.sqlite` (or `--cache`). A generation is written and
read back inside one transaction; the active pointer moves only if it still names the generation
the writer started from. A corrupt cache or another store schema is moved aside and rebuilt.
Zero-Git writes `.getzilla/index/` into `.git/info/exclude`, and this repository ignores it.

## Incremental updates

Only parsing is incremental: a file with the same path and bytes reuses its parse. Imports and
calls are resolved again over the whole scope, so the result equals a full rebuild (tested on
generated add/modify/delete/rename sequences). A config or extractor change, or a declared change
set that does not match the digests, triggers a full rebuild. Counters report `parsed`, `reused`
and `resolved_files` separately.

## Limits

This is a Python MVP. JavaScript, Go, PHP and other languages are reported, not analysed; a
repository with them is never described as fully analysed. Call resolution is deliberately
bounded and not a sound whole-program analysis. Measurements are in
`engineering/audit-remediation/2026-10-16/m3-acceptance.md`; there is no performance SLA.
