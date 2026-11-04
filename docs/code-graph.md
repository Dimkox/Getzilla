# Python code graph and impact (M3 MVP)

`getzilla graph` builds a static graph of the **Python** files of one project and answers
"what may this change affect, and what must still be verified". It never imports, executes or
installs project code.

```text
getzilla graph build  --root DIR [--cache FILE] [--config graph.json]
getzilla graph status --root DIR [--cache FILE]
getzilla graph impact --root DIR [--changed PATH ...]
getzilla graph export --root DIR
getzilla graph history --root DIR [--base COMMIT] [--end COMMIT]
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

## Committed-history evidence

`history` reads committed Git objects and metadata independently of the Python parser. It branches before
the graph cache and working-set discovery, so it creates no index, cache, graph generation or
repository files. It never imports repository code, executes hooks/text converters/external
diffs, fetches objects or follows a parent repository for a selected plain folder.

```text
getzilla graph history --root . --base BASE_SHA --end END_SHA
getzilla graph history --root . --history-window 1704067200 1704240000 --history-window 1704240000 1704412800
getzilla graph history --root . --history-exclude vendor --history-exclude generated --history-bulk-components 5
```

The range excludes the resolved base and includes the resolved end (default `HEAD`). The report
records both object IDs, end tree and object format. All reachable commits are traversed before
time filtering, including histories with nonmonotonic dates. Windows use **committer** Unix
timestamps, UTC, start inclusive/end exclusive. Merge diffs are excluded; reachable side-branch
commits still count. Root commits compare with the empty tree. Renames count as deletion plus
addition, without heuristic rename detection. Tabs, newlines and Unicode in file paths use NUL
records; authors, messages, source and absolute source paths do not enter the report.

Mappings reuse the existing `architecture/system.yaml` and `architecture/rules.yaml` loader and
longest declared path binding, including deleted paths. The architecture digest, explicit history
config digest, extractor version and fixed policy strings bind numerical evidence. Missing or
ambiguous mappings stay unknown. Exclusions are explicit relative prefixes; no vendor/generated
path is silently inferred. A component's `touches` counts distinct touching commits;
`file_touches` counts file entries. Insertions/deletions are line counts, separate from touches.
Binary changes count touches and `binary_touches`; `line_churn_complete:false` means unknown
binary line churn, not zero churn.

Line churn uses a declared independent algorithm: LF records retain their terminators, exact
common prefixes/suffixes are anchored, then Python `difflib.SequenceMatcher(autojunk=False)`
counts inserted/deleted records. It does **not** claim Git-Myers-equivalent counts. Binary means
a NUL in the first8000 raw blob bytes. Raw old/new objects are admitted with `cat-file blob`
before counting; missing objects cannot borrow working-tree files. Blob bytes stay private and
never enter exported reports or model packets. Local Git attributes, diff drivers and custom
function-name regexes do not choose this line algorithm. Only NUL-safe raw tree entries are
collected by Git; source working-tree content is not used.

Co-change pairs count distinct commits touching both components. A commit touching more than
the configured component threshold retains touches/churn but contributes no pairs. The report
lists bulk SHAs and the denominator: all considered non-bulk, non-merge commits, including
empty/excluded diffs. No percentage or dependency strength is inferred from those populations.

`coverage.complete` applies only to the declared available range and mappings. Reasons include
`NO_GIT_HISTORY`, `UNBORN_HISTORY`, `SHALLOW_HISTORY`, `PARTIAL_HISTORY`, `EMPTY_RANGE`,
`EMPTY_WINDOW`, `MAPPING_UNAVAILABLE`, `UNSUPPORTED_MAPPING`, `UNMAPPED_PATHS`,
`AMBIGUOUS_MAPPING`, `COMMIT_BUDGET`, `BYTE_BUDGET` and `TIME_BUDGET`. No-Git or incomplete
history never means clean risk. A normal JSON response exits0 even for incomplete coverage;
callers must inspect coverage. Invalid CLI/config arguments refuse (exit2/3). For example:

```json
{"coverage":{"complete":false,"reasons":["NO_GIT_HISTORY"],"risk_assessment":"not_performed"},"facts":[]}
```

Defaults cap metadata/diff reads at1000 commits,8MiB cumulative Git output and30 seconds;
`--history-max-commits`, `--history-max-bytes` and `--history-max-seconds` set finite limits.
`--history-max-file-touches` (50000) and `--history-max-pair-observations` (20000) also bound
parsed entries and total pair/commit evidence, including combinatorial cross-component changes.
`--history-max-line-records` (50000) bounds a changed pair's parsed line records;
`--history-max-line-comparisons` (1000000) bounds the product of unmatched old/new line counts
after anchoring. An over-budget pair reports `LINE_DIFF_BUDGET`; it does not publish that
commit's partial counters. This is a finite prototype, not an arbitrary-history performance SLA.
The byte probe can retain one extra byte to detect overflow. The deadline also covers per-file
analysis; bounded process cleanup may follow it. Only fully analysed commits publish counters.
Reported wall time, Git command/read counts, peak retained Git buffer and observed process-lifetime
RSS are separate observations outside `metrics_digest`. RSS is not attributed solely to mining
and is explicitly unavailable where the platform does not expose it. Prehistory is not recorded.

Facts are advisory. Hotspots mean observed touch frequency; co-change never proves causation,
a dependency, a defect or developer performance. An increase fact requires at least two equal,
nonoverlapping, nonempty UTC windows and complete comparable coverage. Each fact carries its
metric, window bounds and commit SHAs. Numerical evidence and deterministic facts do not replace
the existing architecture/code-graph checks or any security, review or test obligation.

The Python API provides `interpretation_packet(report)` and
`validate_model_selection(report, response)`. A model-facing packet freezes only existing fact
IDs, values and SHAs. The closed response contains the exact `packet_digest` and selected
`claims:[{"id":"existing fact ID","commits":["exact SHAs"]}]`. Translation reconstructs
canonical claims and rejects extra prose, invented facts, stale packets and changed citations.
These are recorded-adapter translation controls. This component performs **zero model calls**;
actual provider interpretation, efficacy, token usage and model cost remain **NOT_RUN** until
separately exercised. It does not complete the model-interpretation acceptance of issue#163.

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
