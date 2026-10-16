# M3 acceptance: Python code/impact graph (G01–G10)

Branch `feat/audit-remediation-20261016`, measured on claw (Linux, Python 3.12, SQLite 3.45.1) on 2026-10-16.
No performance SLA is claimed; these are measurements.

## Correctness evidence (tests)

| Card | Test file | What it proves |
|---|---|---|
| G01 | `tests/test_code_graph_models.py` | identity covers source/working set, every file digest, config and extractor; unsupported/omitted files are in coverage; distinct symbol ids; foreign edges refused; no source text in the export |
| G02 | `tests/test_code_graph_python_symbols.py` | nested/async qualified names and spans; nothing executed; syntax/encoding errors are `incomplete`; deterministic inventory of `tests/fixtures/code_graph/python` |
| G03 | `tests/test_code_graph_python_imports.py` | absolute/relative/aliased imports; namespace profile; ambiguous modules, missing internal modules and names outside the package roots stay unresolved; external modules are not invented as files |
| G04 | `tests/test_code_graph_python_calls.py` | exact only with static proof; rebinding and monkey patching give candidates; attribute dispatch, reflection and computed callees are unresolved |
| G05 | `tests/test_code_graph_store.py` | readers see old or new complete generation; interrupted write is not active; corrupt cache and schema mismatch rebuild; concurrent writer refused; cache not in the source scope |
| G06 | `tests/test_code_graph_incremental.py` | 40 generated add/modify/delete/rename steps equal a full rebuild; no stale edges; config change and inconsistent change set force a full rebuild |
| G07 | `tests/test_code_graph_impact.py` | reverse deps over old and new edges; cycles; unresolved calls, limits and unsupported languages widen to `configured_project`; security checks always required |
| G08 | `tests/test_code_graph_architecture_bindings.py` | declared paths bind to `architecture/system.yaml` nodes; ties stay unknown; rules reported; model not mutated; another architecture version is refused |
| G09 | `tests/test_code_graph_task_bindings.py` | attachment validates the existing `workflow-task-graph-v1` record and its digest; foreign baseline and workflow identity mismatch refused; incomplete graph keeps full verification; nothing mutated; evidence refs resolve |
| G10 | `tests/test_code_graph_e2e.py`, `tests/test_code_graph_performance.py` | CLI on an ingested Git project; incremental equals full; single-leaf edit parses one file; dynamic call widens impact; status goes stale; export redacted; source and Git state unchanged |

All exports are checked against `schemas/code-index-state-v1.schema.json` with `getzilla.spec.validate_schema`
(`tests/test_new_schema_conformance.py`).

## Generated corpus (1001 files, 10-file import cycles, getattr gaps every 97 files)

| Measure | Value |
|---|---|
| Full build (parse + resolve + publish) | 3.32 s |
| Incremental after a single-leaf edit | 2.45 s; parsed 1, reused 1000, re-resolved 1001 |
| Impact of one changed module | 0.69 s; 1000 files affected (cycles plus reflection gaps reach everything, as intended) |
| Python heap peak (tracemalloc) | 17.8 MB |

## This repository (`getzilla graph` CLI, cache outside the tree)

| Measure | Value |
|---|---|
| Files in scope / Python parsed | 5353 / 505 complete, 1 incomplete (a deliberately broken fixture that was on disk at measurement time; it now lives in memory so linters never see it) |
| Other code languages (reported, not analysed) | 56 |
| Full build | 12.5 s wall, 590 MB max RSS |
| Rebuild after a one-file edit | 10.8 s wall, parsed 1, reused 505 |
| Impact of `.getzilla/getzilla/release_state.py` | 7.2 s; `complete: false`, `fallback_scope: configured_project` |

The repository impact is deliberately wide: 56 non-Python code files are in scope and the
`getzilla.*` modules live under `.getzilla/`, which is not a package root in the default config, so
their imports are `unresolved` (`MODULE_NAME_IN_SCOPE_OUTSIDE_PACKAGE_ROOTS`) instead of guessed.
With `{"package_roots": [".getzilla", "."]}` 578 `getzilla.*` imports resolve as internal; 944
imports stay unresolved (mostly code under other roots such as `factory/src`, relative imports in
directories without `__init__.py`, and namespace packages, which the default profile does not enable).

Incremental updates re-resolve every file; only parsing is reused. That keeps the result equal to a
full rebuild at the cost of resolution time, and the counters show it.

## Not claimed

No JavaScript/Go/PHP analysis (X01–X05 need a separate scope decision); no sound whole-program call
graph; no SLA.
