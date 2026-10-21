# Core code review — wave 4

**Recommendation: PASS within the reviewed Core scope.** No new material security, duplicate-write, or test defect was found. The six known Low test gaps remain deferred to issue #122. This report is independent review evidence, not merge authority.

## Source and isolation

- Candidate: `/home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-phase2`.
- Route: `44fe064efbab`; `code_reviewer` is selected. Package: `engineering/changes/20261021-task-44fe06`.
- Comparison base: `f9f02dd53ba9f6e69d51ae5322df0c96e3d41b02`.
- Private scratch: `/home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave4`.
- Scratch parent and child are trusted, non-sticky, mode `0700`. The private clone reproduced all 5,525 tracked entries, including bytes and modes. Both source and clone were clean. All tests, installed fixtures, mutations, and temporary outputs stayed in private scratch.
- Inventory: 55 changed paths, recorded in `code-review-wave4/source-inventory.tsv`; SHA256 `60ef5052cd97836da5dc8d6814276b38d8940dacbc5c94ba2dd1d27be5323527`. I inspected the actual change inventory, diff, contracts, and surrounding implementation. The full scope includes EU policy/audit code, decision data, templates, installer/CLI, V2 schema, tests, and documentation/evidence. Current changes since wave 3 add component-bound wrappers and test/dependency repairs. A fresh byte comparison confirmed the previously inspected EU evaluator, scaffold, audit, adapters, V2 schema, and receipt helper were unchanged since wave 3.
- Startup measured 26 usable logical CPUs with a two-CPU reserve. Tests used CPUs `0-7` and two pytest workers. This leaves room for their bounded subprocesses within the eight-process allocation.

| Identity | Before review | After review |
| --- | --- | --- |
| HEAD | `ccfe4a404c33003ede0cf0ef42c0faf91f9ce67d` | same |
| Git tree | `889358dc9453cf77df73ec23dd0ed7f10f6c1229` | same |
| Tree fingerprint | `24262cfdb7ad5afd747b4ad924f32ecfff9271336b97fdf7fa3744cda03c34c8` | same |
| Git status | empty | empty |

The restored private clone has the same final identities and empty status.

reviewed-tree-modified: no

Source identity command, run before and after review:

```sh
python3 /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/source_identity.py /home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-phase2
```

Final clone identity command:

```sh
python3 /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/source_identity.py /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave4/candidate
```

Both final commands exited `0` and returned the identities above.

## Findings and checked claims

- The installer supplies both EU wrappers only with the selected EU component. Lean installation omits them. Shared CLI dispatch gives the component-install hint and leaves the lean project unchanged.
- Direct installed-wrapper controls reject missing, disabled, or malformed opt-in and a missing matrix. The explicit target root determines opt-in. Refusal leaves all fixture files unchanged.
- Two concurrent installed scaffold calls produce exactly one adapter. One call succeeds and one fails. Retry preserves consumer edits. The registry remains unchanged. A symlink parent is refused without an outside write. No new external-write path was found by inspection.
- Static review confirms fixture subprocess imports bind to the fixture. The timing test retains the covered denial, checks fixture module origins and tracing state, and separates an eight-second CPU limit from its 15-second child timeout. Test/security reviewers own fresh executable probes for those changes.
- V1, product hooks/policy, verifier, receipt grammar, test runners, and coverage configuration are unchanged against the actual base. Core does not import the isolated Trust CI producer.

## Fresh controls

Working directory: private `code-review-wave4/candidate` clone.

```sh
TMPDIR=/home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave4/tmp PYTHONDONTWRITEBYTECODE=1 taskset -c 0-7 python3 -m pytest -q -n 2 -p no:cacheprovider --tb=short /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave4/test_installed_boundaries.py tests/test_compliance_scaffold.py::ScaffoldTests::test_installed_dispatcher_requires_component_and_preserves_registry tests/test_install_extras.py::InstallExtrasTests::test_eu_audit_and_compliance_scripts_ship_only_with_the_eu_component tests/test_eu_ai_act.py::OptInTests::test_the_component_is_installed_only_on_request tests/test_eu_ai_act.py::OptInTests::test_components_add_installs_the_matrix_and_records_the_opt_in
```

Observed: exit `0`; **11 passed, 2 subtests passed in 4.61s**.

```sh
TMPDIR=/home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave4/tmp PYTHONDONTWRITEBYTECODE=1 taskset -c 0-7 python3 -m pytest -q -n 2 -p no:cacheprovider --tb=short tests/test_compliance_scaffold.py::ScaffoldTests::test_dispatcher_returns_language_hints_and_leaves_registry_unchanged
```

Observed: exit `0`; **1 passed in 1.16s**.

Read-only comparisons, run in the source candidate:

```sh
git diff --exit-code f9f02dd53ba9f6e69d51ae5322df0c96e3d41b02 HEAD -- .grok/hooks/ .getzilla/getzilla/policy.py .getzilla/getzilla/_policy_legacy.py .getzilla/getzilla/util.py scripts/getzilla_verify.py engineering/contracts/schemas/trust-ci-attestation-envelope.v1.json trust-ci/
git diff --exit-code f9f02dd53ba9f6e69d51ae5322df0c96e3d41b02 HEAD -- .coveragerc .getzilla/getzilla/python_test_runner.py .getzilla/getzilla/stack_runners.py
git diff --exit-code cf18a79cf1e97a4100e9999be7ce212e3f258974 HEAD -- .getzilla/getzilla/compliance_scaffold.py .getzilla/getzilla/eu_ai_act.py .getzilla/getzilla/cost_guard.py .getzilla/getzilla/diff_risk.py .getzilla/getzilla/project_ingestion.py .getzilla/templates/eu-ai-act/ scripts/getzilla_audit_bundle.py scripts/getzilla_cli.py engineering/contracts/schemas/trust-ci-attestation-envelope.v1.json engineering/contracts/schemas/trust-ci-attestation-envelope.v2.json trust-ci/ .getzilla/getzilla/util.py
```

Each comparison exited `0` with no output. Byte identity does not reuse prior test results as current passing evidence.

## Fresh mutation probes

The private harness changes only its clone and restores bytes in `finally`. Runs were sequential because they share mutable private source. These commands refer to a private review harness and expose no exploit steps.

```sh
GETZILLA_SERIAL=1 python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave4/run_mutant.py O1
GETZILLA_SERIAL=1 python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave4/run_mutant.py O2
GETZILLA_SERIAL=1 python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave4/run_mutant.py O3
GETZILLA_SERIAL=1 python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave4/run_mutant.py O4
```

| Probe | Fault introduced | Observed child test result | Outcome |
| --- | --- | --- | --- |
| O1 | Remove the CLI opt-in check | Exit `1`; 1 failed, 1 passed, 1 subtest passed; 2.13s | killed |
| O2 | Classify optional wrappers as Core payload | Exit `1`; 1 failed; 1.01s | killed |
| O3 | Remove exclusive adapter creation | Exit `1`; 1 failed; both concurrent calls wrongly succeeded; 1.57s | killed |
| O4 | Check wrapper-root opt-in instead of requested-root opt-in | Exit `1`; 2 failed; 1.82s | killed |

Exact child commands, environment overrides, and output are in private `code-review-wave4/out-O1.txt` through `out-O4.txt`. Harness exits were `0` after recording the failing child results. Four mutants were killed; none survived or were inconclusive in this set. This is not a blanket mutation-coverage claim.

## Limits

Fresh fixture-import, security-budget, capture-race, and verifier-boundary probes were assigned to the parallel reviewers and are not my executions. Native Windows, real C2PA signing, TypeScript checking, joined signed V2 producer flow, full local PR verification, and automatic exact-head CI were not executed here. These claims remain unexecuted in this report. Prior review waves are historical.

The optional fresh `jsonschema==4.26.0` install remains BLOCKED/NOT_RUN from the handoff. I made no install attempt or baseline-extraction retry. The coordinator reports host `4.10.3`; I do not claim a pinned-version pass. One optional metadata-only query, `python3 -B -c 'from importlib.metadata import version; print(version("jsonschema"))'`, was denied as `ambiguous-command-root`. I did not retry it. The completed controls do not depend on that query. Automatic exact-head CI must validate the declared pin separately.

No candidate evidence file, verification receipt, or approval was written by this reviewer.
