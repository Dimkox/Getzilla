# Core source handoff — UNVERIFIED

Route `7223a929fd61`; initial HEAD `6dd06ff5b96692a01812fbac6252fd08f6169f91`; agreed parent PR base `540c12f93e798c2f483455a5086ab0018ac3216e`. One selected integration writer owns this isolated leaf. No external state changed.

## Result

- #60: derive package ancestry from the exact head/base Python inventories and initializer markers, with conventional src namespace support. Preserve aliases and multi-level relative imports. Keep real queue adapters governed and package escapes fail closed. Remove the actual harness import workaround.
- #71: rewalk root-to-parent paths without links before directory creation, temporary creation, chmod/content writes, publication, removal and safe cleanup. Compare captured root and ancestor identities. Shared API: `fsx.validate_directory_path(root, relative_parent, opened_handle, *, opened_ancestors=None)`; existing public APIs stay intact.
- #71: classify the final inventory before selecting exactly one final verifier. Keep focused single-landing admission narrow. Mixed or uncertain inventory selects PR; its existing selector remains unchanged.
- Parent #78: generated PreToolUse launchers emit the harness-specific DENY for absent hooks, nonzero hook exit or import faults. Capture partial stdout so a failed hook cannot leave an allow response. Handle failed hooks inside the interpreter, so the shell fallback only discovers an available interpreter. Use the nearest installed project even when its hook is missing; do not fall through to an outer project. Keep explicit project-root precedence.
- Regenerate settings/hooks and canonical skill mirrors. Update only the Hooks failure paragraph in REFERENCE; parent resolves the docs leaf overlap.

## RED and focused observations

Before fixes, the ordinary relative fsx case reported `unsupported`; both post-open parent relocation regressions failed because the writer returned success. The launcher matrix failed all twenty cases (five missing-output errors and fifteen failure/exit cases). Detailed launcher RED log is private runtime evidence.

Commands use `TMPDIR=/home/pall/projects/getzilla/.getzilla/runtime/issues/core-worker taskset -c 8-11`. One test process at a time; no parallel test workers. Capacity snapshot records actual cgroup ancestors, affinity and child probe.

- `python3 -m unittest tests.test_harnesses`: 38 tests, PASS, 2.014 s. Includes initial post-open relocation, root replacement with same parent identity, replacement symlink, relocation after content write, one-verifier selection and the five-transport launcher failure matrix.
- `python3 -m unittest tests.test_fsx`: 10 tests, PASS, two Windows-only tests skipped, 0.005 s. Includes shared validation and WindowsDirectory replacement identity using path handles.
- `python3 -m unittest tests.test_architecture_fitness.ArchitectureFitnessTests.test_relative_whole_module_keeps_real_package_identity tests.test_architecture_fitness.ArchitectureFitnessTests.test_mixed_local_module_exports_are_member_specific tests.test_architecture_fitness.ArchitectureFitnessTests.test_boundary_qualified_relative_and_module_none_imports_are_checked tests.test_architecture_fitness.ArchitectureFitnessTests.test_boundary_src_namespace_packages_keep_runtime_module_identity tests.test_architecture_fitness.ArchitectureFitnessTests.test_boundary_relative_escape_or_missing_package_context_fails_closed`: five selected methods, PASS, 13.335 s. The new method has six subcases: ordinary/real queue with module, alias and multi-level relative import.
- `python3 -m unittest tests.test_harness_hook_payloads.GeneratedHookCommandTests`: six tests, PASS, 3.950 s. Includes valid allow/deny formats, planted hook refusal, nested real worktree identity and protected harness paths. That test file was read only.
- `python3 scripts/getzilla_harness.py --write`: generated mirrors updated.
- `python3 -m ruff check .getzilla/getzilla/fsx.py .getzilla/getzilla/harnesses.py .getzilla/getzilla/architecture_fitness.py tests/test_harnesses.py tests/test_architecture_fitness.py tests/test_fsx.py`: PASS.
- `git diff --check`: PASS.

These are bounded observations, not verification receipts. No full PR, coverage, independent review, external CI or release ran in this leaf. Owner defers those to the combined parent.

## Residual risk and recovery

Fresh identity checks detect bounded races; they do not provide atomic OS confinement between a check and a syscall. This limit is documented in the helper. A moved parent blocks target publication; preserve an already-created detached owned temp as evidence. Do not delete it through an outside-root descriptor. This is a bounded ruling against the analysis suggestion to clean a detached temp: outside-contour cleanup would create an extra mutation. A human or authorized recovery task can remove retained evidence after identity checks.

Native Windows execution is NOT_RUN on this Linux host. Parent exact-head Windows CI must qualify shell quoting and native directory behavior. Parent must regenerate mirrors after its canonical hook edits, run all selected reviews with required critical probes, freeze the combined reports, run one qualifying full local gate and require external exact-head CI. Canonical `_lib.py` and `pre_tool_use.py` belong to the parent AI writer and are untouched here.

Rollback: revert this source commit through a reviewed PR and regenerate mirrors. This restores prior behavior; it does not remove retained runtime evidence or change external systems.
