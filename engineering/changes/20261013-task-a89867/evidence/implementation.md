# Issue75 source repair — UNVERIFIED internal integration

Initial HEAD: 6dd06ff5b96692a01812fbac6252fd08f6169f91. Agreed parent PR base: 540c12f93e798c2f483455a5086ab0018ac3216e. Writer: integration_implementer. CPU allocation: 12-15, at most two concurrent test processes. Startup snapshot lives in canonical runtime/issues/install-worker/cpu.json; mounted root quota was unavailable, so the allocation is conservative. All four leaf analysis reports and the controller installer analysis were read.

## Clause matrix

- Requirements JSON, evidence, agent scratch/runtime, generated egg-info/cache, user AGENTS/CI and unknown files: bounded descriptive inventory; preserve all consumer bytes. Requirement and evidence contents are not read for classification.
- Dirty consumer Git trees: bounded five-second Git status observation; optional index writes and fsmonitor disabled. Non-Git, unreadable and excessive status output are disclosed as unknown. No clean-tree condition.
- Fresh installation ownership: versioned manifest records normalized paths, exact hashes and modes, and deterministic source-payload identity. Manifest excludes itself. Publication uses the existing verified atomic stage and its failure cleanup.
- Consumer divergence and conflicts: existing payload paths receive preserve-conflict decisions; changed manifest-backed paths are user-change. Invalid manifests and unsafe/unreadable inventory fail closed for quarantine eligibility.
- Legacy migration: path-only RETIRE authority removed. PRESERVE rows remain named replacement candidates. Exact unchanged manifest-backed legacy paths may receive plan-only quarantine rows with hashes, modes and named destinations. Restore guidance forbids clobber. Unknown legacy ownership yields no quarantine entry.
- Update/uninstall/quarantine execution: no such existing APIs. None added. No cleanup executed. A future executor needs exact scoped approval, revalidation, durable recovery manifest and restore tests before mutation.
- Factory metadata: source inventory excludes egg-info and Python/tool cache directories. Installer performs no pip/build invocation and never invokes the supplied dependency runner. It does not install project dependencies or create packaging metadata in consumer source. Existing independent package build paths remain outside this change.
- Partial failure and recovery: existing atomic-stage recovery, publication race, descriptor/link and source-mutation tests retained. New test checks concurrent mutation blocks quarantine eligibility.

## Bounded evidence

RED: python3 -m unittest tests.test_installer.OwnershipPlanTests: two errors for absent ownership manifest and consumer inventory before behavior repair.

Commands use TMPDIR=/home/pall/projects/getzilla/.getzilla/runtime/issues/install-worker and taskset -c 12-15.

- python3 -m unittest tests.test_installer: 48 tests passed in 53.136 seconds (before the last added recovery test).
- python3 -m unittest tests.test_installer.OwnershipPlanTests: final six tests passed in 3.779 seconds, including new quarantine/race coverage.
- python3 -m unittest tests.test_installer.OwnershipPlanTests tests.test_installer.InstallerTests.test_existing_target_modes_are_read_only: six tests passed after bounded Git observer and mode-race repair (before last added recovery test).
- python3 -m unittest tests.test_install_scripts: 15 tests passed in 13.723 seconds.
- git diff --check: passed.

During repair, prior installer assumptions needed updates for the new explicit manifest entry. A temporary-file Git observer also violated the strict no-write planning test; the final observer uses bounded pipes and creates no files. These intermediate failures are not final passes.

No full PR gate, coverage run, independent review receipt, push, pull request, merge, release or production mutation occurred. Parent integration must run all selected reviews and final exact-head gates after all repairs.

## Recovery and limits

Revert the source commit through the parent PR to undo this behavior. Existing consumers are untouched. Fresh installations retain their exact stage-based publication and rollback behavior. The manifest is a consumer-local observation, not authenticated deletion authority. No deployed service, external system, real consumer, credential, or production dump was accessed.
