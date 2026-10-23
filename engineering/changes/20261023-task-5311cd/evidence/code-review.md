# Independent code review

Recommendation: PASS. No new findings in security, duplicate writes or tests.

- Route: 5311cdded150.
- Base: 8a02bab3d3e2a4e4cf8e023068a9652cbb89a5be.
- Reviewed commit, before and after: e3c683a59a3de2d64e71da4b2f2e207c4d925104.
- Git tree, before and after: 02c1fac8db7935826ba6d0e041fd8e663a7e5f89.
- Tracked working-tree SHA256 fingerprint, before and after: 801075b98f21040e40f8d6998ffcd63e7d923da1395c7c26a076e5c12d02b338.
- Staged, unstaged and untracked inventory: empty before and after.
- reviewed-tree-modified: no

Reviewed the actual successor diff, typed criteria and surrounding start/stop code. Also revisited current PR127 audit inputs, external verifier boundary and scaffold writes. The guard checks the controller before any start side effect. It preserves pidfd identity checks. Scaffolding retains exclusive creation and refuses unsafe paths. Audit checks retain committed archive/input binding and the ordinary local receipt requirement.

Private scratch: /home/pall/projects/getzilla/.getzilla/runtime/scratch/pr127-code-review-gqkd3080. Its parent and directory are owned by pall, mode0700 and non-sticky. Every tracked source byte and mode was copied and checked before probes. Symlink targets were checked. Candidate files were never written.

Executed:

```text
python3 /home/pall/projects/getzilla/.getzilla/runtime/scratch/pr127-code-review-probes.py
```

The harness ran this regression from the private snapshot with system Python3.12, PYTHONDONTWRITEBYTECODE=1 and TMPDIR inside private scratch:

```text
/usr/bin/python3.12 -m unittest factory.tests.test_linux_process_adapter.LinuxProcessAdapterTests.test_missing_controller_pidfd_api_refuses_start_before_launch -v
```

- Baseline: PASS, one test.
- Remove controller guard: KILLED, both missing-API subtests fail with “True is not false”.
- Omit pidfd_open check: KILLED, missing-open subtest fails.
- Omit pidfd_send_signal check: KILLED, missing-signal subtest fails.
- No surviving mutants in these three probes. This is not a general mutation-score claim.

The same harness ran independent controls:

```text
/usr/bin/python3.12 scripts/getzilla_par.py -j 8 -- "/usr/bin/python3.12 -m unittest factory.tests.test_linux_process_adapter factory.tests.test_offline_release_builder -v" "/usr/bin/python3.12 -m unittest tests.test_compliance_scaffold tests.test_eu_audit_attestation -v"
```

Results: 21 process/inventory tests passed in13.479s; 32 audit/scaffold tests passed in14.112s. Parallel wall14.4s. Logs and results.json remain in private scratch.

Initial snapshot/probe attempts did not qualify: Git archive changed bin/getzilla.cmd bytes, then an outer scratch directory with mode0775 caused fixture setup refusal. The coordinator secured that directory. The final run used an independently verified working-tree snapshot and passed without weakening source checks. Those earlier failures are not mutant kills.

Limits: this review did not run the full PR/PostgreSQL gate, deployed signature service, or native Windows/macOS checks. External verifier tests use offline fixtures. These checks remain separate delivery obligations. Historical release review and Low issues122/134 remain outside this successor's selected review scope.
