# Independent test review — PASS with one deferred Low finding

- Route: 5311cdded150. Base: 8a02bab3d3e2a4e4cf8e023068a9652cbb89a5be.
- Reviewed HEAD before/after: 59c1a38f45edf1417ce9e4e82a80d20f0f2e97b1.
- Git tree fingerprint before/after: 6ae0aba8a925b29851f64e6946c26cf13bc93f5f.
- Clean-source fingerprint before/after: fc39c489f002fa2925908973fc57e3be160dd67c6d4c20767776cc7c43252226.
- Staged, unstaged and untracked inventories: empty before/after.
- reviewed-tree-modified: no

Finding:
- Low — tests/test_compliance_scaffold.py:153 omits engine_archive=True. The existing installed-command test does not detect module-relative template lookup returning. Actual archived-install behavior passes a private control. This gap is recorded at https://github.com/Dimkox/Getzilla/issues/122#issuecomment-6359615975 and does not block this repair.

The final delta from 0c1de2b052a8ec4d48c76680ce840034b03842e1 changes only state.json. It adds the pending release_review obligation and normalizes JSON string encoding. No PASS is invented. The earlier metadata/report/EOF delta from e3c683a59a3de2d64e71da4b2f2e207c4d925104 was inspected. Requirements, typed evidence and route include release review. The handoff records failed admission attempts and the push blocker. Factory, scripts, tests and .getzilla product bytes remain unchanged from e3c683a. No new security or duplicate-write concern appeared.

Fresh final-candidate controls:
- git diff --check 8a02bab3d3e2a4e4cf8e023068a9652cbb89a5be HEAD — exit0.
- python3 /home/pall/projects/getzilla/.getzilla/runtime/scratch/pr127-test-review-final-snapshot.py — exact snapshot and source stability checks passed.
- That helper ran /usr/bin/python3.12 -m unittest factory.tests.test_linux_process_adapter.LinuxProcessAdapterTests.test_missing_controller_pidfd_api_refuses_start_before_launch -v — 1 test passed, 0.006s.

Private scratch: /home/pall/projects/getzilla/.getzilla/runtime/test-review-e3c683a. The historical directory name is unchanged; snapshot now holds exact HEAD59c1a38. The parent is owner-only mode0700 beneath a trusted non-sticky runtime directory. The clone matched the current tree and clean inventory. PYTHONDONTWRITEBYTECODE=1 and a private TMPDIR kept fixtures outside the candidate. The final helper removed inherited PYTHONPATH. Before/after records and regression-59c1a38.log are in this directory.

Historical/reused critical probes:
At HEAD0c1de2b052a8ec4d48c76680ce840034b03842e1, tree510b97b6add6feef519cb754f18fb12ed5038f38, fingerprint579cfe9563bb91b7bd405fd484f972db01e96bda983507db2e8f9b1a57860235, this reviewer ran:
- python3 /home/pall/projects/getzilla/.getzilla/runtime/scratch/pr127-test-review-refresh.py
- Its helpers: /usr/bin/python3.12 /home/pall/projects/getzilla/.getzilla/runtime/scratch/pr127-test-review-mutations.py and /usr/bin/python3.12 /home/pall/projects/getzilla/.getzilla/runtime/scratch/pr127-test-review-archive-probe.py.

Each mutation used /usr/bin/python3.12 -m unittest <target> -v. Targets:
- P: factory.tests.test_linux_process_adapter.LinuxProcessAdapterTests.test_missing_controller_pidfd_api_refuses_start_before_launch
- A: tests.test_eu_audit_attestation.CiAuditTests.test_an_uncommitted_engine_archive_stops_the_audit
- S: tests.test_compliance_scaffold.ScaffoldTests.test_installed_dispatcher_requires_component_and_preserves_registry

| Historical/reused claim and probe at 0c1de2b | Target | Observed result |
| --- | --- | --- |
| Unmodified baselines | P, A, S | Passed |
| Omit controller pidfd_open condition | P | Killed: preflight incorrectly True |
| Omit controller pidfd_send_signal condition | P | Killed: preflight incorrectly True |
| Omit start preflight before writes/launch | P | Killed: state appeared and mocked launch errored |
| Omit engine archive from audit inventory | A | Killed: RuntimeError not raised |
| Restore module-relative template lookup | S | Survived: unpacked fixture |
| Private engine_archive=True fixture, actual source | S | Passed, 2.294s |
| Same archive fixture, module-relative mutant | S | Killed: getzilla.zip is not a directory, 2.233s |

All private mutants and fixture edits were restored. The archive probe removed inherited PYTHONPATH. Logs are preserved under previous-0c1de2b/. These are reused observations of identical product bytes, not fresh final-head mutation results. Mutation: skipped for the final non-critical accounting-only delta.

Historical/reused broad controls:
At HEADe3c683a59a3de2d64e71da4b2f2e207c4d925104, tree02c1fac8db7935826ba6d0e041fd8e663a7e5f89, separate pytest -n8 commands passed 21 Factory process/inventory tests and 44 Core EU/scaffold/install tests. A first mixed-suite command hit a tests-package collection collision; separate interpreters resolved it. These broad suites were not rerun for metadata-only changes and cannot authorize verification skips.

Limits: this review did not execute the full PR gate, actual PostgreSQL, Windows/macOS, external CI or release qualification. The probes cover only their named claims. The surviving existing-test mutant remains the disclosed Low gap. This review does not qualify merge or release.
