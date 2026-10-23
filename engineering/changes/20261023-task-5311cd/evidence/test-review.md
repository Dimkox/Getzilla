# Independent test review — PASS with one Low finding

- Route: 5311cdded150. Base: 8a02bab3d3e2a4e4cf8e023068a9652cbb89a5be.
- Reviewed HEAD before/after: e3c683a59a3de2d64e71da4b2f2e207c4d925104.
- Git tree fingerprint before/after: 02c1fac8db7935826ba6d0e041fd8e663a7e5f89.
- Staged, unstaged and untracked inventories were empty before/after. The clean-source fingerprint derived from this captured HEAD is 29867ca50f320d63cf20fedd92d9ac570ed032ddb1249bcfbdbfc2c660fd5f8c.
- reviewed-tree-modified: no

Finding:
- Low — tests/test_compliance_scaffold.py:153 uses PayloadSelection without engine_archive=True. Its installed-command test does not cover the archived engine that motivated the PR127 template-path repair. Reverting template lookup to module-relative paths survives that existing test. Keep this test gap with deferred Low issue122. No current product failure was found.

Scope: actual successor diff, Linux adapter start/preflight/shutdown surroundings, and current PR127 audit/scaffold/installation tests. No duplicate external-write path was added.

Private scratch: /home/pall/projects/getzilla/.getzilla/runtime/test-review-e3c683a. Its owner-only parent has mode0700 beneath the non-sticky owner-controlled runtime directory. A shared local clone checked out the exact candidate HEAD and matched its tree and clean inventory. All tests, fixtures and mutants stayed there. The source candidate stayed unchanged.

Controls used /usr/bin/python3.12 from the private snapshot with PYTHONDONTWRITEBYTECODE=1 and TMPDIR=/home/pall/projects/getzilla/.getzilla/runtime/test-review-e3c683a/tmp:

- /usr/bin/python3.12 -m pytest -n 8 -q factory/tests/test_linux_process_adapter.py factory/tests/test_offline_release_builder.py — 21 passed, 2 subtests passed, 4.47s.
- /usr/bin/python3.12 -m pytest -n 8 -q tests/test_eu_audit_attestation.py tests/test_compliance_scaffold.py tests/test_install_extras.py — 44 passed, 44 subtests passed, 22.74s.

The first combined Factory/Core pytest invocation had a tests-package collection collision. Splitting the suites into separate interpreter processes resolved it. The failed setup run is not counted as a pass.

Mutation commands:
- python3 /home/pall/projects/getzilla/.getzilla/runtime/scratch/pr127-test-review-mutations.py
- python3 /home/pall/projects/getzilla/.getzilla/runtime/scratch/pr127-test-review-archive-probe.py

The first helper ran /usr/bin/python3.12 -m unittest <target> -v for each baseline and mutant. Each baseline passed. It restored each private source file before the next mutation. Targets:
- P: factory.tests.test_linux_process_adapter.LinuxProcessAdapterTests.test_missing_controller_pidfd_api_refuses_start_before_launch
- A: tests.test_eu_audit_attestation.CiAuditTests.test_an_uncommitted_engine_archive_stops_the_audit
- S: tests.test_compliance_scaffold.ScaffoldTests.test_installed_dispatcher_requires_component_and_preserves_registry

| Claim and mutant | Target | Observed result |
| --- | --- | --- |
| Require controller pidfd_open; omit that condition | P | Killed: preflight incorrectly True |
| Require controller pidfd_send_signal; omit that condition | P | Killed: preflight incorrectly True |
| Refuse before launch/state creation; omit start preflight | P | Killed: state directory appeared; mocked launch also caused an error |
| Bind engine archive to committed audit input; omit archive inventory | A | Killed: expected RuntimeError not raised |
| Use installed template root; restore module-relative lookup | S | Survived: existing fixture uses unpacked engine |

The second helper changed only the private S fixture to engine_archive=True and removed inherited PYTHONPATH. The actual candidate passed that archive-install control (2.456s). The module-relative mutant then failed with getzilla.zip not being a directory (2.308s). This confirms current lean behavior while exposing the persistent test gap. The fixture and source were restored. Raw logs and JSON summaries remain in the private scratch directory.

Limits: no full PR gate, PostgreSQL execution, Windows/macOS execution or release qualification ran in this review. Those remain coordinator/external checks. Mutation probes cover the named claims only. The surviving existing-test mutant is the Low finding above, not a blanket clean mutation claim.
