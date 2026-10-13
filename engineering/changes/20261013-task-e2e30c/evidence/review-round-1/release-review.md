# Independent release review

Recommendation: PASS for local source readiness to enter the final qualifying gate. NOT READY for merge, publication, production activation, or closure of live acceptance criteria.

- Source: route `e2e30c9f2878`; base `540c12f93e798c2f483455a5086ab0018ac3216e`; HEAD `f995a5ab35a26abf967516fffccfbf1b3ba42063`; tree `8ed90be2368af8abc653beba10c38c057bd6d7b3`.
- Before/after HEAD and tree match. Before/after fingerprint: `c8edeebeaab9ec8764de395fb176a896ff281c57711460854ce66b61f4dc8dbe`. Git staged, unstaged and untracked inventories are empty.
- reviewed-tree-modified: no
- Private scratch: `/home/pall/projects/getzilla/.getzilla/runtime/reviews/all-issues-f995a5a/release`, mode 0700. Test source is its `source/` Git archive of the clean reviewed HEAD. CPU discovery is in `cpu-startup.json`; allocated CPUs18–23, at most two workers; no finite ancestor quota found.

Findings and residual risk:

- Security: no new blocking release finding. Mandatory-hook exceptions deny. Doctor separates installed files from unobserved host enforcement. Lock consumers validate profiles, install hash-bound wheels without dependency resolution, and install the local project without build isolation. Actual image builds and platform wheel availability remain unexecuted here.
- Double writes: dispatch changes a durable reservation before the paid call. Duplicate reservations deny. Unknown spend keeps its ceiling and blocks fallback. Independent Unix backend writes deny without shared authority. Schema3 rollback must retain journals and reservations. Use a reviewed forward fix; do not downgrade the database or replay paid requests. Installer migration and incident cleanup remain plans; neither authorizes deletion or quarantine.
- Tests: three independent bounded recovery/replay checks pass. No release blocker was found in the inspected rollback, lock, installer, admission and launcher paths. These checks are observations, not a final receipt.
- Clean-start evidence at `e1b309e4f24048ed88c15057f1a914d3739239dd` is historical launcher-process evidence. The diff to this candidate contains only active change-package files. Installation, safe read/status, repeated launcher processes, denial and injected guard recovery were recorded. Native host startup/interception and a real owner-bounded write remain NOT_OBSERVED. Do not label this full startup acceptance.
- Source VERSION/README identify unpublished2.2.2. Published2.2.1 identities remain separate; tracked release artifact bytes did not change. No fresh2.2.2 artifact provenance exists yet.

Executed in private source scratch:

```text
taskset -c 18 env PYTHONDONTWRITEBYTECODE=1 python3 trust-ci/lock_profiles.py --check
exit0, no output

timeout 90s taskset -c 19 env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=factory/src:. python3 -m unittest factory.tests.test_paid_admission.PaidAdmissionTests.test_versioned_upgrade_rolls_back_on_fault_then_recovers factory.tests.test_paid_admission.PaidAdmissionTests.test_duplicate_does_not_resend_and_survives_restart factory.tests.test_paid_admission.PaidAdmissionTests.test_unknown_outcome_retains_reservation_and_blocks_fallback -v
3 tests, 0.102s, OK
```

Mutation probes: not run by this release reviewer. Critical admission probes belong to the independent code/test reviews; this report does not replace them. Non-critical release prose: mutation skipped (non-critical).

Outstanding gates: persist all independent reports, commit/freeze, run the final local PR gate, then require fresh exact-head external checks and resolved review threads. PR79 old-head results do not qualify this candidate. Full graph advisory qualification, real image installs, native host enforcement, shared-host credential isolation, provider revocation, incident attribution/cleanup and exact-target production acceptance remain unexecuted here. Keep paid execution disabled until separate authorized acceptance. This review permits no external or production action.
