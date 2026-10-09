# Code review — PASS with Low test limitations

Fresh review covers security, duplicate external writes and tests from base `5d5b45f42f8a9f2bc0303b4d16b5d4e54caad5b9` through HEAD. Inspected new compatibility repair `9ea7..HEAD`. No blocking defect found. Historical saved reports are not fresh PASS evidence.

- Low #73 remains deferred: the existing nonancestor test also changes source and masks removal of ancestry validation.
- Low additional test limitation: the unsafe-selected-metadata test uses a package report. Removing safe-read error discrimination survives because fallback rejects that report location. Add a conventional global report to isolate fallback. Current code correctly rejects that case.
- The micro exception requires low risk, micro complexity and no route change ID. Present malformed/null/unsafe metadata stays fail closed. Standard/high-risk absent packages remain rejected.
- Generated ownership expands only to `.grok/skills`; inspected repair retains `.grok/hooks.json` and `.grok/agents` as canonical sources. No external-write path changed; duplicate external writes do not apply.

Identity before/after: HEAD `80215eecb7ecec69cc31a965cbf4d678bee842a3`; tree `39d3f24c62e964081ccd903820e6e7c90ca74ce5`; fingerprint `82e94c0074b5e548b35ea4c6e5f6f182fa7d130f4fcbbbe53448ab6251cc1370`; clean candidate.

reviewed-tree-modified: no

Private scratch `/home/pall/getzilla-session/code-review-compat-0gax3z1g` has mode0700 under owner-controlled non-sticky mode0700 `/home/pall/getzilla-session`. `git clone --quiet --no-hardlinks /home/pall/getzilla-session/Getzilla <scratch>/repo` reproduced exact candidate. All executions below ran only in scratch, sequentially, with `PYTHONDONTWRITEBYTECODE=1 TMPDIR=<scratch>/tmp taskset -c 0-3`.

Control command:

```text
python3 -m unittest tests.test_review_source tests.test_harnesses.HarnessTests.test_grok_skills_are_rendered_from_the_canonical_sources tests.test_harnesses.CursorRuleTests.test_grok_skill_drift_repair_and_retirement_preserve_configuration tests.test_installer.InstallerTests.test_installed_grok_skills_equal_canonical_sources -q
21 tests; OK, 11.619s.
```

Each mutation replaced the named guard with `if False` (or `elif False`), ran `python3 -m unittest tests.test_review_source.ReviewSourceTests.<test> -q`, then restored scratch bytes:

| Disabled guard | Exact test suffix | Result |
|---|---|---|
| Durable-route requirement | `test_missing_durable_or_malformed_selected_package_fails_closed` | KILLED, exit1, one assertion failure. |
| Active-record dictionary check | `test_missing_durable_or_malformed_selected_package_fails_closed` | KILLED, exit1, unexpected type error. This checks the refusal interface; later checks also protect admission. |
| Safe-read error discrimination | `test_micro_unsafe_selected_metadata_does_not_fall_back` | SURVIVED, exit0; Low limitation above. |
| Report-role allowlist | `test_rejects_source_delta_and_dirty_or_untracked_candidate` | KILLED, exit1, committed-source-delta assertion failed. |
| Consumption binding | `test_consumption_rejects_missing_and_forged_binding` | KILLED, exit1, four assertions failed. |

Fresh independent probes used a Python fixture and fresh subprocess calling `review_source_binding(root, source, report)`:

- Ancestry: `git commit-tree <fixture HEAD tree> -m 'unrelated equal tree'` creates an unrelated identical-tree commit. Control exits1 with nonancestor refusal. Removing ancestry check exits0, ADMITTED. Mutant KILLED by this probe.
- Unsafe fallback: low-risk micro route, committed `engineering/reviews/code-review.md`, selected active-change symlink to fixture source. Control exits1 with safe-read refusal (ELOOP). Removing the `FileNotFoundError` discrimination exits0, ADMITTED. Mutant KILLED by this probe.

Final `git rev-parse HEAD HEAD^{tree}`, `git status --porcelain`, and `getzilla.util.tree_fingerprint(Path.cwd())` returned the unchanged identities and empty status above.

Limits: no Windows execution, full suite, race probe, external CI, or production qualification. Null/malformed control coverage comes from the executed tests; no separate JSON fallback mutant was run. Route-ID-change binding and route change-ID-only missing-package cases were inspected but not separately mutated. Static filesystem/publication claims are not executable proof. Final qualifying verifier and exact-head external gates remain pending.
