Recommendation: **FAIL**. Two Medium findings remain. The known Low test gaps stay deferred in issue122.

- **Medium — local receipt fingerprint mismatch.** `scripts/getzilla_audit_bundle.py:66` uses sanitized Git reads for the fingerprint inventory. Those reads disable global Git config. Existing receipt generation in `.getzilla/getzilla/util.py` still uses global excludes. A private fixture changed from eligible to blocked after adding one harmless globally ignored editor file. The existing receipt fingerprint stayed unchanged; the audit fingerprint changed. Repeating the current verifier cannot produce the digest the audit expects. Use the same file inventory policy for receipt creation and consumption. Preserve the Git identity isolation.
- **Medium — shared security finding.** Security review confirmed that a transient live opt-in can pass the initial check while the captured committed config is disabled. The audit then returns PASS with `compliance.eu_ai_act` null. Require opt-in from captured committed bytes. This report does not claim that I repeated that probe.

Source: `/home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-phase2`; route `44fe064efbab`. Base: `287e64f99b01db44cb6eeeb10f307ccda6f91c1d`. Before and after review, HEAD was `61827791b7f49a5ad340a62f07756888a03964a3`, tree was `96612a25a2dca3ed8e306f622e82ed2c8b3cbecf`, and fingerprint was `53a32ef677284d79a7de11b13b81176fce0e520d485d247c522883f21cb5c733`. Staged, unstaged and untracked inventories were empty.

The complete base-to-HEAD inventory contains 49 files. It covers EU modules/data/templates, audit and compliance wrappers, installer/dispatcher, V2 schema/architecture, five test modules, docs and change evidence. Exact statuses and paths are in `code-review-wave2/source-inventory.tsv` under the private parent below. Its SHA-256 is `f02aef2876ab16832678c4c9936cfcbcfbb9cb68303ca6c302933fd6e25c53de`. First-wave reports are historical failures.

Private parent: `/home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021`. Scratch: `code-review-wave2` beneath that parent. Both directories were trusted, non-sticky, mode0700. The fresh clone matched all 5,525 tracked source entries, including working-tree bytes and modes. No dirty source changes needed copying. All mutants ran only in its `candidate` subdirectory. That clone was clean after restoration.

reviewed-tree-modified: no

Snapshot command: `python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave2-setup.py`. Observed: 5,525 verified entries; clean HEAD/tree as above. The before/after identity command was `python3 /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/source_identity.py /home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-phase2`; both outputs matched.

The following baseline ran from the scratch `candidate` directory. It checked ordinary receipt grammar, eleven path-state cases, untracked content versus runtime noise, captured HEAD, Git environment/replacement isolation, one date/metadata snapshot and exact signed-command claims.

```bash
TMPDIR=/home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave2/tmp PYTHONDONTWRITEBYTECODE=1 taskset -c 0-5 python3 -m pytest -q -n 6 -p no:cacheprovider --tb=short /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave2/test_fingerprint_parity.py tests/test_eu_audit_attestation.py::CiAuditTests::test_head_date_and_optional_metadata_use_one_snapshot tests/test_eu_audit_attestation.py::CiAuditTests::test_git_replacements_and_inherited_git_environment_do_not_change_audit tests/test_eu_audit_attestation.py::CiAuditTests::test_bundle_receipt_fingerprint_keeps_captured_head_and_existing_grammar tests/test_eu_audit_attestation.py::AttestationClaimTests::test_exact_successful_execution_is_required
```

Observed: **9 passed, 22 subtests passed**. The additional normal-use global-ignore probe used only private fixture configuration and a fixture receipt. It read no real user config.

```bash
TMPDIR=/home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave2/tmp PYTHONDONTWRITEBYTECODE=1 taskset -c 0-5 python3 -m pytest -q -n 6 -p no:cacheprovider --tb=short /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave2/test_global_ignore_receipt.py
```

Observed: **1 failed** at fingerprint parity. Output: `before=eligible`, `after=blocked`, `local_fingerprint_unchanged=true`, `audit_fingerprint_matches=false`; reason: no passing verification receipt.

Fresh mutation commands ran sequentially because they shared the private snapshot:

```bash
GETZILLA_SERIAL=1 python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave2/run_mutant.py F1
GETZILLA_SERIAL=1 python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave2/run_mutant.py F2
GETZILLA_SERIAL=1 python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave2/run_mutant.py F3
GETZILLA_SERIAL=1 python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave2/run_mutant.py F4
```

| Claim / mutant | Observed outcome |
|---|---|
| F1: use live HEAD instead of captured HEAD | Killed; one fingerprint assertion failed |
| F2: omit untracked source from the digest | Killed; source change left the digest unchanged |
| F3: inherit Git location settings in audit reads | Killed; the expected isolated read failed |
| F4: permit replacements in the shared Git reader | Killed; the reader returned the replacement blob |

Each mutant test exited1. No fresh mutant survived or was inconclusive. Commands, selected tests and output remain in private `out-F1.txt` through `out-F4.txt`. These outcomes do not erase the deferred first-wave test gaps or the current failing compatibility probe.

Fresh V1 control: `git diff --exit-code 287e64f99b01db44cb6eeeb10f307ccda6f91c1d HEAD -- engineering/contracts/schemas/trust-ci-attestation-envelope.v1.json` in the source worktree returned exit0 with no output.

Unexecuted here: direct five-input/executable-union mutations, Windows refusal and Node timeout controls; parallel reviewers own them. Static inspection covered those repairs, fresh parser use and Core/Trust CI separation, but is not executable proof. Native Windows, real signed V2 integration, real C2PA signing, TypeScript type checking, full PR verification and external checks also remain unexecuted here. No new duplicate external-write path was found by inspection. No receipt or phase2 completion is established.
