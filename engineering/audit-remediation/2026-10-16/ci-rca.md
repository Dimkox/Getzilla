# A02 — CI root cause on the exact head (2026-10-16)

## Input
- Execution ref: `refs/heads/main` = `c2bf95d62f8491525848ac2643b1f30fc8c438cf`, tree `9f20ca23c2b51c6b39417cadd6e0c62ed65a9515` (same commit and tree as the audit snapshot; see `refs.json`).
- Run: GitHub Actions `getzilla` run 38869248207 on `c2bf95d`, jobs `linux` (116869178510) and `windows` (116869178771), both `failure`.
- Matrix today: Python 3.13 on `ubuntu-latest` and `windows-latest`. The audit's 3.10/3.11/3.12 matrix is no longer in `.github/workflows/getzilla.yml`; its historical failure is not carried over to this head.

## Failing boundary
Linux: `Ran 1665 tests ... FAILED (failures=2, skipped=6)`; Windows: `FAILED (failures=2, skipped=5)`. Every other test passed on both runners. The two failures are the same on both OS:

- `tests/test_install_scripts.py::InstallScriptContractTests::test_documented_install_checks_sha256_of_the_pinned_installer_before_running_it`
- `tests/test_install_scripts.py::InstallScriptContractTests::test_published_install_contract_allows_a_new_source_version_without_git_history` (calls the first)

`AssertionError` at line 57: `PROJECT_STATE.json.published_release.installers` (v2.2.1 digests `39e64ee5…`/`32f5dfd0…`) != SHA-256 of the source `scripts/install.sh`/`install.ps1` (`5c4b7737…`/`5c757c69…`).

## Root cause (confirmed)
The test compared the **published** installer digests with the **source candidate** bytes. README/QUICKSTART correctly fetch the installers from the immutable tag `v2.2.1` and check the published digests; `git cat-file blob v2.2.1:scripts/install.sh | sha256sum` = `39e64ee5…` and `install.ps1` = `32f5dfd0…`, so the published record and the docs are right. The installers changed on main for the unreleased 2.2.2 candidate (PR #82), and the test could only pass if source bytes never diverge from the last release — every installer change made main red until a release.

Reproducer: `python3 -m pytest -q -p no:cacheprovider tests/test_install_scripts.py -k Contract` → `2 failed, 13 passed` on `c2bf95d` (see `ci-reproducer.json`).

## Fix (A03)
- Docs keep the published digests, now read from `published_release.installers`; a new test binds those digests to the bytes at the published tag and the tag object OID (CI already checks out with `fetch-depth: 0`; a release archive without Git history skips only that binding, with the reason).
- Source installers must equal the published ones **or** a declared `source_installers` candidate of the current `product_version`; an undeclared installer change still fails (checked by appending a line to `install.sh`: 1 failed).
- No required check removed or skipped; the security intent of issue #63 (never pipe an unverified download into a shell) is unchanged.

Result on the fixed tree: `1660 passed, 6 skipped` (claw, 26 workers).
