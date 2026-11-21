# Installer and dependency-lock integration analysis

Source: route e2e30c9f2878; HEAD6dd06ff5b96692a01812fbac6252fd08f6169f91; comparison base540c12f93e798c2f483455a5086ab0018ac3216e. Read-only analysis. No ii-tonya tree, private files, installs, image builds or network requests inspected/executed.

## Issue75: smallest compatible repair

Current installer only plans existing repositories and atomically materializes absent targets. It already avoids clean-tree requirements, supports target kept-local declarations and protected directory bindings. Keep that boundary. Plan entries describe desired payload hashes, not an installed ownership record. Legacy migration currently labels every file in legacy managed directories RETIRE by path and tells the operator to remove it. This does not establish ownership of local changes or scratch/evidence inside those directories.

Acceptance:
- Read-only plan inventories bounded tracked/untracked statuses and path metadata without requiring cleanliness or reading requirement contents. Classify requirements, evidence, user changes, generated metadata, positively owned installation bytes and unknowns; overlapping or uncertain matches stay unknown/preserved.
- Requirements JSON, evidence bundles and agent scratch are preserved. Egg-info/cache may be classified generated but path naming alone is not deletion authority. Record uncertainty if inventory is truncated, unreadable or contains unsafe links.
- Existing AGENTS.md and CI/configuration are consumer-owned: show preserve/conflict decisions instead of a blind create payload row. Their presence must not trigger overwrite or cleanup.
- Fresh materialization persists a versioned ownership manifest for delivered regular files: normalized path, hash, mode and source identity. Exclude the manifest itself from recursive hashing. Positive hash match establishes ownership; missing/modified entries do not authorize removal.
- Legacy RETIRE becomes a non-destructive migration candidate with ownership/conflict classification. No automatic quarantine or deletion in plan. Any future quarantine must name exact paths, bind current bytes and destination, retain recovery inventory and refuse clobber. Do not add existing-repository update/uninstall commands merely to close this issue.
- Fixtures reproduce the reported categories using synthetic content only; plan runs on unrelated dirty Git state and preserves its bytes/status. Test modified installed files, unknown files under owned-looking directories, unsafe symlinks, manifest tampering and AGENTS/CI conflicts.
- Prevent packaging metadata generation in consumer source by retaining copy-to-private-scratch build paths; do not broadly ignore or erase historical evidence/requirements.

Likely files: scripts/install_into.py; tests/test_installer.py; tests/test_install_scripts.py; consumer documentation/templates only if workflow guidance changes. Ownership manifest parser/install payload inclusion must preserve deterministic materialization and inventory limits. Installer planning and manifest behavior are independent of Trust CI dependency locking.

Recovery: existing consumers remain read-only. Failed fresh materialization uses current owned-stage cleanup. Ownership records never infer deletion authority over changed or unknown files. Explicit quarantine is recoverable and not a production cleanup grant.

## Issue42: committed lock and consumption

Confirmed gap: trust-ci/pyproject.toml pins runtime roots and test httpx only; no Trust CI lock exists. API/worker/test Dockerfiles and runner install project with resolver-enabled pip. Public Actions copies Trust CI into runner scratch but also resolves dependencies. Existing factory/uv.lock demonstrates repository lock format. known_vulns already parses uv.lock and requirements*.txt, including transitives; no new service or scanner library is required.

Acceptance/design:
- Generate trust-ci/uv.lock from current pyproject using existing uv tooling. Preserve direct versions; resolve runtime, test and runner-quality tool closure for supported Python/platform profiles. Do not copy factory lock blindly; it is a different project and graph.
- Export committed hash-locked requirements projections with a deterministic frozen check. Separate runtime/test/runner profiles if that avoids shipping test tools to production. Ensure setuptools build requirement is locked too; avoid unconstrained isolated build dependency resolution.
- Existing pip can consume requirements with --require-hashes, then install the local Trust CI project using --no-deps --no-build-isolation after locked build tooling exists. This avoids adding uv as an image/runtime dependency. All API, worker, test, runner and public CI install paths must consume the same committed closure or explicit profile; avoid trailing resolver-enabled pip installs that widen the graph.
- OSV inventory must include committed Trust CI uv.lock/export entries, including a transitive package such as starlette. Test manifest drift, stale exports, unsupported profile and missing lock fail closed. Test that Dockerfiles/workflow cannot revert to unbounded .[test] installation. Assert installation source paths remain private scratch, not consumer egg-info.
- Handle platform markers and binary package variants explicitly. A constraints-only file or direct pin list is insufficient because pip can still resolve unconstrained transitives. Hash requirements ensure bytes, not just versions.

Likely files: trust-ci/uv.lock; trust-ci/*requirements*.txt or deterministic export/check script; trust-ci/pyproject.toml only if named dependency groups are needed; trust-ci/Dockerfile.api, Dockerfile.worker, Dockerfile.test, runner.Dockerfile; .github/workflows/getzilla.yml; focused lock/source tests; operator instructions. Check compose build contexts and local Trust CI install documentation for consumption parity. Existing known_vulns parser likely needs tests only, not behavior change.

Dependencies: generate lock before exported requirements/install-path wiring; record supported profiles before resolution. Public metadata resolution may be required by implementer, with no package installation or deployed image mutation. Source image lock changes do not update running production services. No full PR gate or CI dispatch before the owner-requested complete repair set.

Rollback: restore previous source files through reviewed PR or rebuild prior immutable source under operational authority. Do not downgrade deployed dependencies or clear runtime state automatically. Lock refresh is a reviewed dependency change; never refresh silently during installation.

Commands: read controller issue75/42 bodies from all-issues.json; inspect scripts/install_into.py lines912-1026; read Trust CI pyproject and four Dockerfiles; inspect public workflow pip commands; read existing factory/uv.lock header; inspect known_vulns MANIFESTS parser. No tests executed; design analysis only.

reviewed-tree-modified: no
