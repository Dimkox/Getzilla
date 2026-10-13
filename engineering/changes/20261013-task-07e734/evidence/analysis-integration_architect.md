# lock integration analysis

Source: common HEAD6dd06ff5b96692a01812fbac6252fd08f6169f91, base540c12f93e798c2f483455a5086ab0018ac3216e. Read-only selected analysis. Reuses controller analysis-install-lock.md and current issue bodies; no repeated broad inspection, installs, image builds, paid calls or full tests. Leaves remain UNVERIFIED until combined parent reviews and one final qualifying gate under owner sequencing override.

Route07e734; #42. Add Trust CI uv.lock and deterministic hash-locked runtime/test/runner projections using existing tooling; preserve direct versions and platform marker semantics. Existing OSV collector supports uv.lock and requirements transitives. API/worker/test/runner Dockerfiles plus public CI must consume the committed closure; trailing resolver-enabled pip must not widen it. Lock setuptools build requirements and avoid isolated unconstrained build resolution. Pip --require-hashes followed by local package --no-deps --no-build-isolation avoids introducing uv as deployed runtime dependency.

Minimal files: Trust CI lock/profile exports; four Dockerfiles; public workflow; focused lock/source tests; operator installation guidance. Verify missing/stale lock/profile fails closed and transitive starlette appears in OSV inventory. Constraints-only roots are insufficient. Exact projection export check and profile completeness are prerequisite to install wiring. Source changes do not rebuild or deploy production. CI/package metadata must remain in copied scratch, not consumer trees. Coordinate documentation/version references with docs leaf; do not dispatch workflows before all repairs. Rollback through reviewed source/image procedure; never silently refresh lock or downgrade deployed service.

No candidate writes. Static design findings only; no PASS review or gate.
reviewed-tree-modified: no
