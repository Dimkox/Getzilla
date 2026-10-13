# Frozen Python dependencies

`uv.lock` contains the runtime, test, runner and build graphs for Python >=3.11. Runtime/test/runner pip profiles include the locked setuptools build backend. Existing dependency roots and audited transitive versions stay constrained in `pyproject.toml`. Windows-only colorama and tzdata markers remain in the universal exports.

The API and worker images use the runtime profile. The database-test image uses the test profile. The runner and public Linux CI use the runner profile. Windows CI checks profiles without installing Trust CI. Each install checks graph and byte bindings first, installs hash-verified binary artifacts without dependency resolution, then installs the local project without dependencies or build isolation. CI builds that project from a private source copy.

Validate without uv, network access or installation:

```sh
python trust-ci/lock_profiles.py --check
```

For a reviewed dependency update, set `UV_CACHE_DIR` to a task cache under the canonical project root `.getzilla/runtime`. Do not use a home cache or treat a nested worktree as a new canonical root. Use uv0.11.12, then resolve metadata and regenerate frozen exports:

```sh
: "${UV_CACHE_DIR:?Set the canonical task cache first}"
uv lock --project trust-ci --no-build --no-python-downloads
python trust-ci/lock_profiles.py --refresh
python trust-ci/lock_profiles.py --check
```

The refresh command checks the manifest against the lock offline and exports with `--frozen`; it does not update the lock. Hash bindings detect changed inputs/markers. Graph validation detects missing transitive pins even if export hashes are rebound. All artifacts are SHA-256 bound to the lock. Unsupported platforms or Python versions without a locked binary wheel fail installation; no source build or fresh dependency resolution is allowed by the consumers.

The vulnerability inventory derives the complete42-package third-party graph from `uv.lock`. Existing requirements parsing does not enumerate every hash-continuation line; profile validation is separate. No live installation, image build, deployment or paid advisory qualification is established by these source locks. Refresh through a reviewed PR. Keep the required parent reviews and final verification after the complete source repair set.
