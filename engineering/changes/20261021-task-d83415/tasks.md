# Tasks

1. General implementer owns Getzilla source/tests/docs; root coordinates package state.
2. Run bounded regressions with at most eight CPUs.
3. Commit candidate and dispatch code, test, security and release reviewers.
4. Save reports, freeze, run full gate, record exact-source review receipts.
5. Use the corrected tool on a fresh Liqvera audit, then publish complete passing evidence.

Capacity: 26 verified CPUs, two reserved. Four analyses used at most one CPU each. Getzilla implementation controls may use eight CPUs; Liqvera build-heavy Python tests remain serialized on four CPUs to avoid shared build-directory races. Heavy gates will not oversubscribe.

First full gate failed; preserve it and repair metadata, measured queue capacity, local hook resolution, pinned inventory and PDF guard with the same sole source writer. Use short trusted non-Git TMPDIR and explicit supported UV_PYTHON. Keep the factory timeout and original full comparison range. Fresh four-role review and a new full gate remain mandatory.
