# Review status

Independent research review: PASS with one Low test-coverage finding. This approval covers the research publication only. It does not approve product integration.

Defer the masked reader-test cases to [issue 172](https://github.com/Dimkox/Getzilla/issues/172) for one later test PR. Do not change the registered queries, qrels, settings or rankings. Supplemental reviewer probes killed the three guard-removal mutants that the supplied tests missed. `code-review.md` contains the complete review. `reviewer-evidence/` contains exact read-only copies of its audit and probe scripts. These are evidence, not repaired benchmark tests. Do not run them against the published tree; the audit intentionally mutates its private scratch copy.

The review covered manifest SHA256 `dbc862ccb4ca67c2654272b1348a9f2a38cd28dcbb6e585f100b87112becbd57`. `reviewed-SHA256SUMS.json` preserves that exact manifest. Every one of its 101 payload files remains byte-identical. The original report and reproduction guide remain historical reviewed files. The current `SHA256SUMS.json` also covers this review evidence.

## Fresh reproduction layout

Keep the published bundle as `<experiment-root>/publication/`. Copy its scripts, Dockerfiles, `data/`, `support/` and `execution/` into `<experiment-root>/` as working files. Do not execute the scripts from inside `publication/`. In particular, `check_publication.py` expects its sibling `publication/` directory. Use a new owned experiment root below the canonical repository runtime scratch directory. The scripts use `/home/pall/projects/getzilla` for exact Git-object reads, so retain the pinned Getzilla commit there or adapt that canonical-root constant in the new working copy and record the change.

Run `check_publication.py` from the working copy to validate the preserved bundle. Then follow the reviewed guide's dependency order for source preparation, model preparation, image preparation, offline runs and artifact checks. Copy the recorded `execution/packages.stdout` before using `Dockerfile.replay`. Do not rerun `seal.py` to claim a new independent review. The existing seal binds only the published corpus/query/config identities. Keep it only while those bytes remain identical.

`finalize.py` writes `<experiment-root>/publication/`. Do not run it over the preserved published bundle. Use another disposable working root if you want a new report. New timing results are new observations, not replacements for the reviewed historical measurements.

## Cleanup

The tools image remains available for the parent's product gate. No shared image, volume or cache is pruned. `cleanup-receipt.json` lists only owned disposable inputs removed after their hashes were checked. Original source files, supporting tests, source snippets, full results, metrics, pins and scripts remain. Restore removed model assets with `prepare_model.py`; restore the duplicate Gitless view with `launch.py prepare`; restore the small Git object cache with `git_parity.py`. Inference remains offline after preparation.
