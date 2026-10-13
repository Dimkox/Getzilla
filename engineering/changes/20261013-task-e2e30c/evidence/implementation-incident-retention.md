# Scoped incident evidence plan

The existing landing backup module now creates a read-only, bounded cleanup plan. It binds each exact source asset to a pre-existing equal backup by SHA-256, size and mode. The plan names finite retention, quarantine and restore destinations, refuses clobber, and records zero mutations. Missing backups, unsafe paths, links, credentials and changed bytes deny. No cleanup executor or deletion authority is added.

RED: the new three-case regression module failed because the planner was absent. GREEN: `PYTHONPATH=factory/src:.getzilla python3 -m unittest factory.tests.test_incident_evidence_plan factory.tests.test_landing_backup` ran 19 tests in 1.540 seconds. Ruff passed on the changed module and test. All fixtures were synthetic and private. These are bounded source observations, not live incident cleanup, provider revocation, host credential removal or delivery evidence.

Rollback: revert the additive planner and tests. Existing backup and restore behavior remains unchanged. Preserve original incident files and backups until a separately scoped operation passes its checks.
