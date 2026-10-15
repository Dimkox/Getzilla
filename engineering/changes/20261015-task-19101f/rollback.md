# Rollback

Set language_quality_gates.mode to off and remove per-tool on overrides.
This stops all LQG execution and leaves existing gates unchanged.
Set language_quality_gates.cache to off to disable shadow reuse alone.
Cache files are non-authoritative observations and need no migration or deletion.
Set GETZILLA_TEST_WORKERS=0 for sequential test execution.
Revert this feature series to remove the optional registry and CPU policy.
There is no migration, external mutation or data recovery operation.
After rollback, test policy-off behavior and the existing mandatory quality gates.
