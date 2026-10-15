# Requirements

Typed acceptance criteria AC-001 through AC-009 live in change-spec.yaml.
Use auto/on/off, shadow/blocking, changed/full. Defaults are auto/shadow/changed.
Unknown fields, duplicate keys, unsafe paths and unsupported policy values fail closed.
Detailed execution outcomes distinguish PASS, FAIL, ERROR, TIMEOUT, CANCELLED,
NOT_CONFIGURED, NOT_APPLICABLE, SKIPPED_BY_POLICY and UNSUPPORTED_RUNNER.
CACHED_UNVERIFIED is an advisory observation, never a fresh tool result. Doctor
can report NOT_RUN for an admitted configuration without executing a tool.

Read only inventoried source and approved configuration/manifests. Do not mount the
checkout, credentials, runtime state or host dependencies. Tools, SDKs and dependency
closure must exist in an operator-admitted immutable image. Missing closure is not
fixed by an automatic install. Generic Node availability does not qualify ESLint.

Custom configured files and .getzilla/config/policy.json invalidate changed scope.
Open source descriptors without blocking; reject non-regular files before reading.
Cancellation remains observable after output pipes close. Cleanup failure refuses PASS.

Cache is clone-local and keyed by every current execution input and implementation.
Only shadow observations can reuse it. Disk claims remain unverified even if their
corruption hash matches. Blocking does zero cache reads or writes. Cache I/O failure
does not overwrite fresh execution status. Bound size, entry count, age and traversal.

CPU default and ceiling are max(1, host logical CPU count - 2), then affinity/cpuset
and ancestor quota caps. Explicit worker requests may lower the allocation. Zero
retains sequential test-runner rollback. Concurrent owners share the global budget.

Doctor performs readiness checks without running consumer code. Public/private CI
selection and mandatory quality checks remain unchanged. Install the LQG documentation
with its consumer link. Record reproducible fixture samples and source identity.
No SDK, container-startup or external CI performance claim follows from synthetic data.

No new service, database, dependency, deployed Trust CI change, security key,
package install, auto-fix or AI call. Real SDK smoke and external CI baseline remain
unavailable until qualified runners and representative consumer evidence exist.
