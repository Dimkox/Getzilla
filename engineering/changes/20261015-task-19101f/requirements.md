# Requirements

Typed criteria AC-001 through AC-006 live in change-spec.yaml.
Use auto/on/off, shadow/blocking, changed/full. Defaults are auto/shadow/changed.
Unknown fields, duplicate keys, unsafe paths and unsupported policy values fail closed.
Detailed results distinguish PASS, FAIL, ERROR, TIMEOUT, CANCELLED, NOT_CONFIGURED,
NOT_APPLICABLE, SKIPPED_BY_POLICY and UNSUPPORTED_RUNNER.

Read only inventoried source plus approved language configuration/manifests. Do not mount the
checkout, credentials, runtime state or host dependencies. Tools and their dependency closure
must already exist in the immutable image. Missing closure may produce ERROR; do not install it.
ESLint plugins and Dart/Flutter packages require a consumer-specific qualified image; generic
Node availability is not proof that those SDKs/dependencies are present.

CPU default and maximum are max(1, host logical CPU count - 2), then affinity/cpuset and finite
ancestor quota caps. Positive explicit worker requests may lower the allocation, not raise it.
Zero retains the existing sequential test-runner rollback. LQG runs tools serially and caps each
container allocation. The coordinator caps all concurrent heavy child work at the shared budget.

No new service, database or package dependency. No deployed Trust CI or branch-protection changes.
No cache reuse until identities and receipt trust are proven. Real tool smoke and consumer
p50/p95 benchmarks are pending where SDKs or representative projects are unavailable.
