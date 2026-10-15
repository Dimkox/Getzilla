# Architecture

Typed authority: change-spec.yaml. Adapter ABI: [design](../../../docs/superpowers/specs/2026-10-15-language-quality-gates-design.md).

Verification -> language_quality.core -> pure adapter -> ContainerExecutor ->
normalized result -> advisory report -> optional blocking CheckResult. Existing
receipts retain the report. Doctor calls the same registry in preflight mode.
Core never imports Trust CI; public/private CI selection is unchanged.

One policy authority: .getzilla/config/policy.json#language_quality_gates.
Adapters have no process, policy, cache or receipt authority. Source and config paths
are package-relative. Unknown Git bases/statuses, renames/deletes, configured files,
project policy and known build/SDK/lock changes force full package scope.

Host-owned /etc/getzilla/language-quality.json separately admits exact image digests.
Repository policy and environment markers cannot authorize an image. Without admission,
no container process runs. Getzilla never writes the host registry. Source reads use
no-follow directory descriptors and nonblocking file opens, then regular-file checks.
The snapshot digest is checked before execution. The immutable local container runs
offline, read-only, non-root, capability-free and bounded by CPU/RAM/PIDs/time/output.
Cancellation kills/reaps its process and cleanup removes its owned container.

ShadowCache stores bounded JSON under clone-local private runtime directories.
Its key binds account/checkout identity, commit/base, all approved dirty input bytes,
config/dependencies/policy, tool and image-bound SDK identity, argv/package/scope,
current admitted image resolution, implementation bytes and effective platform/budget.
The directory is 0700; entries are 0600, regular, single-link files. Descriptor traversal,
nonblocking locks/opens, atomic replacement, TTL24h, 128-entry/32MiB totals and
256KiB entry bounds prevent unbounded or redirected cache I/O.

Cache hashes detect corruption, not authenticity. A loaded claim becomes
CACHED_UNVERIFIED with execution_performed=false and evidence_kind=cached-unverified.
Persisted PASS/FAIL and diagnostics stay under cached_observation. No cached authority
fields are accepted. Current policy and bindings are rebuilt. Blocking bypasses cache;
projection also refuses cached provenance defensively. No signing keys are introduced.

cpu_budget.py reserves two host logical CPUs once and caps by allowed CPUs and quota.
The test runner and each serial LQG container use it. The coordinator allocates concurrent
owners separately. Fixtures measure only the Python orchestration path with injected
outputs; real SDK/container startup and external CI timings remain unqualified.

No migration or external mutation. Gradle results cannot pass without a bounded
structured report; supported CLI paths are used. Deployed CI remains outside this change.
