# Architecture

Typed authority: change-spec.yaml. Adapter ABI: [design](../../../docs/superpowers/specs/2026-10-15-language-quality-gates-design.md).

Existing verification -> language_quality.core -> pure adapter -> ContainerExecutor -> normalized
result -> advisory report -> optional blocking CheckResult. Existing receipts retain the report.
Core never imports Trust CI. Public/private CI selection stays unchanged.

Policy authority is .getzilla/config/policy.json#language_quality_gates.
The adapter boundary is immutable models.py. Tool IDs are finite; adapters have no process,
policy, receipt or cache authority. The core owns source scope and package boundaries.
Changed scope uses exact comparison bases and status channels. Ambiguity selects full package.

Host-owned /etc/getzilla/language-quality.json separately admits exact image digests.
Repository policy and environment markers cannot authorize an image. No admission means
UNSUPPORTED_RUNNER before any container subprocess. Getzilla never writes host admission.
ContainerExecutor reads approved inputs through no-follow directory descriptors. It validates
snapshot digest before launch. An immutable already-local Docker/Podman image runs non-root,
network-none, read-only, capability-free, bounded by CPU/RAM/PIDs/time/output. The host client
uses a clean environment. Timeout/cancellation kills the client and removes the owned container.
Only private scratch is writable. No host execution fallback exists.

cpu_budget.py derives host logical reserve, actual process affinity (already intersected with
online/cpuset constraints) and minimum visible cgroup quota. selected_workers and select_engine
both enforce it. PR fallback and LQG use the same helper.

No API/event schema or data migration changes. No external mutations, retry queue or production
rollout. Cache is deliberately disabled pending trustworthy persisted reuse. Gradle remains
nonpassing until a bounded report artifact contract is added.
