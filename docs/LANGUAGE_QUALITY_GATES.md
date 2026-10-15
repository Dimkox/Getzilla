# Optional language quality gates

Getzilla discovers ESLint, Detekt, ktlint, Dart Analyzer, dart format, SwiftLint and
SwiftFormat packages. Defaults are auto/shadow/changed. Results appear in verification
JSON at advisory.lqg.results. Existing mandatory gates and npm scripts keep their behavior.

Configure the existing .getzilla/config/policy.json language_quality_gates section:

```json
{
  "language_quality_gates": {
    "mode": "auto", "enforcement": "shadow", "scope": "changed",
    "autofix": false, "ai_retries": 0, "cache": "shadow",
    "sandbox": {"image": "registry.example/project-lint@sha256:<64 lowercase hex digits>"},
    "tools": {"eslint": {"driver": "cli", "launcher": ["/opt/tools/eslint"], "version": "9.0.0"}}
  }
}
```

Replace the digest and declared version with reviewed values. Repository policy cannot
authorize a host image. The operator separately admits exact digests in
/etc/getzilla/language-quality.json, with schema_version1 and an images array. The
file and parent must be root-owned, not symlinks and not group/world writable.
Getzilla never writes this registry. Environment flags cannot provide admission.
Missing admission or local image gives UNSUPPORTED_RUNNER. Images are never pulled.

The image must contain the pinned tool, SDK and complete dependency layout. ESLint
plugins and Dart/Flutter packages resolve there. Host node_modules and .dart_tool are
not mounted. Generic Node is not ESLint. No npx, package installer, pub get, Homebrew
or Gradle wrapper runs. The declared tool version is metadata bound to the admitted
image; it is not a live version probe.

Only inventoried source and approved language configuration/manifests enter the
snapshot. Source/root mounts are read-only. The container has no network, no capabilities,
a non-root user, private bounded temporary storage, and CPU/RAM/PID/time/output bounds.
Cleanup removes its owned container. Unsafe special files fail before content reads.

Per-tool fields: mode, enforcement, scope, driver, launcher, version, config, task,
requires_macos. Modes: auto/on/off. Enforcement: shadow/blocking. Config paths are
package-relative. The launcher names an absolute image-local executable. Unknown fields
fail closed. Detekt/analyzers use full package scope. Unknown base/status, rename/delete,
custom config, project policy and known config/build/lock changes force full scope.

| Tool | Execution contract |
| --- | --- |
| ESLint | JSON reporter, no fixes |
| Detekt | Full CLI input and documented exit codes |
| ktlint | JSON reporter, changed or full package |
| Dart Analyzer | dart analyze or flutter analyze once per package, no pub get |
| dart format | output=none and set-exit-if-changed |
| SwiftLint | Strict JSON lint |
| SwiftFormat | Lint-only JSON reporter |

The container client requires POSIX. Windows reports UNSUPPORTED_RUNNER. Gradle cannot
yield PASS without a structured report, including on exit0. CLI alternatives are supported.
Native macOS and iOS build validation are not provided. Deployed Trust CI remains unchanged.

PASS, FAIL, ERROR, TIMEOUT, CANCELLED, NOT_CONFIGURED, NOT_APPLICABLE, SKIPPED_BY_POLICY and
UNSUPPORTED_RUNNER stay distinct. Applicable blocking nonpasses refuse admission.
Doctor reports readiness without running consumer code; NOT_RUN means configured and
operator-admitted, with execution and SDK availability still untested.

The optional cache defaults to shadow; cache=off disables it. Blocking always runs fresh
and performs no cache reads/writes. The clone-local cache binds account/checkout, Git
identities, all approved dirty bytes, config/dependencies/policy, package/scope/argv,
tool/image-bound SDK, current admitted image identity, implementation and CPU/platform.
Limits: 24hours, 128 entries, 32MiB total, 256KiB per entry. Unsafe storage is ignored.

A hit returns CACHED_UNVERIFIED, execution_performed=false and evidence_kind=cached-unverified.
The claimed old PASS/FAIL and diagnostics stay under cached_observation. The disk hash only
detects corruption; even a recomputed forged hash cannot make a fresh PASS or admission.
Current policy/bindings are rebuilt. Cache errors are disclosed and fresh execution continues.

The source checkout provides scripts/benchmark_lqg.py for reproducible synthetic fixtures.
These measure orchestration, hashing, normalization and cache with deterministic outputs.
They do not measure real SDKs, container startup or external CI latency. Actual SDK smoke is
NOT_RUN where unavailable; external CI baseline is unavailable. No production p50/p95 target
is claimed. The real Node isolation fixture is separate from language SDK qualification.

Rollback: set mode=off and remove per-tool on overrides. Use cache=off to disable reuse alone.
CPU budget reserves two from total host logical CPUs once, then caps by affinity/cpuset and
ancestor quota. Explicit positive allocations may lower that budget only.
