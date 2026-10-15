# Optional language quality gates

Getzilla discovers packages for ESLint, Detekt, ktlint, Dart Analyzer, dart format,
SwiftLint and SwiftFormat. Defaults are auto/shadow/changed. Detailed results are
in verification JSON at advisory.lqg.results. Existing mandatory gates and npm
scripts retain their own behavior.

Configure the existing .getzilla/config/policy.json language_quality_gates section:

```json
{
  "language_quality_gates": {
    "mode": "auto", "enforcement": "shadow", "scope": "changed",
    "autofix": false, "ai_retries": 0,
    "sandbox": {"image": "registry.example/project-lint@sha256:<64 lowercase hex digits>"},
    "tools": {"eslint": {"driver": "cli", "launcher": ["/opt/tools/eslint"], "version": "9.0.0"}}
  }
}
```

Replace the example digest and version with reviewed values. Project policy
cannot authorize a host image. The operator separately admits exact image digests
in /etc/getzilla/language-quality.json with schema_version1 and an images array.
That file and its parent must be root-owned, not symlinks and not group/world
writable. Getzilla never writes this operator policy. Environment variables and
repository files cannot provide admission. Missing admission or local image gives
UNSUPPORTED_RUNNER. The image is never pulled automatically.

The image must already contain the pinned tool, SDK and dependency closure.
ESLint plugins and Dart/Flutter packages must resolve through its prepared package
layout. Host node_modules and .dart_tool are not mounted. Generic Node availability
does not provide ESLint. No npx, package installer, pub get, Homebrew or Gradle wrapper.

Only inventoried source and approved language configuration/manifests enter the
snapshot. Unrelated checkout and credential files stay outside. The container has
read-only source/root, no network, no capabilities, a non-root user, private bounded
temporary storage and bounded CPU/RAM/PIDs/time/output. Cleanup removes its container.

Per-tool fields are mode, enforcement, scope, driver, launcher, version, config,
task and requires_macos. Modes: auto/on/off. Enforcement: shadow/blocking.
Drivers: cli/gradle/dart/flutter. Config paths are package-relative. Launcher is an
absolute image-local executable, optionally followed by a pinned script path.
Unknown fields are errors. Analyzer and Detekt use full package scope. Unknown
base, rename/delete, config/lock/build changes and ambiguous status force full scope.

| Tool | Execution contract |
| --- | --- |
| ESLint | JSON reporter, no fixes |
| Detekt | Full CLI input and documented exit codes |
| ktlint | JSON reporter, changed or full package |
| Dart Analyzer | dart analyze or flutter analyze once per package, no pub get |
| dart format | output=none and set-exit-if-changed |
| SwiftLint | Strict JSON lint |
| SwiftFormat | Lint-only JSON reporter |

The current container client requires POSIX; Windows reports UNSUPPORTED_RUNNER.
Gradle returns ERROR without a structured report, including exit0, because tasks
can skip execution or ignore findings. Native macOS execution and iOS build
validation are not provided. Private Trust CI without an admitted backend reports
unsupported. Deployed Trust CI policy and images remain unchanged.

PASS, FAIL, ERROR, TIMEOUT, CANCELLED, NOT_CONFIGURED, NOT_APPLICABLE,
SKIPPED_BY_POLICY and UNSUPPORTED_RUNNER remain distinct. Shadow is advisory.
Applicable blocking nonpasses refuse admission. Persistent cache reuse, real SDK
matrix qualification and representative latency benchmarks remain pending.
Container isolation smoke is not SDK qualification.

Rollback: set mode off and remove per-tool on overrides. CPU work budget reserves
two from total host logical CPUs once, then caps by actual affinity/cpuset and
ancestor quota. Positive explicit allocations may lower the budget only.
