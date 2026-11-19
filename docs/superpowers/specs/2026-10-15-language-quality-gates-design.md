# GZ-LQG-001 optional language quality gates

Base: `7cf4f65dd2ba9bb1390dc84c6185ba0f104255c8` (Getzilla 2.2.2).
Sources: owner-supplied `2026-10-15-getzilla-optional-eslint-implementation-plan.md`
and `GZ-LQG-001-ESLINT-ADDENDUM.md`. No ESLint implementation existed at baseline.
Owner consent: “и сразу запускай реализацию параллельно” and
“все в параллель делай потом одному владельцу сдавай”.
The owner resumed with “Делай код разрешаю” after the workspace move.
This authorizes local scope/design and implementation, not production writes.

## Behavior and authority

Use the existing `.getzilla/config/policy.json` authority, section
`language_quality_gates`. Exactly seven IDs: eslint, detekt, ktlint,
dart_analyzer, dart_format, swiftlint, swiftformat. Defaults: auto, shadow,
changed, autofix=false, ai_retries=0. Use enforcement spelling blocking.

Source/package discovery excludes generated and vendored files. Unknown base,
rename/delete, configuration/build/SDK/lock changes and ambiguity select full
package scope. Invalid paths fail closed. Explicit on with no configuration
is NOT_CONFIGURED. Detailed outcomes: PASS, FAIL, ERROR, TIMEOUT, CANCELLED,
NOT_CONFIGURED, NOT_APPLICABLE, SKIPPED_BY_POLICY, UNSUPPORTED_RUNNER,
CACHED_UNVERIFIED. Doctor uses NOT_RUN for an admitted preflight without execution.
Configured custom paths and the policy file invalidate changed scope too.

Shadow observations are report.advisory.lqg. Only applicable blocking decisions
project to existing CheckResult statuses. Mandatory QG rules and legacy npm
checks remain unchanged. Existing lint scripts can still block.

## Adapter ABI v1

Frozen dataclasses: AdapterCapabilities(incremental, full=True),
AdapterRequest(tool_id, driver, launcher, scope, files, config_path=None, task=None),
ToolOutput(returncode, stdout, stderr),
Diagnostic(severity, code, message, path=None, line=None, column=None),
AdapterResult(status, summary, diagnostics=()).
Driver: cli, gradle, dart, flutter. Paths are validated package-relative paths.
Each adapter exports capabilities(tool_id, driver), build_argv(request),
normalize(request, output). Core owns package cwd and validated launcher.

## Security and evidence

Adapters never run processes, install tools, select policy or write receipts.
Consumer configuration/build scripts run only in a qualified sandbox: immutable
locally available image, no network, read-only source/root, non-root user,
bounded CPU/RAM/PIDs/time/output and timeout/cancellation cleanup. No host
fallback or implicit download. No approved backend means UNSUPPORTED_RUNNER.
Environment flags are not authorization. Core never imports Trust CI.

Evidence binds repository, commit/base, dirty inputs, package, requested/actual
scope and fallback, policy/config/dependency/tool/executor identity, timing and
diagnostics. Source descriptors are opened without blocking and checked as regular
files before reading. Cleanup errors cannot become a successful execution.

Shadow cache requires a complete binding: checkout/account, base/HEAD, all dirty
input/config/dependency/policy bytes, package, scope/files/argv, pinned tool/image,
live resolved image identity, implementation bytes, platform and sandbox limits.
Entries expire after 24 hours and are bounded to 256 KiB each, 128 entries and
32 MiB per clone. Private descriptor-based storage rejects symlinks, hardlinks,
special files and unsafe modes. Errors disclose a miss or write error and preserve
the fresh execution result. Blocking bypasses all cache reads and writes.

Disk cache is untrusted. A hit has CACHED_UNVERIFIED status, execution_performed=false
and nested historical claims; it cannot produce a fresh PASS, admission or receipt.
A payload digest detects corruption and is not authentication. The loader derives
current bindings itself and does not import authority fields from cache. No fixes,
AI remediation or success cache receipts are invented. Policy cache=off disables reuse.

Public/private CI selection and deployed Trust CI policy remain unchanged.
Private nested execution without a qualified backend is unsupported. Swift lint
is not iOS build validation. Missing SDK/backend smoke is NOT_RUN. Mock tests
prove contracts only. Doctor checks readiness without executing a consumer tool.
The consumer payload includes its linked language-gate guide. Deterministic fixture
benchmarks record raw cold/warm and stage timings with an injected executor; they
do not qualify real SDK latency or external CI queue time. Those baselines remain
unavailable, and all unavailable SDK/macOS smoke remains NOT_RUN.
Rollback: policy off or revert the feature commit series.
