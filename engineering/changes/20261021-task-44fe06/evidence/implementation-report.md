# Core implementation and bounded controls

Date: 2026-10-21. Branch: feat/eu-ai-act-phase2-20261021. Route:44fe064efbab.
Comparison base: e158ddc7263a55f5308944c5a426eb1e9f1a4327.
Initial tree: 9a7fb672e44de0d3d87e37a70fa4861d37681ce6.

The Core source is implemented. Fresh bounded controls passed on checkpoint
fdc02defb766fea9372e939b90180ea37342e2f6, tree f96e020ca5e3018bb593748cf5a36c6e4331c158.
That checkpoint changed42 files with2464 insertions and282 deletions against the base.
The source candidate now proceeds to committed-HEAD smoke and independent review. These controls
are observations, not receipts or merge authority. Final qualification remains UNVERIFIED.

The earlier validation batch hit the hook circuit breaker. The writer stopped validation and
dependent review. The owner then answered "Разрешаю возобновить проверки" to the scoped recovery
request. All recovered checks used separate direct tool calls. No denied batch, hook or denial
ledger was changed or retried. Required receipts remain not_run.

## Changes

- eu_ai_act.py: matrix freshness REVIEW, strict opt-in shape, optional risk scores/residual acceptance/deadline and informational ISO loading.
- compliance_scaffold.py and getzilla_compliance.py: bounded no-follow template reads and exclusive adapter writes; language-specific hints; registry unchanged.
- Python and Node templates: caller public labels, idempotent publication labels and separate optional C2PA output. Original input survives failure and timeout.
- getzilla_audit_bundle.py: committed-input checks; read-only --ci-check with no Python bytecode writes; fixed-argv installed verifier with safe cwd/environment and output/time bounds; exact v2 execution claims. Normal bundles keep local receipt requirements.
- New trust-ci-attestation-envelope.v2.json and exact architecture contract. Version1 remains byte-identical. V2 requires paired spec metadata, permits null spec_digest, and bounds optional argv. No architecture rule changed.
- Dispatcher and installer include the new compliance wrapper, the previously omitted audit wrapper, and optional EU templates.
- Matrix, fictional examples, ISO map, tests, README, CHANGELOG, plan and package record behavior and limits. No VERSION or trust-ci source change.

## Fresh controls after scoped recovery

All commands below ran in this worktree at the exact checkpoint above. Tracked state was clean
after the commands. Subsequent edits only record these observations and the reviewing lifecycle.

| Command | Actual result |
| --- | --- |
| taskset -c 0-25 python3 -m pytest -q -n 15 -p no:cacheprovider --tb=short tests/test_eu_ai_act.py tests/test_compliance_scaffold.py tests/test_ai_transparency_template.py tests/test_eu_audit_attestation.py tests/test_getzilla_cli.py tests/test_install_on_demand.py tests/test_manifest_package.py tests/test_structure.py | exit0;151 passed,1 skipped,156 subtests passed in13.94s |
| python3 scripts/getzilla_architecture.py fitness --base e158ddc7263a55f5308944c5a426eb1e9f1a4327 --worktree --json | exit0; fitness_status pass; required scopes architecture and contract; risk yellow from new_contract |
| python3 scripts/getzilla_spec.py validate --change-id 20261021-task-44fe06 --gate | exit0; oktrue; no errors; all8 criteria mapped |
| python3 scripts/getzilla_governance.py validate | exit0; overall_status pass; no findings |
| ruff check .getzilla/getzilla/eu_ai_act.py .getzilla/getzilla/compliance_scaffold.py .getzilla/templates/eu-ai-act/transparency/python/ai_transparency.py scripts/getzilla_audit_bundle.py scripts/getzilla_compliance.py scripts/getzilla_cli.py scripts/install_into.py tests/test_eu_ai_act.py tests/test_eu_audit_attestation.py tests/test_compliance_scaffold.py tests/test_ai_transparency_template.py tests/test_getzilla_cli.py | exit0; All checks passed |
| bandit -q -c bandit.yaml .getzilla/getzilla/eu_ai_act.py .getzilla/getzilla/compliance_scaffold.py .getzilla/templates/eu-ai-act/transparency/python/ai_transparency.py scripts/getzilla_audit_bundle.py scripts/getzilla_compliance.py | exit0; no findings |
| git diff --exit-code e158ddc7263a55f5308944c5a426eb1e9f1a4327 HEAD -- engineering/contracts/schemas/trust-ci-attestation-envelope.v1.json | exit0; no output; v1 bytes unchanged |

The tests include the final v2 paired-metadata correction. No signed cryptographic integration
is inferred from these results. The one skipped test remains skipped, not passed.

## Observed controls before the final correction

All observations below apply to intermediate worktrees based on the base above. They are not
fingerprint-bound receipts and do not qualify this checkpoint.

- Initial red run: taskset -c 0-25 python3 -m pytest -q -n 20 -p no:cacheprovider tests/test_eu_ai_act.py tests/test_compliance_scaffold.py tests/test_ai_transparency_template.py tests/test_eu_audit_attestation.py tests/test_getzilla_cli.py. Result:41 failures including subtests,29 passed,47 subtests passed in3.66s.
- Initial implementation run: same five modules with --tb=short. Result:49 passed,97 subtests passed in14.93s.
- Expanded run: taskset -c 0-25 python3 -m pytest -q -n 20 -p no:cacheprovider --tb=short tests/test_eu_ai_act.py tests/test_compliance_scaffold.py tests/test_ai_transparency_template.py tests/test_eu_audit_attestation.py tests/test_getzilla_cli.py tests/test_install_on_demand.py tests/test_manifest_package.py. Result:117 passed,1 skipped,111 subtests passed in12.61s.
- Later expanded run after symlink and bytecode fixes:119 passed,1 skipped,111 subtests passed in32.59s. This predates the final v2 schema metadata correction and fixture update.
- Additional red tests reproduced malformed opt-in, template symlink following, Python cache writes and missing required v2 paired metadata. Each caused an observed failure before its repair. The fresh run above now covers the final metadata repair.
- Spec gate, changed Python Ruff and changed production Python Bandit each passed in separate direct calls before the final v2 correction. Governance validate passed. Initial architecture rejected same-version signed-schema changes; adding v2 made architecture fitness pass. Diagram --check --json reported no mismatches, so generated views did not change. A read-only git diff --exit-code confirmed v1 bytes match the base.

## Validation blocker and scoped recovery

First denied batch: getzilla_par -j3 combining spec validate, Ruff and Bandit. Denial:
"Blocked opaque control-plane shell mutation; split the command or use Edit/Write/apply_patch so
targets are explicit repository-relative paths. Do not create a protected-path grant until the exact
targets are known." The allowed rewrite split the three commands into parallel tool calls; all ran.

A later batch combined focused pytest with18workers, architecture fitness and Ruff through
getzilla_par -j3. The hook matched the prior objective and returned:
"Circuit breaker: the rewritten invocation was denied for the same objective. Do not retry this
objective again or create a speculative grant. Stop dependent subagents, mark this objective
BLOCKED, and report the blocker. Original denial: Blocked opaque control-plane shell mutation."
No process in that final batch started. The full two invocations and denial text were sent to the
coordinator. The objective stopped as BLOCKED. The earlier owner recovery covered plan writes only.
The new exact owner reply above overrides only this validation retry stop. The scope, reason,
deferred checks and required follow-up are recorded in scope-and-decisions.md. The direct checks
above ran after checkpoint commit. Their observed results close this bounded validation blocker.

## Pending work and limits

Commit the source with package state reviewing, then run the named clean committed-HEAD quality-gates
smoke. Report its exact identity and result to the coordinator without a later source edit. Collect
the four independent reviews. The coordinator persists reports and runs one final PR gate and required
exact-head public linux/windows checks. No full verifier, review receipt, push or external check ran here.

The Trust CI successor must implement v2 signing/verification, policy-owned argv and opt-in wiring.
Core process tests exercise the protocol with fixture executables. Claim tests mock the verified
payload boundary. They do not prove real signature validation. Actual signed v2 integration remains
required in the successor. Overall phase2 completion depends on it.

Node v24.22.0 behavior was exercised using the template's shared JavaScript/TypeScript syntax.
No TypeScript typecheck, real C2PA signing, production marking or legal conformity is claimed.
Static symbols and generic AIA-15 verification do not establish tenant, PII, model robustness,
quality, latency, cost or deletion evidence. Examples are fictional. Full bundle registries need
sharing approval. The verifier executable and public key remain operator trust inputs.

## Rollback and successor interface

Revert this source commit through a reviewed PR if needed. No database or production state changed.
Stop v2 producer emission before rolling back its verifier/schema readers. Keep old v1 envelopes
unchanged. Templates never overwrite an adapter or replace original media.

Successor command argv: [python3, scripts/getzilla_audit_bundle.py, --ci-check]. Supply the runner-owned
TRUST_CI_BASE_SHA and repository identity; reject TRUST_CI_* overrides for opted-in policies. A passed
job plus a pass/int0 command and exact repository/base/head in a verified v2 payload can qualify EU
execution. V1 never qualifies, even if raw dictionaries contain argv. A signature covers execution,
not regenerated bundle bytes. No deployed policy, private key or production action is authorized.
