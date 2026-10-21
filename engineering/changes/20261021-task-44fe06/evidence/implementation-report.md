# Core implementation and repair evidence

Date: 2026-10-21. Branch: feat/eu-ai-act-phase2-20261021. Route:44fe064efbab.
Current comparison base: 287e64f99b01db44cb6eeeb10f307ccda6f91c1d.
Original comparison base: e158ddc7263a55f5308944c5a426eb1e9f1a4327.
Initial tree: 9a7fb672e44de0d3d87e37a70fa4861d37681ce6.

## Repair after the first qualifying gate

Qualification remains UNVERIFIED. Four wave3 reviews passed before the coordinator froze
d7f91344feda5031cc67130b4d772ad4e6f464f3, tree3e5e2bd4951340f35646495afbe66bee71ace594,
fingerprintb80425f7c514c1c65a602f46688ea7c7be3dda242fe040859569f9bfd8ac80d4.
The complete reports remain unchanged. Their claims are historical after this test-only repair.

The final local gate on that frozen source failed:8 failed,2307 passed,17 skipped,4013 subtests.
Coverage reached81.76%, but the failed test run did not qualify. The selector used full-pr-suite,
reason out-of-scope-or-invalid-paths, changed-path digest
090abc993fb25c2520daa1706a3cacc39baa2f9eb56c43c22ddf54fcf32f66d4 and no scope skips.
The preserved failed receipt SHA256 is
f4353665d12506a07ab4b9a4f6b38222007e712a939cf43ba60326e9a8076086.
No passing final verification or review receipt was created. Delivery PR:
https://github.com/Dimkox/Getzilla/pull/127. Frozen d7f91344 was transported as UNVERIFIED using
source grant9bd794918ce8811a and canonical shared-Git grant91c3a034061519f3. The successful exact
SHA refspec left canonical main unchanged. The PR target was f9f02dd53ba9f6e69d51ae5322df0c96e3d41b02;
the recorded comparison base remains287e64. No rebase is required for that unrelated target change.

Current-head triage separated two existing test-environment defects:

- Six affected methods without coverage or runner PYTHONPATH passed:6 tests,30 subtests in7.07s.
- Coverage alone reproduced only the huge-argv time assertion:8.8017s exceeded8s, while the deny verdict was correct. Result:1 failed,5 passed,30 subtests in24.85s. The unchanged74% coverage threshold also rejected this diagnostic subset at9.17%.
- The runner's source/tests/.getzilla PYTHONPATH, without coverage, reproduced all five hook-method failures:7 failures and28 passing subtests in8.65s. Healthy source imports hid the fixture's deliberately broken policy or fsx. Expected degraded events were absent, a broken self-test passed and a high-risk synthetic payload was allowed.
- The new poisoned-PYTHONPATH regression failed before repair:0 degraded events instead of2, exit1 in3.71s. No destructive payload was executed.

The explorer proved that the implicated tests, hooks, policy, enforcement and runner were
byte-identical to base287e64. Exact-base execution is BLOCKED after an authoritative extraction
denial. No baseline test ran; static parity does not prove a baseline runtime failure. The private
triage report and exact commands are in canonical scratch
eu-act-reviews-20261021/core-fullgate-triage-d7f9134.md. The baseline report is in eu-baseline-kOAMw6/analysis.md.

Public Linux CI independently ran2331 tests with21 skips and one error: the new V2 schema test
could not import jsonschema. The local host's undeclared Debian4.10.3 installation hid that omission.
The Linux log is preserved in canonical scratch eu-act-reviews-20261021/core-linux-d7f9134-failure.txt.
Serial unittest had no hook failures. These results do not replace fresh exact-head CI.

The coordinator approved this bounded repair:

- Bind run_hook subprocess PYTHONPATH to the fixture root and fixture/.getzilla. Preserve the remaining environment, including coverage variables. Scope the direct enforcement API self-test the same way.
- Keep the original huge-argv policy call and deny assertion under coverage. Deterministic controls prove the3s deadline and20000-entry limit using an ordinary non-secret read: an exhausted budget gives the marker and denies; an unspent budget allows. A second ordinary Python child imports the same fixture policy, clears its scan cache and evaluates the same payload. The coordinator explicitly refined the test contract to CPU process_time<8s, wall time as an observation and a15s child timeout. Assert no trace/profile/monitoring and exact fixture module origins. No skip, retry, tracer stop, product-budget change or coverage exclusion.
- Declare test-only jsonschema==4.26.0 for real Draft2020-12 V2/legacy contract validation. No existing repository pin existed. The [official release](https://pypi.org/project/jsonschema/4.26.0/) supports Python>=3.10. Do not change global Python or runtime dependencies.

Repair observations so far:

- Runner-PYTHONPATH plus coverage diagnostic passed all7 affected methods and30 subtests in47.73s. Exit1 came only from the unchanged74% aggregate threshold: this subset covered9.03%. This is a test observation, not a passing coverage gate.
- A concurrent six-module run returned2 failed,96 passed,389 subtests in50.65s. The first failure was a removed time import still needed by the glob test; the import is restored. The ordinary timed child also measured9.7127s under concurrent20+6-worker load. One authorized isolated probe then measured wall4.2242174698s and process CPU4.223540568s, with no trace/profile/monitoring, cold cache and matching fixture source. This exposed the initial recommendation's failure to separate work from scheduling delay. The approved CPU-bound contract above replaces the wall assertion; it does not promise wall<8s under arbitrary load.
- Before changing the timing assertion, the two deterministic deadline/entry controls passed with4 subtests in3.68s. Both allow and deny controls use an ordinary source path, so a secret suffix cannot hide a broken budget.
- After the approved timing refinement, the six-module hook/policy run with the runner's source/tests/.getzilla PYTHONPATH passed100 tests and393 subtests in17.55s. Command: `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=<candidate>:<candidate>/tests:<candidate>/.getzilla taskset -c 0-23 python3 -m pytest -q -n 24 -p no:cacheprovider --tb=short tests/test_hook_degraded.py tests/test_enforcement_report.py tests/test_degraded_fail_closed.py tests/test_policy_hardening.py tests/test_hooks.py tests/test_hook_encoding.py`. The architect used the remaining two CPUs; no second heavy suite competed with the timing child.
- Changed-test Ruff and git diff --check passed after restoring the import.
- Typed spec validation passed with all8 criteria mapped, and governance passed without findings. Architecture initially failed on tests/test_hook_degraded.py: FIT-BOUNDED-WORKER-JOBS, queue_provenance_unresolved. The touched module exposes the existing chain verification→receipts→review_source→state→agent_lifecycle→policy→_policy_legacy→cost_guard→risk_terms:9 modules exceed the unchanged depth limit8. The architect confirmed this with a bounded private probe. Move the new regression, with all its assertions, to the lighter test_degraded_fail_closed.py and restore test_hook_degraded.py exactly to d7f91344. No architecture rule or analyzer changed.
- After relocation, the two affected modules passed9 tests and30 subtests in5.70s with the runner PYTHONPATH and24 workers. Architecture fitness passed with only new_contract risk and no findings. Changed-test Ruff passed. A read-only diff confirmed the restored test module, hooks, policy, runner, coverage configuration, schemas and all four wave3 reports matchd7f91344.
- Requirement-binding controls passed114 tests and190 subtests, with4 skips, in25.49s: `taskset -c 0-23 python3 -m pytest -q -n 24 -p no:cacheprovider --tb=short tests/test_ci_gate.py tests/test_install_scripts.py tests/test_project_state.py tests/test_python_test_runner.py`. Skips are not passes.
- Final covered diagnostic ran alone with26 workers after relocation and the approved CPU/budget assertions:9 tests and34 subtests passed in20.56s. Its exit1 came only from aggregate coverage9.85% below the unchanged74% threshold. This subset is not a passing coverage gate. The original policy verdict remained covered; the child proved fixture origins and no trace/profile/monitoring.
- A fresh venv exists at canonical scratch eu-act-reviews-20261021/schema-venv. Its dependency installation never ran: a direct venv pip command was denied as opaque control-plane mutation, and the one explicit python3 -m pip --python rewrite hit the same-objective circuit breaker. No exact protected target was named. This exact optional objective stays BLOCKED/NOT_RUN. Do not retry, request a speculative grant, change global Python or claim the4.26.0 test passed.

Blocked install commands, in order:

1. `/home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/schema-venv/bin/python -m pip install --disable-pip-version-check -r /home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-phase2/.getzilla/config/python-test-requirements.txt`
2. `python3 -m pip --python /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/schema-venv/bin/python install --disable-pip-version-check -r /home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-phase2/.getzilla/config/python-test-requirements.txt`

The first denial required explicit protected targets for an opaque mutation; it named none.
The second denial explicitly prohibited further retry for the same objective. Static pip-guard
diagnosis by the explorer also stopped after its own circuit-breaker denial. The fresh interpreter
has no installed test requirements and is not ready for the full gate. Host4.10.3 observations
remain separate from the pending pinned4.26.0 execution.

Final process ruling: the fresh scratch install was an optional diagnostic, not a route or skill
prerequisite. Stopping every review and qualifying gate because of it was too broad. Keep this
objective blocked without an alternative installation. Required local controls and the unchanged
final gate use the existing host jsonschema4.10.3 and do not prove installation of4.26.0. The normal
required exact-head GitHub CI job installs declared pins; it is a separate gate, not a dispatch or
replacement of the denied local action. If a required gate itself requires the blocked operation,
stop that dependent gate. No circuit-breaker override or fake PASS is created by this ruling.

The coordinator then found foreign remote head55e7cb05a9be4648012086664d2b1e001cc81300 on PR127.
The writer made no commit or push before that finding and stopped source work for inspection.
Its parent05d3e6c merges actual mainf9f02dd53ba9f6e69d51ae5322df0c96e3d41b02 into d7f91344;
55e7cb05 changes the compliance CLI, installer and EU/install tests. Preserve this authorized work.
The coordinator approved a test-repair checkpoint followed by a no-ff merge of that exact remote
head, with no reset/rebase/force. Refresh the comparison base through the official API only after
the merge, retain its history, and run affected CLI/install controls before source state reviewing.
All current observations above become historical across that integration. No final PASS is claimed.
The coordinator owns the next report freeze, final local gate and required public linux/windows
checks. Six Low gaps remain deferred at https://github.com/Dimkox/Getzilla/issues/122.

## Historical repair after the second review wave

Current qualification is UNVERIFIED. All four wave2 reports returned FAIL and remain unchanged
from report commit b23baf3af48864a87b858116fe7684d2f2d14e79, tree3a7ec725b7dc34987990553ba4bd0157d5e13cd4.
They reviewed source61827791b7f49a5ad340a62f07756888a03964a3, tree96612a25a2dca3ed8e306f622e82ed2c8b3cbecf,
fingerprint53a32ef677284d79a7de11b13b81176fce0e520d485d247c522883f21cb5c733, on current base287e64.
The earlier complete first-wave reports remain in Git at4abde00. The prior 61827791 smoke passed
in0.101s with stable source and no receipt; that observation is historical after this repair.

Repair scope is only the two confirmed Medium findings. Six Low test gaps, including the new
first-use provider-cache gap, stay deferred together at https://github.com/Dimkox/Getzilla/issues/122.
The existing scoped validation recovery still requires separate direct commands. No getzilla_par
retry, hook change, receipt creation, production action or external check is part of this batch.

- Derive required opt-in and required input presence from captured committed config. No live enabled() read authorizes the audit. CI rejects null or skipped EU reports before producing a decision.
- Preserve receipt ignore behavior only for untracked ls-files. Its bounded runner keeps normal global/system config, restores only the three GIT_CONFIG_GLOBAL/SYSTEM/NOSYSTEM overrides, and removes Git location/index/object/inline-config overrides. Strictly resolved git-dir and work-tree pin its identity. Replacement objects, fsmonitor, untracked cache and protocol access stay disabled.
- Keep strict Git reads for HEAD/base, capture, blobs and tracked changes. Keep util.tree_fingerprint and receipt format unchanged. Limit the compatibility inventory to16MiB and30seconds, validate NUL-delimited relative paths, and terminate/reap the owned process on failure.

Observed controls before the source commit:

- Red: taskset -c 0-25 python3 -m pytest -q -n 12 -p no:cacheprovider --tb=short tests/test_eu_audit_attestation.py -k 'opt_in_swap or null_or_skipped or global_and_system or global_excludes_cannot or global_ignore_cannot' returned7failed,2passed in2.41s. The real-read swap reproduced the CI opt-in race. Null/skip and global/system ignore assertions also failed. One failure was fixture setup: applying the ignore before initial commit prevented tracking the required rule file. The fixture now commits before applying that ignore.
- Additional red/control: the two named global-ignore input and bounded-inventory tests returned1failed,1passed in1.46s. The input control passed after the fixture correction; the bounded runner API was not yet present.
- Fresh focused run: taskset -c 0-25 python3 -m pytest -q -n 20 -p no:cacheprovider --tb=short tests/test_eu_audit_attestation.py tests/test_eu_ai_act.py returned48passed,67subtests passed in9.53s. It covers real swap reads, private global/system excludes, fixture receipt eligibility, unignored changes, location/index/object/config redirection, ignored decision inputs, process timeout/output limits and malformed path output.
- ruff check scripts/getzilla_audit_bundle.py tests/test_eu_audit_attestation.py returned exit0, All checks passed.
- bandit -q -c bandit.yaml scripts/getzilla_audit_bundle.py returned exit0 with no findings.
- python3 scripts/getzilla_architecture.py fitness --base 287e64f99b01db44cb6eeeb10f307ccda6f91c1d --worktree --json returned exit0, fitness_status pass, required scopes architecture/contract and risk yellow from new_contract.
- python3 scripts/getzilla_spec.py validate --change-id 20261021-task-44fe06 --gate returned exit0, ok true, no errors and all8criteria mapped. The observed working-tree fingerprint was21964a3d06367f2db93c50d85dd75803566857fa2603916d2786231c2ec46d81.
- python3 scripts/getzilla_governance.py validate returned exit0, overall_status pass and no findings. git diff --check returned exit0 with no output.
- Read-only git diff --exit-code confirmed all four wave2 reports and util.py matchb23baf3. V1, trust-ci and architecture/rules.yaml matchbase287e64. The controls ran on this working repair based onb23baf3; later changes only record observations and lifecycle state.

Bounded controls passed. The source is prepared in state reviewing. Commit it, then run the fresh
committed-HEAD smoke and collect four independent reviews. No full PR gate has run. All older
sections below are historical. These observations create no verification or review receipt.

## Repair after the first review wave

Bounded repair controls passed. Qualification remains UNVERIFIED until fresh independent reviews and final gates finish.
All four complete first-wave reports remain in Git as historical evidence. Their source was
5e8b8734739c7f59f6c3af56b82dedc02fb1dcc5, tree 71beaeabf6e15d70a800333dced87e69f3ee33c5.
The coordinator saved them in 4abde003d25997c2d6cd86af20e046f005367a67. Code/security review found
three Medium defects. Five Low test gaps are deferred together to
https://github.com/Dimkox/Getzilla/issues/122 and were not repaired in this batch.

Rebase onto actual fetched origin/main e42398ddaa41e662e921d7af68ab87b1e28e3554 completed without
conflicts. The rebased report HEAD is 5613f7fa2544b3e7ed2e6fc687aca515f19fc2a4,
tree 378942329a8111ddbc10bd8b53b2bbc340ee7c36. The official update_route API changed the comparison
base and recorded its history. It retained route44fe064efbab and the original creation fingerprint.
Canonical main, Trust CI source, V1 schema and deployed systems were not changed by this writer.

Repair checkpoint aa009d58e87785a0b09ec7222d2a0c49fd780961 then rebased onto actual fetched
origin/main a103b373031f477efad0e7bd9ffab24a96e6c63f after PR123 and PR124. The resulting HEAD is
ab523c9d943da7acdbed2f6a1bed8d7909a6723e, tree 1f88fcbcb43b28bd469e812c2675afccd26cca6c.
Text conflicts kept both groups of CHANGELOG/mistakes entries. The installer diff against this base
only adds the audit/compliance wrappers and optional EU templates. The official update_route API
appended the second base transition. The history retains e158, e423 and a103 identities.

After those controls, the coordinator reported merged PR125 at actual origin/main
287e64f99b01db44cb6eeeb10f307ccda6f91c1d. Source bf86edbc57092d083a235ca96329eaf6aa505785 rebased
without conflicts to 607d85c67b205ccc7f983d717908d8202b806506, tree ce9bd35c6ba9397a0e2f4fc89eef9510e75a0cd4.
The official update_route API appended the a103-to-287e64 history. The only new main paths are
router.py, docs/INVESTOR_DEMO.md, tests/test_demo.py and tests/test_risk_task_focus.py. A read-only
git diff --exit-code from585edde8 over all EU production files, data, templates, contracts and the
15 focused test modules returned exit0 with no output. Those product bytes are unchanged.
The212-test observations below are historical on585edde8, not a new-base verification receipt.
Per the bounded rerun ruling, only the clean committed-HEAD smoke is repeated before fresh reviews.
The unchanged final qualifying PR gate remains required on the new base.

Repairs:

- Bind compliance.json, obligations.json, ai-systems.json, diff-risk-rules.json and cost-providers.json to committed bytes. Only the registry can be absent in both HEAD and disk for an enabled audit. Compare committed and present executable inputs to catch hidden deletion.
- Pass immutable committed data explicitly through evaluation. Reuse existing parsers, bypass cached provider path loads, and preserve ordinary --root. Capture one UTC date and resolve head/base once. Read optional ISO/VERSION from that commit.
- Reuse sanitized Git reads with replacement objects disabled. A local audit fingerprint helper retains the existing receipt grammar and compares paths against the captured commit. The global util is unchanged.
- Refuse scaffold before any creation without descriptor-relative safe creation, including Windows. Help, docs and acceptance state the manual-template option. No Win32 subsystem was added.
- Use SIGKILL for the Node child timeout. Real-process regression cleanup kills and reaps the fixture group on an outer timeout.

Observed repair controls before the final fingerprint correction:

- Red pytest run with 26 workers over audit/scaffold/template modules: 11 failed, 22 passed, 27 subtests passed in 38.13s. Failures reproduced ignored rules/providers, hidden deletion, foreign defaults, moving HEAD, inherited Git state, Windows mutation and a Node child still running after 35 seconds. Cleanup killed and reaped the fixture group.
- An intermediate run reported 2 failed, 51 passed, 70 subtests passed in 49.01s. The audit fixture omitted generates_content:false. A later assertion expected BLOCK where the existing policy gives REVIEW for an unregistered provider. Both fixture assumptions were corrected without changing production decisions.
- That intermediate Node run exceeded its 35-second outer guard. An exact-template standalone probe completed in 30.12 seconds with c2patool timeout and unchanged input. The next targeted Node test and fresh four-module run passed. The final test gives Node startup and CI scheduling a 45-second outer guard; the actual tool deadline remains 30 seconds. The cause of the one intermediate outer timeout was not established.
- Fresh four-module run: taskset -c 0-25 python3 -m pytest -q -n 20 -p no:cacheprovider --tb=short tests/test_eu_audit_attestation.py tests/test_compliance_scaffold.py tests/test_ai_transparency_template.py tests/test_eu_ai_act.py: 53 passed, 70 subtests passed in 36.20s.
- Adjacent helper/install run: taskset -c 0-25 python3 -m pytest -q -n 20 -p no:cacheprovider --tb=short tests/test_project_ingestion_routing.py tests/test_cost_guard_diff.py tests/test_diff_risk.py tests/test_cost_guard_prompt.py tests/test_cost_contract.py tests/test_cost_schedule.py tests/test_getzilla_cli.py tests/test_install_on_demand.py tests/test_manifest_package.py tests/test_structure.py: 152 passed, 1 skipped, 129 subtests passed in 86.21s.
- Architecture fitness against e42398d, typed spec gate, governance, Ruff and Bandit passed before the final fingerprint correction. First-wave reports and V1 bytes stayed unchanged; git diff --check passed.
- Two named build tests for inherited Git/replace state and moving HEAD failed in 3.04s, then passed in 1.33s after the local fingerprint correction. They preserve the existing receipt grammar, including an untracked note. Fresh post-repair controls remain required.

## Historical repair controls before the non-overlapping PR125 rebase

All controls below ran on clean checkpoint 585edde8be99ad2145a389dd86164daf2e2fc1c7,
tree 011d43f5d873e105719b96ca36dcb1c68d34b8e3, against base a103b373031f477efad0e7bd9ffab24a96e6c63f.
This includes the final fingerprint correction, the 45-second outer Node test guard and the rebase.
Status remained clean. The checkpoint diff was 49 files, 3177 insertions and 307 deletions.
Later tracked edits only record these observations and the reviewing lifecycle.

| Command | Actual result |
| --- | --- |
| taskset -c 0-25 python3 -m pytest -q -n 20 -p no:cacheprovider --tb=short tests/test_eu_audit_attestation.py tests/test_compliance_scaffold.py tests/test_ai_transparency_template.py tests/test_eu_ai_act.py tests/test_project_ingestion_routing.py tests/test_cost_guard_diff.py tests/test_diff_risk.py tests/test_cost_guard_prompt.py tests/test_cost_contract.py tests/test_cost_schedule.py tests/test_getzilla_cli.py tests/test_install_on_demand.py tests/test_manifest_package.py tests/test_structure.py tests/test_install_extras.py | exit0; 212 passed, 1 skipped, 199 subtests passed in 33.90s |
| python3 scripts/getzilla_architecture.py fitness --base a103b373031f477efad0e7bd9ffab24a96e6c63f --worktree --json | exit0; fitness_status pass; scopes architecture and contract; risk yellow from new_contract |
| python3 scripts/getzilla_spec.py validate --change-id 20261021-task-44fe06 --gate | exit0; ok true; no errors; all 8 criteria mapped |
| python3 scripts/getzilla_governance.py validate | exit0; overall_status pass; no findings |
| ruff check .getzilla/getzilla/eu_ai_act.py .getzilla/getzilla/compliance_scaffold.py .getzilla/getzilla/diff_risk.py .getzilla/getzilla/cost_guard.py .getzilla/getzilla/project_ingestion.py .getzilla/templates/eu-ai-act/transparency/python/ai_transparency.py scripts/getzilla_audit_bundle.py scripts/getzilla_compliance.py scripts/getzilla_cli.py scripts/install_into.py tests/test_eu_ai_act.py tests/test_eu_audit_attestation.py tests/test_compliance_scaffold.py tests/test_ai_transparency_template.py tests/test_getzilla_cli.py | exit0; All checks passed |
| bandit -q -c bandit.yaml .getzilla/getzilla/eu_ai_act.py .getzilla/getzilla/compliance_scaffold.py .getzilla/getzilla/diff_risk.py .getzilla/getzilla/cost_guard.py .getzilla/getzilla/project_ingestion.py .getzilla/templates/eu-ai-act/transparency/python/ai_transparency.py scripts/getzilla_audit_bundle.py scripts/getzilla_compliance.py | exit0; no findings |
| git diff --check a103b373031f477efad0e7bd9ffab24a96e6c63f HEAD | exit0; no output |

Read-only git diff --exit-code confirmed that v1 matches the current base and all four first-wave
reports match their original report commit 4abde003d25997c2d6cd86af20e046f005367a67.
The Windows refusal tests emulate the platform and reject creation before the swap callback can run.
Native Windows was not available. The Node test used a real POSIX child that ignored SIGTERM;
the adapter stopped it and preserved the original media. No receipt or review PASS was created.

The named smoke also passed on bf86edbc57092d083a235ca96329eaf6aa505785,
tree bcf2f780b2f90df0c16f55ef6c9e32afec4052d9: GETZILLA_TEST_WORKERS=22 taskset -c 0-21 python3
scripts/getzilla_verify.py --mode fast --no-record --test tests.test_quality_gates --budget 180.
Observed exit0, python-named-smoke0.158s and source-stability PASS; receipt not_recorded.
That smoke is historical after the PR125 rebase. The next committed source requires its own smoke.

## Historical first-source controls

The initial Core source was implemented. Bounded controls passed on checkpoint
fdc02defb766fea9372e939b90180ea37342e2f6, tree f96e020ca5e3018bb593748cf5a36c6e4331c158.
That checkpoint changed42 files with2464 insertions and282 deletions against the base.
The initial source then received committed-HEAD smoke and the first independent review wave.
These controls are historical observations, not receipts or merge authority for the repair.

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

## Historical controls after scoped recovery

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

The source is prepared in package state reviewing. Run the named clean committed-HEAD quality-gates
smoke next. Report its exact identity and result to the coordinator without a later source edit. Collect
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
