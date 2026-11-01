# Getzilla v2.3.1

> **Origin.** Getzilla is the renamed successor of the [predecessor project](https://github.com/Dimkox/adaptive-grok-build-pro/tree/c4e506f3d3a45e000f5b9f9121f698c1d16814e3). This repository was started on 2026-10-05 from that project's final PR #242 head (identical to its merged main commit `f97966c`) `c4e506f3d3a45e000f5b9f9121f698c1d16814e3` without its git history. Pull-request numbers, releases, tags and checks mentioned in historical sections below belong to the predecessor repository. Renamed: the core package and stack (`.getzilla/getzilla`), `scripts/getzilla_*.py`, `getzilla_factory`, `getzilla_delivery` and the `GETZILLA_*` test variables. Kept on purpose: the Grok Build CLI contract (`.grok/`), Grok provider settings, the deployed Trust CI identity (`adaptive-trust-ci/verified`, App `adaptive-trust-ci`) and L5 runtime paths (`adaptive-l5`). Installs made before the rename are upgraded through `scripts/install_into.py --plan`, which reports the pre-rename stack files for retirement.

MIT-licensed tooling for task-routed AI-assisted development, external verification and human-controlled delivery with **Grok Build**.

## What it does in five minutes

The initial route is provisional. Commit source, then run `python3 scripts/getzilla_route.py --reconcile --json` before dispatching reviewers. A complete assessment binds the trusted base, exact HEAD/tree, policy digest and plan. One ordinary code reviewer covers correctness and test adequacy; security/data/release audits require both a changed sensitivity category and its configured risk threshold. Prompt words and background repository domains do not select audits. Add and retain an explicitly requested reviewer with `--add-reviewer test_reviewer` (repeat for other roles). Existing legacy selections remain. A file Git identifies as binary with a regular, non-executable file mode (an image, a PDF; not a library, bytecode or archive) is high risk and takes the full review profile. Dirty, unknown or otherwise incomplete source inventory, including source code that turned binary, cannot qualify; final verification rederives the plan and receipts bind its digest.

`python3 scripts/getzilla_report.py --since all --json` reports bounded local observations by route and session. Successful grant materializations are counts of persisted grants, not counts of human interventions. Fast-lane coverage uses measured admission with an explicit known/unknown denominator. Failed check/review outcomes are not confirmed defects. Exact commit/line denominators require a complete Git inventory. Costs, CI minutes, confirmed before-merge findings and introduced tracked evidence at the actual merged head remain null when their evidence is unavailable; session end is not merge evidence.

Import provider facts explicitly with `python3 scripts/getzilla_report.py --import-observations .getzilla/runtime/scratch/observations.json --json`. The bounded JSON list uses schema_version 2, stable event_id, UTC at, event (`ci`, `merge`, `cost`, `finding`), route_id, session_id, exact head/base/tree, source (`github`, `codex`, `bandit`, `review`) and source_ref (a stable provider ID). CI uses seconds; cost uses amount and currency USD; a finding uses finding_id and confirmed. No automatic provider call or authority is created. Unknown costs remain null; an observed zero is zero. Malformed rows, conflicting replays and unsafe files are disclosed as coverage gaps. The journal is ignored runtime evidence; these observations do not establish savings or the issue's empirical targets by themselves.

Historical mistakes are preserved byte-for-byte in [dated incidents](../engineering/incidents/README.md), with source ranges and hashes. [Recurring lessons](../engineering/mistakes.md) link distinct occurrences and countermeasures. Root [mistakes.md](../mistakes.md) retains the compatibility entrypoint and exact governance projection.

Getzilla installs a local Grok/Codex-style agent workflow into another repository. The short path is:

1. inspect a target repository without changing it;
2. apply the accepted plan as a reviewed branch change in the target repository;
3. let the agent route the task on its own branch; create a runtime change package when the selected delivery lane requires one;
4. run local verification and review evidence;
5. ship through a pull request instead of trusting chat output.

External merge checks follow repository visibility: GitHub Actions for public repositories, paid Trust CI with its configured signed approvals and holdout checks for private repositories. Local exploration and installation planning do not grant merge authority.

## Working order

Route the task automatically and explore on its own branch. Keep bounded low-risk exploration free of a change package or review wave until delivery needs them. Commit the candidate and reconcile the route with its exact diff before selecting reviews and final verification. The [delivery contract](../AGENTS.md#delivery-contract) defines light, full and release qualification; [QUICKSTART.md](../QUICKSTART.md) shows the commands. Nothing merges without the selected reviews, qualifying local evidence and required external exact-head checks.

## First run: simple path

```bash
git clone https://github.com/Dimkox/Getzilla.git
cd Getzilla
python3 scripts/getzilla_doctor.py --offer-install
python3 scripts/install_into.py --plan /absolute/path/to/your/repo
```

For an existing repository the installer only reads and reports a plan. Apply that plan manually as a reviewed change in a normal branch of the target repository. For a brand-new Linux target, use an absent path:

```bash
python3 scripts/install_into.py --materialize-new /absolute/path/to/new/repo
```

Then open the target in Grok, trust the project hooks, and give one concrete task. The local loop is:

```bash
cd /absolute/path/to/your/repo
python3 scripts/getzilla_route.py "Добавить поведение с явными критериями приёмки" --session first-task --json
python3 scripts/getzilla_status.py
```

This starts the local task. Follow the [quickstart delivery steps](../QUICKSTART.md) to select a package, reviews and final verifier from the actual diff. An admitted light change uses `--mode fast` without a package; full delivery uses `--mode pr` and a typed runtime package unless the existing low-risk docs/micro exemption applies. Fast can still discover the full test suite. Local work does not grant merge, deployment or production authority.

## What this repository contains

The [ADLC handoff map](adlc-handoffs.md) records phases, owners, existing artifacts and evidence gaps. The [media design](media-production.md) and [ADR](../engineering/adr/0002-media-production.md) include a bounded offline synthetic example under `examples/media-design/`. It is available in the source checkout/archive; the consumer installer does not install it. It performs planning only, with execution and paid operations disabled.

- `scripts/install_into.py`: read-only install planning for existing repos and no-replace materialization for absent repos.
- `.agents/skills/`: domain skills for agent work, including Bitrix, API/events, frontend, data, security and release tasks.
- `.getzilla/`: local routing, verification, architecture, governance and receipt code.
- `factory/`, `delivery/`, `pilot/`: default-off factory, staged delivery and pilot boundaries.
- `trust-ci/`: separately deployed merge authority for private repositories. Public repositories use GitHub Actions; local installation does not deploy either service.
- `.getzilla/runtime/changes/` and `.getzilla/runtime/reviews/`: ignored local task packages and evidence. Historical tracked `engineering/changes/` records stay unchanged; `decisions.md` and `mistakes.md` retain durable lessons.

## What this is not

- It is not a hosted SaaS.
- It is not a CI service. `python3 scripts/getzilla_ci.py --plan|--write --target <repo>` selects the gate by repository visibility: public → a pinned, read-only GitHub Actions workflow; private → Trust CI (no workflow).
- It is not an automatic merge bot.
- It does not make the agent a production operator by default.
- It does not turn local receipts into merge authority.

## Fail-closed boundaries and current limits

Fail-closed here means that unclear, unknown or out-of-policy input is rejected instead of guessed through.

Boundaries that currently cut execution:

- The installer plans existing repositories read-only. New-target materialization refuses existing targets, symlinks, special files and platforms without the required no-replace filesystem primitives.
- Closed schemas reject unknown keys, malformed JSON and unsupported versions.
- Workflow-source adapters parse bounded artifacts. They do not execute imported shell commands, call networks or ask an LLM to interpret foreign workflow text.
- PR verification leaves the `docs-state-focused` profile when a changed path is outside the explicit allowlist, when Git status is ambiguous, or when the comparison base cannot be trusted. This profile is distinct from measured light-lane admission.
- Merge authority is outside chat and local receipts. It requires a pull request and the configured external checks on its exact head SHA: public GitHub Actions or private App-owned `adaptive-trust-ci/verified@<policy-sha12>`, plus applicable approvals.
- Providers, pilot flows, Linux setup and factory publication are default-off unless a separate operator action enables them.

Known weak seams this line is closing:

- A prose claim is not evidence that a live check exercised the risky path.
- An empty acceptance-criteria set is not coverage.
- A receipt fingerprint without the bound file is not durable evidence.
- A timeout or interrupted verifier is incomplete, not a pass.
- A restarted attempt cannot reuse an old model/config/profile identity without requalification.

Current source admits a light lane for a complete clean low-risk diff of at most 50 added plus deleted code lines, with sensitive paths checked before ordinary tests and prose exclusions. It needs no change package and keeps one ordinary code review as the floor; configured or explicitly retained additional reviews still apply. Full CI remains required. This source feature is separate from published `v2.3.0`. Liqvera is a completed owner-accepted factory-built product; empirical autonomy qualification and production authority remain separate.

## Advanced startup baseline

**Step zero, before all other startup work:** [measure resources](../AGENTS.md#mandatory-startup-algorithm-measure-then-dispatch)—physical/online logical CPUs, process affinity, effective cpuset and finite cgroup quotas; try a bounded child-only affinity expansion when appropriate, derive verified effective capacity and record the snapshot. Only then inspect backlog/routes, build dependencies and dispatch all independent route-permitted work in parallel, spreading eligible heavy work across that capacity. Isolated writer ownership comes next, followed by verification/delivery gates. Remeasure every startup: the September 26 observation of **14 physical / 28 logical CPUs**, with default affinity exposing 22 and a verified `taskset -c 0-27` child exposing 28, is not a permanent guarantee.

The second startup step records trusted base/HEAD and dirty inventory. The merged [fail-closed scope selector](#verification-scope-selection) runs inside the final PR/release gate, after source commit and runtime report persistence and before that gate's heavy checks. Light delivery instead requires positive admission in its final `--mode fast` gate; release mode remains separate. Its closed focused inventory admits named docs/state paths, tracked `packages/**` release bytes, and exactly five binding test modules: `tests/test_structure.py`, `tests/test_project_state.py`, `tests/test_manifest_package.py`, `tests/test_workflow_sources.py` and `tests/test_repo_router.py`. Only that inventory may skip coverage/full discovery/PostgreSQL; all other executable changes, non-admitted paths or ambiguous inventories require full verification.

The past observation of **controller + 12 child-agent slots**, the route's routing cap and test-process workers are separate limits; discover the current harness slots at startup. Keep one writer per isolated task/route/branch/worktree; independent isolated writers may run concurrently. An exact delegated branch push before verification is labelled **UNVERIFIED transport only**. Protected/shared branches prohibit direct pushes; merge requires a PR, the configured public Actions or private Trust CI checks on the exact head and all applicable approvals.

## Current state

Identity: **2.3.1 source candidate**, unpublished. Fetch current refs to establish the source head; dated observations below do not cap the current source inventory. Latest published [v2.3.0](https://github.com/Dimkox/Getzilla/releases/tag/v2.3.0) is immutable: published 2026-10-21T11:01:37Z, annotated tag `815aeabc5d215d65e72651692a6457920de9fa71`, commit `2bb417431f1e4b9494e4af71ebf27adb1d04d898`, tree `81076df2cd7db8713f7178ead66ebaa2728f861e`, with ZIP and checksum assets. This publication does not establish installation, provider activation or production acceptance.

Historical source snapshot on 2026-10-24: `a45fbdd90e4f98e05c2f45c43afb28a63b3e448c`, the PR #179 merge. Since v2.3.0, `main` gained `getzilla update` (#132, #135), the light lane for small changes (#121, #142), exact-diff review plans (#144), disk cleanup for issue #168 (#174–#178) and session-bound protected-path grants (#179). The dated `PROJECT_STATE.json.current_continuation` names the Low batch in issue #134 and the 2.3.1 release; reconcile that handoff with fetched branches and current issues before choosing work.

The finished PR #79 contour (`fix/codex-cmd-hooks-20261011`, route `43786cadd549`, [source package](../engineering/changes/20261012-task-43786c/brief.md)) is kept in `historical_pr79_continuation`. Today, reports and receipts live in ignored runtime storage under `.getzilla/runtime` and in portable evidence exports, not in committed Markdown. PASS receipts require `--reviewed-commit <exact-full-sha>`; runtime consumers recheck exact reviewed HEAD/tree and the report-content hash. Historical tracked receipts retain their legacy compatibility rules. Public Actions linux/windows provide the required exact-head checks. The historical private Trust CI identity is `adaptive-trust-ci/verified@06ecf1c875bc`, App ID `<redacted-app-id>`; this record is not fresh verification. Conditional AGENTS L5 covers exact-grant merge/tag/release after checks, independent review and resolved threads; production mutation, deploy, external writes and human security approvals remain separate.

The native harness executes local tasks. Do not add a daemon or enable providers to complete this source repair. The [historical M8 package](../engineering/changes/20261004-task-b25860/brief.md) and predecessor release records remain dated provenance.

Historical pre-publication core observation: the conditional source included the frozen test-only025 [cursor reset seam](../factory/tests/postgres_fixture_reset.py), its two unchanged-boundary callers and narrowly typed lock-refusal acceptance controls. Pending joined-fitness/source-acceptance statements in that old record remain dated provenance, not current release instructions. F's026 inventory/runtime work remains absent.

The source tree also carries closed default-off BB contracts, an authenticated offline-only model-rotator registry, a bounded explicit-root VibeVM package store, and an opt-in offline Linux setup manager. U4/macOS remains excluded; no component activates providers, models, services, deployment, or production authority.

| Layer | Dated source and runtime observations |
| --- | --- |
| Historical core observation | Historical `main` was `3f41be92161fef451a2dfa7451eb458ce8f022b3`; the pre-publication core comparison base was `63799f8760d3a55028d83ab5ff0116ececf8f7d1`, with source/PR/check/merge/tag unknown in that dated candidate record. The predecessor publication is preserved in `historical_v2_1_1_published_release`; current Getzilla publication is in `published_release`. Historical `2.1.0` custody retains exact source `e5856acfd4bc7a186f40a740b54ec86459462db5`, tree `0dfa04f3ec3ea9c7a04c723e9d127603fc72999b` and its unchanged ZIP/sidecar hashes in `PROJECT_STATE.json`. |
| 2.1.0 candidate capabilities | U5 prediction artifacts are observation-only and require declared history before they can report availability. U6's pinned FPF snapshot can only emit deterministic evaluation evidence; external qualification remains `not_qualified`/not established and all authority effects remain `none`. |
| Installed L5 (September 19) | Primary Qwen is accepted at `f12807c2` / `qwen-omni-intl`; Grok stays accepted at `26a0d3d`. Both are **active and enabled**. Separate Omni remains at `e7d0f72`. |
| Proven runtime result (September 19) | Primary Qwen Omni produced `artifact_ready` in **4.991 s**, usage **766/195**; separate readback made zero POSTs. Grok previously completed in **26.947 s**. [Exact evidence and limits](../engineering/runbooks/l5-primary-continuation-2026-09-19.md). |
| Completed product | M8 **DONE**: owner confirms the working Liqvera Mezo Buildathon demo was built by this factory. Released `v0.0.5` source `19284fb07fedd4909672c7e9a641cb066efbb7cc` pins factory `v2.0.19` / `cb9af4073ba6c3d515145164d771c75ebdfa3224`. Accepted-product dependencies and M8/M9 follow-up planning are unblocked; [exact provenance and boundaries](../PROJECT_STATE.json) distinguish owner acceptance from runtime telemetry. |
| Bounded owner autonomy | One accepted Liqvera case qualifies the enabled local M8 owner policy. Accounting and human readiness are complete by explicit owner confirmation; numeric totals remain unknown. Activate per clone with the commands below. Initial L1 admits only local reads/tests; ceiling L2 confers no external authority. |
| Remaining acceptance | Empirical M7 durable current lookup and exact-profile evidence, general M9 signed environment/recovery qualification, and factory-runtime public-site publication remain unestablished. Another first completed pilot is not required. |

Historical `v2.0.19` delivery records the source line through PR #193 in release-sync PR #189. Its [release-sync change package](../engineering/changes/20260922-release-v2-0-19-from-candidate-5d93fc3-0ea342/brief.md) and [artifact-child package](../engineering/changes/20260924-build-v2-0-19-artifact-child-from-merged-release-09407b/brief.md) preserve separate source verification, artifact provenance and publication; they do not instruct another artifact build, tag or release of published `v2.1.1`.

Source templates default to live execution off. The observed Qwen and Grok services use separately provisioned configurations with live execution explicitly enabled.

- Current source adds [`getzilla-landing-submit`](../engineering/runbooks/l5-provider-failover.md): durable text/safe-DOCX submission through Qwen → Grok → OpenAI → Claude → OpenRouter, authenticated capability/attempt APIs, and atomic SQLite observations. Ambiguous submissions reconcile the same child; existing artifacts prevent further generation. Grok and primary Qwen now have accepted direct runtime results; the three added providers/full chain remain unqualified for inference. Monetary cost remains unknown; publication stays separate.
- Trust CI repository-scoped immutable profiles are implemented in code and documented by the example catalog; the worker uses `TRUST_CI_HOLDOUT_PATH` and `TRUST_CI_HOLDOUT_HOST_PATH` as independently configured trusted roots, validated binary-first before dependency construction. The capability is pending a separately reviewed and approved server-side policy/holdout installation; no deployed policy or branch protection is changed by it.

Start with [START_HERE.md](../START_HERE.md) and [PROJECT_STATE.json](../PROJECT_STATE.json). Runtime operation is described in the [L5 runbook](../engineering/runbooks/l5-production-runtime.md); milestone acceptance remains in the [roadmap](../DARK_FACTORY_ROADMAP.md). Delivery is PR-only. Public Getzilla requires Actions linux/windows on the exact head; private installations use the App-owned policy-epoch Trust CI check. Local receipts are preflight evidence and never create external attestation or bypass branch protection.

## Optional Python test workers

Without opt-in, fast verification and the Trust runner keep their existing behavior. Unconfigured Core PR/release verification selects `min(6, max(1, capacity - 2))` workers from live affinity or CPU-count fallback and the visible finite Linux quota. It subtracts a two-CPU margin, keeps at least one worker and caps the request at six. A private test child runs sequentially. Saved startup records do not widen the current affinity or increase this default.

To select the existing automatic policy, create `.getzilla-test-runner.json` containing `{"schema_version":1,"workers":"auto"}`; `GETZILLA_TEST_WORKERS` overrides the requested value after the configuration file is validated. Accepted requests are `auto` or an integer from 0 through 64. Explicit integers are not quota-clamped, and `GETZILLA_TEST_WORKERS=0` selects sequential execution. An explicit allocation takes precedence over the PR/release default, so a coordinator can share its measured CPU budget across concurrent tasks.

On Linux, `auto` uses the minimum of 28, process affinity or CPU-count fallback, and finite CPU quotas visible through actual cgroup membership and mounts. Finite quotas use `max(1, quota // period)`; malformed, unreadable or ambiguous capacity conservatively selects one worker. This does not establish hidden ancestor limits, reserved CPU time or available PID/memory capacity.

On Windows, `auto` uses the minimum of 28 and the logical CPU count; Windows has no cgroup quotas or `sched_getaffinity`. Each owned child starts suspended, joins its own Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and no breakaway right, and only then runs. Cancellation, timeout, the output limit, normal child exit and controller exit therefore end the whole process tree, including descendants whose parent already exited. This is the counterpart of the POSIX session that the runner stops with `SIGTERM`, then `SIGKILL`.

Where this runner cannot provide its required parallel-process cleanup (a POSIX session or a Windows Job Object), a positive request selects the existing `unittest-degraded` engine before execution. Supported parallel execution retains its strict pins; measured serial execution retains pinned coverage. An actual failed parallel run is never retried serially. The implementation lives in `.getzilla/getzilla/python_test_runner.py` and its private `_cpu_capacity.py` helper; native Windows and older-interpreter qualification remain separate from fixture-based evidence.

Core reports show the selection source, requested and effective worker allocation, observed bounded capacity when read, backend, test budget and terminal state. Zero workers denotes sequential execution; the module-based coverage fallback caps its allocation by the module count. An allocation is a ceiling, not reserved CPU time or available PID/memory capacity. The Core test budget remains 900 seconds. A timeout fails verification and cannot qualify partial coverage. Inspect the allocation and start a fresh full PR gate with `GETZILLA_TEST_WORKERS=N python3 scripts/getzilla_verify.py --mode pr`, where `N` fits the task's available measured allocation. The runner does not retry automatically or increase the timeout.

## Bounded local M8

The owner-approved policy requires **one** completed owner-accepted factory task; Liqvera supplies that case with immutable product/factory provenance. `factory/src/getzilla_factory/owner_autonomy.py` consumes the typed policy, case and activation contracts in `factory/contracts/jsonschema/owner-autonomy.v1.schema.json`; `scripts/getzilla_m8.py` invokes the actual admission consumer. This is an additive offline control. It does not invoke providers or execute arbitrary commands. Owner-confirmed accounting and human readiness are not external signed Trust CI approvals; unavailable cost/intervention totals remain `null`.

The separate cohort evaluator explicitly supports legacy `CohortEvidenceV1` (minimum30, unchanged schema/digest domain) and `CohortEvidenceV2` (minimum1, `earned-autonomy.v2.schema.json` and distinct V2 domain). Nested M7/tuple/task and recommendation/profile records remain V1; M9's exact-V1 handoff does not accept V2. Neither cohort version bypasses blocked empirical M7 currentness.

From a source checkout with an actual compatible active route, run:

```bash
python3 scripts/getzilla_m8.py status
python3 scripts/getzilla_m8.py activate
python3 scripts/getzilla_m8.py admit --action local_read
python3 scripts/getzilla_m8.py admit --action local_test
python3 scripts/getzilla_m8.py revoke
python3 scripts/getzilla_m8.py admit --action local_test
```

The first status denies with L0 if activation is absent; activate and eligible admissions return L1. Revoke succeeds and subsequent admission denies with L0 and exit 2. Records live only in ignored `.getzilla/runtime/owner-autonomy/`, are immutable, expire after at most one hour, and bind this clone/worktree, current Git HEAD and complete Git-visible tracked/untracked bytes/modes, authoritative route semantics, policy and accepted case. Ignored runtime/dist files do not invalidate activation; unsafe links, credential paths and inventory/read bounds fail closed. A fresh clone with no active route denies: continue or route the task through the normal workflow, never fabricate a route for activation. Medium-risk API work with base/contracts profiles and no human gates permits only local reads/tests; high risk, security/production scope or required gates are unsupported. Phase/timestamps alone are not authority changes. Policy expiry is 2026-11-04. Changed, missing, malformed, disabled, expired or revoked inputs deny each use. To renew an expired activation, remove only that clone's ignored `activation.json` and activate against its current source; a revocation tombstone requires a new explicitly authorized owner policy. L2 is a ceiling, not automatic promotion: local edits or expanded actions require a separately reviewed policy/consumer change and owner authorization. Roll back by revoking activation and disabling the owner policy; legacy V1 consumers continue to require thirty. Merge, provider execution, deployment, publication and production retain their independent exact grants and external gates.

M9 already evaluates one-step preview/staging/bounded-canary decisions with an in-memory adapter and stop/reduce/previous-artifact recovery. Actual M9 qualification still requires signed artifact inputs, the applicable environment/provider deployment, exercised recovery and human production authority; this M8 change does not activate M9.

The current 2.3.1 source remains a release candidate until its exact merged tested source passes the required gates and GitHub Release publication occurs. ZIP/checksum assets are published through GitHub Releases; ZIPs are not source Git content. Published releases and their checksums remain immutable history.

## Как пользоваться опубликованной версией 2.1.1

v2.1.1 опубликован 2026-10-03 из PR #238; ZIP и контрольная сумма доступны в GitHub Releases. Наличие исходников F/G не означает их принятие, развёртывание Trust CI или готовую автономную фабрику. BB, rotator, VibeVM, FPF, prediction и Linux setup остаются выключенными по умолчанию; полный внешний пилот и эксплуатационная квалификация не подтверждены. U4/macOS в этот объём не входят.

1. Получите исходники и зафиксируйте, что именно проверяете:

   ```bash
   git clone https://github.com/Dimkox/Getzilla.git
   cd Getzilla
   git fetch --all --prune
   git switch --detach v2.1.1
   git rev-parse HEAD
   ```

   Это неизменяемый опубликованный снимок `97a7581238022356b2de8d193a9bd8363fc92dc3`. Для новой задачи создайте отдельную ветку от принятого снимка; текущая очистка исходников проходит отдельный PR #241, заменяющий PR #239. Перед дальнейшей работой выполните измерение CPU/affinity/cgroup по AGENTS.md и сохраните результат локально; затем прочитайте START_HERE.md, PROJECT_STATE.json и AGENTS.md. Команды Git создают локальную копию/обновляют refs, но не меняют удалённый репозиторий.

2. Проверьте инструменты:

   ```bash
   python3 scripts/getzilla_doctor.py --offer-install
   ```

   Doctor выводит состояние и предложения установки; он не устанавливает зависимости за вас. Для локального стека нужны Python ≥3.10 и Git ≥2.34; для Python-пакета factory — Python ≥3.11. Grok Build CLI нужен для TUI: установите его отдельно и выполните `grok` для входа. Node/npm, PHP/Composer нужны соответствующим профилям, Docker — отдельному операторскому/проверочному окружению. Старый `scripts/bootstrap.sh` удалён; используйте явные команды doctor/install из этого README.

3. Сначала получите план для явно выбранного своего репозитория:

   ```bash
   python3 scripts/install_into.py --dry-run /absolute/path/to/your/repo
   # Эквивалентный явный режим:
   python3 scripts/install_into.py --plan /absolute/path/to/your/repo
   ```

   План — JSON с управляемыми файлами, конфликтами и советами по зависимостям. Эти режимы читают существующую цель, не переписывают её и не запускают dependency runner. Примените план обычным проверяемым изменением в отдельной ветке своего репозитория. `--force` запрещён.

   Для нового проекта на поддерживаемом Linux выберите ещё не существующий путь:

   ```bash
   python3 scripts/install_into.py --materialize-new /absolute/path/to/new/repo
   ```

   Эта команда создаёт файлы: сначала проверенный соседний staging-каталог, затем атомарно публикует новую цель. Существующая цель, symlink или отсутствие требуемых no-follow/renameat2 возможностей приводят к отказу. Установка доставляет scripts/, .grok/, .getzilla/, AGENTS.md и исходный factory payload; не запускает сервис, миграции или inference. trust-ci/ и GitHub Actions не устанавливаются. Архитектурные system.yaml/rules.yaml/adoption.json принадлежат целевому проекту и требуют отдельного ручного принятия.

4. Откройте целевой проект в Grok Build, доверьте проверенные project hooks через `/hooks-trust` и сформулируйте одну конкретную задачу. UserPromptSubmit создаёт локальный маршрут. Если интеграция не вызвала hook, создайте его явно:

   ```bash
   cd /absolute/path/to/your/repo
   python3 scripts/getzilla_route.py "Добавить нужное поведение с указанными критериями приёмки" --session first-task --json
   python3 scripts/getzilla_route.py --show --json
   python3 scripts/getzilla_gate.py status
   python3 scripts/getzilla_status.py
   ```

   `getzilla_route.py` создаёт предварительный маршрут. Для полного пути создайте пакет командой `getzilla change start`; при существующем пакете повторный `start` пропустите. Измеренный light lane не требует пакета; сохранено и существующее исключение для low-risk docs/micro. Создание маршрута/пакета пишет локальное состояние .getzilla/runtime/active-route.json и .getzilla/runtime/changes/<id>/ (старые пакеты в engineering/changes/ — история). Не перезаписывайте уже активную задачу новым маршрутом. Используйте `/getzilla-delivery`: только выбранные allowed_agents, один write_agent на изолированную ветку/worktree, проверки и независимые reviewers. Если route.human_gates содержит scope_and_design_approval, человек сначала утверждает конкретный scope/design; `getzilla_gate.py decide` лишь фиксирует уже принятое решение, не выдаёт внешнее разрешение. Production/external actions требуют собственного точного делегирования и применимых внешних approvals.

5. Для уже реально созданного дочернего агента heartbeat/watchdog дают наблюдаемость. Hook SubagentStart регистрирует его автоматически; при отсутствии hook:

   ```bash
   python3 scripts/getzilla_agent.py start --agent-id child-1 --agent-type SELECTED_ROLE
   ```

   SELECTED_ROLE берите из маршрута; сохраните возвращённые generation, route_id и task_id. Ниже замените GENERATION/ROUTE/TASK точными значениями ответа, а не названием задачи:

   ```bash
   python3 scripts/getzilla_agent.py heartbeat --agent-id child-1 --generation GENERATION --route-id ROUTE --task-id TASK
   python3 scripts/getzilla_agent.py progress --agent-id child-1 --generation GENERATION --route-id ROUTE --task-id TASK --checkpoint implementation
   python3 scripts/getzilla_agent.py watchdog
   python3 scripts/getzilla_agent.py watch --iterations 12 --interval 5
   python3 scripts/getzilla_status.py
   ```

   heartbeat/progress обновляют локальный agent-state.json; watchdog/watch читают диагностические записи и печатают JSON. По умолчанию предупреждения начинаются после 180 секунд без heartbeat и 600 секунд без полезного checkpoint. Watch ограничен числом итераций; фонового daemon нет. Свежий heartbeat не доказывает продвижение. При зависании: status-request → реальное сообщение контроллера → status-ack после ответа. Для восстановления: interrupt-request → реальное native interrupt → interrupt-ack после наблюдаемого подтверждения → resume → native followup тому же агенту с новой generation. Watchdog сам никого не прерывает и не заменяет writer; подробные команды — engineering/runbooks/local-agent-watchdog.md.

   Отдельный детектор замечает три одинаковых завершённых провала теста, сборки или линтера при неизменном исходном коде. Следующий точный повтор останавливается. `getzilla agent progress-inspect --session-id SESSION` показывает наблюдения; `progress-recover` разрешает одну попытку после новой диагностики. Команды, границы поддержки и восстановление — [session progress](../engineering/runbooks/session-progress.md).

6. Проверяйте результат по файлам и свежему evidence, а не по сообщениям агента:

   ```bash
   git status --short
   git diff
   python3 scripts/getzilla_verify.py --mode fast --no-record --test tests.test_quality_gates --test tests.test_python_test_runner.NamedSmokeTests --budget 180
   python3 scripts/getzilla_status.py
   ```

   PR/release по умолчанию останавливают последующие проверки при первом отказе, неизвестном статусе или недопустимом skip. Отчёт сохраняет реальный результат и явно помечает незапущенные проверки; source-stability и финальный QG остаются обязательными. `--keep-going` собирает диагностику, сохраняя архитектурный preflight и правила admission. Именованный fast smoke требует чистый committed HEAD, `--no-record` и явные unittest-имена; бюджет subprocess — 1–180 секунд (по умолчанию 180), после таймаута добавляется ограниченная очистка процесса и проверка идентичности. Он не создаёт и не заменяет receipt. Полный успешный PR gate может занять больше 180 секунд; smoke или таймаут не заменяют его.

   После CPU-снимка и маршрутизации зафиксируйте trusted base/HEAD и staged/unstaged/untracked inventory. Именованные controls выше — observation, без receipt и scope admission. Затем все независимые route-selected reviewers проверяют кандидат; полные отчёты сохраняются вне Git: в папке evidence пакета `.getzilla/runtime/changes/<id>/` или в `.getzilla/runtime/reviews/<route-id>/`. Коммит отчётов и заморозка дерева не нужны. Выберите один финальный local gate: `python3 scripts/getzilla_verify.py --mode fast` для положительно допущенного light lane либо `--mode pr` для полного пути. PR/release selector выбирает scope по действительному base..HEAD и dirty inventory до тяжёлых checks; release сохраняет `--mode release`. Fast не обещает запуск только изменённых тестов. Зафиксируйте profile/reason, проверенные пути и skips; skipped не означает passed. Этот gate пишет локальный receipt в .getzilla/runtime/receipts/<route-id>/ и может идти параллельно с внешними exact-head checks — public Actions или private Trust CI — после точного delegated UNVERIFIED branch transport. Полный local gate до review не требуется. Status показывает evidence_gaps, package_incomplete и agent_diagnostics; изменение дерева делает прежние receipts устаревшими.

7. Доставка — отдельная ветка и PR. Условное AGENTS L5 разрешает merge/tag/release своего репозитория после зелёных exact-head checks, независимого review и закрытых threads, с точными action/resource grants. Прямой push в main запрещён. Public Getzilla требует Actions linux/windows; private consumer требует настроенный App-owned Trust CI и применимые подписанные approvals. Локальный PASS не заменяет внешнюю проверку. Production, deploy и external writes требуют отдельного точного разрешения.

   При отказе verifier изучите конкретный failed check, соберите связанные замечания в один ремонт тому же writer и повторите затронутые короткие controls. После независимого review сохраните полные отчёты вне Git, не меняя проверенный коммит; финальные локальная проверка и внешний exact-head check могут идти параллельно после явно делегированного UNVERIFIED branch transport. Identical merged tree без новых product changes — no-op, без нового полного прогона. При отказе установщика сохраните указанный stage для ручной инспекции, если сообщено `manual cleanup required`; не удаляйте неизвестную цель. При неоднозначном runtime/provider результате сохраните состояние и audit, выполните документированное reconcile, не повторяйте публикацию/inference вслепую. Для реального factory control plane и L5 нужны отдельные операторские конфигурация, зависимости, authority и rollout/recovery runbooks; установка локального стека сама их не активирует и не выдаёт live URL.

## Verification scope selection

At [startup](../AGENTS.md#second-mandatory-startup-step-select-verification-scope-before-heavy-work), after measured capacity and route/dependency scheduling, record trusted base/HEAD plus the staged/unstaged/untracked inventory. Bounded committed-HEAD controls are observations, without scope admission or verification receipts. Independent selected reviews precede the final qualifying local gate on the unchanged committed source candidate. Reports stay in ignored runtime storage; no report-only or freeze commit is needed. An admitted light change uses `--mode fast`; full delivery uses `--mode pr`, and release verification uses `--mode release`. The PR/release selector derives its disclosed scope before heavy checks. A named `--mode fast --no-record --test ... --budget 180` run is only a bounded observation, without a receipt or lane admission. Record profile/reason, exact identities, path digest and skips; no manual "factory unaffected" heuristic or historical component pass expands its closed allowlist. Historical evidence retains its original exact Git identity and scope and never becomes a fresh pass. The configured external exact-head checks (public Actions or private Trust CI) and applicable approvals remain mandatory. Ten minutes is an unconfirmed delivery target; serial PostgreSQL and Core/PostgreSQL overlap have not been optimized by this change.

`getzilla_verify --mode pr` and `--mode release` classify the changed-path inventory before choosing what to run. A release documentation/state successor changes only prose, the dated state model, tracked release bytes, and the modules that bind them; it cannot move an executed product statement, so it does not owe a full-suite coverage run.

Admission is decided by **explicit content role, never by the directory name alone**: named prose/dated state, tracked release bytes and exactly the five binding test modules listed below. Admitted content is re-derived by a module this lane itself runs (root identity, the dated state model and package bytes from the lockstep trio; README's Workflow-sources table from `tests/test_workflow_sources.py`; a delivered change package's route record from `tests/test_repo_router.py`), or has no machine binding to lose (per-change workflow records, ADRs, backlogs, reviews, runbooks). Two prose-looking classes are rejected even though they live under a documentation path — `docs/bitrix-local-AGENTS.md`, which `scripts/install_into.py` installs verbatim as `local/AGENTS.md` into every consumer Bitrix install (agent-executed instructions shipped as product), and any `<anything>/evidence/historical-*` bundle, whose bytes `tests/test_history.py` pins to a literal sha256 (declared-immutable evidence). There is accordingly no `docs/` prefix: admitted documentation is a named file set plus `docs/superpowers/plans/`, `docs/superpowers/specs/` and the `engineering/` prose directories, and a new prose file is not admitted until it is declared.

The focused profile `docs-state-focused` still runs the spec, architecture, governance, workflow-artifact, secret, contract, SQL, Ruff, Bandit, pilot and factory-unit checks, plus five admitted modules: the lockstep trio `tests/test_structure.py`, `tests/test_project_state.py`, `tests/test_manifest_package.py` and the two binding tests whose subject is admitted content, `tests/test_workflow_sources.py` (README's Workflow-sources table) and `tests/test_repo_router.py` (a delivered change package's route record). It skips three checks and says so: the full-discovery runner it replaced (`python-unittest` here, `pytest` in a consumer install whose runner is pytest), `coverage`, and `factory-postgres-exit`. Measured on this checkout: the serial `coverage run -m unittest discover -s tests` path costs 629 s, the five admitted modules about 14 s.

Selection is closed and fail-closed. Any path outside the explicit allowlist — every `.getzilla/`, `scripts/`, `trust-ci/`, `factory/`, `pilot/`, `architecture/`, `schemas/`, `governance/`, `engineering/contracts/`, hook, `Makefile`, config and dotfile path, every `tests/` module outside the five, and any unnormalized path — keeps the full PR suite, as do an empty or invalid inventory, a deleted/renamed/copied/unmerged Git status, a status channel not positively reported as trusted, an unresolvable comparison base, an absent route, and an absent admitted module. The classifier's own modules sit outside its allowlist, so a change to the shortcut can never be verified by the shortcut.

The profile, its reason code, the exact admitted paths and each skipped check are reported by the `docs-state-scope` check and stored as `docs_state_scope` in the receipt with `evidence_kind` `verification:docs-state-focused` or `verification:full-pr-suite`. `python3 scripts/getzilla_verify.py --mode pr --full-scope` (or `GETZILLA_VERIFY_FORCE_FULL=1`) forces the full suite regardless of classification. Exact-tree fingerprint binding, independent reviews and the configured external exact-head checks are unchanged by scope selection; the implementation is `.getzilla/getzilla/verification_scope.py`.

## Delivery history

<details>
<summary>Published releases, source lineage and earlier evidence</summary>

- `v2.0.16`: PR #79 checked head `2b1517986b9b5b83a95b1286baac161074c58175`, App check `103797448701`, attestation `90cb34aa-6eb5-49ca-a0ec-104e11c5e722`; tag object `8486ddb648f97e79a5f3a81d9b539378d2d4b301` binds merge `969c4f65f54ef9230f3f94587e228098d1c2ecb9`. ZIP SHA-256 `71f63a1089f4009cc65ed0afb5b755418fa5a8bf1dd4ce2aebae2f1b8cc746d7`. Candidate wording inside the released archive is its historical build snapshot.
- L5 source landing: PR #75 merged the union of slices #65-#71 on `2026-09-13T17:35:51Z` as `eb9df64bca333f30ec58f8c725a021360e22ed92`, tree `1c8d72a50c0631c0222d111de1403ace4347aab2`, identical to attested final-slice head `e6a813e4c16543f262ced2d9ea353caaad9452d1`. Union head `ac7ae2def67a267c227ab5703843337d4bb6f4be` passed App check `103760385178`, attestation `e859743f-d0ed-48f0-a389-f5637e645c30`; #65 landed separately and the remaining slices closed by content. [Exact slice ledger](../engineering/reviews/l5-delivery-stack.json) and [evidence policy](../engineering/changes/20260913-l5-split-g-final-base-offline-recovery-and-assem-2a890b/evidence/README.md) preserve each check. PR #72 landed that evidence; PR #77 delivered contract-inventory, prohibited deploy-member and PDF-worker hardening. Installation and provider activation followed this source landing separately.
- `v2.0.15`: PR #27 checked head `9fcc9d943c74260c02a920a59490143f91cb38b2`, App check `101365945968`, merged as `fd51dcfed6b33f4a8707c0db602328146df17cc9`; published `2026-09-05T20:17:20Z`, ZIP SHA-256 `1f0f64557fd258df7e533f674bb4e7c55d4a1a51454d48bcfecfa5487d08e9d7`. GitGuardian was `SKIPPED` after the operator classified its public CSP digest finding as a false positive. The separate default-off [`pilot/`](../pilot/) targets one pinned issue/repository through one Codex turn and separately granted branch/draft-PR transports. The [pilot handoff](../engineering/runbooks/design-partner-pilot-v2.0.15.md) records the initial target drift and review repairs; it is not external maintainer acceptance.
- `v2.0.14`: PR #24 checked head `66a7fe5c4a59b3ea7e1350b34e0a547faf5a9f57`, App check `101099224099`, merged as `1751b5855e46782b9a1bfceb6e1ab0102cba03b0`; published `2026-09-04T16:58:48Z`, ZIP SHA-256 `b03c64e67ac757f7d84abfed407cbd0ace2771afd960c67e24684099b3cc0264`. This was the offline L5 19-member artifact epoch, retained alongside later 20/22-member epochs.
- `v2.0.13`: PR #22 delivered M1-M9 repository source, preserving migrations `001`-`018`. Checked head `b5eba759c309a92f92f4d4003d025795c7f8a1f9`, App check `100955508827`, attestation `74f1bbb2-3098-4d35-a42f-d49351d81c4a`, merged `2026-09-04T08:31:49Z` as `8599d45f4f28285381b05a53feb3059de92eb2a8`. Earlier M1-M3 stack and M4-M9 checkpoints remain in `PROJECT_STATE.json`.
- M0 Live Trust Authority and the PR #7/#6 runtime/policy-loop repairs are delivered. Independent [`trust-ci/`](../trust-ci/) has service identity **2.1.0**, separate from the product version; it owns PostgreSQL jobs, isolated runners, external holdout checks and signed attestations. Deployed policy and credentials stay outside the PR trust domain.
- PR #12 delivered the approval CLI repair; PR #19 delivered the optional SEO side project. Open/unresolved work has a dated inventory in `PROJECT_STATE.json`; historical check success requires fresh base/head validation before merge.

</details>
## Read first

1. [START_HERE.md](../START_HERE.md)
2. [PROJECT_STATE.json](../PROJECT_STATE.json)
3. [AGENTS.md](../AGENTS.md)
4. [decisions.md](../decisions.md)
5. [mistakes.md](../mistakes.md)
6. [DARK_FACTORY_ROADMAP.md](../DARK_FACTORY_ROADMAP.md)
7. [CHANGELOG.md](../CHANGELOG.md)
8. [QUICKSTART.md](../QUICKSTART.md)
9. [`trust-ci/README.md`](../trust-ci/README.md)
10. [`factory/README.md`](../factory/README.md)
11. [delivered design-partner pilot package](../engineering/changes/20260905-feature-implement-a-single-operator-codex-github-0ce2d6/brief.md)
12. `.getzilla/runtime/active-route.json` if present (machine-local route; it may be absent in a clean clone and is not merge authority)
13. This README’s [map](#map) and [executable architecture](#executable-architecture)

## How work runs

Source-of-truth order is in AGENTS.md. Typed M1 intent is validated first, executable M2 architecture second, and target-owned M3 governance third; local receipts bind all configured layers to one worktree fingerprint but remain preflight evidence. Canonical governance JSON and exact handoffs outrank generated `decisions.md` / `mistakes.md` projections, while the external merge gate remains independent: public Actions, or private Trust CI policy, holdout, signed approvals and exact-SHA attestation as described in AGENTS.md. Large work is split into small subtasks that share `decisions.md` / `mistakes.md`. Local loop: recorded startup capacity → route/dependency plan → parallel independent work → one write owner per isolated task/route/branch/worktree → independent local reviews of a committed source candidate with ignored runtime state → persist reports outside Git → one final qualifying gate → pull request (runtime state may move to `ready` without changing source). An exact delegated isolated-branch push may happen earlier only as explicitly UNVERIFIED transport; it establishes no completion or merge authority. For private repositories, the deployed Trust CI service verifies the exact PR SHA under server-side policy, executes an external holdout bundle before repository checks, rejects source mutation, checks signed human approval scopes, signs the attestation, and publishes `adaptive-trust-ci/verified@<policy-sha12>` through its GitHub App. Conditional AGENTS L5 covers exact-grant repository merge, tag and release after green exact-head checks, independent review and resolved threads. Production promotion remains separately scoped.

For a fresh clone, bootstrap state comes from `START_HERE.md` / `PROJECT_STATE.json` first. Runtime route files are not expected to be committed; when no route exists, continue the explicitly named active PR/branch or route a new task before implementation.

## Map

- [START_HERE.md](../START_HERE.md) — zero-context agent/human entrypoint
- [PROJECT_STATE.json](../PROJECT_STATE.json) — machine-readable milestone handoff
- [AGENTS.md](../AGENTS.md)
- [decisions.md](../decisions.md)
- [mistakes.md](../mistakes.md)
- [DARK_FACTORY_ROADMAP.md](../DARK_FACTORY_ROADMAP.md)
- [CHANGELOG.md](../CHANGELOG.md)
- [QUICKSTART.md](../QUICKSTART.md)
- [VERSION](../VERSION)
- [`.grok/skills/`](../.grok/skills/)
- [`.grok/agents/`](../.grok/agents/)
- [`.grok/hooks/`](../.grok/hooks/)
- [Hook compatibility template](../.getzilla/templates/hook_root_shim.py) — root aliases for older consumer installs only; a fresh install keeps every hook entry script in `.grok/hooks/`, the canonical source.
- [`scripts/getzilla_route.py`](../scripts/getzilla_route.py)
- [`scripts/getzilla_change.py`](../scripts/getzilla_change.py)
- [`scripts/getzilla_agent.py`](../scripts/getzilla_agent.py) — local heartbeat, checkpoints, watchdog and recovery; [watchdog runbook](../engineering/runbooks/local-agent-watchdog.md), [repeated-failure guard](../engineering/runbooks/session-progress.md)
- [`scripts/getzilla_spec.py`](../scripts/getzilla_spec.py)
- [`scripts/getzilla_artifacts.py`](../scripts/getzilla_artifacts.py)
- [`schemas/change-spec.schema.json`](../schemas/change-spec.schema.json)
- [workflow source schema](../schemas/workflow-source-v1.schema.json)
- [workflow task graph schema](../schemas/workflow-task-graph-v1.schema.json)
- [workflow convergence report schema](../schemas/workflow-convergence-report-v1.schema.json)
- [architecture model](../architecture/system.yaml)
- [architecture rules](../architecture/rules.yaml)
- [architecture adoption marker](../architecture/adoption.json)
- [architecture system schema](../schemas/architecture-system.schema.json)
- [architecture rules schema](../schemas/architecture-rules.schema.json)
- [architecture CLI](../scripts/getzilla_architecture.py)
- [generated architecture views](../architecture/generated/context.mmd)
- [governance rules](../governance/rules/index.json)
- [governance debt](../governance/debt/index.json)
- [canonical-example registry](../governance/canonical-examples/index.json)
- [governance rule schema](../schemas/governance-rule.schema.json)
- [debt schema](../schemas/debt-entry.schema.json)
- [canonical-example schema](../schemas/canonical-example.schema.json)
- [governance handoff schema](../schemas/governance-handoff-v1.schema.json)
- [governance CLI](../scripts/getzilla_governance.py)
- [`scripts/getzilla_verify.py`](../scripts/getzilla_verify.py)
- [`scripts/getzilla_review.py`](../scripts/getzilla_review.py)
- [`scripts/getzilla_approve.py`](../scripts/getzilla_approve.py) — exact action/resource delegated local grant only
- [`scripts/getzilla_deploy.py`](../scripts/getzilla_deploy.py)
- [`scripts/getzilla_doctor.py`](../scripts/getzilla_doctor.py)
- [`scripts/getzilla_demo.py`](../scripts/getzilla_demo.py)
- [local demo assets and fixtures](../.getzilla/demo/index.html)
- [local demo OpenAPI v1 contract](../engineering/contracts/openapi/adaptive-demo.v1.json)
- [investor demo guide](../docs/INVESTOR_DEMO.md)
- [`scripts/install_into.py`](../scripts/install_into.py)
- [`trust-ci/`](../trust-ci/) — external merge trust, deployed independently
- [`factory/`](../factory/) — delivered M4-M8 control/evaluation source plus the L5 HTTP/media normalizer, dedicated SQLite/Unix host, deterministic artifacts and offline recovery; operational providers remain disabled by default
- [`delivery/`](../delivery/) — delivered M9 staged-delivery/recovery source plus the explicit owner-controlled filesystem publication adapter and durable reconciliation; operational effects require exact authority
- [`pilot/`](../pilot/) — published single-operator exact-issue/Codex/candidate/validation/draft-proposal vertical; disabled by default and without merge/deploy authority
- [`DARK_FACTORY_ROADMAP.md`](../DARK_FACTORY_ROADMAP.md) — dependency-ordered M0-M9 program status and acceptance-relative schedule
- [`engineering/runbooks/`](../engineering/runbooks/)
- [`packages/`](../packages/)
- [`examples/bitrix-module/`](../examples/bitrix-module/)
- [`.agents/skills/seo-landing/`](../.agents/skills/seo-landing/) — optional Codex SEO landing skill
- [`side-projects/seo-landing-showcase/`](../side-projects/seo-landing-showcase/) — non-indexable Russian showcase
- [LICENSE](../LICENSE)

## Advanced control planes

The first run above is intentionally small. These subsystems exist for teams that need stricter autonomous-delivery controls:

- Zero-context handoff through `START_HERE.md` and `PROJECT_STATE.json`.
- Task routing plus domain skills for Bitrix, API/events, data, frontend, security, incidents and releases.
- New change packages under `.getzilla/runtime/changes/`; tracked `engineering/changes/` packages remain history.
- Typed change intent with stable criterion/evidence IDs and deterministic spec fingerprints.
- Executable architecture checks with deterministic digests, exact-state diff, drift, fitness and projection-only diagrams.
- Governance checks for candidate-owned inputs, reviewed lifecycle, exact evidence digests, canonical examples and intentional-debt records.
- Advisory Spec Kit, BMAD and Superpowers imports. These are parsed as workflow artifacts; they never become route, approval, receipt, governance or merge authority.
- Default-off factory, delivery and pilot boundaries under `factory/`, `delivery/` and `pilot/`.
- Local verification and review receipts via `scripts/getzilla_*.py`.
- Offline [historical evidence accounting](../engineering/runbooks/historical-autonomy-evidence.md).
- Separately deployed Trust CI for private repositories, with GitHub App-owned policy checks, external holdout validation and signed exact-SHA attestations; public repositories use GitHub Actions.

## Executable architecture

The M1 typed change spec remains business-intent and acceptance authority. The separate architecture authority is the canonical [system model](../architecture/system.yaml) plus [fitness rules](../architecture/rules.yaml), validated by the [system schema](../schemas/architecture-system.schema.json) and [rules schema](../schemas/architecture-rules.schema.json). This repository explicitly records adoption in [architecture/adoption.json](../architecture/adoption.json). Generated Mermaid files under [`architecture/generated/`](../architecture/generated/context.mmd) are sorted text projections only:

Declared repository paths are exclusive ownership boundaries. A more-specific nested path owns its subtree; equal-specificity ties are invalid. The shared `trust-ci/compose.yaml` configuration is owned once by the Trust CI worker node, while the Docker engine remains a separately modeled runtime node connected by the explicit Docker API deployment edge.

- [context](../architecture/generated/context.mmd)
- [container](../architecture/generated/container.mmd)
- [deployment](../architecture/generated/deployment.mmd)
- [data flow](../architecture/generated/data-flow.mmd)
- [trust boundary](../architecture/generated/trust-boundary.mmd)

The [architecture CLI](../scripts/getzilla_architecture.py) is dependency-free and bounded. `validate`, `summary`, and `drift` inspect the current target-owned model. `diagram` renders all five literal artifacts to stdout without mutating the repository; `diagram --check` performs a no-follow comparison against the checked-in projections. `diff` and `fitness` require an explicit base plus an exact 40-character head SHA or `--worktree`; exact inputs are read from Git objects and do not consult mutable route state. Worktree evidence is diagnostic and never claims an exact head SHA.

Architecture change growth is governed by six finite overlapping error rules. The original M2 rule remains unchanged over its exact six non-factory prefixes (`1,000,000` bytes / `10,820` lines / `5,000` AST); separate rules bound the seven-prefix aggregate and the `factory`, `factory/src`, `factory/contracts`, and `factory/tests` scopes. Every matching rule is enforced independently with complete path-segment matching, and unknown line metrics fail closed; minification and stacked-route partitioning are not budget substitutes.

```bash
python3 scripts/getzilla_architecture.py validate --json
python3 scripts/getzilla_architecture.py summary --json
python3 scripts/getzilla_architecture.py drift --json
python3 scripts/getzilla_architecture.py diagram --json
python3 scripts/getzilla_architecture.py diagram --check --json
python3 scripts/getzilla_architecture.py diff --base <40-char-sha> --head <40-char-sha> --json
python3 scripts/getzilla_architecture.py fitness --base <40-char-sha> --head <40-char-sha> --pre-risk red --json
```

Diagram rendering is stdout-only and repository-read-only. To update a checked-in projection, apply the reviewed rendered text through the normal source-edit workflow and then run `diagram --check`; projections are never authority. Malformed, unknown, unsafe, excessive, partially missing, or applicable-but-unsupported adopted architecture fails closed. Installer-delivered examples live under [`.getzilla/templates/architecture/`](../.getzilla/templates/architecture/system.example.yaml), but every plan and payload excludes the consumer-owned `architecture/system.yaml`, `architecture/rules.yaml`, and `architecture/adoption.json`; follow the manual review-and-adopt sequence in [QUICKSTART.md](../QUICKSTART.md).

The M4 factory is modeled as an isolated local-preflight trust domain with only Unix HTTP and its own PostgreSQL edge. Installer payloads include its source, migrations, OpenAPI contract, locked dependency solution, mandatory disposable verification harness and placeholder-only local configuration, but never credentials, sockets, databases or runtime state. Installation does not run migrations, run verification or activate a service.

The queue and installer safety boundary is specified in the [approved pivot design](../docs/superpowers/specs/2026-08-27-m2a-queue-installer-pivot-design.md) and its [implementation plan](../docs/superpowers/plans/2026-08-27-m2a-queue-installer-pivot.md). Queue fitness and `new_queue` risk consume one bounded abstract-interpreter result: relevant uncertainty fails closed, while unrelated common method names remain non-queue.

## Controlled governance

The canonical M3 authority is the three target-owned JSON registries under [`governance/`](../governance/rules/index.json), validated against the four closed governance schemas. Registry content, repository text, agent notes, reviewer names, and `actor_kind` values are untrusted claims until the required independent external authority binds the exact record and digest. Agents can create candidates only; expired, deprecated, revoked, conflicted, stale, or unsupported records do not become effective.

Validation runs after typed-spec and architecture validation. A configured governance failure prevents any local verification or review receipt from being recorded. Successful local receipt cores include `governance_contract_version`, `governance_digest`, and a domain-separated `governance_evidence_digest` bound to current rule/debt/example/schema state, M2 architecture digest, applicable Git commits, and the worktree fingerprint. These local bindings are not the exact committed `GovernanceHandoffV1` and are never merge authority.

```bash
python3 scripts/getzilla_governance.py validate --json
python3 scripts/getzilla_governance.py summary --json
python3 scripts/getzilla_governance.py check-projections
python3 scripts/getzilla_governance.py handoff --base <40-char-sha> --head <40-char-sha> --architecture-evidence <path> --json
```

`project` prints proposed non-authoritative `decisions.md` and `mistakes.md` content without writing; `check-projections` compares those views without mutation. Exact handoff publication additionally requires a clean exact Git state, independently rederived M2 evidence, matching base/head SHAs, and zero governance findings.

## Requirements

Pins are **minimum or newer**. `built` is the version this local stack was verified on. If a tool is missing or older than minimum, `python3 scripts/getzilla_doctor.py` prints an **install offer** for the fallback (or install a newer version).

| Tool | Minimum | Built | Fallback | Required |
| --- | --- | --- | --- | --- |
| Python 3 | 3.10 | 3.12.3 | 3.12 | yes |
| Git | 2.34 | 2.43.0 | 2.43 | yes |
| Grok Build CLI | 1.0.0 | 1.0.5 | 1.0.5 | for the TUI |
| GitHub CLI (`gh`) | 2.40 | 2.86.0 | 2.86 | for exact-grant GitHub Release |
| Node.js | 18 | 24.19.0 | 20 LTS | frontend profiles |
| npm | 9 | 11.17.0 | 10 | frontend profiles |
| PHP | 8.1 | 8.2 | 8.2 | PHP/Bitrix profiles |
| Composer | 2.2 | 2.7 | 2.7 | PHP/Bitrix profiles |
| Docker Engine | 24.0 | 29.7.2 | 29 | Trust CI host (optional) |
| Syft | 1.0 | 1.51.0 | 1.51 | supply-chain SBOM (optional) |
| Trivy | 0.50 | 0.74.0 | 0.74 | supply-chain vuln scan (optional) |
| Cosign | 2.0 | — | 2.4 | supply-chain sign/verify (optional) |

```bash
python3 scripts/getzilla_doctor.py --offer-install
```

Machine-readable local pins: `.getzilla/config/toolchain.json` (its `workflow_sources` block pins the advisory workflow-document parsers). Trust CI uses separately built API, worker and runner images pinned by immutable SHA-256 digest in deployment and server policy.

### Workflow sources (dated advisory-parser compatibility pins)

| Component | Pinned | Upstream | Observed latest | Observed |
| --- | --- | --- | --- | --- |
| Superpowers | 6.4.2 | obra/superpowers | 6.4.2 | 2026-10-06 |
| BMAD Method | 6.12.1 | bmad-code-org/BMAD-METHOD | 6.12.1 | 2026-10-06 |
| GitHub Spec Kit | 1.1.0 | github/spec-kit | 1.1.0 | 2026-10-06 |

These rows are dated currency observations for the workflow artifact adapters. The required installed Superpowers, BMAD, Spec Kit and OSV/OpenGrep baseline has its own pinned manifest. `getzilla baseline status --project /path/to/repo` inspects installation and project wiring; `getzilla baseline apply --project /path/to/repo` connects an installed workflow baseline. See [baseline setup](baseline.md) for user-level installation and security tools. Optional tool updates are separate from that requirement. `tests/test_workflow_sources.py` keeps them bound to `.getzilla/config/toolchain.json` and to named parser tests. Accepted document shapes and the known-unparsed list are defined in the upstream format amendments of [2026-09-15](../docs/superpowers/specs/2026-09-15-workflow-artifact-adapters-upstream-amendment.md) and [2026-10-06](../docs/superpowers/specs/2026-10-06-workflow-artifact-adapters-upstream-amendment.md).

## Install into a project

Existing repositories are read-only installer inputs. Generate a deterministic manifest and dependency advice, then apply an update through a normal reviewed source-change commit:

```bash
python3 scripts/install_into.py --plan /path/to/your/repo
```

The historical positional form and `--dry-run` are planning aliases. `--force` is rejected; dependency advice is output only and no dependency runner is executed.

To create a complete installation, the target must be absent:

```bash
python3 scripts/install_into.py --materialize-new /path/to/new/repo
```

This materialization mode is supported only on Linux with descriptor-relative `O_NOFOLLOW`/`O_DIRECTORY` operations and both libc and the target filesystem supporting `renameat2(RENAME_NOREPLACE)`. If any required capability is unavailable or the filesystem rejects it, materialization exits nonzero and fails closed without publishing the target; there is no fallback to replace, merge, or in-place copying. Use `--plan` plus a normal reviewed source-change for an existing consumer or for a platform/filesystem without those capabilities.

Materialization builds and verifies one owned sibling stage and publishes it with fail-closed no-replace semantics. If constructor identity becomes unresolved, it preserves the entry for manual inspection and reports `manual cleanup required: installer ownership is unresolved`; it never deletes an unproven replacement. It refuses an existing, symlink, or special-file target. The payload includes:

```text
.grok/            → project .grok/          (config, hooks, agents, skills)
.agents/skills/   → project .agents/skills/
.getzilla/      → project .getzilla/
scripts/          → project scripts/
AGENTS.md         → project AGENTS.md
decisions.md      → project decisions.md
mistakes.md       → project mistakes.md
engineering/      → project engineering/  (if empty scaffold needed)
```

It includes the governance engine, CLI, four closed schemas, and explicitly non-authoritative change-package templates. It excludes `trust-ci/`, `.github/workflows/`, `architecture/adoption.json`, `architecture/system.yaml`, `architecture/rules.yaml`, and every target-owned `governance/**/index.json` registry. The installer never creates or overwrites a target governance registry. Adopt architecture and governance manually only after reviewing target truth as described in [QUICKSTART.md](../QUICKSTART.md).

Then in the project:

```bash
cd /path/to/your/repo
grok inspect    # should see skills + AGENTS.md
grok            # start TUI
```

Invoke the main controller skill:

```text
/getzilla-delivery
```

or just describe a development task — Grok should pick up skills from `.grok/skills/`.

The independent `trust-ci/` service is deployed once as infrastructure; it is not copied into every consumer unless that repository will use the same external check protocol.

## Scripts

Local loop: measured route → change package when required → bounded committed-HEAD observations → independent selected reviews → persist reports outside Git → one final local gate selected by the delivery lane, parallel with the required exact-head external gate (public Actions or private Trust CI) after exact delegated UNVERIFIED branch transport → current receipts/protected PR eligibility. `scripts/getzilla_deploy.py` is prepare-only and must not bypass protected-branch or exact-SHA requirements.

MCP tools fail closed: a tool of any server is an external write, and needs an exact external-write grant, unless its name, in plain ASCII, starts or ends with a read verb (`get`, `list`, `search`, `read`, `lookup`, `describe`, `download`) and holds no write verb anywhere (`get_or_create_user` is a write); a name that starts with `run` or `request` is a write, and `query`/`fetch` tools are writes unless listed. A project lists its own read tools with other names, exactly, in `.getzilla/config/policy.json` under `"mcp_read_tools": {"Server": ["tool"]}`. A GitHub write is also checked against this repository; a GitHub proxy whose server name does not contain `github` gets the grant check only.

Declared route `human_gates` are flags: their decisions are recorded in the active change package and their open state is shown (gate status and the `open_human_gates` entry in the change history), but they never block a change transition or an action. The one exception is `paid_run_approval`: the first live paid run stays blocked until an approved decision names its exact resource, and a missing or changed declaration of that gate fails closed. Inspect gate status with `python3 scripts/getzilla_gate.py status`; record only an explicit operator decision with `python3 scripts/getzilla_gate.py decide <gate> <approved|rejected> --reason "..." --actor "..."` (production decisions also require `--action`; approve the migration plan with `--action migration-plan`; external-write decisions require exact `--action external-write --resource ...`). Decisions are bound to the active route, change, gate and scope digest. They are mutable local workflow evidence, not authenticated human identity, delegated grants, Trust CI signed approvals or merge authority. Production and external-write operations still require their exact delegated grants.

Every command runs as `getzilla <command>` through `bin/getzilla` (`bin\getzilla.cmd` on Windows), or as `python3 scripts/getzilla_cli.py <command>`. `getzilla <command> --help` shows its options. The [README command table](../README.md#commands) groups them by task.

| Command | Script | Role |
|--------|------|------|
| `doctor` | `scripts/getzilla_doctor.py` | Local health check; `--offer-install` offers missing tools |
| `setup-agent` | `scripts/getzilla_setup_agent.py` | Coding agent and model provider setup; `--forget-key` removes the stored key |
| `install-into` | `scripts/install_into.py` | Plan an existing repository read-only, or atomically materialize an absent new target |
| `adopt` | `scripts/adopt_existing.py` | Adopt a folder without Git into a new local workspace (`plan`, `apply`, `status`, `resume`, `abort`) |
| `components` | `scripts/getzilla_components.py` | Show and add optional components (`agent:<name>`, `extra:bitrix`, `extra:seo-landing`, `compliance:eu-ai-act`, `factory`) |
| `baseline` | `scripts/getzilla_baseline.py` | Inspect with `status --project <repo>`; connect installed workflow tools with `apply --project <repo>` |
| `harness` | `scripts/getzilla_harness.py` | Check, or with `--write` regenerate, the generated agent harness copies |
| `update` | `scripts/getzilla_upgrade.py` | Update Getzilla, write the new files into the project on a `getzilla-update-<version>` branch, then update third-party tools (`--no-self`, `--no-tools`, `--accept-local`, `--retire-legacy`); the project's own lint and coverage configuration stays |
| — | `scripts/getzilla_update.py` | Third-party tools only (agent CLIs, Superpowers, BMAD, Spec Kit, vibevm, CVE database, OpenGrep); `--status` shows the last results |
| `cpu` | `scripts/getzilla_startup_cpu.py` | Startup step zero: measure and record usable CPUs (`--reserve`, `--attach`) |
| `par` | `scripts/getzilla_par.py` | Run independent commands in parallel on the measured CPUs (`-j`, `--each`) |
| `route` | `scripts/getzilla_route.py` | Classify, show, reconcile, complete or cancel the task route; `--reconcile --add-reviewer <role>` keeps an extra reviewer |
| `status` | `scripts/getzilla_status.py` | Local runtime status: route, change package, evidence gaps, agents |
| `change` | `scripts/getzilla_change.py` | Start, transition or show the change package |
| `spec` | `scripts/getzilla_spec.py` | Validate and summarize typed change specifications |
| `agent` | `scripts/getzilla_agent.py` | Agent heartbeat, checkpoints, watchdog, `progress-inspect` and one-shot `progress-recover` |
| `test` | `scripts/getzilla_cli.py` | Run the test suite with pytest-xdist on the measured CPUs, otherwise serial unittest |
| `verify` | `scripts/getzilla_verify.py` | Local verification preflight (unittest, Ruff, Bandit, known vulnerabilities, measured coverage in `pr`/`release`) |
| `review` | `scripts/getzilla_review.py` | Record a local review receipt bound to `--reviewed-commit` |
| `gate` | `scripts/getzilla_gate.py` | Inspect or record route-bound local human-gate decisions |
| `vulns` | `scripts/getzilla_vulns.py` | Known vulnerabilities in pinned dependencies from OSV (`--online`, `--db DIR`, `--download-db DIR`) |
| `duplicates` | `scripts/getzilla_duplicates.py` | Read-only source duplication analysis; uses jscpd when it is installed |
| `graph` | `scripts/getzilla_graph.py` | Read-only Python code graph: `build`, `status`, `impact`, `export` |
| `architecture` | `scripts/getzilla_architecture.py` | Validate, diff and draw the architecture model |
| `governance` | `scripts/getzilla_governance.py` | Validate/summarize target-owned governance, check read-only projections, and emit an exact clean-state handoff |
| `artifacts` | `scripts/getzilla_artifacts.py` | Import, compile and converge Spec Kit, BMAD and Superpowers artifacts |
| `risk-terms` | `scripts/getzilla_risk_terms.py` | Risk vocabulary language packs: `check`, `languages`, `scaffold` |
| `compliance` | `scripts/getzilla_compliance.py` | Scaffold an EU AI Act adapter for a registered AI system (optional layer) |
| — | `scripts/getzilla_audit_bundle.py` | EU AI Act release audit bundle (optional layer) |
| `approve` | `scripts/getzilla_approve.py` | Delegated local grant for exact actions and resources. Protected-path grants bind repository, caller session, change, branch, anchor and file set; other scopes bind route, exact HEAD and tree. Not accepted by Trust CI |
| `protected-write` | `scripts/getzilla_protected_write.py` | Apply an approved protected-path write from a manifest (`--dry-run` first) |
| `ci` | `scripts/getzilla_ci.py` | Select the CI gate by visibility; `--write` renders the pinned public workflow; `--protect-plan` shows branch protection |
| `trust-ci` | `scripts/getzilla_trust_ci.py` | Trust CI host: `init`, `status`, `github-app`, `trust-key` |
| `deploy` | `scripts/getzilla_deploy.py` | Prepare-only delivery commands |
| — | `scripts/getzilla_evidence.py` | Export bounded local workflow evidence, without approvals or secrets, with `--output <file>` |
| `cleanup` | `scripts/getzilla_cleanup.py` | `inventory` (read-only disk report with repository copies), `worktrees [--remove]` (guarded removal), `snapshot <commit>` / `snapshot --remove <path>` (review copies) |
| `branches` | `scripts/branch_lifecycle.py` | Branch retention `report`; `apply` deletes only from a reviewed plan with `--allow-delete` |
| `report` | `scripts/getzilla_report.py` | Per-profile overhead, observation gaps and defects caught before merge |
| `history` | `scripts/getzilla_history.py` | Offline historical evidence accounting from a snapshot file (`getzilla history <snapshot.json>`) |
| — | `scripts/getzilla_m8.py` | Bounded local M8 owner policy: `status`, `activate`, `admit --action <action>`, `revoke` |
| `demo` | `scripts/getzilla_demo.py` | Start the loopback-only read-only product tour using bundled sample and checkout-derived evidence |
| — | `scripts/package_stack.py` | Build the release ZIP and its checksum sidecar |
| — | `adaptive-trust-ci` | External API, worker, migration, signed approvals, holdout verification, attestation verification and app-bound branch protection |

## Reviewed verification dispositions

The optional target-owned `engineering/verification-dispositions.json` classifies two narrow observations from `secret-scan` and `git-diff-check`. The installer does not own this file, and Getzilla ships no active dispositions. Absence preserves strict detection. These records are local review evidence, not authenticated approvals or merge authority. Independent review must check the public identity or historical origin, rationale, and evidence before adding an entry.

Version 1 has exactly two top-level fields: `schema_version` (integer `1`) and `dispositions` (an array). Each entry has `id`, `check`, `kind`, `rule`, `path`, `sha256`, `line`, `reason`, and `evidence`. The `evidence` object has exactly `path` and `sha256`. A public-token entry additionally requires `column` and `match_sha256`. All hashes are lowercase SHA-256 of complete raw bytes; the match hash covers the exact UTF-8 scanner match, including assignment and quotes. Positions are one-based Unicode text line/column positions. No matched secret value is included in the report.

| Check | Kind | Rule | Eligible observation |
|---|---|---|---|
| `secret-scan` | `public-token-address` | `generic-secret` | An exact lowercase standalone `token` assignment whose entire quoted value is `0x` plus 40 hexadecimal digits |
| `git-diff-check` | `immutable-markdown-whitespace` | `new-blank-line-at-eof` | Git's exact `new blank line at EOF.` diagnostic on a regular, nonexecutable `.md` file |

Public-address shape alone grants no disposition. The entry must identify the exact occurrence, file bytes, and separate review evidence. Credential variable names such as `auth_token`, `password`, `secret`, and `api_key` do not qualify. Private-key and AWS rules never qualify. Every match is retained, so another credential or another occurrence still fails. An immutable Markdown entry covers only its exact EOF diagnostic. Trailing whitespace, other files, unknown output, Git errors, and range-selection errors remain blocking.

Standalone-token admission uses a limited source-prefix grammar. The entire prefix must be ASCII, including completed strings and comments; even harmless Unicode text before the occurrence makes it ineligible. The name must start the source or follow ASCII whitespace (space, tab, CR, LF, form feed or vertical tab) or one of `{`, `[`, `(`, `,`, `;`. Completed single/double-quoted strings and line/block comments are recognized while inspecting preceding context. Member-access punctuation across whitespace or comments and occurrences inside strings or comments are ineligible. Code outside strings and comments permits ASCII letters, digits, whitespace and `_ $ ( ) [ ] { } . , : ; = + - * ! & | % ? ^ ~ < >`. Legacy HTML comments, regex/division syntax, templates, code escapes and unsupported code characters before the occurrence are conservatively refused. This is an eligibility check, not a language parser. Ordinary standalone declarations and comma-separated object fields remain eligible; unsupported context keeps the raw finding blocking.

This is an inert shape example. Replace every placeholder with reviewed source information; do not copy it as active policy:

```json
{
  "schema_version": 1,
  "dispositions": [
    {
      "id": "public-contract",
      "check": "secret-scan",
      "kind": "public-token-address",
      "rule": "generic-secret",
      "path": "src/protocol.ts",
      "sha256": "<full-file-sha256>",
      "line": 12,
      "column": 3,
      "match_sha256": "<exact-assignment-sha256>",
      "reason": "Review establishes the chain and public token contract identity.",
      "evidence": {"path": "engineering/reviews/public-contract.md", "sha256": "<review-sha256>"}
    },
    {
      "id": "historical-eof",
      "check": "git-diff-check",
      "kind": "immutable-markdown-whitespace",
      "rule": "new-blank-line-at-eof",
      "path": "docs/evidence/historical-report.md",
      "sha256": "<full-file-sha256>",
      "line": 42,
      "reason": "Review establishes that these historical evidence bytes are immutable.",
      "evidence": {"path": "engineering/reviews/historical-report.md", "sha256": "<review-sha256>"}
    }
  ]
}
```

The loader rejects unknown fields, versions, rules and kinds, duplicate JSON keys, duplicate IDs or finding identities, invalid hashes, stale occurrences, missing or changed evidence, and unsafe paths. Every entry is validated, including entries outside the changed-file selection. Paths use ASCII letters, digits, underscores, dots and hyphens separated by single `/` characters; absolute paths, dot components, traversal, globs, symlinks and runtime paths are refused. Configuration, evidence and targets must be tracked regular source files without assume-unchanged or skip-worktree flags. Evidence must be separate nonexecutable `.md` source. Configuration is also nonexecutable. These requirements keep the inputs in the normal source fingerprint; ignored or untracked review policy is not authority.

Limits are 128 KiB of configuration, 128 entries, 2,000,000 bytes per target/evidence file, and 32,000,000 aggregate source bytes. IDs use an ASCII letter followed by at most 63 letters, digits, underscores or hyphens. Reasons contain 1–2,000 characters of nonempty single-line text. A change to reviewed bytes requires a new review and new hashes; removal of the policy restores ordinary failures.

For whitespace, the worktree must still contain the reviewed target bytes. Each command also checks the actual worktree, index or HEAD blob it inspected, including its executable mode. A current worktree hash cannot authorize a different staged or committed blob. All existing selected ranges run. Full stdout, stderr, command and original exit code are retained in `diff-check-command` details; the combined output is not truncated before classification or reporting. Source and Git-layer bytes are checked again during classification. Unexpected or incomplete output cannot produce a disposition.

The verification report keeps schema version 1 with additive detail fields. Original `severity`, rule, path and observation remain visible; `effective_severity` becomes `info` only for a matched reviewed disposition. Its `disposition` object contains ID, kind, reason, evidence, configuration path/hash and file hash. Text output includes the disposition ID in the finding message. The `disposition-summary` detail reports the configuration hash and counts of configured entries, observed findings, disposed findings, and unresolved error records (including configuration or command errors). A check can pass with raw error observations only when every blocking observation has a valid disposition and no unresolved error remains. Report consumers must use check status or effective severity for that outcome; raw severity continues to describe what the scanner or Git observed. The mandatory quality gates and receipt binding stay in force.

## Known vulnerabilities

`getzilla_verify.py` runs a `known-vulnerabilities` check next to Ruff, Bandit, Semgrep and Trivy. It reads exact pins from `requirements*.txt`, `pyproject.toml`, `uv.lock`, `poetry.lock`, `Pipfile.lock`, `package-lock.json`, `npm-shrinkwrap.json`, `go.mod`, `Cargo.lock`, `composer.lock` and `Gemfile.lock` (tracked files; `tests/**`, `**/fixtures/**`, `node_modules` and `vendor` are excluded by default) and looks every version up in [OSV](https://osv.dev), which merges the GitHub Advisory Database, PyPA, RustSec, the Go vulnerability database, npm and NVD-derived records. A finding fails the check with its OSV/GHSA/CVE ids, severity and fixed versions.

It never touches the network unless asked: `GETZILLA_OSV_ONLINE=1` (or `--online`) queries `api.osv.dev`; `GETZILLA_OSV_DB=<dir>` (or `--db`) reads an offline mirror made with `python3 scripts/getzilla_vulns.py --download-db <dir>`. With neither, the check is skipped and says how many dependencies went unchecked; `--mode pr`/`release` refuse that skip (only a repository without pinned dependencies may skip), so set one of them for those modes. The GitHub Actions workflow from `getzilla_ci.py --write` sets `GETZILLA_OSV_ONLINE=1`; Trust CI mounts its host mirror read-only at `/vulndb` when the sandbox policy sets `vulnerability_db_host_path`.

A finding can be accepted for a limited time in `.getzilla/config/known-vulnerabilities.json`:

```json
{
  "exclude": ["tests/**", "**/fixtures/**", "**/node_modules/**", "**/vendor/**"],
  "accept": [{"id": "CVE-2024-22195", "reason": "templates are trusted input", "expires": "2026-12-31"}]
}
```

`id` matches the OSV id or any alias; an expired entry fails the check again. Offline range matching uses the advisory's enumerated versions first and a generic version order otherwise, so the online API is the reference when they disagree.

## Local browser demo

```bash
python3 scripts/getzilla_demo.py --open
```

The command binds only `127.0.0.1`, prints `http://127.0.0.1:8765/`, and needs no frontend build, package installation, database, credential or Git query. The tour computes route and typed-spec previews in memory, reads architecture and governance summaries from this checkout, and shows bundled sample verification evidence. Nothing is written and nothing leaves the host. Press `Ctrl-C` to stop.

Browser assets are same-origin only under `default-src 'self'`, render text through `textContent`, and use system font stacks, so the page works offline. See [docs/INVESTOR_DEMO.md](../docs/INVESTOR_DEMO.md) for the five-minute walkthrough, expected states and port troubleshooting.

## Hooks

Lifecycle adapters live in `.grok/hooks/` and are registered in both:

- `.grok/hooks.json` — doctor/structure contract (`command` + `commandWindows`)
- `.grok/hooks/adaptive.json` — Grok project-hook discovery

Trust the folder once (`/hooks-trust` or `grok --trust`). Hooks classify prompts and enforce local policy (secrets, Bitrix core, destructive commands, control-plane mutations, and exact delegated side-effect grants). Hook failure remains fail-open to avoid locking an interactive agent; this is why hooks are not merge authority. External gates retain their own enforcement: public GitHub Actions or the private App-owned Trust CI required Check Run.

## Package

```bash
python3 scripts/package_stack.py
```

Creates `dist/getzilla-v<VERSION>.zip` and its checksum sidecar. See the [release package and operator guide](../packages/README.md) for published artifacts and packaging requirements.

## Bitrix

See skills under `.grok/skills/bitrix-development/` and example module in `examples/bitrix-module/`.

## License

[MIT License](../LICENSE).

Explicit owner overrides of local workflow rules must record the exact rule, scope, reason, deferred checks and follow-up validation. Keep the result UNVERIFIED until those checks run. Do not fabricate passing evidence, external attestation, branch-protection bypass or human-key authority.

New workflow state stays under ignored runtime and can move to `ready` without changing source. Reports bind exact reviewed HEAD/tree and content hashes. No report-only or workflow freeze commit is needed. Historical tracked evidence remains unchanged.

Saved report-only deltas use exactly `code-review.md`, `test-review.md`, `bitrix-review.md`, `security-review.md`, `data-review.md` or `release-review.md` directly under the active change evidence directory. Analysis, README/index, checkpoint and arbitrary custom Markdown files are source changes, not saved review reports.
