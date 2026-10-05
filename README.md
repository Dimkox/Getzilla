# Getzilla v2.2.0
# Getzilla

Getzilla lets an AI write code for your project and checks that code before it is allowed to stay.

## The short version

With "vibe coding", you ask an AI for something, it writes the code, and you hope it works. It is fast and fun. You usually find out later what it broke.

Getzilla keeps the fast part and adds a checking part. The AI still builds what you asked for. Before that work joins the real project, it gets checked: tests run, a second AI reviews it, and a person decides whether to keep it.

Think of a child building a LEGO tower. Building is the fun part, and nobody should slow it down. But before the tower goes on the shelf next to everything else, someone makes sure it is steady, so it does not knock the whole shelf over. Getzilla is that someone.

## Vibe coding vs. Getzilla

| | Plain vibe coding | With Getzilla |
| --- | --- | --- |
| "It works" | The AI says so | Tests and checks really ran, and the results are saved |
| Who checks the work | The same AI that wrote it | A different AI reviewer. The author cannot approve itself |
| Where changes go | Wherever the AI puts them, sometimes straight into `main` | Every task gets its own branch and pull request |
| Memory | Gone when the chat ends | Every task leaves a folder: the request, the plan, test results, reviews |
| Mistakes | The next session repeats them | Lessons are written down in `mistakes.md` and `decisions.md` for the next session |
| Small vs. risky tasks | Treated the same | Small tasks take a short path. Risky ones get more checks and a human sign-off |
| Something unclear | The AI guesses | Getzilla stops instead of guessing |
| Who ships | The AI | You do. The agent works through a pull request, and a person merges it |

You do not give up vibe coding. The rule is **vibe first, check second**: build it fast, then run it through Getzilla before it is kept.

## How a task goes

```bash
git clone https://github.com/Dimkox/Getzilla.git
cd getzilla
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
python3 scripts/getzilla_change.py start --title "Первая задача"
python3 scripts/getzilla_status.py
python3 scripts/getzilla_verify.py --mode pr
```

This gives you a candidate and evidence. It does not merge, deploy, publish, or mutate production systems.

## What this repository contains

- `scripts/install_into.py`: read-only install planning for existing repos and no-replace materialization for absent repos.
- `.agents/skills/`: domain skills for agent work, including Bitrix, API/events, frontend, data, security and release tasks.
- `.getzilla/`: local routing, verification, architecture, governance and receipt code.
- `factory/`, `delivery/`, `pilot/`: default-off factory, staged delivery and pilot boundaries.
- `trust-ci/`: optional separately deployed merge authority. It is advanced operator infrastructure, not part of the first run.
- `engineering/changes/`, `decisions.md`, `mistakes.md`: durable evidence and lessons for later agents.

## What this is not

- It is not a hosted SaaS.
- It is not a GitHub Actions workflow.
- It is not an automatic merge bot.
- It does not make the agent a production operator by default.
- It does not turn local receipts into merge authority.

## Fail-closed boundaries and current limits

Fail-closed here means that unclear, unknown or out-of-policy input is rejected instead of guessed through.

Boundaries that currently cut execution:

- The installer plans existing repositories read-only. New-target materialization refuses existing targets, symlinks, special files and platforms without the required no-replace filesystem primitives.
- Closed schemas reject unknown keys, malformed JSON and unsupported versions.
- Workflow-source adapters parse bounded artifacts. They do not execute imported shell commands, call networks or ask an LLM to interpret foreign workflow text.
- PR verification leaves the docs/state fast lane when a changed path is outside the explicit allowlist, when Git status is ambiguous, or when the comparison base cannot be trusted.
- Merge authority is outside chat and local receipts. It requires a pull request, the App-owned `adaptive-trust-ci/verified@<policy-sha12>` check on the exact head SHA, and the required human approvals.
- Providers, pilot flows, Linux setup and factory publication are default-off unless a separate operator action enables them.

Known weak seams this line is closing:

- A prose claim is not evidence that a live check exercised the risky path.
- An empty acceptance-criteria set is not coverage.
- A receipt fingerprint without the bound file is not durable evidence.
- A timeout or interrupted verifier is incomplete, not a pass.
- A restarted attempt cannot reuse an old model/config/profile identity without requalification.

The price is deliberate. For a small personal patch this can feel too heavy. For an autonomous agent touching someone else's repository, the route, change package, fitness checks, receipts, external holdout and human merge gate are the safety boundary. The published release is `v2.1.1`. Liqvera is a completed owner-accepted factory-built product; empirical autonomy qualification and production authority remain separate.

## Advanced startup baseline

**Step zero, before all other startup work:** [measure resources](AGENTS.md#mandatory-startup-algorithm-measure-then-dispatch)—physical/online logical CPUs, process affinity, effective cpuset and finite cgroup quotas; try a bounded child-only affinity expansion when appropriate, derive verified effective capacity and record the snapshot. Only then inspect backlog/routes, build dependencies and dispatch all independent route-permitted work in parallel, spreading eligible heavy work across that capacity. Isolated writer ownership comes next, followed by verification/delivery gates. Remeasure every startup: the September 26 observation of **14 physical / 28 logical CPUs**, with default affinity exposing 22 and a verified `taskset -c 0-27` child exposing 28, is not a permanent guarantee.

The second startup step records trusted base/HEAD and dirty inventory. The merged [fail-closed scope selector](#verification-scope-selection) runs inside the single final qualifying PR gate, after reviews/report persistence/commit/freeze and before that gate's heavy checks. Its closed focused inventory admits named docs/state paths, tracked `packages/**` release bytes, and exactly five binding test modules: `tests/test_structure.py`, `tests/test_project_state.py`, `tests/test_manifest_package.py`, `tests/test_workflow_sources.py` and `tests/test_repo_router.py`. Only that inventory may skip coverage/full discovery/PostgreSQL; all other executable changes, non-admitted paths or ambiguous inventories require full verification.

The observed **controller + 12 child-agent slots**, routing cap `max_parallel_analysis=10` and test-process workers are separate limits. Keep one writer per isolated task/route/branch/worktree; independent isolated writers may run concurrently. An exact delegated branch push before verification is labelled **UNVERIFIED transport only**. Protected/shared branches prohibit direct pushes; merge requires a PR, App-owned Trust CI on the exact head and all required approvals.

## Current state

Identity: **2.2.0 source candidate** with executable bounded local owner autonomy. The latest published release in this pre-publication snapshot is [v2.1.1](https://github.com/Dimkox/adaptive-grok-build-pro/releases/tag/v2.1.1), published on 2026-10-03 from PR #238 at `97a7581238022356b2de8d193a9bd8363fc92dc3`, ZIP SHA-256 `f5116c5e1303232ae883ed7a3aa804b71f0b5654d2c385924653b5ffd2d631c1`. Its core includes verifier recovery, architecture and governance hardening, and heartbeat/watchdog. The [approved decomposition](engineering/changes/20261002-assemble-2-1-1-factory-source-with-heartbeat-and-ffb3d8/delivery-topology-addendum.md) retains F durable evidence and G current-authority behavior as successors; owner-local M8 does not establish those empirical interfaces. Prior release records remain immutable.

PR #244 delivered the accepted-product record at `2a8e3839a469b3e05da167e9d8a807bf18e6adbf`. Continue `feat/m8-one-task-autonomy`, route `b258608f2ced`, through the [M8 change package](engineering/changes/20261004-task-b25860/brief.md) and `PROJECT_STATE.json.current_continuation`: independent review, report freeze, one final full verifier and exact-head external Trust CI precede delivery. The previous cleanup continuation is historical. Release assets require exact merged tested source and separately delegated publication.

Historical pre-publication core observation: the conditional source included the frozen test-only025 [cursor reset seam](factory/tests/postgres_fixture_reset.py), its two unchanged-boundary callers and narrowly typed lock-refusal acceptance controls. Pending joined-fitness/source-acceptance statements in that old record remain dated provenance, not current release instructions. F's026 inventory/runtime work remains absent.

The source tree also carries closed default-off BB contracts, an authenticated offline-only model-rotator registry, a bounded explicit-root VibeVM package store, and an opt-in offline Linux setup manager. U4/macOS remains excluded; no component activates providers, models, services, deployment, or production authority.

| Layer | Dated source and runtime observations |
| --- | --- |
| Historical core observation | Historical `main` was `3f41be92161fef451a2dfa7451eb458ce8f022b3`; the pre-publication core comparison base was `63799f8760d3a55028d83ab5ff0116ececf8f7d1`, with source/PR/check/merge/tag unknown in that dated candidate record. Current published identity is separately bound by `published_release` (PR #238). Historical `2.1.0` custody retains exact source `e5856acfd4bc7a186f40a740b54ec86459462db5`, tree `0dfa04f3ec3ea9c7a04c723e9d127603fc72999b` and its unchanged ZIP/sidecar hashes in `PROJECT_STATE.json`. |
| 2.1.0 candidate capabilities | U5 prediction artifacts are observation-only and require declared history before they can report availability. U6's pinned FPF snapshot can only emit deterministic evaluation evidence; external qualification remains `not_qualified`/not established and all authority effects remain `none`. |
| Installed L5 (September 19) | Primary Qwen is accepted at `f12807c2` / `qwen-omni-intl`; Grok stays accepted at `26a0d3d`. Both are **active and enabled**. Separate Omni remains at `e7d0f72`. |
| Proven runtime result (September 19) | Primary Qwen Omni produced `artifact_ready` in **4.991 s**, usage **766/195**; separate readback made zero POSTs. Grok previously completed in **26.947 s**. [Exact evidence and limits](engineering/runbooks/l5-primary-continuation-2026-09-19.md). |
| Completed product | M8 **DONE**: owner confirms the working Liqvera Mezo Buildathon demo was built by this factory. Released `v0.0.5` source `19284fb07fedd4909672c7e9a641cb066efbb7cc` pins factory `v2.0.19` / `cb9af4073ba6c3d515145164d771c75ebdfa3224`. Accepted-product dependencies and M8/M9 follow-up planning are unblocked; [exact provenance and boundaries](PROJECT_STATE.json) distinguish owner acceptance from runtime telemetry. |
| Bounded owner autonomy | One accepted Liqvera case qualifies the enabled local M8 owner policy. Accounting and human readiness are complete by explicit owner confirmation; numeric totals remain unknown. Activate per clone with the commands below. Initial L1 admits only local reads/tests; ceiling L2 confers no external authority. |
| Remaining acceptance | Empirical M7 durable current lookup and exact-profile evidence, general M9 signed environment/recovery qualification, and factory-runtime public-site publication remain unestablished. Another first completed pilot is not required. |

Historical `v2.0.19` delivery records the source line through PR #193 in release-sync PR #189. Its [release-sync change package](engineering/changes/20260922-release-v2-0-19-from-candidate-5d93fc3-0ea342/brief.md) and [artifact-child package](engineering/changes/20260924-build-v2-0-19-artifact-child-from-merged-release-09407b/brief.md) preserve separate source verification, artifact provenance and publication; they do not instruct another artifact build, tag or release of published `v2.1.1`.

Source templates default to live execution off. The observed Qwen and Grok services use separately provisioned configurations with live execution explicitly enabled.

- Current source adds [`getzilla-landing-submit`](engineering/runbooks/l5-provider-failover.md): durable text/safe-DOCX submission through Qwen → Grok → OpenAI → Claude → OpenRouter, authenticated capability/attempt APIs, and atomic SQLite observations. Ambiguous submissions reconcile the same child; existing artifacts prevent further generation. Grok and primary Qwen now have accepted direct runtime results; the three added providers/full chain remain unqualified for inference. Monetary cost remains unknown; publication stays separate.
- Trust CI repository-scoped immutable profiles are implemented in code and documented by the example catalog; the worker uses `TRUST_CI_HOLDOUT_PATH` and `TRUST_CI_HOLDOUT_HOST_PATH` as independently configured trusted roots, validated binary-first before dependency construction. The capability is pending a separately reviewed and approved server-side policy/holdout installation; no deployed policy or branch protection is changed by it.

Start with [START_HERE.md](START_HERE.md) and [PROJECT_STATE.json](PROJECT_STATE.json). Runtime operation is described in the [L5 runbook](engineering/runbooks/l5-production-runtime.md); milestone acceptance remains in the [roadmap](DARK_FACTORY_ROADMAP.md). Delivery is PR-only: the App-owned `adaptive-trust-ci/verified@06ecf1c875bc` check from GitHub App ID `<redacted-app-id>` must cover the exact PR head. Local receipts are preflight evidence. **No GitHub Actions:** this repository keeps deployed verification policy and holdout validation outside the PR-controlled tree, runs checks on the exact SHA, and binds the required result to its GitHub App identity.

## Optional Python test workers

The existing runner remains unchanged without opt-in. To select automatic workers, create `.getzilla-test-runner.json` containing `{"schema_version":1,"workers":"auto"}`; `GETZILLA_TEST_WORKERS` overrides the requested value after the configuration file is validated. Accepted requests are `auto` or an integer from 0 through 64. Explicit integers are not quota-clamped, and `GETZILLA_TEST_WORKERS=0` selects sequential execution.

On Linux, `auto` uses the minimum of 28, process affinity or CPU-count fallback, and finite CPU quotas visible through actual cgroup membership and mounts. Finite quotas use `max(1, quota // period)`; malformed, unreadable or ambiguous capacity conservatively selects one worker. This does not establish hidden ancestor limits, reserved CPU time or available PID/memory capacity.

Where this runner cannot provide its required parallel-process cleanup, a positive request selects the existing `unittest-degraded` engine before execution. Supported parallel execution retains its strict pins; measured serial execution retains pinned coverage. An actual failed parallel run is never retried serially. The implementation lives in `.getzilla/getzilla/python_test_runner.py` and its private `_cpu_capacity.py` helper; native Windows and older-interpreter qualification remain separate from fixture-based evidence.

## Bounded local M8 in the 2.2.0 source candidate

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

2.2.0 is a release candidate until its exact merged tested source passes the required gates and GitHub Release publication is separately authorized. ZIP/checksum assets are published through GitHub Releases; ZIPs are not source Git content. Published `v2.1.1` and its checksums remain immutable history.

## Как пользоваться опубликованной версией 2.1.1

v2.1.1 опубликован 2026-10-03 из PR #238; ZIP и контрольная сумма доступны в GitHub Releases. Наличие исходников F/G не означает их принятие, развёртывание Trust CI или готовую автономную фабрику. BB, rotator, VibeVM, FPF, prediction и Linux setup остаются выключенными по умолчанию; полный внешний пилот и эксплуатационная квалификация не подтверждены. U4/macOS в этот объём не входят.

1. Получите исходники и зафиксируйте, что именно проверяете:

   ```bash
   git clone https://github.com/Dimkox/Getzilla.git
   cd getzilla
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
   python3 scripts/getzilla_change.py start --title "Первая задача"
   python3 scripts/getzilla_gate.py status
   python3 scripts/getzilla_status.py
   ```

   `getzilla_route.py` создаёт маршрут, а `getzilla_change.py start` — пакет новой задачи; если пакет уже существует, повторный `start` пропустите. Создание маршрута/пакета пишет локальное состояние .getzilla/runtime/active-route.json и engineering/changes/<id>/. Не перезаписывайте уже активную задачу новым маршрутом. Используйте `/getzilla-delivery`: только выбранные allowed_agents, один write_agent на изолированную ветку/worktree, проверки и независимые reviewers. Если route.human_gates содержит scope_and_design_approval, человек сначала утверждает конкретный scope/design; `getzilla_gate.py decide` лишь фиксирует уже принятое решение, не выдаёт внешнее разрешение. Production/external actions требуют собственного точного делегирования и применимых внешних approvals.

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

6. Проверяйте результат по файлам и свежему evidence, а не по сообщениям агента:

   ```bash
   git status --short
   git diff
   python3 scripts/getzilla_verify.py --mode fast --no-record --test tests.test_quality_gates --test tests.test_python_test_runner.NamedSmokeTests --budget 180
   python3 scripts/getzilla_status.py
   ```

   PR/release по умолчанию останавливают последующие проверки при первом отказе, неизвестном статусе или недопустимом skip. Отчёт сохраняет реальный результат и явно помечает незапущенные проверки; source-stability и финальный QG остаются обязательными. `--keep-going` собирает диагностику, сохраняя архитектурный preflight и правила admission. Именованный fast smoke требует чистый committed HEAD, `--no-record` и явные unittest-имена; бюджет subprocess — 1–180 секунд (по умолчанию 180), после таймаута добавляется ограниченная очистка процесса и проверка идентичности. Он не создаёт и не заменяет receipt. Полный успешный PR gate может занять больше 180 секунд; smoke или таймаут не заменяют его.

   После CPU-снимка и маршрутизации зафиксируйте trusted base/HEAD и staged/unstaged/untracked inventory. Именованные controls выше — observation, без receipt и scope admission. Затем все независимые route-selected reviewers проверяют кандидат; полные отчёты сохраняются в engineering/changes/<id>/evidence/. Закоммитьте отчёты и заморозьте дерево. Единственный финальный qualifying local gate — `python3 scripts/getzilla_verify.py --mode pr`: его fail-closed selector выбирает scope по действительному base..HEAD и dirty inventory до тяжёлых checks. Зафиксируйте profile/reason, проверенные пути и skips; skipped не означает passed. Этот gate пишет локальный receipt в .getzilla/runtime/receipts/<route-id>/ и может идти параллельно с внешним App-owned exact-head Trust CI после точного delegated UNVERIFIED branch transport. Полный local gate до review не требуется. Status показывает evidence_gaps, package_incomplete и agent_diagnostics; изменение дерева делает прежние receipts устаревшими.

7. Доставка — отдельная ветка и PR. Только явно делегированные push/PR/merge/publish операции выполняются с точными ресурсами и соответствующими grants. Прямой push в main запрещён. Локальный PASS не разрешает merge: внешний GitHub App должен выдать adaptive-trust-ci/verified@<policy-sha12> на точный актуальный PR HEAD, а человек — требуемые подписанные approvals вне среды агента. Изменение HEAD/base/policy/holdout требует новой проверки и approvals. Установленный consumer stack не разворачивает эту внешнюю службу; её настраивает оператор отдельно.

   При отказе verifier изучите конкретный failed check, соберите связанные замечания в один ремонт тому же writer и повторите затронутые короткие controls. После независимого review сохраните полные отчёты, закоммитьте и заморозьте кандидат; финальные локальная проверка и внешний exact-head check могут идти параллельно после явно делегированного UNVERIFIED branch transport. Identical merged tree без новых product changes — no-op, без нового полного прогона. При отказе установщика сохраните указанный stage для ручной инспекции, если сообщено `manual cleanup required`; не удаляйте неизвестную цель. При неоднозначном runtime/provider результате сохраните состояние и audit, выполните документированное reconcile, не повторяйте публикацию/inference вслепую. Для реального factory control plane и L5 нужны отдельные операторские конфигурация, зависимости, authority и rollout/recovery runbooks; установка локального стека сама их не активирует и не выдаёт live URL.

## Verification scope selection

At [startup](AGENTS.md#second-mandatory-startup-step-select-verification-scope-before-heavy-work), after measured capacity and route/dependency scheduling, record trusted base/HEAD plus the staged/unstaged/untracked inventory. Bounded committed-HEAD controls are observations, without scope admission or verification receipts. Independent selected reviews precede the sole final qualifying local `python3 scripts/getzilla_verify.py --mode pr` run on the committed/frozen report-containing candidate. Its unchanged selector derives scope before its heavy checks. Record profile/reason, exact identities, path digest and skips; no manual "factory unaffected" heuristic or historical component pass expands its closed allowlist. Historical evidence retains its original exact Git identity and scope and never becomes a fresh pass. External exact-head Trust CI and approvals remain mandatory. Ten minutes is an unconfirmed delivery target; serial PostgreSQL and Core/PostgreSQL overlap have not been optimized by this change.

`getzilla_verify --mode pr` and `--mode release` classify the changed-path inventory before choosing what to run. A release documentation/state successor changes only prose, the dated state model, tracked release bytes, and the modules that bind them; it cannot move an executed product statement, so it does not owe a full-suite coverage run.

Admission is decided by **explicit content role, never by the directory name alone**: named prose/dated state, tracked release bytes and exactly the five binding test modules listed below. Admitted content is re-derived by a module this lane itself runs (root identity, the dated state model and package bytes from the lockstep trio; README's Workflow-sources table from `tests/test_workflow_sources.py`; a delivered change package's route record from `tests/test_repo_router.py`), or has no machine binding to lose (per-change workflow records, ADRs, backlogs, reviews, runbooks). Two prose-looking classes are rejected even though they live under a documentation path — `docs/bitrix-local-AGENTS.md`, which `scripts/install_into.py` installs verbatim as `local/AGENTS.md` into every consumer Bitrix install (agent-executed instructions shipped as product), and any `<anything>/evidence/historical-*` bundle, whose bytes `tests/test_history.py` pins to a literal sha256 (declared-immutable evidence). There is accordingly no `docs/` prefix: admitted documentation is a named file set plus `docs/superpowers/plans/`, `docs/superpowers/specs/` and the `engineering/` prose directories, and a new prose file is not admitted until it is declared.

The focused profile `docs-state-focused` still runs the spec, architecture, governance, workflow-artifact, secret, contract, SQL, Ruff, Bandit, pilot and factory-unit checks, plus five admitted modules: the lockstep trio `tests/test_structure.py`, `tests/test_project_state.py`, `tests/test_manifest_package.py` and the two binding tests whose subject is admitted content, `tests/test_workflow_sources.py` (README's Workflow-sources table) and `tests/test_repo_router.py` (a delivered change package's route record). It skips three checks and says so: the full-discovery runner it replaced (`python-unittest` here, `pytest` in a consumer install whose runner is pytest), `coverage`, and `factory-postgres-exit`. Measured on this checkout: the serial `coverage run -m unittest discover -s tests` path costs 629 s, the five admitted modules about 14 s.
1. **Build it.** Get the feature working quickly on its own branch.
2. **Sort it.** Getzilla looks at the task and decides how careful to be: which skills to use, which reviewers to call, whether a person must approve the plan first.
3. **Check it.** Tests and other checks run. The results are saved next to the task.
4. **Review it.** Separate AI reviewers read the change and write down what they find.
5. **Ship it.** A pull request is opened, and a person merges it. Teams that want an extra lock can add Trust CI, a separate service that tests the exact version again before merge.

## Try it

You need Python 3.10 or newer and Git. The AI agent itself runs in the Grok Build CLI.

```bash
git clone https://github.com/Dimkox/Getzilla.git
cd Getzilla
python3 scripts/getzilla_doctor.py --offer-install   # checks which tools you have
python3 scripts/getzilla_demo.py --open              # read-only tour in your browser
```

To add Getzilla to your own project, start by asking for a plan. This only reads your project and changes nothing:

```bash
python3 scripts/install_into.py --plan /absolute/path/to/your/repo
```

Then follow [QUICKSTART.md](QUICKSTART.md).

## What is inside

- `scripts/`: the commands you run, such as `getzilla_route.py` and `getzilla_verify.py`
- `.grok/` and `.agents/skills/`: instructions and skills for the AI agents
- `.getzilla/`: the engine that sorts tasks, runs checks and saves the evidence
- `engineering/changes/`: one folder per task, with its plan, tests and reviews
- `architecture/`: a map of the system ([system.yaml](architecture/system.yaml), [rules.yaml](architecture/rules.yaml), [diagrams](architecture/generated/))
- `trust-ci/`: the optional outside checker, run as its own service
- `factory/`, `delivery/`, `pilot/`: bigger automation pieces, switched off by default

## What it is not

- Not a hosted service. It runs on your machine, inside your repository.
- Not a GitHub Actions workflow.
- Not a bot that merges or deploys on its own.

## Learn more

- [QUICKSTART.md](QUICKSTART.md): setup, step by step
- [docs/REFERENCE.md](docs/REFERENCE.md): the full technical reference, with the current state, every subsystem and the release history
- [START_HERE.md](START_HERE.md): where a new AI agent or contributor starts
- [AGENTS.md](AGENTS.md): the rules every agent follows
- [docs/INVESTOR_DEMO.md](docs/INVESTOR_DEMO.md): a five-minute demo walkthrough

Getzilla grew out of an [earlier project](https://github.com/Dimkox/adaptive-grok-build-pro/tree/c4e506f3d3a45e000f5b9f9121f698c1d16814e3) and was renamed. Older pull-request numbers and releases mentioned in the docs belong to that project.

Current version: [VERSION](VERSION). License: [MIT](LICENSE).
