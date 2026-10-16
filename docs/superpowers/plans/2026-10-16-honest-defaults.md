# Getzilla — ТЗ «Честные дефолты»: риск по факту изменения, лёгкий путь для мелочей, защита от платных циклов — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Spec:** `docs/superpowers/specs/2026-10-16-honest-defaults-design.md`

**Goal:** Риск по факту изменения, лёгкий путь для доказанных мелочей, обязательный бюджет для платных циклов, честный уровень принуждения, обязательный закреплённый базис (безопасность, Superpowers, BMAD, Spec Kit) сразу после установки и всё остальное по необходимости, реальные проверки .NET, Rust, PowerShell, Node, Go и Java с тулчейнами, которые подтягиваются сами (Windows в первую очередь), обещания лендинга привязаны к механизмам.

**Architecture:**
- **Чистые модули:**
  - `diff_risk.py` — классификация диффа поверх `code_graph` и правил путей;
  - `cost_guard.py` — детектор платных и неограниченных операций и проверка бюджетного контракта;
  - `enforcement.py` — инвентаризация фактического принуждения.
- **Точки подключения:** роутер, verification (receipt), stop и pre-tool хуки, `install_into` (профили), лендинг (`claims.json`).

**Tech Stack:** Python 3.12 stdlib, unittest/pytest (`-n 26` на claw), существующие `getzilla.spec.validate_schema`, `code_graph`, `workflow_artifacts`.

## Global Constraints

- Риск только повышается. Ни одна задача не понижает `required_evidence` ниже нынешнего маршрута, кроме профиля `trivial`, и только при доказанном диффе.
- Инвариант «автор ≠ одобряющий» на всех профилях.
- В тестах нет сети и живых платных вызовов. Внешние API только через фикстуры.
- Новые схемы используют подмножество ключевых слов `getzilla.spec.validate_schema` (без `oneOf` и `title`); экземпляры проверяются тестом.
- Правила записи текста: `encoding=` в `text=True`, `newline="\n"` в `write_text`, проверяет `tests/test_text_writes.py`.
- Каждый пакет: полный набор в 26 потоков на claw, ruff, `bandit -c bandit.yaml`, отдельный коммит.
- **Локальных прогонов в Windows Sandbox нет.** Поддержка Windows остаётся в коде и в unit-тестах (пути, PATH, `.ps1`, фикстуры ответов). Реальную проверку на Windows делает CI-джоб `windows` на PR; его падение чиним в том же PR. То, что CI-джоб не покрывает (чистая установка через `install.ps1`, реальная загрузка тулчейнов на Windows, MSVC), явно перечисляется в описании PR как «на Windows не проверено».
- Golden-таблица роутера (задача H01) — регрессионный контракт: последующие задачи её не ломают.

## Порядок и зависимости

```
H01 ─► H02 ─► H03 ─► L01
C01 ─┐
C02 ─┴► C03
E01, E02, E03, E04 — независимы
F02 — независима (обязательный базис)
F01 ─► F03 (по необходимости, одна копия)
S01 ─► S02 (.NET), S03 (Rust), S04 (PowerShell), S05 (Node/TS), S06 (Go) ─► S07 (Java)
        S01 использует ensure-механизм F03
O01 — независима
M01 — последней (после H, L, C, E, F, S)
```

P0: H01–H03, C01–C03, E02, E03, **F02**. P1: L01, E01, E04, F01, F03, S01–S05, M01. P2: S06, S07, O01. Вне ТЗ: C/C++ (CMake + MSVC) — отдельное решение о scope.

---

### Task H01: Закрыть дыры словаря риска и зафиксировать golden-таблицу

**Files:**
- Modify: `.getzilla/getzilla/router.py` (`HIGH_RISK`, `MEDIUM_RISK`)
- Create: `tests/test_router_risk_golden.py`
- Create: `tests/fixtures/router/risk-golden.json`

**Interfaces:** без изменений API. `build_route` возвращает новый `risk` на расширенный словарь.

- [ ] **Step 1: Написать падающий тест.** В golden-таблицу внести формулировки из 1.3 с ожидаемыми значениями:
  - `high`: «add a checkout with saved cards», «fix login for existing accounts», «почини логин после вчерашнего обновления», «сделай вход через Google», «перепиши обработку оплаты заказа», «списывай деньги с карты каждый месяц»;
  - не ниже `medium`: «сделай в n8n сценарий: генерируй 20 вариантов видео через Kling и выбери лучший», «подключи OpenRouter и гоняй генерацию картинок, пока не получится хорошо»;
  - `low/micro`: «исправь опечатку в README».

  Добавить отрицательные контроли, которые не должны повышаться: «логотип», «карточка товара», «картинка в README». Они проверяют, что стеммы вроде «карт» не матчат лишнее.
- [ ] **Step 2: Run** `python3 -m pytest -q tests/test_router_risk_golden.py`. Ожидаемо: FAIL на строках `high`.
- [ ] **Step 3: Implement.** Добавить термины с границами слова через существующий `_has_term`:
  - `HIGH_RISK`: `оплат`, `checkout`, `saved card`, `сохранённ… карт`, `card number`, `login`, `логин`, `вход через`, `sign in`, `signup`, `session token`, `subscription`, `подписк`, `списан`, `refund`, `возврат денег`;
  - `MEDIUM_RISK`: `n8n`, `генерац`, `generate … variants`, `пока не`, `until it`, `cron`, `webhook`.

  Многословные термины разбирать по токенам, а не подстрокой, чтобы «картинка» и «карточка» не матчили «карт».
- [ ] **Step 4: Re-run.** Ожидаемо: PASS. Плюс полный `tests/test_router*.py` и `tests/test_repo_router.py`, без регрессий.
- [ ] **Step 5: Commit** `fix(router): risk vocabulary for payments, login and paid loops; golden routing table`.

**Приёмка:** golden-таблица зелёная. Все прежние тесты роутера зелёные. Отрицательные контроли не повышаются.

**Уточнение владельца (2026-10-16): база — английский, остальные языки агенты переводят сами.**
- Словарь вынесен в `.getzilla/config/risk-terms/`: `en.json` — база (id термина, категория, английские термины), `ru.json` — первый языковой пакет.
- `getzilla risk-terms scaffold --lang <код> --script <SCRIPT>` выдаёт агенту заготовку с английскими подсказками; `getzilla risk-terms check` проверяет полноту и синтаксис.
- Промпт в письменности, которую не покрывает ни один пакет, получает минимум `medium` с причиной `PROMPT_LANGUAGE_NOT_COVERED:<SCRIPT>`; сломанный словарь — тоже `medium`.
- Тесты: `tests/test_risk_terms.py`. Документация: `docs/risk-terms.md`.

### Task H02: Риск диффа на точном HEAD

**Files:**
- Create: `.getzilla/getzilla/diff_risk.py`
- Modify: `.getzilla/config/routing.json` (новая секция `diff_risk_rules`: правила путей)
- Create: `schemas/diff-risk-v1.schema.json`
- Test: `tests/test_diff_risk.py`

**Interfaces:**
- `classify_diff(root: Path, base: str, head: str, config) -> DiffRisk`
- Поля `DiffRisk`: `risk`, `profile_candidate` (`trivial|standard|full`), `reasons[]` (путь или символ плюс правило), `changed_paths[]`, `coverage` (complete/gaps), `head`, `tree`.

- [ ] **Step 1: Failing tests** на временных git-репозиториях (`tests/branch_support.py`):
  - дифф только в `docs/*.md` даёт `low` и `profile_candidate=trivial`;
  - правка `auth/*.py`, `**/payment*`, `**/billing*` или символа, на который ссылается `architecture/system.yaml` с `data_classification` из ограниченных, даёт `high`;
  - правка `.github/**`, `pyproject.toml`, lock-файлов или `requirements*.txt` даёт не ниже `medium` с причиной `DEPENDENCY_OR_CI`;
  - удаление файла теста даёт `high` с причиной `TEST_REMOVED`;
  - изменение `tests/test_*.py` без изменения кода даёт `medium` с причиной `TESTS_CHANGED_WITHOUT_CODE`;
  - дифф с неразобранным Python (`incomplete`) или файлом на неподдерживаемом языке не может получить `trivial`;
  - `head` и `tree` совпадают с `git rev-parse`.
- [ ] **Step 2: Run** `python3 -m pytest -q tests/test_diff_risk.py`. Ожидаемо: ImportError.
- [ ] **Step 3: Implement.**
  1. Изменённые пути: `git diff --name-status -z base..head` через изолированный Git, как в `project_ingestion._git`.
  2. Правила путей из `routing.json`.
  3. Для `.py` построить граф (`code_graph.builder.build_generation`) по точному дереву HEAD и связать затронутые файлы с архитектурой (`architecture_bindings`).
  4. `trivial` только при `coverage.complete` и всех путях из допускающего списка (`*.md`, `docs/**`, кроме `docs/bitrix-local-AGENTS.md` и `**/evidence/historical-*`; список совпадает с правилом допуска в `AGENTS.md`).
- [ ] **Step 4: Re-run.** Ожидаемо: PASS. Экземпляр валидируется по `diff-risk-v1` через `validate_schema`.
- [ ] **Step 5: Commit** `feat(risk): exact-head diff risk classification`.

**Приёмка:** каждая причина указывает путь или символ и id правила. При неполном покрытии `trivial` недостижим.

### Task H03: Повышение маршрута по диффу при verify

**Files:**
- Modify: `.getzilla/getzilla/verification.py` (запись `diff_risk` в receipt)
- Modify: `.getzilla/getzilla/router.py` (`escalate_route(route, diff_risk) -> Route`)
- Modify: `.grok/hooks/stop_gate.py` (сообщение о повышении)
- Test: `tests/test_route_escalation.py`

**Interfaces:**
- `escalate_route(route, diff_risk)` объединяет `review_agents` и `required_evidence` для `max(route.risk, diff_risk.risk)` и никогда их не удаляет.

- [ ] **Step 1: Failing tests:**
  - маршрут `low` по промпту плюс дифф в `payments/` дают в receipt `risk=high` и добавленные `security_review` и `release_review`; `getzilla_verify --mode pr` возвращает fail с причиной `ROUTE_ESCALATED_EVIDENCE_MISSING`, пока evidence не появится;
  - маршрут `high` плюс тривиальный дифф остаются `high`, понижения нет;
  - receipt содержит `route_risk`, `diff_risk`, `effective_risk`.
- [ ] **Step 2: Run** `python3 -m pytest -q tests/test_route_escalation.py`. Ожидаемо: FAIL.
- [ ] **Step 3: Implement.** Повышение считается в verify на точном HEAD и пишется в receipt. Stop-гейт показывает его как предупреждение.
- [ ] **Step 4: Re-run.** Ожидаемо: PASS. Полный набор зелёный.
- [ ] **Step 5: Commit** `feat(verify): escalate the route to the exact-head diff risk`.

**Приёмка:** нельзя пройти `--mode pr` с evidence ниже фактического риска диффа.

### Task L01: Профиль `trivial` — лёгкий путь только для доказанных мелочей

**Files:**
- Modify: `.getzilla/config/routing.json` (`review_floors.trivial: ["code_reviewer"]`)
- Modify: `.getzilla/getzilla/router.py`, `.getzilla/getzilla/verification.py`
- Test: `tests/test_trivial_profile.py`

- [ ] **Step 1: Failing tests:**
  - «исправь опечатку в README» плюс дифф только в `README.md` дают `required_evidence=[verification, code_review]` и `review_agents=[code_reviewer]`; ревьюер не автор (`write_agent ≠ reviewer`);
  - тот же промпт плюс дифф, задевший `.py`, дают обычный профиль `standard` и `test_review`;
  - `trivial` без receipt verify не проходит;
  - профиль и причина (`TRIVIAL_PROVEN_BY_DIFF`) записаны в receipt, так что сокращение видно.
- [ ] **Step 2: Run** `python3 -m pytest -q tests/test_trivial_profile.py`. Ожидаемо: FAIL.
- [ ] **Step 3: Implement.** Профиль выбирается **только** по `diff_risk.profile_candidate == 'trivial'` и `effective_risk == 'low'`. Промпт в одиночку `trivial` дать не может.
- [ ] **Step 4: Re-run.** Ожидаемо: PASS. Golden H01 зелёная.
- [ ] **Step 5: Commit** `feat(route): proven-trivial profile with one independent review`.

**Приёмка:** обещание лендинга «A typo gets a light touch» выполняется, и инвариант независимого ревью не нарушен.

### Task C01: Распознавание платных и неограниченных операций в промпте

**Files:**
- Create: `.getzilla/getzilla/cost_guard.py` (`prompt_cost_signals(text) -> list[CostSignal]`)
- Create: `.getzilla/config/cost-providers.json` (провайдеры и ключевые слова: OpenAI, OpenRouter, Anthropic, Replicate, Kling, Runway, Midjourney, ElevenLabs, Stability, n8n, Make, Zapier; а также «N вариантов», «пока не», «until», «каждый час/день/месяц», «cron»)
- Modify: `.getzilla/getzilla/router.py` (сигнал → `risk ≥ medium`, `required_evidence += cost_guard`, `human_gates += first_live_paid_run`)
- Test: `tests/test_cost_guard_prompt.py`

- [ ] **Step 1: Failing tests:**
  - две формулировки про n8n/Kling и OpenRouter из 1.3 дают `cost_guard` в `required_evidence` и gate `first_live_paid_run`;
  - «добавь кнопку» сигналов не даёт;
  - «напиши тест для генератора отчётов» не даёт (слово «генератор» без провайдера и цикла не сигнал).
- [ ] **Step 2: Run** `python3 -m pytest -q tests/test_cost_guard_prompt.py`. Ожидаемо: ImportError.
- [ ] **Step 3: Implement.** Сигнал = (провайдер ИЛИ платформа автоматизации) И (множественность ИЛИ цикл ИЛИ расписание), либо явный неограниченный цикл.
- [ ] **Step 4: Re-run.** Ожидаемо: PASS. Golden H01 обновлена на две строки.
- [ ] **Step 5: Commit** `feat(cost): paid and unbounded operation signals in routing`.

### Task C02: Распознавание платных циклов в диффе

**Files:**
- Modify: `.getzilla/getzilla/cost_guard.py` (`diff_cost_findings(root, base, head) -> list[CostFinding]`)
- Test: `tests/test_cost_guard_diff.py`
- Fixtures: `tests/fixtures/cost_guard/` (n8n JSON с `SplitInBatches` или `Loop` без лимита и с лимитом; Python с `while True: client.images.generate(...)`; retry без `max_attempts`; цикл с явным `for _ in range(MAX)` и проверкой бюджета)

- [ ] **Step 1: Failing tests:**
  - неограниченные фикстуры дают находку `UNBOUNDED_PAID_LOOP` с путём и строкой;
  - ограниченные находок не дают;
  - импорт платного SDK (`openai`, `replicate`, `anthropic`, HTTP-клиент на хост из `cost-providers.json`) без цикла даёт `PAID_CALL` (информационная находка, требует бюджетного контракта, но не блокирует);
  - ничего не исполняется (проверка через `ast` для Python и разбор JSON для n8n).
- [ ] **Step 2: Run** `python3 -m pytest -q tests/test_cost_guard_diff.py`. Ожидаемо: FAIL.
- [ ] **Step 3: Implement.** Python: `ast`-обход вызовов внутри `while` или `for` без константной границы и без break по бюджетной переменной. n8n: граф узлов, где цикл ведёт к узлу HTTP или провайдера и нет `maxIterations` или проверки счётчика. Остальные языки: только поиск хостов провайдеров; при совпадении находка `UNANALYSED_PAID_CALL`, coverage gap.
- [ ] **Step 4: Re-run.** Ожидаемо: PASS.
- [ ] **Step 5: Commit** `feat(cost): unbounded paid loop findings in the diff`.

### Task C03: Бюджетный контракт и gate первого живого запуска

**Files:**
- Modify: `schemas/change-spec-v1.schema.json` (необязательный `cost_contract`: `max_calls`, `max_spend_usd`, `stop_condition`, `alert`, `provider`)
- Modify: `.getzilla/getzilla/verification.py` (проверка `cost_guard`)
- Modify: `.getzilla/getzilla/human_gates.py` (gate `first_live_paid_run`)
- Test: `tests/test_cost_contract.py`

- [ ] **Step 1: Failing tests:**
  - есть сигнал C01 или находка C02, но нет `cost_contract`: verify `--mode pr` даёт fail с `COST_CONTRACT_MISSING`;
  - контракт есть, но нет теста, ссылающегося на `max_calls` (тест из `green` задачи должен упомянуть символ лимита): fail `COST_BOUND_UNTESTED`;
  - контракт и тест есть: pass; gate `first_live_paid_run` остаётся открытым до одобрения человеком (существующий механизм `human_gates`, ключ агенту недоступен);
  - живой вызов в тестах запрещён: фикстура с реальным хостом провайдера без мока падает (сетевой guard в `tests/_support.py` уже есть или добавляется).
- [ ] **Step 2: Run** `python3 -m pytest -q tests/test_cost_contract.py`. Ожидаемо: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Re-run.** Ожидаемо: PASS. Полный набор зелёный.
- [ ] **Step 5: Commit** `feat(cost): budget contract, bound test and first-live-run gate`.

**Приёмка:** сценарий, аналогичный кейсу −$1200 («генерируй, пока не получится»), не проходит verify без лимита, стоп-условия и теста на них, а живой запуск требует человека.

### Task E01: `getzilla doctor --enforcement`

**Files:**
- Create: `.getzilla/getzilla/enforcement.py` (`inspect_enforcement(root, *, github=None) -> EnforcementReport`)
- Modify: `scripts/getzilla_doctor.py`
- Test: `tests/test_enforcement_report.py`

- [ ] **Step 1: Failing tests:**
  - отчёт перечисляет агентов с установленными хуками;
  - для каждого агента self-test хуков (запуск хука на синтетическом payload с проверкой ответа);
  - режим stop-гейта (`soft` или `strict`);
  - наличие `getzilla-verify.yml`;
  - состояние branch protection: из фикстуры ответа `gh api` (если передан клиент), иначе `unknown`, без догадок;
  - Trust CI: настроен или нет;
  - итоговый уровень `advisory`, `ci-enforced` или `external` по правилу «минимум из подтверждённого».
- [ ] **Step 2: Run** `python3 -m pytest -q tests/test_enforcement_report.py`. Ожидаемо: FAIL.
- [ ] **Step 3: Implement.** Сеть только через переданный клиент, в тестах фикстуры.
- [ ] **Step 4: Re-run.** Ожидаемо: PASS.
- [ ] **Step 5: Commit** `feat(doctor): report the enforcement level actually in effect`.

### Task E02: Видимость fail-open

**Files:**
- Modify: `.grok/hooks/_lib.py`, `.grok/hooks/pre_tool_use.py`, `.grok/hooks/stop_gate.py`
- Modify: `.getzilla/getzilla/verification.py` (receipt: `hook_degraded_events`)
- Test: `tests/test_hook_degraded.py`

- [ ] **Step 1: Failing tests:**
  - исключение внутри политики `pre_tool_use` пишет событие `HOOK_DEGRADED` в журнал рантайма (`.getzilla/runtime/`), действие при этом не блокируется, как и раньше;
  - stop-гейт выводит предупреждение с числом событий;
  - receipt verify содержит их число;
  - `--mode pr` с событиями деградации для `effective_risk=high` даёт fail `HOOKS_DEGRADED_ON_HIGH_RISK`.
- [ ] **Step 2: Run** `python3 -m pytest -q tests/test_hook_degraded.py`. Ожидаемо: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Re-run.** Ожидаемо: PASS.
- [ ] **Step 5: Commit** `feat(hooks): record and surface fail-open degradation`.

### Task E03: Утверждение «тесты прошли» только с receipt

**Files:**
- Modify: `.grok/hooks/stop_gate.py`
- Modify: `.getzilla/config/policy.json` (`stop_gate_mode`: `soft` по умолчанию, `strict` для `effective_risk=high`)
- Test: `tests/test_stop_gate_claims.py`

- [ ] **Step 1: Failing tests:**
  - последнее сообщение агента содержит утверждение о прохождении тестов или проверок (русские и английские формы из фикстуры), а receipt на текущий fingerprint отсутствует: в `soft` предупреждение, в `strict` ответ хука `decision: block` с причиной (формат Stop-хука Claude/Codex);
  - receipt есть: тишина;
  - сообщение без утверждения: тишина.
- [ ] **Step 2: Run** `python3 -m pytest -q tests/test_stop_gate_claims.py`. Ожидаемо: FAIL.
- [ ] **Step 3: Implement.** Если формат блокировки агентом не поддерживается, хук деградирует до предупреждения и пишет `HOOK_DEGRADED`, как в E02.
- [ ] **Step 4: Re-run.** Ожидаемо: PASS.
- [ ] **Step 5: Commit** `feat(stop-gate): verification claims need a matching receipt`.

### Task E04: `getzilla ci protect --plan`

**Files:**
- Modify: `scripts/getzilla_ci.py`, `.getzilla/getzilla/ci_gate.py`
- Test: `tests/test_ci_protect_plan.py`
- Docs: `docs/enforcement.md`

- [ ] **Step 1: Failing tests:**
  - `--plan` печатает точный JSON правила branch protection (required checks = имена jobs из `getzilla-verify.yml`, `strict: true`, запрет force-push на `main`) и команду `gh api` для применения; ничего не отправляет;
  - без `--plan` и без `--yes` exit 2.
- [ ] **Step 2: Run** `python3 -m pytest -q tests/test_ci_protect_plan.py`. Ожидаемо: FAIL.
- [ ] **Step 3: Implement.** Применение (`--yes`) отправляет запрос только через переданный клиент. В тестах фикстура. Реальное применение — решение владельца.
- [ ] **Step 4: Re-run.** Ожидаемо: PASS.
- [ ] **Step 5: Commit** `feat(ci): plan branch protection for exact-head required checks`.

### Task F01: Объём установки в плане

**Files:**
- Modify: `scripts/install_into.py` (`--plan` выводит `components: {name: {files, bytes}}`)
- Test: `tests/test_install_footprint.py`

- [ ] **Step 1: Failing test:** план на пустом репозитории содержит компоненты с числами файлов и байт: `core`, `baseline:security`, `baseline:workflow` (Superpowers, BMAD, Spec Kit), `agent:<name>` для каждого агента и `factory`. Сумма равна общему числу файлов payload.
- [ ] **Step 2–4:** RED → implement → GREEN.
- [ ] **Step 5: Commit** `feat(install): per-component footprint in the plan`.

### Task F02: Обязательный базис сразу после установки (P0)

Базы безопасности, Superpowers, BMAD и Spec Kit ставятся всегда. Флага, переменной окружения или вопроса, чтобы их пропустить, нет. Если они не встали, установка не считается завершённой.

**Files:**
- Modify: `scripts/install.sh`, `scripts/install.ps1`:
  - убрать `offer_tool_update` и вопрос `[y/N]`;
  - сбой базиса даёт ненулевой код выхода вместо `WARNING`;
  - установить зависимости базиса: Node.js для установщика BMAD и `uv` для `specify`.
- Modify: `.getzilla/getzilla/updater.py`:
  - новый `install_baseline(...)` ставит **закреплённые** версии из `toolchain.json`, а не `HEAD`;
  - `update_sources` остаётся отдельной командой обновления.
- Modify: `.getzilla/config/toolchain.json`:
  - для каждого компонента добавить `pinned_commit` и `install` (механизм подключения к каждому агенту);
  - политику *«never an install target»* заменить на `mandatory_baseline`.
- Create: `.getzilla/getzilla/baseline.py`:
  - `inspect_baseline(home, project=None) -> BaselineStatus` — что стоит, какая версия и commit, к каким агентам подключено, свежесть OSV;
  - `require_baseline(...)` — исключение с перечнем недостающего.
- Modify: `scripts/install_into.py`: при установке в проект ставит проектную часть базиса:
  - BMAD — его штатным установщиком в `_bmad/`;
  - Spec Kit — `specify init` для выбранного агента.

  Существующие `_bmad/` и `.specify/` в проекте не перезаписываются: при другой версии это фиксируется в отчёте, решение остаётся за владельцем.
- Modify: `.getzilla/getzilla/verification.py`:
  - в `--mode pr` и `--mode release` отсутствующий или устаревший базис даёт `fail` с `SECURITY_BASELINE_MISSING` или `WORKFLOW_BASELINE_MISSING`, а не `skip`;
  - `opengrep: skip` «not available» превращается в `fail`.
- Modify: `scripts/getzilla_doctor.py` (секция `baseline`).
- Modify: `PROJECT_STATE.json` (`source_installers`): новые дайджесты кандидатов инсталлеров (правило A03: опубликованные дайджесты не меняются до релиза).
- Test: `tests/test_mandatory_baseline.py`, `tests/test_install_scripts.py` (расширить).

**Interfaces:**
- `install_baseline(home, *, agent, run, fetch) -> list[Result]` — сеть только через переданные `run` и `fetch`, как уже устроен `updater`.
- `BaselineStatus.complete: bool`, `missing: list[str]`, `components: {id: {version, commit, agents[], fresh}}`.

- [ ] **Step 1: Failing tests:**
  1. В `install.sh` и `install.ps1` нет вопроса об установке Superpowers, BMAD и Spec Kit и нет переменной, которая их пропускает (статическая проверка текста скриптов).
  2. `install_baseline` ставит ровно `pinned`/`pinned_commit` из `toolchain.json`. Если upstream-тег указывает на другой commit, результат `fail` с `PINNED_COMMIT_MISMATCH`, без установки (фикстурный `run`).
  3. Superpowers, BMAD и Spec Kit подключены к выбранному агенту. Агент видит скиллы и команды там, где их ищет закреплённая версия upstream. Конкретный путь или механизм для каждого агента выписан в `toolchain.json` по README закреплённой версии и проверяется тестом с фикстурой. Механизмы не выдумываются; если upstream агента не поддерживает, это явная запись `unsupported` с причиной.
  4. Сбой OSV или OpenGrep: установщик завершается с ненулевым кодом и сообщением, что именно не встало и какой командой дотянуть. `doctor` показывает `baseline: incomplete`.
  5. Платформа без закреплённой сборки OpenGrep: установка `incomplete` с `UNSUPPORTED_PLATFORM:opengrep`, без тихого `skip`.
  6. `verify --mode pr` без OSV, без OpenGrep или без любого компонента workflow-базиса даёт `fail` с перечнем, а не `skip`. С полным базисом проходит.
  7. Повторный запуск установщика дотягивает только недостающее и уже стоящее не трогает (идемпотентность по версии и commit).
  8. Проект с уже существующими `_bmad/` или `.specify/` другой версии: файлы не перезаписаны, в отчёте `PROJECT_HAS_OWN_<ID>`.
- [ ] **Step 2: Run** `python3 -m pytest -q tests/test_mandatory_baseline.py tests/test_install_scripts.py`. Ожидаемо: FAIL.
- [ ] **Step 3: Implement.** Обновление до свежих версий остаётся отдельной командой `getzilla update --only sources`. Новая версия становится установочной только после зелёных `verification_tests` из `toolchain.json` и обновления `pinned` и `pinned_commit`.
- [ ] **Step 4: Re-run.** Ожидаемо: PASS. Плюс e2e установки на claw во временном `HOME`. Для `install.ps1` — статические проверки и unit-тесты с фикстурным `run`; на Windows его проверяет CI-джоб `windows`.
- [ ] **Step 5: Commit** `feat(install): mandatory pinned security and workflow baseline, fail closed`.

**Приёмка:**
- после установки на чистой машине Superpowers, BMAD и Spec Kit закреплённых версий доступны выбранному агенту, а OSV и OpenGrep на месте;
- если чего-то нет, установка, `doctor` и `verify --mode pr` красные;
- способа «не ставить» нет.

### Task F03: Остальное — само по необходимости, одна копия вместо пяти

**Files:**
- Modify: `scripts/install_into.py`:
  - канонический источник скиллов и описаний агентов (`.agents/`), для каждого используемого агента только его обёртки;
  - `factory/` в первичную установку не входит.
- Create: `.getzilla/getzilla/on_demand.py`:
  - `ensure_components(root, need) -> list[Added]` доставляет недостающий компонент из закреплённой копии Getzilla (`GETZILLA_HOME` той же версии), без сети;
  - каждое добавление записывается в managed-манифест.
- Modify: точки срабатывания:
  - `scripts/getzilla_cli.py`: перед командами фабрики → `factory`;
  - `scripts/getzilla_setup_agent.py`: выбран агент → его обёртки;
  - SessionStart-хук: обнаружен каталог нового агента → его обёртки;
  - роутер: домен `bitrix` или `php` → доменный пакет.
- Test: `tests/test_install_on_demand.py`.

- [ ] **Step 1: Failing tests:**
  - первичная установка на пустой репозиторий: нет `factory/`; обёртки только для выбранного агента; каждый скилл лежит один раз в каноническом месте; базис F02 на месте; число файлов зафиксировано тестом с верхней границей (значение снять при реализации);
  - появился каталог второго агента (`.codex/`) → при следующем запуске хука или `getzilla` его обёртки добавлены автоматически, без вопроса, и записаны в манифест;
  - первая команда фабрики → `factory/` добавлен из закреплённой копии той же версии, команда выполнена;
  - профиль репозитория с Bitrix → доменный пакет добавлен;
  - ничего не скачивается из сети (только из `GETZILLA_HOME`), версия совпадает с установленной;
  - добавления видны в `git status` и попадают в активный change record как изменения managed-слоя;
  - verify и роутер работают в первичной установке (e2e на временном репозитории);
  - полная раскладка (как сейчас, 672 файла) остаётся служебным параметром только для тестов совместимости, не пользовательским вариантом.
- [ ] **Step 2: Run** `python3 -m pytest -q tests/test_install_on_demand.py`. Ожидаемо: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Re-run.** Ожидаемо: PASS. Существующие тесты установки зелёные (переведены на служебную полную раскладку там, где проверяют полный набор).
- [ ] **Step 5: Commit** `feat(install): single canonical copy, components pulled when needed`.

**Приёмка:**
- в проект попадает базис плюс то, что реально используется;
- остальное появляется само в момент необходимости, без флагов и вопросов, с записью в манифест;
- README и QUICKSTART описывают это поведение.

### Task S01: Реестр стеков, честная отметка «не проверено», доставка тулчейнов

**Files:**
- Create: `.getzilla/config/stacks.json`. Для каждого стека: `markers`, `toolchain` (для каждой ОС: источник, версия по умолчанию, файл закрепления версии в проекте, способ проверки контрольной суммы, `needs_admin`), `checks` (для `fast` и `pr`), `osv_ecosystem`.
- Create: `.getzilla/getzilla/stacks.py`:
  - `detect_stacks(root) -> list[Stack]`;
  - `stack_checks(root, mode, stack, toolchain) -> list[CheckResult]`.
- Create: `.getzilla/getzilla/toolchains.py`: `ensure_toolchain(stack, version, *, fetch, run, os) -> Toolchain | Blocker`. Тулчейн ставится в `~/.getzilla/toolchains/<stack>/<version>/`:
  - без прав администратора;
  - системный PATH не меняется, путь передаётся только процессу проверки;
  - кэши пакетов лежат в `~/.getzilla/cache/<stack>`, а не в проекте.
- Modify: `.getzilla/getzilla/verification.py` (диспетчер стеков рядом с `_python_checks`, `_node_checks` и PHP).
- Modify: `.getzilla/getzilla/on_demand.py` (F03): тулчейн — ещё один компонент «по необходимости».
- Test: `tests/test_stacks_registry.py`, `tests/test_toolchains.py`.

- [ ] **Step 1: Failing tests:**
  - репозиторий с `Cargo.toml` и стеком без записи в реестре даёт в receipt `STACK_NOT_VERIFIED:<stack>`. В `--mode pr` при изменённых файлах этого стека — `fail`, потому что «молча зелёный» больше не бывает;
  - `ensure_toolchain` с фикстурным `fetch`:
    - архив с неверной контрольной суммой — `fail` с `TOOLCHAIN_CHECKSUM_MISMATCH`, ничего не распаковано;
    - повторный вызов с тем же закреплением ничего не скачивает;
    - версия берётся из файла закрепления в проекте (`global.json`, `rust-toolchain.toml`, `go.mod` `toolchain`, `.nvmrc`/`engines`, `.java-version`), иначе по умолчанию из `stacks.json`;
  - компонент с `needs_admin` (MSVC Build Tools) при отсутствии даёт `fail` с `TOOLCHAIN_NEEDS_ADMIN:<id>` и готовой командой для человека. Getzilla сам его не ставит;
  - нет сети или источник недоступен — `fail` с `TOOLCHAIN_UNAVAILABLE`, а не `skip`;
  - PATH процесса проверки содержит каталог тулчейна, а системный PATH и профиль пользователя не изменены (на Windows — тест, что код не пишет в `HKCU\Environment`, через фикстурный слой записи реестра).
- [ ] **Step 2: Run** `python3 -m pytest -q tests/test_stacks_registry.py tests/test_toolchains.py`. Ожидаемо: ImportError.
- [ ] **Step 3: Implement.** Источники только официальные, с опубликованной контрольной суммой:
  - .NET — метаданные релизов Microsoft;
  - Rust — `rustup-init` с `.sha256`;
  - Go — список загрузок go.dev;
  - Node — `SHASUMS256.txt` с nodejs.org;
  - JDK — Eclipse Temurin;
  - модули PowerShell — PowerShell Gallery с проверкой подписи.

  Точные URL и формат манифеста фиксируются в `stacks.json` и проверяются тестом с записанной фикстурой, без выдумывания. Никакого `curl | sh` и выполнения скачанного без проверки.
- [ ] **Step 4: Re-run.** Ожидаемо: PASS.
- [ ] **Step 5: Commit** `feat(stacks): stack registry, honest not-verified marker, checksummed user-level toolchains`.

Для каждой задачи S02–S07 одинаково: фикстурный мини-проект в `tests/fixtures/stacks/<stack>/` (проходящий вариант и вариант с ошибкой для каждой проверки), unit-тесты с фикстурным `run`, e2e с реальной загрузкой тулчейна на claw, и коммит. Windows-ветки кода (имена архивов, `.exe`, `.ps1`) покрыты unit-тестами с фикстурами; на настоящей Windows их проверяет CI-джоб `windows`, насколько он их запускает.

### Task S02: .NET (C#, F#) — P1

- **Признаки:** `*.sln`, `*.slnx`, `*.csproj`, `*.fsproj`, `global.json`, `Directory.Build.props`.
- **Тулчейн:** .NET SDK по `global.json` (иначе текущий LTS из `stacks.json`) через официальный установщик Microsoft в пользовательский каталог. Workloads (MAUI, WASM и т.п.) не ставятся: при необходимости `DOTNET_WORKLOAD_NOT_SUPPORTED`, явно.
- **Проверки:**
  - `fast`: `dotnet format --verify-no-changes`;
  - `pr`: `dotnet restore` (`--locked-mode` при наличии `packages.lock.json`), `dotnet build --no-restore`, `dotnet test --no-build`, `dotnet format --verify-no-changes`.
- **Уязвимости:**
  - добавить `NuGet` в `known_vulns.ECOSYSTEMS` и в загрузку OSV (`updater.update_osv`);
  - разбирать `packages.lock.json`; без lock-файла после restore разбирать `obj/project.assets.json` во временной копии сборки;
  - без того и другого — `NUGET_DEPENDENCIES_UNKNOWN` (gap, в `pr` — fail).
- **Windows:** проверять сборку проекта с путём длиннее 260 символов и с пробелами в пути.
- **Test:** `tests/test_stack_dotnet.py`.
- **Commit:** `feat(stacks): .NET build, test, format and NuGet vulnerabilities`.

### Task S03: Rust — P1

- **Признаки:** `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`.
- **Тулчейн:**
  - `rustup` в пользовательский каталог (`RUSTUP_HOME` и `CARGO_HOME` внутри `~/.getzilla/toolchains/rust`), toolchain по `rust-toolchain.toml`, компоненты `rustfmt` и `clippy`;
  - **Windows:** целевая платформа `*-msvc` требует компоновщик MSVC (Visual Studio Build Tools, рабочая нагрузка C++). Он ставится только с правами администратора, поэтому при отсутствии — `TOOLCHAIN_NEEDS_ADMIN:msvc-build-tools` с командой для человека;
  - если проект явно закрепил `*-gnu`, ставится он, без MSVC.
- **Проверки:**
  - `fast`: `cargo fmt --check`, `cargo clippy --all-targets --locked`;
  - `pr`: дополнительно `cargo build --locked`, `cargo test --locked`.

  Предупреждения clippy — находки в отчёте. Блокирующими становятся только при `-D warnings` в конфигурации проекта.
- **Уязвимости:** OSV `crates.io` по `Cargo.lock` (разбор уже есть). Без `Cargo.lock` — `CARGO_LOCK_MISSING` (gap).
- **Test:** `tests/test_stack_rust.py`. Сценарий Windows без Build Tools (фикстура: нет `link.exe`) обязан дать `TOOLCHAIN_NEEDS_ADMIN`, а не зависнуть и не пропустить проверку.
- **Commit:** `feat(stacks): Rust fmt, clippy, build and test`.

### Task S04: PowerShell — P1 (Windows-нативный стек; полезно и самому Getzilla для `install.ps1`)

- **Признаки:** `*.ps1`, `*.psm1`, `*.psd1`.
- **Тулчейн:** модули `PSScriptAnalyzer` и `Pester` 5.x в пользовательскую область из PowerShell Gallery, закреплённых версий, с проверкой подписи. Встроенный в Windows Pester 3.4 не используется. Запуск под `pwsh`, если он есть, иначе Windows PowerShell 5.1; версия интерпретатора записывается в receipt.
- **Проверки:**
  - `fast`: `Invoke-ScriptAnalyzer -Recurse` (уровни Error и Warning — находки);
  - `pr`: дополнительно `Invoke-Pester`, если есть `*.Tests.ps1`.
- **Test:** `tests/test_stack_powershell.py`. Прогон на собственных `scripts/install.ps1` и `scripts/bootstrap.ps1` с базовым набором подавлений, записанным в репозитории.
- **Commit:** `feat(stacks): PowerShell analysis and Pester`.

### Task S05: Node / TypeScript — P1 (доделать существующие `_node_checks`)

- **Признаки:** `package.json`; менеджер по lock-файлу: `package-lock.json` → npm, `pnpm-lock.yaml` → pnpm, `yarn.lock` → yarn.
- **Тулчейн:** Node по `.nvmrc`, `.node-version` или `engines.node`, иначе LTS из `stacks.json`. pnpm и yarn через `corepack` закреплённой версии. Вместо нынешнего `skip`, когда нет npm, — доставка тулчейна.
- **Проверки:**
  - `pr`: установка по lock-файлу (`npm ci`, `pnpm install --frozen-lockfile`, `yarn install --immutable`), затем скрипты `lint`, `typecheck` и `test`, если они есть, иначе `tsc --noEmit` при наличии `tsconfig.json`;
  - без lock-файла — `NODE_LOCK_MISSING` (gap).
- **Уязвимости:** OSV `npm` (уже есть), добавить разбор `pnpm-lock.yaml` и `yarn.lock`.
- **Test:** `tests/test_stack_node.py`.
- **Commit:** `feat(stacks): pinned Node toolchain, lockfile installs, pnpm and yarn`.

### Task S06: Go — P2

- **Признаки:** `go.mod`.
- **Тулчейн:** Go по директиве `toolchain` или `go` в `go.mod`, с контрольной суммой из списка загрузок go.dev.
- **Проверки:**
  - `fast`: `gofmt -l` (непустой вывод — fail), `go vet ./...`;
  - `pr`: дополнительно `go build ./...`, `go test ./...`.
- **Уязвимости:** OSV `Go` (уже есть).
- **Test:** `tests/test_stack_go.py`.
- **Commit:** `feat(stacks): Go fmt, vet, build and test`.

### Task S07: Java / Kotlin — P2

- **Признаки:** `pom.xml`, `build.gradle`, `build.gradle.kts`, `mvnw`, `gradlew`.
- **Тулчейн:** JDK Temurin по `.java-version` или `toolchains` в сборке, иначе LTS из `stacks.json`. Maven и Gradle только через wrapper проекта (`mvnw`, `gradlew`); без wrapper — `BUILD_WRAPPER_MISSING` (gap), глобальные Maven и Gradle не ставятся.
- **Проверки (`pr`):** `mvnw -B verify` или `gradlew check`.
- **Уязвимости:** добавить `Maven` в `known_vulns.ECOSYSTEMS`; разбирать `gradle.lockfile`. Без lock — `MAVEN_DEPENDENCIES_UNKNOWN` (gap).
- **Test:** `tests/test_stack_java.py`.
- **Commit:** `feat(stacks): Java via project wrappers and Maven vulnerabilities`.

**Приёмка пакета S:**
- на claw фикстурные проекты .NET, Rust, PowerShell и Node проверяются реально (сборка, тесты, линтер, форматтер, уязвимости), а тулчейн скачивается сам при первом обнаружении стека;
- где тулчейн требует администратора или недоступен — красный результат с причиной и командой для человека, а не `skip`;
- стек без проверок помечается `STACK_NOT_VERIFIED`, и это видно в receipt.

### Task M01: Реестр обещаний лендинга

**Files:**
- Create: `side-projects/getzilla-landing/claims.json` (`[{id, text, mechanism, tests[], requires[]}]`)
- Modify: `side-projects/getzilla-landing/template/index.template.html` (сноска с условием для обещаний с непустым `requires`)
- Test: `tests/test_landing_claims.py`

- [ ] **Step 1: Failing tests:**
  - каждое предложение лендинга из списка маркеров обещаний («keeps … out of main», «tests that actually ran», «cannot grade its own homework», «hidden tests», «typo gets a light touch», «payments … full treatment») есть в `claims.json`;
  - каждый `tests[]` указывает на существующий тест;
  - обещания, требующие Trust CI или branch protection, выводятся с условием;
  - golden H01 и L01 покрывают обещания про опечатку и платежи.
- [ ] **Step 2–4:** RED → implement → GREEN. Пересборка лендинга существующим генератором.
- [ ] **Step 5: Commit** `feat(landing): every behavioural claim names its mechanism and test`.

### Task O01: Счётчики выгоды и `getzilla report`

**Files:**
- Create: `.getzilla/getzilla/route_metrics.py`
- Modify: `.getzilla/getzilla/verification.py`, `.grok/hooks/stop_gate.py` (запись событий)
- Create: `scripts/getzilla_report.py` (регистрация в `getzilla_cli.py` как `report`)
- Test: `tests/test_route_metrics.py`

- [ ] **Step 1: Failing tests:**
  - по каждому маршруту считается длительность от создания до receipt, число прогонов verify, число ревью, число блокирующих находок ревью и verify до merge, профиль и `effective_risk`;
  - отчёт за период агрегирует по профилям;
  - данные локальные (`.getzilla/runtime/metrics.jsonl`) и не содержат промптов и путей вне репозитория.
- [ ] **Step 2–4:** RED → implement → GREEN.
- [ ] **Step 5: Commit** `feat(report): per-route overhead and caught-defect counters`.

**Приёмка:** владелец может ответить на вопрос «окупается ли ритуал» цифрами по своим маршрутам.

---

## Итоговая приёмка ТЗ

1. Golden-таблица роутера: формулировки из 1.3 классифицируются как в H01 и C01; опечатка идёт по `trivial`; платежи и логин идут по `full`.
2. На временном репозитории «генерируй через провайдера, пока не получится» не проходит `getzilla_verify --mode pr` без `cost_contract` и теста на лимит. Живой запуск требует human gate.
3. `getzilla doctor --enforcement` на текущем репозитории выводит фактический уровень и не выдаёт `unknown` за `ok`.
4. После установки на чистой машине (claw, временный `HOME`) обязательный базис на месте и подключён к агенту:
   - OSV и OpenGrep;
   - Superpowers, BMAD и Spec Kit закреплённых версий.

   Без базиса установка, `doctor` и `verify --mode pr` красные. Остальное (`factory/`, второй агент, доменные пакеты) появляется само при первой необходимости. Каждый скилл лежит в одной копии; число файлов первичной установки зафиксировано тестом.
5. Каждое поведенческое обещание лендинга связано с механизмом и тестом; условия Trust CI и branch protection видны.
6. Проекты .NET, Rust, PowerShell и Node проверяются по-настоящему на Windows и Linux. Тулчейн подтягивается сам при обнаружении стека: закреплённая версия, проверенная контрольная сумма, без прав администратора. Стек без проверок помечен `STACK_NOT_VERIFIED` и не даёт молча зелёный `pr`.
7. Полный набор в 26 потоков зелёный, ruff и bandit чистые. CI-джобы `linux` и `windows` на PR зелёные. Непроверенное на Windows перечислено в описании PR.
