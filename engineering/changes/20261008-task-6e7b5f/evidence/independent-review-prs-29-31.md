# Независимое READ-ONLY ревью PR #29, #31, #30 (Getzilla)

- **Репозиторий:** https://github.com/Dimkox/Getzilla · база `main` = `a8f9338`
- **reviewed-tree-modified: no** (клон `/workspace/repos/review-getzilla` — `git status` чист, HEAD `a8f9338`; мутации только в приватной копии `0700` `/workspace/repos/review-notes/scratch2/gz29`, восстановлена)
- **Проверенные SHA:** #29 head `8d6655a09538cccf3889b12e23e62af1b00c8d3a` tree `1f4cfb40`; #31 head `47b9a4877c15850577c03afcdcf15df25626d816` tree `579731c0` (стек на #29); #30 head `d7c1a90da2a541b1c73e96339cf885165f41f8d2` tree `11b1f277`
- **Шаг 0 / CPU:** 2026-10-08T17:53 MSK, 8 логических CPU, нет cgroup-квоты, делится с воркерами → self-cap 2. Полный `getzilla_verify` не запускался; переиспользованы `/workspace/repos/logs/verify3-gz-trustci.log`, `vulns-after.log`; точечно: unittest, OSV API, мутационные пробы.
- **Дата:** 2026-10-08

---

## PR #29 — fix(architecture): сходимость queue-анализа на list-append циклах — **ВЕРДИКТ: APPROVE**

Основное изменение — не в `architecture_fitness.py`, а в `.getzilla/getzilla/queue_provenance.py` (абстрактный интерпретатор FIT-BOUNDED-WORKER-JOBS).

### Оценка ключевых вопросов

**1. Корректно ли расширение циклов (loop-widening)? Может ли дать ложный PASS (пропустить реальную очередь)?** — Нет, расширение консервативно и звуково.
- `widen_sequence` (`queue_provenance.py:203-216`) схлопывает растущую последовательность в `_unbounded_sequence(_aggregate(current))`. `_aggregate` джойнит ВСЕ элементы и `default`; `join_value(QUEUE, …)` никогда не даёт `NON_QUEUE` → метка QUEUE/UNKNOWN_QUEUE не теряется, а эскалирует.
- `_select` на последовательности неизвестной длины возвращает summary/`default`, а отрицательный индекс/распаковку — `UNKNOWN_QUEUE` (`:218-233`). Доступ по любому индексу отвечает summary или UNKNOWN. 
- Добавление очереди в уже расширенную последовательность помечает её `UNKNOWN_QUEUE` (`:728-738`): `if _aggregate(container)==NON_QUEUE and _aggregate(added)==NON_QUEUE: return True else set UNKNOWN`. Защита в глубину.
- Проверено на сценарии, не покрытом тестами (очередь входит до цикла, далее только обычные append, чтение после цикла): `items=[Queue()]; for x: items.append(make()); items[0].enqueue(job)` → `analyze_queue_tree`: `uncertain=True`, присутствует `semantic-call:…enqueue`. Очередь не пропущена.

**2. Безопасно ли «не списывать бюджет за неизменённые привязки»? Нет ли неограниченной работы/DoS?** — Безопасно.
- `_join_envs` (`:467-472`) теперь вызывает `self._join` только при `other is not value and other != value`. В типичном случае после `_fork` (`dict(env.values)` — общие ссылки) неизменённая привязка — тот же объект → срабатывает дешёвый `is`, глубокое сравнение не выполняется. Результат джойна тождественен прежнему (`join(x,x)=x`), меняется только счётчик бюджета, т.е. на РЕЗУЛЬТАТ анализа изменение не влияет → ложный PASS невозможен.
- DoS нет: завершение гарантируют `loop_limit`, `statement_limit`, `alias`-лимит независимо от бюджета значений; расширение обеспечивает сходимость цикла.

### Мутационные пробы (приватная копия `0700`, тесты `test_architecture_fitness.py`)
| Мутант | Что ломает | Результат |
|---|---|---|
| M1: `widen_sequence` возвращает `current` (расширение выкл.) | сходимость | **killed** (ошибка «limit exceeded») |
| M5: `_LOOP_WIDENING_DELAY = 10**9` (никогда не расширять) | сходимость | **killed** |
| M3: append в расширенную seq всегда `return True` (теряет очередь) | звуковость/ложный PASS | **killed** (assert `inside/after` ловит пропуск enqueue) |
| M2: вернуть джойн для неизменённых привязок | тест бюджета | **killed** (value limit exceeded) |
| M4: `widen_sequence` → `_unbounded_sequence(NON_QUEUE)` (теряет summary) | звуковость summary | **survived** — пробел в тестах (см. находку L1); при этом shipped-код на том же сценарии проверен звуковым |

### Находки
| Серьёзность | Файл:строка | Что | Доказательство | Рекомендация |
|---|---|---|---|---|
| low (L1) | `tests/test_architecture_fitness.py:1829-1898` | Новые тесты не фиксируют звуковость summary при расширении: мутант M4 выжил. Причина — ассерты вида `uncertain OR enqueue-signal`, а ветки с очередью, вошедшей ДО цикла и читаемой после цикла (только обычные append после), нет. | M4 survived; при этом shipped-код на сценарии `items=[Queue()]; for …: items.append(make()); items[0].enqueue(job)` даёт `uncertain=True` (звуково). | Добавить тест, который именно через summary (не через append-после-расширения) доказывает сохранение QUEUE. |
| info | `queue_provenance.py:471` | Глубокое `!=` для AbstractValue в `_join_envs` не метрицируется бюджетом. Ограничено `value_limit` (размер структур), потому не DoS. | — | Опц.: учитывать стоимость сравнения или полагаться на `value_limit`. |

### Процесс
Пакет изменения `engineering/changes/20261008-task-d259e6/` (brief/requirements/architecture/test-plan/change-spec/evidence); CHANGELOG, decisions.md, mistakes.md обновлены; Conventional Commits. **Заголовок честен:** перечисленные FAIL (architecture-drift, governance, known-vulnerabilities, bandit, python-unittest, coverage, factory-postgres-exit) действительно pre-existing на main и закрываются #30/#31 (подтверждено ниже).

---

## PR #31 — fix: ремонт падений CI #19–#23 — **ВЕРДИКТ: APPROVE** (с замечанием)

### Оценка ключевых вопросов

**1. Идентична ли восстановленная стадия OpenGrep утраченной и реально ли она применяется (не пропускаема)?**
- **Идентична.** `def _opengrep` восстановлен byte-identical оригиналу из `c290132` (40 строк совпадают построчно; константы `OPENGREP_RULES`/`OPENGREP_EXCLUDES` и запись skip в `quality_gates.py` идентичны). Стадия вновь включена в `_verification_run` (`verification.py:2382-2384`) — в оригинале после `trivy`, сейчас после `known-vulnerabilities`; обе версии её выполняют.
- **Применение частичное (замечание, medium):** `opengrep` НЕ входит в `MANDATORY_PR_CHECKS`, а `quality_gates._allowed_skip` (`:83-84`) разрешает skip с summary `"opengrep not available"`/`"no OpenGrep rules installed"`. Значит локально без установленного `opengrep` стадия тихо пропускается; реальное принуждение — в CI (`.github/workflows/getzilla.yml`), где opengrep ставится с проверкой `sha256sum` и `_opengrep` вызывается напрямую. Это ТОЧНО соответствует исходному дизайну (skip-запись была в оригинале) → восстановление верное, не регресс данного PR. Но SAST как жёсткий гейт держится только на CI.

**2. Реальный ли фикс bandit B105 или подавление, что-то скрывающее?** — Реальный фикс, не подавление.
- `scripts/getzilla_vulns.py:60-64`: литерал-словарь `{'pass':0,'skip':0,'fail':1}.get(status,2)` (ключ-строка `'pass'` триггерил B105 hardcoded-password) заменён явным `status=…; raise SystemExit(0 if status in {'pass','skip'} else 1 if status=='fail' else 2)`. Нет `# nosec`. Отображение кодов возврата тождественно прежнему (pass/skip→0, fail→1, иначе→2). 

**3. Корректны ли пины pypdf/fastapi?** — Да (проверено по OSV API).
- `factory/pyproject.toml`: `pypdf 6.18.1→6.19.0` (OSV: старая 6 → новая **0**), `fastapi 0.128.2→0.142.4` (fastapi сам чист в обеих, но тянет транзитивный `starlette 0.50.0`→`1.7.0`; OSV starlette: старая **10** → новая **0**). `factory/uv.lock` обновлён согласованно (specifier + resolved + starlette 1.7.0 + runtime-wheels json).

### Прочее
- `customers.py` зарегистрирован в `architecture/system.yaml` (членство trust-ci) → снимает дрейф архитектуры #21 (в логе PR30 он падал именно на этом).
- Лендинг: удалён дублированный `<p class="note">…predecessor-record…</p>` (#20) в `index.html` и `template/index.template.html` (единственная строка); frozen-digest в `tests/test_getzilla_landing.py:211` обновлён под новый текст — легитимное обслуживание снапшота (изменение ровно одной строки).

### Находки
| Серьёзность | Файл:строка | Что | Доказательство |
|---|---|---|---|
| medium (M1) | `quality_gates.py:12-30,83-84` + `verification.py:1671-1708` | SAST OpenGrep не является жёстким локальным гейтом: не в `MANDATORY_PR_CHECKS` и skip разрешён при отсутствии бинаря/правил. Принуждение — только в CI. (Дизайн-ограничение, восстановлено как было, не регресс PR.) | diff идентичности + состав MANDATORY_PR_CHECKS |
| info | заголовок/стек | На дереве #31 `known-vulnerabilities` всё ещё FAIL (trust-ci `cryptography==46.0.4`, закрывается #30). Это честно указано в заголовке. | OSV: cryptography 46.0.4 → 13 уязвимостей |

### Процесс
Пакет `engineering/changes/20261008-task-1d9b18/`; CHANGELOG/mistakes/decisions обновлены; Conventional Commits; запись в mistakes.md о merge `4ae0447`, уронившем стадию. **Заголовок честен** (FAIL known-vulnerabilities, factory-postgres-exit).

---

## PR #30 — fix(deps): пины cryptography/fastapi в trust-ci — **ВЕРДИКТ: APPROVE**

### Оценка ключевых вопросов

**1. Закрывают ли пины все OSV-уязвимости?** — Да (OSV API).
- `trust-ci/pyproject.toml`: `cryptography 46.0.4→50.0.2` (OSV: **13 → 0**), `fastapi 0.128.2→0.142.4` (транзитивный starlette `0.50.0`→`1.7.0`: **10 → 0**).

**2. Ломающие изменения API cryptography/fastapi для кода trust-ci?** — Риск низкий.
- `cryptography` 46→50 — скачок на 4 мажора, но trust-ci использует только стабильные API: `serialization.load_pem_private_key`, `Ed25519PrivateKey.generate/sign`, `Encoding.{Raw,PEM}`, `PublicFormat.{Raw,SubjectPublicKeyInfo}`, `PrivateFormat.PKCS8`, `NoEncryption`, `rsa.RSAPrivateKey`, `padding.PKCS1v15()`, `hashes.SHA256()`, `key.sign/verify` (`signing.py`, `github_app.py`). Ни один из них не удалён/не задепрекейчен в этом диапазоне. fastapi 0.128→0.142 — минорный шаг, код trust-ci (`api.py`) использует базовые `FastAPI/Depends/Header/HTTPException/Request`.

**3. Целостность lockfile.** — У trust-ci нет lockfile (только пины `==` в pyproject), обновлять нечего; `factory/uv.lock` этим PR не трогается (правильно — это #31).

### Находки
| Серьёзность | Файл:строка | Что | Доказательство |
|---|---|---|---|
| low (L1) | `trust-ci/pyproject.toml` | У trust-ci нет lockfile → транзитивные зависимости (например starlette) резолвятся при установке, а не пинятся; прямой OSV-скан покрывает только прямые `==`-пины. Безопасность starlette обеспечена косвенно через fastapi 0.142.4. | нет `uv.lock`/`requirements.txt` в trust-ci |
| info | лог `verify3-gz-trustci.log` | На изолированном дереве #30 FAIL: architecture (customers.py — #21, чинит #31), bandit (#23, чинит #31), known-vulnerabilities (factory-пины — #31). Ожидаемо для одиночного PR из стека; заголовок помечен `[UNVERIFIED transport]`. | лог |

### Процесс
Пакет `engineering/changes/20261008-task-abdea3/`; `trust-ci/README.md` обновлён; Conventional Commits; заголовок `[UNVERIFIED transport]` — корректная метка делегированного pre-verification push по AGENTS.md.

---

## Сквозное замечание (medium, не блокирующее)
Ни один из трёх PR по отдельности не проходит `known-vulnerabilities`: #31 падает на trust-ci `cryptography` (закрывает #30), #30 падает на factory `pypdf`/customers (закрывает #31), #29 объявляет всё pre-existing. Чистое состояние даёт только совокупный merge #29+#30+#31 (подтверждается `logs/vulns-after.log`: `PASS known-vulnerabilities: no known vulnerabilities in 35 pinned dependencies`). **Рекомендация:** мержить как согласованный набор и прогнать один финальный full-verify на объединённом head; авторитетный гейт (CI/Trust CI) в любом случае считается на итоговом SHA.

## Итоговые вердикты
- **PR #29 — APPROVE.** Расширение циклов звуково/консервативно; пропуск бюджета — семантический no-op без DoS; 4 из 5 мутантов убиты, выживший M4 = только пробел в тестах (L1, low).
- **PR #31 — APPROVE** с замечанием M1 (SAST не жёсткий локальный гейт — восстановлено как было). OpenGrep byte-identical и применяется в CI; B105 — настоящий фикс без подавления; pypdf/fastapi/starlette пины закрывают OSV.
- **PR #30 — APPROVE.** cryptography/fastapi пины закрывают все OSV; ломающих API trust-ci не использует; lockfile отсутствует by design (L1, low).
- Блокирующих находок нет.

## Методология/ограничения
Диффы — `git diff`/`git show` в собственном клоне; мутации — в приватной копии `0700` (восстановлена, reviewed-tree-modified: no). OSV — запросы к `api.osv.dev` по изменённым пакетам (старые и новые версии). Полный verify не перезапускался — использованы существующие логи. Комментарии/апрувы на GitHub не ставились.
