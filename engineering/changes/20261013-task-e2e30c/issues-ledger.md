# All-issues delivery ledger

Owner order: stop premature full runs; repair all open issues first, then final verification. Raw issues and comments are preserved in ignored controller runtime. No issue is closed without exact criterion evidence.

- [78](https://github.com/Dimkox/Getzilla/issues/78): Control-plane: LLM фактически имеет приоритет перед правилами фабрики — pending criterion audit/repair/final evidence.
- [76](https://github.com/Dimkox/Getzilla/issues/76): Incident: shared-host Gemini/Veo spend requires paid-call budgets, credential isolation and attribution — pending criterion audit/repair/final evidence.
- [75](https://github.com/Dimkox/Getzilla/issues/75): Incident: factory metadata and requirements left untracked block consumer workflow; safe migration cleanup needed — pending criterion audit/repair/final evidence.
- [73](https://github.com/Dimkox/Getzilla/issues/73): Low follow-up: ancestry regression isolation and frozen-state documentation — pending criterion audit/repair/final evidence.
- [72](https://github.com/Dimkox/Getzilla/issues/72): L5: довести Getzilla до production к 08:00 GMT+3 2026-10-09 — pending criterion audit/repair/final evidence.
- [71](https://github.com/Dimkox/Getzilla/issues/71): Follow-ups from #67 review — pending criterion audit/repair/final evidence.
- [63](https://github.com/Dimkox/Getzilla/issues/63): Handoff/security: проверить и закрыть пункты внешнего ревью (установщик, digests, модель угроз) — pending criterion audit/repair/final evidence.
- [60](https://github.com/Dimkox/Getzilla/issues/60): fix(architecture): false FIT-BOUNDED-WORKER-JOBS when a module newly adds `from . import <module>` — pending criterion audit/repair/final evidence.
- [42](https://github.com/Dimkox/Getzilla/issues/42): trust-ci: no lockfile, transitive dependencies are unpinned — pending criterion audit/repair/final evidence.
- [38](https://github.com/Dimkox/Getzilla/issues/38): security(approve): grant с wildcard-ресурсом открывает запись во весь control plane — pending criterion audit/repair/final evidence.
- [37](https://github.com/Dimkox/Getzilla/issues/37): security(hooks): блокировки merge/push/publish и rm -rf / обходятся другими написаниями команд — pending criterion audit/repair/final evidence.
- [36](https://github.com/Dimkox/Getzilla/issues/36): security(hooks): чтение секретов через shell не проверяется, секретные файлы в корне не защищены — pending criterion audit/repair/final evidence.

# Dependency and ownership plan

1. AI control/budget writer owns #78/#76 in parent contour.
2. Isolated core writer owns #60/#71 (queue resolver, safe descriptor writes and one-verifier workflow).
3. Isolated installer writer owns #75 (classification, ownership, recoverable migration).
4. Isolated dependency writer owns #42 (complete locked Trust CI graphs and consumers).
5. Isolated docs/tests writer owns #63/#73, preserving immutable releases and external human boundaries.
6. Revalidate #36/#37/#38 against delivered source, then final targeted evidence; #72 remains the release/target acceptance goal.

Leaf source work is UNVERIFIED integration only. No independent leaf full PR run, push, merge or release is authorized. Final parent combines all source changes, runs bounded controls, every selected independent review, persists reports and freezes, then one full local gate and exact-head external checks. This records the owner override of redundant leaf final-gate sequencing; no final/external gate is bypassed.

Host activation, real paid budgets/credentials, provider-side revocation and production target acceptance remain separate real-human decisions. Do not replace them with source tests or fabricated receipts.

## Source integration checkpoint

The parent reached `0f47b7c7e95b6e29c43124ff2e24cefd81497705` with AI source `98f0cb94d1272bdc949396e735b1ed93c313bfc5`, core `4a059a4a86c09c966525332fc76f722f52960a61` and installer `9844afa2bb35020ae2b2a6f11df229988c7d6221` integrated. Docs `de11e1ea9c2c49ffc72891a0b2132e0ea2062b8a` and lock `69b565468f1c187e28ccb5cf681e647ed8a53d9f` are committed isolated inputs; integration is pending at this checkpoint.

Leaf implementation observations are not independent reviews or qualifying receipts. Installer evidence reports 48 installer tests, 15 install-script tests and eight committed focused tests. Core evidence reports 59 focused methods and two Windows skips. Docs evidence reports 38 focused tests and six private implementation mutants. Lock evidence reports 32 focused tests, two Docker binding tests and seven committed smoke tests, with no installs or image builds. AI evidence reports 225 adjacent tests, 47 hook tests and 16 paid admission tests. These counts identify the implementation reports only; final combined source must receive its own controls, reviews and gates.

Consumer cleanup is plan-only. No update/uninstall/quarantine executor exists. Unknown ownership remains preserved. Native host enforcement, cross-process shared paid authority, incident attribution and provider revocation remain unproven. Production acceptance remains NOT_RUN. No issue closure or release is justified by this checkpoint.

## External delivery observation

Read-only `gh pr view 79 --repo Dimkox/Getzilla --json number,state,headRefOid,baseRefOid,mergeStateStatus,statusCheckRollup,url` confirms PR #79 remains OPEN/BLOCKED on old head `6dd06ff5b96692a01812fbac6252fd08f6169f91`, base `540c12f93e798c2f483455a5086ab0018ac3216e`. Linux is CANCELLED; Windows and GitGuardian are SUCCESS for that old head only. The combined issue candidate has not been transported. No external result qualifies the new source.

## Combined source clause audit

The read-only selected repo explorer audited combined HEAD `084f6e97e9ba79b3ad198ba3033b8c6710280025`. Complete report: `evidence/analysis-combined-clauses.md`. It found missing general non-paid scope/time admission (#78), and missing classification/fixture coverage for the exact incident requirements paths (#75). Both returned to the same parent writer before review. This analysis is not an independent review or PASS receipt.

The new Windows-only lock pin `colorama==0.4.6` received a public OSV exact-version query with zero returned advisory IDs. Raw response is retained in ignored controller `runtime/issues/colorama-osv.json`. This observation covers one package/provider; it does not prove the combined graph or paid database coverage.

## All 12 current issues: source findings

The selected read-only analysis inspected all 12 bodies and available comments from fresh GitHub data. Complete clause matrix is retained in `evidence/analysis-combined-clauses.md`. Additional confirmed source gaps: semantic platform-marker verification (#42), complete installed/loaded/bounded-test/full-gate/delivery status (#78), incident retention and exact recoverable cleanup record (#76), and exact incident classifications (#75). All six #73 Low source repairs are present. Original #71/#60/#63 source criteria and historical #36/#37/#38 repairs are present; final qualification remains pending. #72 production acceptance remains unproved.

Writer repair `c82e3429b08817b5c58a9694b53adb1297285284` now covers both incident factory JSON paths, .qwen user scratch and docs/test-evidence. Its RED exposed five missing roles; seven OwnershipPlanTests passed in 4.102s after repair. Preserved bytes and empty quarantine authority are tested. This is bounded implementation evidence, not independent review or completion. Remaining source findings returned to the same parent writer.

## Combined source repairs and fresh start

Source candidate e1b309e4f24048ed88c15057f1a914d3739239dd contains repairs for all six additional source findings. Full implementation report: evidence/implementation-integration.md. It retains the failed/stopped observations and distinguishes live criteria. The clean installation and generated launcher process checks passed in evidence/clean-start-observation.md; actual host interception remains NOT_OBSERVED. No issue is closed by these local observations.
