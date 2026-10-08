# Architecture — Refuse missing bandit and OpenGrep binaries in pr/release gates

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Current behavior

Missing scanners are admitted.

## Proposed behavior

Missing scanners are refused in pr/release.

## Components and boundaries

quality_gates.py plus tests in test_quality_gates.py, test_opengrep.py, test_verification_doctor.py and test_python_test_runner.py.

## Data flow

Unchanged.

## API and event contracts

Unchanged.

## Governance context

Canonical governance JSON under `governance/` remains separately reviewed authority. Any rule, example, debt, or digest named here is non-authoritative context until the verifier rederives current governance evidence.

- Applicable rule IDs: none.
- Applicable canonical example IDs/versions: none.
- Open or overdue debt IDs: none.
- Expected governance handoff or receipt impact: none.

## Bitrix-specific impact

- Modules/events/agents/components affected: none.
- Cache and managed cache impact: none.
- Installation/update/uninstall impact: none.
- Core modification: forbidden unless explicitly approved.

## Decisions

Keep `no OpenGrep rules installed` admitted: a tree without the rule pack has nothing to run, which is the analogue of `no non-test python paths`. Fixtures that used `bandit not available` only as a harmless skip now use the admitted reason, so their intent is preserved.

## Risks and mitigations

Local pr/release verifies on hosts without bandit or opengrep now fail. This is intended; CI and Trust CI install both. Consumer repos (for example google-ads-automation) must install them before running a pr verify.
