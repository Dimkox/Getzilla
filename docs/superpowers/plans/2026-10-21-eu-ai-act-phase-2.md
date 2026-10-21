# EU AI Act Evidence Layer, Phase 2: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the remaining option-B gaps of the optional EU AI Act layer: signed and independently checked evidence, a full risk management record, ready-made Art. 50 transparency adapters, an ISO/IEC 42001 control map, and a matrix that knows when it is out of date.

**Architecture:** Everything stays inside the existing layer. `eu_ai_act.evaluate` is the only gate. `scripts/getzilla_audit_bundle.py` is the only release dossier. Trust CI is the only independent verifier, and its Ed25519 attestation is the signature. There is no second orchestrator and no new runtime service. Every new rule is either REVIEW (a person decides) or BLOCK (evidence missing for an obligation in force), with the codes defined in `REVIEW_CODES`.

**Tech Stack:** Python 3.12 stdlib, `unittest`, git. Trust CI uses `cryptography` Ed25519 (`adaptive_trust_ci.signing`). The adapters use the stdlib only; `c2patool` is optional and detected at runtime.

**Spec:** this document's "Spec" section below, plus `docs/eu-ai-act.md` and PR #118 (decision, roles, dates, exemptions), which this plan builds on.

## Spec

What is already in `main` after #112 and #118, and what is not part of this plan:
- Already in `main`: the registry, the draft classifier, the PASS/REVIEW/BLOCK decision, provider and deployer roles, AI Omnibus dates, Art. 50 exemptions, the audit bundle and the opt-in.
- Not part of this plan: legal advice, automatic legal conclusions, IP-based geography, C2PA or a watermark for every output, and ISO 42001 as a release gate.

The plan adds six things:
1. **Matrix freshness.** `obligations.json` records when a person last reviewed it against official sources and lists those sources. A matrix not reviewed for more than 180 days is REVIEW (`MATRIX_STALE`), never BLOCK.
2. **Risk management record (Art. 9).** Each risk has likelihood and severity (1–5) and a residual level (`low`, `medium`, `high`). A `high` residual needs `accepted_by` (a person, a role and a date); without it the result is BLOCK through `OBLIGATION_UNMET`. A risk whose `next_review` date has passed is unmet.
3. **Transparency adapters (Art. 50).** Templates for Python and TypeScript:
   - a disclosure constant;
   - `mark_generated_content`, which attaches machine-readable provenance (IPTC `digitalSourceType` = `http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia`) and calls `c2patool` when it is on PATH;
   - `label_published_content` for Art. 50(4).

   `getzilla compliance scaffold <system-id> --lang python|typescript` copies them into the system's first path and prints the registry fields to set. It never edits the registry.
4. **Signed compliance evidence.** The audit bundle accepts `--attestation <file> --public-key <file>`. It verifies the attestation with `adaptive_trust_ci.signing.verify_attestation`, requires `payload.status == "passed"` and `payload.head_sha == bundle.commit`, and requires one `command_results` entry whose argv runs `scripts/getzilla_audit_bundle.py`. The bundle then records `attestation: {attestation_id, key_id, policy_digest, head_sha}` and its `authority` becomes `trust-ci-attested`. Without an attestation, `authority` stays as it is today.
5. **Independent verifier wiring.** `trust-ci/config/policy.example.json` gets a mandatory `eu-ai-act-audit` command running the bundle in `release` mode. The docs describe how a project adds it.
6. **ISO/IEC 42001 control map.** `iso42001-map.json` maps every obligation id to Annex A control areas by clause (A.2–A.10). Clause-level only; no control text is copied. The map is written into the audit bundle as `iso42001` with `"gating": false`, and it never changes a decision.

## Global Constraints

- Python 3.12; stdlib only in `.getzilla/getzilla/` and in the templates; `cryptography` is allowed only through `trust-ci`.
- Matrix schema id stays `eu-ai-act-obligations-v1`; new fields are optional, so older registries keep working.
- New REVIEW codes go into `eu_ai_act.REVIEW_CODES`; anything not in it blocks.
- Exact values: `MATRIX_REVIEW_DAYS = 180`; residual levels `('low', 'medium', 'high')`; likelihood and severity are integers 1–5; IPTC URI as in Spec item 3.
- No network access in the gate, the bundle or the tests; `c2patool` is invoked only by the template at the consumer's runtime.
- Docs say "engineering evidence, not legal advice" on every new page section; dates and clause numbers carry "check against the official text".
- Every commit message ends with the project's co-author line; every task runs `python3 -m pytest -q -n 26 tests/test_eu_ai_act.py` and the full suite before its commit.

## Review Focus

1. A registry written before this plan (no `residual`, no `next_review`, a matrix without `reviewed`) must still evaluate, and the new fields must only add findings when they are present or required. Tests in Tasks 1 and 2 pin this.
2. An attestation for a different commit, a failed job, or a job that never ran the audit bundle must not make `authority` attested. Tests in Task 4 pin each case.
3. `scaffold` into a path that already has the file must refuse and never overwrite. A test in Task 3 pins this.
4. `c2patool` missing or failing must not break `mark_generated_content`: it returns the metadata with `c2pa: null`, and the error goes into `c2pa_error`. A test in Task 3 pins this.
5. The ISO map must never turn PASS into anything else, even when it is malformed. A test in Task 5 pins this.

## File Structure

- Modify `.getzilla/compliance/eu-ai-act/obligations.json`: add `reviewed`, `sources`.
- Create `.getzilla/compliance/eu-ai-act/iso42001-map.json`.
- Modify `.getzilla/getzilla/eu_ai_act.py`: freshness, risk record, ISO map loader.
- Create `.getzilla/templates/eu-ai-act/transparency/python/ai_transparency.py`.
- Create `.getzilla/templates/eu-ai-act/transparency/typescript/aiTransparency.ts`.
- Create `.getzilla/getzilla/compliance_scaffold.py` and register `compliance scaffold` in the `getzilla` CLI dispatcher (`bin/getzilla` / `.getzilla/getzilla/cli.py`, wherever `components add` is dispatched).
- Modify `scripts/getzilla_audit_bundle.py`: attestation and ISO map.
- Modify `trust-ci/config/policy.example.json`.
- Modify `docs/eu-ai-act.md`, `CHANGELOG.md`, `.getzilla/templates/ai-systems.example.json`.
- Tests: `tests/test_eu_ai_act.py` (extend), `tests/test_compliance_scaffold.py` (new), `tests/test_ai_transparency_template.py` (new).

---

### Task 1: Matrix freshness (`MATRIX_STALE`)

**Files:**
- Modify: `.getzilla/compliance/eu-ai-act/obligations.json`
- Modify: `.getzilla/getzilla/eu_ai_act.py`
- Test: `tests/test_eu_ai_act.py`

**Interfaces:**
- Produces: `MATRIX_REVIEW_DAYS: int = 180`; `matrix_review_problem(data: dict, today: date) -> str | None`; `'MATRIX_STALE'` in `REVIEW_CODES`; `load_obligations` keeps its signature, and a new `load_matrix(root) -> dict` returns the whole file.

- [ ] **Step 1: Write the failing tests**

```python
class MatrixFreshnessTests(unittest.TestCase):
    def test_a_recent_review_passes_and_an_old_one_is_review(self):
        data = {'reviewed': '2026-10-21', 'sources': ['https://eur-lex.europa.eu/eli/reg/2024/1689/oj']}
        self.assertIsNone(eu_ai_act.matrix_review_problem(data, date(2027, 4, 19)))
        self.assertIn('181 days', eu_ai_act.matrix_review_problem(data, date(2027, 4, 20)))

    def test_missing_review_or_sources_is_review(self):
        self.assertIn('reviewed', eu_ai_act.matrix_review_problem({}, TODAY))
        self.assertIn('sources', eu_ai_act.matrix_review_problem({'reviewed': '2026-10-21', 'sources': []}, TODAY))

    def test_stale_matrix_is_review_in_the_gate(self):
        repo = Repo(self)  # copies the shipped matrix
        repo.registry()
        repo.commit('empty registry')
        report = eu_ai_act.evaluate(repo.root, 'pr', [repo.base], 'HEAD', today=date(2028, 1, 1))
        self.assertEqual(codes(report), ['MATRIX_STALE'])
        self.assertEqual(report.decision, 'review')
```

- [ ] **Step 2: Run them and confirm they fail.** Run `python3 -m pytest -q tests/test_eu_ai_act.py -k Freshness`. Expected: FAIL, `matrix_review_problem` is not defined.
- [ ] **Step 3: Implement.**
  - Add `"reviewed": "2026-10-21"` and `"sources"` to `obligations.json`. The sources are the EUR-Lex AI Act URL above, the Omnibus `https://eur-lex.europa.eu/eli/reg/2026/1744/oj`, and the Commission AI Act page `https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai`.
  - In `evaluate`, call `matrix_review_problem` once and prepend `MATRIX_STALE: <problem>` to `problems`.
  - The early return "no AI system registered and no AI provider call" must still report a stale matrix, so move it after this check.
- [ ] **Step 4: Run the EU tests and confirm they pass.** Run `python3 -m pytest -q tests/test_eu_ai_act.py`. Expected: all pass. The existing tests use `TODAY = 2026-10-20`, which falls inside the review window.
- [ ] **Step 5: Commit.** `git commit -m "feat(eu-ai-act): matrix review date and sources; stale matrix is REVIEW"`

### Task 2: Full risk management record (Art. 9)

**Files:**
- Modify: `.getzilla/getzilla/eu_ai_act.py` (`_risk_register_problem`)
- Modify: `.getzilla/templates/ai-systems.example.json` (point it at an example register), and create `.getzilla/templates/eu-ai-act/risk-register.example.json`.
- Test: `tests/test_eu_ai_act.py`

**Interfaces:**
- Produces: `RESIDUAL_LEVELS = ('low', 'medium', 'high')`. `_risk_register_problem(root, head, path, today) -> str | None` keeps its signature and adds the checks below.

- [ ] **Step 1: Write the failing tests.** In `test_risk_record_scores_residual_and_acceptance`, use the high-risk fixture from `test_high_risk_needs_a_current_risk_register_logs_and_oversight` with `today=date(2027, 12, 2)` and assert each of these:
  - `{'likelihood': 6, ...}` gives a problem containing `likelihood must be 1-5`;
  - `'residual': 'severe'` gives a problem containing `residual must be low, medium or high`;
  - `'residual': 'high'` without `accepted_by` gives a problem containing `high residual risk needs accepted_by`;
  - `accepted_by = CONFIRMED` makes AIA-9 `met`;
  - `'next_review': '2027-12-01'` gives a problem containing `next_review 2027-12-01 has passed`;
  - an entry with only the four original keys is still `met`, which keeps backward compatibility.
- [ ] **Step 2: Run it and confirm it fails.** Expected: FAIL on the first assertion.
- [ ] **Step 3: Implement.** Validate the optional keys when they are present. `accepted_by` is required only when `residual == 'high'` and is checked with `_confirmation_problem`. Write the example register with three risks, one of them `high` and accepted.
- [ ] **Step 4: Run the EU tests and confirm they pass.**
- [ ] **Step 5: Commit.** `git commit -m "feat(eu-ai-act): risk scores, residual level, acceptance and next review"`

### Task 3: Art. 50 transparency adapters and `getzilla compliance scaffold`

**Files:**
- Create: `.getzilla/templates/eu-ai-act/transparency/python/ai_transparency.py`
- Create: `.getzilla/templates/eu-ai-act/transparency/typescript/aiTransparency.ts`
- Create: `.getzilla/getzilla/compliance_scaffold.py`
- Modify: the `getzilla` CLI dispatcher (next to `components add`)
- Test: `tests/test_ai_transparency_template.py`, `tests/test_compliance_scaffold.py`

**Interfaces:**
- The Python template:
  - `AI_DISCLOSURE: str`;
  - `IPTC_GENERATED = "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"`;
  - `mark_generated_content(content: bytes | str, *, generator: str, model: str, media_type: str, path: str | None = None) -> dict`. It returns `{"content", "provenance": {"digitalSourceType", "generator", "model", "created", "media_type"}, "c2pa", "c2pa_error"}`.
  - `label_published_content(text: str, *, label: str = "Generated with AI") -> str`.
- The TypeScript template has the same names, in camelCase for the functions.
- `scaffold(root: Path, system_id: str, lang: str) -> list[Path]`. It raises `ScaffoldError` when the system is unknown or has no paths, when `lang` is unknown, or when the target exists.
- Produces registry hints printed as JSON: `{"disclosure_symbol": "AI_DISCLOSURE", "marking_symbol": "mark_generated_content", "publication_disclosure_symbol": "label_published_content"}`.

- [ ] **Step 1: Write the failing template tests.**
  - `test_marking_adds_iptc_provenance_without_c2patool`: with PATH empty, `c2pa is None`, `c2pa_error == "c2patool not found"`, `provenance["digitalSourceType"] == IPTC_GENERATED`.
  - `test_c2patool_failure_is_reported_not_raised`: a fake `c2patool` on PATH that exits 1 gives `c2pa is None` and a non-empty `c2pa_error`.
  - `test_label_is_prefixed_once`: labelling an already labelled text returns it unchanged.
- [ ] **Step 2: Write the failing scaffold tests.**
  - `test_scaffold_copies_into_the_system_path_and_never_overwrites`: the first call returns one path under the glob's directory, and the second call raises `ScaffoldError`.
  - `test_scaffold_refuses_unknown_system_and_language`.
- [ ] **Step 3: Run them and confirm they fail.**
- [ ] **Step 4: Implement the templates.** `mark_generated_content` calls `c2patool <path> --manifest <tmp.json> -o <path>` only when `path` is set and `shutil.which("c2patool")` finds it. It writes a temporary manifest with the `c2pa.actions` assertion `{"action": "c2pa.created", "digitalSourceType": IPTC_GENERATED}`. The timeout is 30 s.
- [ ] **Step 5: Implement `scaffold`.** The target directory is the literal prefix of the system's first `paths` glob before the first wildcard. Refuse a prefix outside the project root. Use exclusive create (`open(..., 'x')`). The CLI prints the copied paths and the registry hints.
- [ ] **Step 6: Run the new tests and the EU tests, and confirm they pass.**
- [ ] **Step 7: Commit.** `git commit -m "feat(eu-ai-act): Art. 50 transparency adapters and compliance scaffold"`

### Task 4: Attested audit bundle (Trust CI as the independent verifier)

**Files:**
- Modify: `scripts/getzilla_audit_bundle.py`
- Modify: `trust-ci/config/policy.example.json`
- Test: `tests/test_eu_ai_act.py` (class `AuditBundleTests`)

**Interfaces:**
- Consumes: `adaptive_trust_ci.signing.Signer.generate()`, `sign_attestation(payload, signer)` and `verify_attestation(envelope, public_key_pem) -> AttestationPayload`. The payload fields are `status`, `head_sha`, `command_results`, `attestation_id`, `key_id` and `policy_digest`.
- Produces: `attestation_problem(payload, commit: str) -> str | None`. `build(root, base, attestation=None)` gains the keyword. The bundle adds an `attestation` object, and `authority` becomes `"trust-ci-attested"` when the attestation verifies.

- [ ] **Step 1: Write the failing tests.** Sign test payloads with `Signer.generate()`:
  - `test_a_matching_passed_attestation_makes_the_bundle_attested`;
  - `test_attestation_for_another_commit_is_rejected`, where `authority` is unchanged and `reasons` contains `attestation head_sha`;
  - `test_failed_job_or_missing_bundle_command_is_rejected`, with two subtests;
  - `test_bad_signature_is_rejected`, with one flipped signature byte.

  Skip the class when `adaptive_trust_ci` cannot be imported, with the message `trust-ci not installed`.
- [ ] **Step 2: Run them and confirm they fail.**
- [ ] **Step 3: Implement.**
  - Add the CLI options `--attestation`, `--public-key`; both or neither.
  - `attestation_problem` checks `status == 'passed'` and `head_sha == commit`, and that some `command_results[i]['argv']` contains `scripts/getzilla_audit_bundle.py`.
  - A rejected attestation adds its problem to `reasons`, so the release decision is `blocked`.
- [ ] **Step 4: Update the example Trust CI policy.** Add `{"name": "eu-ai-act-audit", "argv": ["python3", "scripts/getzilla_audit_bundle.py", "--base", "${BASE_SHA}"], "required": true}` in the form `CommandSpec.from_dict` accepts. Run `python3 -m pytest -q trust-ci/tests -k policy` to prove the example still loads.
- [ ] **Step 5: Run the EU and Trust CI policy tests and confirm they pass.**
- [ ] **Step 6: Commit.** `git commit -m "feat(eu-ai-act): Trust CI attested audit bundle and policy command"`

### Task 5: ISO/IEC 42001 control map (informational)

**Files:**
- Create: `.getzilla/compliance/eu-ai-act/iso42001-map.json`
- Modify: `.getzilla/getzilla/eu_ai_act.py`
- Modify: `scripts/getzilla_audit_bundle.py`
- Test: `tests/test_eu_ai_act.py`

**Interfaces:**
- Produces: `load_iso_map(root) -> dict[str, list[str]] | None`. It returns `None` on a missing or malformed file and never raises. The bundle gets `compliance.iso42001 = {"gating": false, "map": {...}, "note": "..."}`.

- [ ] **Step 1: Write the failing tests.**
  - `test_iso_map_covers_every_obligation`: every id in `obligations.json` has at least one entry matching `^A\.(?:[2-9]|10)$`.
  - `test_malformed_iso_map_never_changes_the_decision`: write `{` to the map and assert that `evaluate(...).decision` is unchanged and the bundle has `iso42001 is None`.
- [ ] **Step 2: Run them and confirm they fail.**
- [ ] **Step 3: Write the map at clause level.**
  - AIA-5 → A.5, A.9;
  - AIA-50-1, AIA-50-2, AIA-50-4 → A.8;
  - AIA-9 → A.5, A.6;
  - AIA-11 → A.6, A.8;
  - AIA-12 → A.6;
  - AIA-14 → A.9;
  - AIA-15 → A.6, A.7.

  Its `note` says: clause-level mapping, verify against ISO/IEC 42001:2023, certification gives no presumption of AI Act conformity.
- [ ] **Step 4: Implement the loader and the bundle field.**
- [ ] **Step 5: Run the EU tests and confirm they pass.**
- [ ] **Step 6: Commit.** `git commit -m "feat(eu-ai-act): informational ISO/IEC 42001 control map in the audit bundle"`

### Task 6: Docs, CHANGELOG, full verification

**Files:**
- Modify: `docs/eu-ai-act.md` (sections "Matrix review", "Risk record", "Transparency adapters", "Independent verification", "ISO/IEC 42001")
- Modify: `CHANGELOG.md` (the current source-candidate entry)

- [ ] **Step 1: Write the docs.**
  - One paragraph per section.
  - Each section names its command or field, and its REVIEW or BLOCK code.
  - Each ends with the "check against the official text" line where it cites dates or clauses.
- [ ] **Step 2: Run the full suite.** Run `python3 -m pytest -q -n 26 -p no:cacheprovider tests`. Expected: 0 failed. Also run `ruff check` on the changed Python files: clean.
- [ ] **Step 3: Commit.** `git commit -m "docs(eu-ai-act): phase 2 evidence, adapters and verification"`
