# EU AI Act phase 2: Core and Trust CI delivery

Approved source scope: finish the six outcomes from merged PR120. This revision applies the five independent analyses and recorded scope rulings. Original plan text remains in Git at base e158ddc7263a55f5308944c5a426eb1e9f1a4327. Engineering evidence, not legal advice.

## Boundaries

- Core, signed-result schema, installer, adapters, tests and docs belong to route44fe064efbab and one writer on feat/eu-ai-act-phase2-20261021.
- Trust CI producer and opt-in policy example belong to a separate successor. FIT-TRUST-CI-SEPARATION stays unchanged. Core never imports Trust CI.
- Source authority does not approve production writes, deployed policy, keys or human security approval.
- Current source remains2.3.1. No release/version bump occurs here.

## Core outcomes

1. Matrix freshness: preserve schema id and old parsing. Missing, malformed, future or older-than-180-day review metadata gives MATRIX_STALE REVIEW, including empty registries. Opt-out stays skipped. The shipped timestamp is an automated source check. It does not claim human review.
2. Risk record: preserve the original four fields. Optional scores are strict integers1–5; optional residual is low/medium/high. High residual requires accepted_by through the existing confirmation validator. Check next_review only when applicable. Examples are fictional.
3. Adapters: use scripts/getzilla_cli.py and new managed scripts/getzilla_compliance.py. Scaffold validates the final generated filename against the first declared glob, rejects unsafe/ambiguous paths and writes exclusively through fsx. Emit Python snake_case or TypeScript camelCase hints. Leave registry unchanged. Test Python and Node behavior. C2PA runs at most30seconds on copied input and distinct output; errors preserve original content. Metadata alone is not embedded marking.
4. Audit evidence: normal bundles retain local receipt rules. New --ci-check requires committed EU opt-in and base, evaluates release obligations and emits stdout evidence only. Base comes from --base or authoritative TRUST_CI_BASE_SHA. No local receipt or release-ready claim. Core calls a trusted installed absolute attestation-verify executable outside the project, using fixed argv, safe cwd/environment and time/output bounds. Signed passed payload must match head/base/repository and contain a passed actual audit invocation with integer exit0. Reject echo/help/wrappers/substrings and legacy results without argv. Signature scope is execution, not regenerated bundle bytes.
5. ISO map: project-authored clause mapping under compliance.iso42001 with gating:false. Missing or malformed mapping is null and cannot affect decisions.
6. Installation and docs: both audit and compliance wrappers are managed optional EU component files, omitted from lean installs. EU templates belong to the same optional component so on-demand installation supplies them. The installed CLI gives an installation hint without writing an adapter before opt-in. Document evidence limits and current2.3.1 source behavior in README and CHANGELOG. Static symbol matches and generic AIA-15 verification are not model evaluation evidence.

## Signed-result successor contract

Keep the v1 schema byte-identical. Add trust-ci-attestation-envelope.v2.json with a distinct v2 $id, payload schema_version2, bounded optional argv and nullable spec_digest. Require both spec_digest and criterion_coverage in v2. Add CONTRACT-ATTESTATION-ENVELOPE-V2 as an exact version2 producer contract and expose it from NODE-TRUST-CI-WORKER. Architecture fitness rejected the initial optional-v1 proposal as same_version_semantic_change; that proposal is superseded. Upgrade verifiers and closed-schema consumers before producer rollout. Old signatures remain valid but v1 cannot qualify EU execution, even with raw argv. Never backfill historical envelopes.

The separate Trust CI writer adds strict CommandSpec.attest_argv defaultFalse, omitted when false, and CommandResult.argv defaultNone. Emit v2 only for opted-in execution; normal v1 jobs keep their original grammar. Runner stamps policy-owned args only when opted in. Preserve legacy policy digests and exact stored-envelope replay. Guard TRUST_CI_* environment overrides for opted-in commands. Example command: [python3, scripts/getzilla_audit_bundle.py, --ci-check], requiredtrue, timeout_seconds300, attest_argvtrue. Run real signed envelope and enabled/disabled audit tests after Core is available. Deployment remains outside scope.

## Verification and progress

The first review wave found three Medium defects. The repair batch binds all decision inputs,
refuses unsafe Windows scaffolding before mutation, and forcefully terminates the Node child at
timeout. Templates remain available for manual Windows use. Five Low test gaps are deferred to
issue122. The branch rebased onto actual main e42398ddaa41e662e921d7af68ab87b1e28e3554 after PR121
and PR114, then a103b373031f477efad0e7bd9ffab24a96e6c63f after PR123/PR124, and finally
287e64f99b01db44cb6eeeb10f307ccda6f91c1d after PR125. PR125 has no EU product overlap; byte parity
with the tested585edde8 checkpoint was confirmed. Its bounded tests remain historical observations.
Repeat the committed-HEAD smoke before reviews; the final qualifying gate is unchanged. Both groups of prose
changes and lean-install behavior remain intact. Earlier controls/reviews remain historical. Fresh controls and all four reviews are
required for the repaired source; no earlier PASS is carried forward.

The second review wave found two further Medium defects and saved all four FAIL reports inb23baf3.
Its repair binds opt-in authorization to captured config and rejects null/skipped CI evaluation.
Only the bounded untracked receipt inventory honors normal global/system Git excludes; strict
identity and source capture remain unchanged. Six Low gaps now share issue122, including first-use
provider-cache coverage. That Low gap remains outside the current repair.

The third review wave passed all four reviews before freeze d7f91344. Its final local gate failed
eight tests. Triage separated inherited fixture imports from coverage timing; public Linux then
found the undeclared jsonschema test dependency. The bounded repair changes tests and their pinned
requirements only. Keep the covered deny assertion and deterministic deadline/entry-budget controls.
The approved timing contract is8s process CPU, observed wall time and15s child timeout, with
untraced fixture imports. Exact-base execution and fresh pinned-dependency installation are BLOCKED;
static source parity or a host package is not a substitute for either test result.
All complete reviews remain historical, and the repaired source needs fresh controls and reviews.

Test-repair checkpoint47d02c4c was merged with authorized remote55e7cb05 using a no-ff merge,
preserving both histories at2a7738c3. Its parent includes actual mainf9f02dd5. The official route
API refreshed the comparison base from287e64 to f9f02dd5 and retained earlier bases and the creation
fingerprint. The remote change makes EU scripts optional and guards scaffold opt-in. Fresh installed
lean/chosen CLI checks cover that integration; all prior reports remain historical.

Final qualification remains UNVERIFIED. A validation batch hit the hook's circuit breaker and the
writer stopped. The owner then approved scoped direct-command recovery. Fresh controls passed on
checkpoint fdc02defb766fea9372e939b90180ea37342e2f6. They are observations, not final qualification.

- [x] Complete five independent analyses and typed package before product changes.
- [x] Observe failing regression tests before behavior changes:41 failures including subtests,29 passed.
- [x] Initial focused implementation tests:49 passed and97 subtests passed. This is a bounded observation, not final verification.
- [x] Implement the Core source and docs. Earlier bounded observations passed 119 tests and 111 subtests with one skip; they precede the final v2 metadata correction.
- [x] Run fresh focused behavior and installation checks after scoped recovery:151 passed,1 skipped,156 subtests passed. Architecture, spec, governance, Ruff and Bandit passed.
- [x] Historical source commit 5e8b873 recorded state reviewing; its bounded committed-HEAD smoke passed without a receipt.
- [x] Historical first wave collected all four reviews. Reports were committed as 4abde00; code/security review found the three Medium repairs above.
- [x] Rebase onto actual main and implement the three confirmed repairs after failing regressions.
- [x] Historical repair controls passed on checkpoint585edde8:212 tests and199 subtests,1 skipped; architecture/spec/governance/Ruff/Bandit passed. Record state reviewing.
- [x] Historical clean-HEAD smoke passed on61827791 in0.101s; no receipt. The second review wave returned four FAIL reports.
- [x] Add red regressions for the two wave2 Medium findings and implement the bounded repair. Focused48tests and67subtests passed.
- [x] Wave2 static/spec/architecture/governance controls passed. Prepare source state reviewing.
- [x] Historical second-repair source cf18a79c passed its clean committed-HEAD smoke.
- [x] Collect four wave3 PASS reviews and freeze d7f91344. Its final local PR gate and public Linux checks failed; those failures remain evidence.
- [x] Add the red poisoned-import regression and implement the bounded test/tool-requirements repair.
- [x] Complete fresh focused controls after test repair and authorized remote integration:170 tests/175 subtests,1 skip; architecture/spec/governance/Ruff/Bandit passed. Prepare source state reviewing on actual basef9f02dd5.
- [ ] Commit source state reviewing and run the named no-record smoke before fresh reviews.
- [ ] Optional fresh local pinned-version installation remains BLOCKED/NOT_RUN. It does not block route-required reviews or gates; normal required exact-head CI must install declared4.26.0.
- [ ] Collect four fresh independent reviews, save reports, commit/freeze and run the next qualifying PR verifier.
- [ ] Require exact-head public linux/windows Actions checks and resolve review threads before delivery.
- [ ] Deliver and qualify the separate Trust CI successor.

The final PR gate belongs to the coordinator. Do not run a full verifier per implementation commit. Measured capacity26 and affinity0–25 are shared. The recovered controls used15 test workers and five light processes. Coordinate remaining capacity with the successor before the committed smoke. Real signed v2 integration and overall phase completion depend on the successor. Engineering evidence, not legal advice.

## Sources and limits

Official source check date2026-10-21: Omnibus2026/1744 in force27July2026; AnnexIII2December2027; AnnexI2August2028; Article50 generally2August2026 with the stated older-system transition2December2026. Scores and review periods are project rules. Check against the official text.

- https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=CELEX%3A32026R1744
- https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-113
- https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-9
- https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-11
- https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-50

ISO mapping is project-authored and copies no paid standard text. An audit bundle is supporting evidence, not complete AnnexIV documentation. An operator must review public labels, credential configuration and actual output behavior. Engineering evidence, not legal advice.
