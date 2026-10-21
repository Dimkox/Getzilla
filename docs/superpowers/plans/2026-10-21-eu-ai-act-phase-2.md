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
6. Installation and docs: both audit and compliance wrappers are managed. EU templates belong to the optional component prefix so on-demand installation supplies them. Document evidence limits and current2.3.1 source behavior in README and CHANGELOG. Static symbol matches and generic AIA-15 verification are not model evaluation evidence.

## Signed-result successor contract

Keep the v1 schema byte-identical. Add trust-ci-attestation-envelope.v2.json with a distinct v2 $id, payload schema_version2, bounded optional argv and nullable spec_digest. Add CONTRACT-ATTESTATION-ENVELOPE-V2 as an exact version2 producer contract and expose it from NODE-TRUST-CI-WORKER. Architecture fitness rejected the initial optional-v1 proposal as same_version_semantic_change; that proposal is superseded. Upgrade verifiers and closed-schema consumers before producer rollout. Old signatures remain valid but v1 cannot qualify EU execution, even with raw argv. Never backfill historical envelopes.

The separate Trust CI writer adds strict CommandSpec.attest_argv defaultFalse, omitted when false, and CommandResult.argv defaultNone. Emit v2 only for opted-in execution; normal v1 jobs keep their original grammar. Runner stamps policy-owned args only when opted in. Preserve legacy policy digests and exact stored-envelope replay. Guard TRUST_CI_* environment overrides for opted-in commands. Example command: [python3, scripts/getzilla_audit_bundle.py, --ci-check], requiredtrue, timeout_seconds300, attest_argvtrue. Run real signed envelope and enabled/disabled audit tests after Core is available. Deployment remains outside scope.

## Verification and progress

Current checkpoint: UNVERIFIED. The validation command batch hit the hook's circuit breaker.
The writer stopped that objective. Do not run dependent reviews or reuse earlier observations as
qualification. The coordinator must obtain a scoped recovery decision before fresh validation.

- [x] Complete five independent analyses and typed package before product changes.
- [x] Observe failing regression tests before behavior changes:41 failures including subtests,29 passed.
- [x] Initial focused implementation tests:49 passed and97 subtests passed. This is a bounded observation, not final verification.
- [x] Implement the Core source and docs. Earlier bounded observations passed 119 tests and 111 subtests with one skip; they precede the final v2 metadata correction.
- [ ] Run fresh focused behavior, installation, architecture and lint checks after scoped recovery.
- [ ] Commit implementation with package state reviewing, then bounded committed-HEAD controls.
- [ ] Collect all four independent reviews, save reports, commit/freeze and run one final PR verifier.
- [ ] Require exact-head public linux/windows Actions checks and resolve review threads before delivery.
- [ ] Deliver and qualify the separate Trust CI successor.

The final PR gate belongs to the coordinator. Do not run a full verifier per implementation commit. Measured capacity26 and affinity0–25 are shared: Core tests20, successor tests6. Real signed v2 integration and overall phase completion depend on the successor. Engineering evidence, not legal advice.

## Sources and limits

Official source check date2026-10-21: Omnibus2026/1744 in force27July2026; AnnexIII2December2027; AnnexI2August2028; Article50 generally2August2026 with the stated older-system transition2December2026. Scores and review periods are project rules. Check against the official text.

- https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=CELEX%3A32026R1744
- https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-113
- https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-9
- https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-11
- https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-50

ISO mapping is project-authored and copies no paid standard text. An audit bundle is supporting evidence, not complete AnnexIV documentation. An operator must review public labels, credential configuration and actual output behavior. Engineering evidence, not legal advice.
