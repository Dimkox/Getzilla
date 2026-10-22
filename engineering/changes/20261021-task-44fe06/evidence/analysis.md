# EU AI Act continuation analysis

Source: e158ddc7263a55f5308944c5a426eb1e9f1a4327. Date: 2026-10-21.
Core route44fe064efbab. Trust CI successor route4667515abad1.
All analyses were read-only. No analysis claimed test execution or verification PASS.

Implementation-time ruling: the original optional-v1 proposal below is superseded. FIT-SIGNED-PAYLOAD-EXACT rejected a same-version semantic change. Keep v1 bytes intact and add a distinct v2 signed envelope, payload version2 and exact version2 architecture contract. Upgrade verifiers/consumers before producer rollout. The original five analysis reports remain below for traceability.

## repo_explorer

PR112 introduced the base layer. PR118 added decisions, roles, dates and exemptions. PR120 adds plans only. All six EU phase2 tasks remain open. Actual CLI dispatcher is scripts/getzilla_cli.py. New wrappers require scripts/install_into.py MANAGED_FILES. Existing audit wrapper is also absent there. Add .getzilla/templates/eu-ai-act/ to the optional component prefix; recursive core copying alone does not support on-demand installation. Existing verification.py gate wiring is sufficient.

CommandResult lacks argv. Closed attestation schema rejects extra fields. FIT-TRUST-CI-SEPARATION forbids mixed trust-ci and Core/engineering-contract changes. FIT-LOCAL-CANNOT-DEFINE-TRUST-CI forbids a Core import of adaptive_trust_ci. The existing offline attestation-verify CLI supplies the needed independent boundary.

Successor minimal source: trust-ci/src/adaptive_trust_ci/models.py, policy.py and runner.py. Tests: test_policy.py, test_runner.py, test_signing.py. An opt-in command fragment and trust-ci/README.md complete delivery. Runner-side attachment avoids sandbox changes. Synthetic holdout/spec/source-integrity results omit argv. Keep exact stored-envelope replay unchanged.

## architect

Use Core/schema first, Trust CI producer/policy second. Keep eu_ai_act.evaluate the sole obligation gate. Missing/stale matrix metadata produces REVIEW even with no systems. Optional risk fields preserve original records; bool scores are invalid. Use the expected confirmation wrapper. Preserve applicability dates.

Scaffold final filenames must match the declared ownership glob. Reject traversal, links, ambiguous/file-only prefixes and overwrite. Use existing safe exclusive writes. Emit language-correct hints. C2PA must stage a different output and preserve source on error. Metadata alone does not prove embedded marking. ISO metadata cannot affect decisions.

Normal bundles retain receipt checks. Separate --ci-check uses committed opt-in and release obligations without receipts; it has evidence-only authority. Reject missing/disabled opt-in. Attested status covers exact-source audit execution, not regenerated bundle bytes. Validate successful actual invocation and reject help/wrapper/substring forms.

Successor CommandSpec.attest_argv is a strict bool defaultFalse and omitted from to_dict when false. This preserves legacy policy digests/check names. CommandResult.argv defaultsNone and is omitted. Runner stamps selected CommandSpec.argv when opted in and forcesNone otherwise, overriding executor metadata. True changes selected policy identity. Legacy replay stays exact. Core contract must merge first.

## docs_researcher

Official dates match current source. Omnibus2026/1744 entered force27July2026. AnnexIII high-risk rules apply2December2027, AnnexI2August2028. Article50 general date2August2026; certain older synthetic systems have until2December2026. Direct EUR-Lex body had a JavaScript challenge; readable official Commission consolidation independently confirms dates.

Sources:
- https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=CELEX%3A32026R1744
- https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-113
- https://ai-act-service-desk.ec.europa.eu/en/ai-act/eu-ai-act-implementation-timeline
- https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-9
- https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-11
- https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-50
- https://raw.githubusercontent.com/contentauth/c2patool/main/docs/usage.md
- https://raw.githubusercontent.com/contentauth/c2patool/main/docs/signing.md

Scores and review intervals are project rules, not statutory thresholds. Risk acceptance declarations do not authenticate a person. A bundle is supporting evidence, not complete AnnexIV documentation. Adapters do not prove effective published marking. ISO pairs are project-authored and must be checked against authorised text; no paid ISO text was read or copied. Do not invent human review metadata or claim ISO certification. Update the source plan for compatibility and safe-C2PA corrections.

Rollout documentation must distinguish cryptographic compatibility from closed-schema acceptance and EU evidence qualification. Old closed validators reject new argv. Install Core/schema readers first. Arguments become durable public evidence and must not contain secrets. Stop new emission before rolling back consumers. Example policy is not deployed activation.

## ai_architect

Existing symbol checks search text in files/tests, not execution. Existing AIA15 verify status does not prove model/security evaluations. State these limits. Test real Python and Node TypeScript adapter behavior. TypeScript hints must use camelCase. Return unsigned provenance separately from successful signing; keep source bytes on failures/timeouts. Avoid secret or environment-derived provenance labels. Treat full-registry bundle content as private until approved for sharing.

Phase2 does not establish model/prompt versions, evaluation identities, tenant filtering, deletion coverage, quality, latency or cost evidence. Document gaps and illustrative risk references. Test actual enabled audit execution; signed argv alone is insufficient if a command can succeed while EU is skipped.

Successor tests must cover policy-owned args overriding executor metadata; real enabled/disabled Core audit; exact command forms; passed job plus pass/int0 command; repository/base/head/policy identity; signing tamper rejection; API/storage/replay preservation; unchanged default profiles. Never backfill args into historical envelopes.

## integration_architect

Existing offline verifier: adaptive-trust-ci attestation-verify --attestation FILE --public-key FILE. Use trusted absolute executable, no shell, safe cwd/environment, time/output bounds. Supplied public key is an operator trust input, not merge authority. Missing verifier, invalid signature or malformed output blocks attestation. Match exact head/base/repository where bound, successful argv and committed unchanged EU inputs. Legacy envelopes without argv cannot qualify EU evidence.

CI mounts workspace read-only and resets generated files. --ci-check emits stdout and requires no receipt. TRUST_CI_BASE_SHA supplies exact base; placeholders are not expanded. Final default bundle keeps local receipts.

Successor command fragment: name eu-ai-act-audit, argv [python3,scripts/getzilla_audit_bundle.py,--ci-check], timeout_seconds300, requiredtrue, attest_argvtrue. It is selected only for an explicitly EU-enabled profile. For opted-in policies reject TRUST_CI_* overrides in command.env and allowed_environment; otherwise actual evaluated base can differ from signed job identity. Keep status pass/int0, job passed, and existing stdout-NUL-stderr output digest. No new API, database, queue, service or deployment.

## Recovery and verification plan

Two plan-write denials stopped work. User explicitly allowed one-time recovery through exact grants. Absolute apply_patch with canonical scoped grants works; compound shell heredocs and broad piped discovery hit root parsing failures. Use exact known paths and short grant reasons. The result remains UNVERIFIED until controls, independent reviews and final local/external gates pass. Never bypass the circuit breaker or reuse stale evidence.

Core and successor have separate worktrees and one selected writer each. Core must merge before successor final qualification. Source-only authority does not authorize deployed policy, keys, branch protection or production writes.
