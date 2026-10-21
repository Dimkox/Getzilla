# Scope and decisions

User instruction: finish EU AI Act from PR120 using Getzilla. Exact plan base: e158ddc7263a55f5308944c5a426eb1e9f1a4327. This is source implementation authority, not production or human security approval.

First repair comparison base: e42398ddaa41e662e921d7af68ab87b1e28e3554, the actual fetched origin/main after PR121 and PR114. The isolated branch rebased without conflicts from report commit 4abde003d25997c2d6cd86af20e046f005367a67 to 5613f7fa2544b3e7ed2e6fc687aca515f19fc2a4. The official getzilla.state.update_route API refreshed only the comparison base and recorded its history. Route44fe064efbab and the original creation fingerprint remain unchanged. Earlier controls and the four complete first-wave reports are historical; they do not qualify the repaired tree.

Second repair comparison base: a103b373031f477efad0e7bd9ffab24a96e6c63f, actual fetched origin/main after PR123 and PR124. Repair checkpoint aa009d58e87785a0b09ec7222d2a0c49fd780961 rebased to ab523c9d943da7acdbed2f6a1bed8d7909a6723e. Both groups of CHANGELOG and mistakes entries were retained. The installer merge preserves lean-install behavior and the EU wrapper/template additions. The official update_route API appended the e423-to-a103 history without changing route selection or the creation fingerprint. Bounded checks passed on checkpoint585edde8 on this base.

Current comparison base: 287e64f99b01db44cb6eeeb10f307ccda6f91c1d, actual fetched origin/main after PR125. Rebase from bf86edbc57092d083a235ca96329eaf6aa505785 to 607d85c67b205ccc7f983d717908d8202b806506 had no conflicts. A read-only diff confirmed all EU product inputs and focused test modules are byte-identical to checkpoint585edde8. PR125 changes only router.py, docs/INVESTOR_DEMO.md, tests/test_demo.py and tests/test_risk_task_focus.py. Keep the212-test result as historical bounded observations; do not rerun it for this non-overlapping base change. Run a fresh named committed-HEAD smoke. The final qualifying PR gate remains unchanged and must check the new base. The official update_route API appended this transition and retained the creation fingerprint.

Confirmed repair scope: bind all five decision data files and the union of committed/present executable inputs; pass immutable committed data, fixed identities and one UTC date into evaluation; disable Git replacement objects through the existing sanitized environment. Refuse scaffold writes without descriptor-relative safe creation, including Windows. Keep manual template use available. Force the Node child to terminate at timeout. No Win32 subsystem or unrelated risk/architecture inputs are added. Five Low test gaps are deferred together to https://github.com/Dimkox/Getzilla/issues/122 and are outside this repair batch.

The unrelated draft 20261015-task-9d5992 was cancelled through the official change command under L5 process authority. Its files and pending checks were retained.

Ruling: split Core/contract and Trust CI producer/policy into two PRs. FIT-TRUST-CI-SEPARATION remains unchanged. Core calls the existing trusted installed offline attestation-verify CLI through a bounded subprocess. It never imports Trust CI.

Ruling: extend the signed-result contract explicitly. Architecture fitness rejected the initial optional-v1 assumption as same_version_semantic_change. That assumption is superseded: preserve v1 bytes, add distinct v2 schema and exact architecture contract, and require payload version2 for EU authority. Legacy envelopes still verify but cannot establish EU execution. Upgrade verifiers and old closed-schema consumers before v2 producer rollout. No architecture rule is weakened.

Ruling: read-only --ci-check requires committed EU opt-in and evaluates release obligations. It emits no release-eligibility or local-receipt claim. Normal bundles retain receipts. Attested status proves audit execution on the exact commit, not a signature over regenerated bundle bytes.

Ruling: preserve legacy matrix and risk parsing. Missing review metadata gives REVIEW. Do not invent a human matrix review or risk acceptance. Label automated source checks and fictional examples.

Ruling: Python and Node TypeScript adapters print language-specific hints. Exclusive scaffold writes leave the registry unchanged. C2PA uses a separate output and preserves source bytes on failure. Bound subprocesses and state marking limits.

Ruling: ISO mapping is a project-authored non-gating aid. Static symbol checks do not prove deployed marking, legal conformity or ISO certification.

Delivery requires selected independent reviews, frozen source, one final PR verifier, exact-head external checks and resolved threads. Deployed policy changes remain outside scope.

Checkpoint limitation: a later validation batch matched an active opaque-mutation denial fingerprint and hit the circuit breaker. The writer stopped validation and dependent review. The earlier recovery approval concerned plan writes only; it did not authorize this new retry. The new validation override below permitted separate direct checks. All six fresh controls passed on fdc02defb766fea9372e939b90180ea37342e2f6 and closed this blocker. Final qualification remains UNVERIFIED pending smoke, independent reviews and gates. Hooks and denial ledgers remain unchanged.

## Scoped validation recovery

The owner answered: "Разрешаю возобновить проверки" to the coordinator's scoped recovery request. This overrides the tool-denial circuit-breaker retry stop only for the blocked focused-test, architecture, spec, governance and lint validation objective. Run each read-only validation command directly through a separate tool call. Do not repeat the denied getzilla_par batches. Reason: the hook classified validation batching as an opaque control-plane mutation; the earlier direct split had run successfully.

The controller restored the substantive route fc8d14b31598 and refreshed the exact Core path grants as d451de679ddfb733. Candidate route44fe064efbab is unchanged. This permission changes no hook, denial ledger, merge check or human security boundary. The implementation checkpoint preceded the fresh controls. Commit honest reviewing state next, then run the clean committed-HEAD quality-gates smoke. Independent reviews, the final PR gate and exact-head external checks remain required. Actual bounded results are in evidence/implementation-report.md; they do not create receipts.

## Explicit recovery override

The initial absolute patch was denied as a protected nested-runtime edit. A shell rewrite was denied as ambiguous-command-root. The circuit-breaker rule stopped dependent work. The root cause was failure to materialize the first denial's named exact grant before rewriting the operation.

The user then answered: "Разрешаю восстановление" to a request for one-time recovery through a scoped Getzilla grant on feat/eu-ai-act-phase2-20261021. This overrides only the retry stop for that recovery. Grant02288d66772fb87a names only this file and evidence/startup-inventory.md. All tests, reviews and source gates remain required. State: UNVERIFIED until they run. No PASS evidence is fabricated.
