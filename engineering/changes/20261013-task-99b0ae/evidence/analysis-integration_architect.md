# docs integration analysis

Source: common HEAD6dd06ff5b96692a01812fbac6252fd08f6169f91, base540c12f93e798c2f483455a5086ab0018ac3216e. Read-only selected analysis. Reuses controller analysis-install-lock.md and current issue bodies; no repeated broad inspection, installs, image builds, paid calls or full tests. Leaves remain UNVERIFIED until combined parent reviews and one final qualifying gate under owner sequencing override.

Route99b0ae; #63/#73. Documents consume actual installer, release/check identity, security boundaries and frozen lifecycle behavior. Public Getzilla uses Actions; private consumers use App-owned Trust CI. Do not treat local review receipts or annotated unsigned release tags as signed external attestations. Signature/holdout mismatch stops the pipeline for diagnosis; never advise changing deployed digests merely to make a check pass. Keys belong outside agent environment; document storage/rotation roles without inspecting key files. Reviewer scratch independence and same-model risk must remain explicit. Root file map must include canonical .agents skills and generated .grok mirror.

Minimal files: docs/REFERENCE.md, threat/key/recovery handoff docs and issue63-relevant README/QUICKSTART sections; tests isolating ancestry. For #73 construct nonancestor commit with identical tree, so source-diff guard cannot mask ancestry rejection. Freeze tracked lifecycle state before independent reviews; no ready-state tracked mutation afterward. Test numbers are dated exact-source observations, not timeless guarantees. SBOM/lock policy must reflect lock leaf final behavior. Installer docs preserve installed-consumer AGENTS/CI and no-overwrite boundary; claim no live production target/task qualification.

Dependencies: consume final core one-verifier sequence and lock profile names before finalizing shared docs; installer pinned public command identity remains distinct from candidate VERSION. Do not modify executable fixtures or protected historical evidence as prose. Recovery/incident guidance uses normal PR and exact external checks, no force push/deployed-policy bypass.

No candidate writes. Static design findings only; no PASS review or gate.
reviewed-tree-modified: no
