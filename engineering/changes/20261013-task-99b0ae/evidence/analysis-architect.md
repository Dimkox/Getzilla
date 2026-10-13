# docs bounded design

Route99b0aed4d02c; HEAD6dd06ff5b96692a01812fbac6252fd08f6169f91. Read-only design.
- Own issue63 security/handoff docs and issue73 isolated ancestry regression/frozen-state text. Preserve dated history and distinguish observations from current guarantees.
- Verify existing installer tag/hash protection before edits. Remove digest-reset advice as a bypass; mismatch stops pipeline, then diagnose source/policy identity and use separate authorized maintenance. Never request or read human approval keys.
- Explain reviewer isolation and residual same-model risk, threat actors, key custody/rotation roles, incident rollback, dependency inventory/SBOM limits and autonomy meanings using actual source. Do not invent metrics, deployed controls or production qualification.
- Issue73 RED: unrelated orphan commit with identical tree to reviewed source; dropping ancestry check alone must make test fail. Keep candidate clean and identical tree so other guards cannot mask the ancestry result.
- Align current ready sequence with frozen reviewing then saved reports/final receipts. Source state must not change after freeze. Docs writer must not conflict with core focused-first skill ownership or parent's release facts.
- Run targeted binding/ancestry tests; mutation in private runtime scratch only. Leaf work remains UNVERIFIED until integrated parent reviews and final gates.

No candidate edits or tests ran. reviewed-tree-modified: no
