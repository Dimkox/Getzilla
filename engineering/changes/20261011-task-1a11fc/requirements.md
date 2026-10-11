# Requirements

Typed authority: [change-spec.yaml](change-spec.yaml).

- AC-001: strip GETZILLA_VERIFY_FORCE_FULL only from child-test environments; keep the parent value and forced full selection.
- AC-002: preserve worker recursion/capability controls and ordinary variables; retain current plugin and coverage isolation.
- AC-003: collect independent reports, freeze a committed candidate, run the complete local PR gate with OSV/OpenGrep, record receipts and compare two archives.

Applicable governance: existing Python verification and environment boundaries; no canonical-example deviation, new dependency or debt. Security and external mutation controls remain intact. Use real child execution for the regression. Verify both defined and absent overrides and preserve parent scope evidence.
