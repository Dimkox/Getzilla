# Architecture

Typed authority: [change-spec.yaml](change-spec.yaml).

The controller owns verification scope. The shared python_test_runner._environment boundary owns the environment for named tests, Core test engines and Trust CI tests. Filter the single scope-control variable here; never clear the controller environment or sanitize the generic execute function.

Existing local verifier/policy nodes cover this change. No architecture model, API/event contract, database, Bitrix or governance authority change is needed. Use the established FORCE_FULL_VARIABLE constant if its import is acyclic. Nested tests may set their own override explicitly.

The key risk is accidentally weakening the parent full-scope policy or removing unrelated capability variables. The regression checks the parent and child separately. Runtime OSV/OpenGrep setup stays outside tracked product configuration.
