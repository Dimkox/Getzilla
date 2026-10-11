# Isolate full-scope verifier control from child tests

Typed authority: [change-spec.yaml](change-spec.yaml).

The installed source fails Core scope tests when the verifier's --full-scope flag is inherited by test processes. scripts/getzilla_verify.py sets GETZILLA_VERIFY_FORCE_FULL in the controller; python_test_runner._environment copies it into the child. An existing scope test fails with that environment and passes without it.

Remove only that controller scope override from the shared child-test environment. Keep the parent's forced full selection and all existing capability, coverage and recursion controls. Add subprocess regression coverage before the repair.

Scope: .getzilla/getzilla/python_test_runner.py, tests/test_python_test_runner.py and this change package. No API, data, architecture authority, provider or production change. OSV and pinned OpenGrep are already available locally; configure the final verifier to use them. Deliver source through an isolated branch and PR, then rebuild the local archive. Published releases remain immutable.
