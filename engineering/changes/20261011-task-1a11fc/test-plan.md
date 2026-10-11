# Test plan

Add a real subprocess regression in tests/test_python_test_runner.py. With GETZILLA_VERIFY_FORCE_FULL=1 in the parent, the child created through _environment must see no override and derive its own scope. The parent value and operator-override decision must remain intact. Verify an ordinary marker variable and GETZILLA_VERIFY_CAPABILITY survive and existing child/coverage controls are set.

RED: execute the new regression before implementation and retain exact failure output. GREEN: repeat it after the minimal filter; run tests.test_python_test_runner and tests.test_verification_scope. Run the bounded committed-HEAD quality-gate smoke before independent reviews.

After reports are saved and committed, run GETZILLA_OSV_ONLINE=1 GETZILLA_TEST_WORKERS=12 python3 scripts/getzilla_verify.py --mode pr --full-scope with the pinned OpenGrep on PATH. Require all mandatory checks, full Core coverage and disposable PostgreSQL/restart checks. Local verification never replaces required public Actions on the exact PR head. Build the clean candidate twice using scripts/package_stack.py and verify checksums plus embedded manifest.
