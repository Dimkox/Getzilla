# Child environment RED/GREEN evidence

Route: 1a11fc0a8f4b. Base/HEAD: 05f85f12b72b3a897c45c24e172fac8317120b7c. Worktree: /home/pall/.local/share/getzilla-worktrees/fix-verify-control-env.

The regression exercises a real child process. It catches inheritance of the parent controller override, parent mutation, blanket removal of GETZILLA variables, broken worker/plugin/coverage isolation and loss of a test-owned override. The parent override remains effective for parent scope selection.

## RED before production change

Command:

```sh
GETZILLA_TEST_WORKERS=2 python3 -m unittest tests.test_python_test_runner.PythonTestRunnerTests.test_child_scope_does_not_inherit_controller_override
```

Exit code: 1. Exact output:

```text
F
======================================================================
FAIL: test_child_scope_does_not_inherit_controller_override (tests.test_python_test_runner.PythonTestRunnerTests.test_child_scope_does_not_inherit_controller_override) (override='1')
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/home/pall/.local/share/getzilla-worktrees/fix-verify-control-env/tests/test_python_test_runner.py", line 452, in test_child_scope_does_not_inherit_controller_override
    self.assertEqual(json.loads(result.stdout), {
AssertionError: {'override': '1', 'scope': 'operator-override', 'worke[674 chars]ide'} != {'override': None, 'scope': 'eligible', 'workers': 0, [666 chars]la'}}
Diff is 1062 characters long. Set self.maxDiff to None to see it.

----------------------------------------------------------------------
Ran 1 test in 0.315s

FAILED (failures=1)
```

The set-parent case failed because the child observed override `1` and selected `operator-override`; the absent-parent case passed. Production code was unchanged for this run.

## GREEN regression

Command:

```sh
GETZILLA_TEST_WORKERS=2 python3 -m unittest tests.test_python_test_runner.PythonTestRunnerTests.test_child_scope_does_not_inherit_controller_override
```

Exit code: 0. Exact output:

```text
.
----------------------------------------------------------------------
Ran 1 test in 0.313s

OK
```

## Bounded invocation correction

Command:

```sh
GETZILLA_TEST_WORKERS=2 python3 -m unittest tests.test_python_test_runner tests.test_verification_scope
```

Exit code: 1. Exact output:

```text
.................................
----------------------------------------------------------------------
Ran 1 test in 0.000s

OK
.....F.....................................................
======================================================================
FAIL: test_repo_root_without_optin_uses_measured_parallel_coverage_fallback (tests.test_python_test_runner.PythonTestRunnerTests.test_repo_root_without_optin_uses_measured_parallel_coverage_fallback)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/home/pall/.local/share/getzilla-worktrees/fix-verify-control-env/tests/test_python_test_runner.py", line 746, in test_repo_root_without_optin_uses_measured_parallel_coverage_fallback
    self.assertIsNone(selected_workers(repo_root))
AssertionError: 2 is not None

----------------------------------------------------------------------
Ran 91 tests in 52.996s

FAILED (failures=1)
```

The command supplied a worker override to an existing regression that requires absent opt-in. This caused `test_repo_root_without_optin_uses_measured_parallel_coverage_fallback` to fail (`2 is not None`). The correction is to unset the worker override and bound subprocess affinity to two allowed CPUs; no production or test change was made to repair this invocation error.

## GREEN bounded runner/scope modules

Command:

```sh
env -u GETZILLA_TEST_WORKERS taskset -c 0,1 python3 -m unittest tests.test_python_test_runner tests.test_verification_scope
```

Exit code: 0. Exact output:

```text
.................................
----------------------------------------------------------------------
Ran 1 test in 0.000s

OK
...........................................................
----------------------------------------------------------------------
Ran 91 tests in 53.349s

OK
```

The two allowed CPUs bound the focused worker load without overriding the test's no-opt-in contract.

## Static validation and handoff

`python3 -m ruff check .getzilla/getzilla/python_test_runner.py tests/test_python_test_runner.py` exited 0: `All checks passed!`. `git diff --check` exited 0 with no output.

Production changes import the acyclic selector constant and omit only that flag in the copied child environment. The selector, CLI and generic execute boundary are unchanged. The regression covers defined/absent parent controls, preserved parent environment and parent scope, test-owned child override, ordinary and GETZILLA marker values, capability retention, import roots, worker recursion, plugin isolation and coverage isolation.

Residual risk: checks ran on Linux; independent reviews and the full PR gate remain for the coordinator. No commit, push, merge, deployment or final verification receipt was created. Roll back the import/filter and regression changes to restore the prior behavior; keep this evidence as the historical RED/GREEN record.



