# Executed verification tools

Getzilla can run seven optional open-source tools and include their executed results in the normal verification report. This layer provides evidence about project-authored tests, API checks and mutation experiments. It does not infer correct requirements from an implementation or prove that all possible behavior is correct.

Without `.getzilla-verification.json`, the verifier schedules no additional checks and probes no optional dependencies. The integration itself uses only the Python standard library. Your project installs and pins the tools it selects; Getzilla does not run package installation or download browsers automatically.

## Select the evidence a task needs

| Tool | License | Evidence accepted by this integration | Project supplies |
| --- | --- | --- | --- |
| [Playwright](https://playwright.dev/docs/test-cli) | Apache-2.0 | JSON test cases, actual attempts and aggregate results | Browser/API scenarios and assertions; application startup and browser installation |
| [Schemathesis](https://schemathesis.readthedocs.io/en/latest/reference/cli/) | MIT | Completed JSON report, tested operations, generated cases, failures and errors | OpenAPI schema and an explicitly selected test service |
| [Hypothesis](https://hypothesis.readthedocs.io/) | MPL-2.0 | Pytest JUnit cases selected by the Hypothesis marker | Properties, strategies and assertions about application behavior |
| [fast-check](https://fast-check.dev/docs/introduction/getting-started/) | MIT | JUnit produced by the project's existing test runner | Property tests and a JUnit reporter, for example Vitest |
| [mutmut](https://mutmut.readthedocs.io/) | BSD-3-Clause | Exported mutation counters from a fresh source copy | Source selection and pytest tests in mutmut's configuration |
| [StrykerJS](https://stryker-mutator.io/docs/stryker-js/configuration/) | Apache-2.0 | JSON mutant outcomes from a fresh source copy | Stryker configuration, source selection and runner plugin |
| [Testcontainers Python](https://testcontainers-python.readthedocs.io/en/latest/) | Apache-2.0 | JUnit from actual integration tests | Container fixtures, assertions, Docker and required images |

The licenses above describe the respective upstream projects. Dependencies retain their own licenses. None of these packages is vendored into Getzilla.

Start with observable acceptance criteria. For example, “a repeated payment request must not create a second charge” needs an assertion against the resulting state and a controlled payment fixture. A browser screenshot, an HTTP 200 response or a passing generated test that repeats the implementation is insufficient evidence for that claim. Mutation testing can expose weak assertions in selected code, but a high mutation score does not validate the requirements themselves.

## Configure the project

1. Copy `.getzilla/templates/verification-tools.example.json` to `.getzilla-verification.json` in the project root.
2. Keep the entries you need, configure their selectors and set `enabled` to `true`. All examples are disabled initially. The example paths are placeholders for your project's tests.
3. Install the selected packages into the project's environment and lock their versions. Python checks use the local `.venv` if present. JavaScript examples use installed `node_modules` directly.
4. Inspect and run the plan:

```sh
getzilla test-tools catalog
getzilla test-tools plan --mode pr --json
getzilla test-tools run --mode pr --json
getzilla verify --mode pr
```

`catalog` and `plan` do not execute project commands. `run` is a standalone diagnostic: it prints normalized evidence and exits nonzero on refusal; it does not issue a verification receipt or authorize a merge. The normal `verify` command includes selected checks in its existing report and receipt, subject to the existing source-stability, review and quality gates. PR/release fail-fast behavior also applies to these checks.

The example commands can also be run through `python3 scripts/getzilla_verification_tools.py`. Use `--root /path/to/project` with this script to select a project explicitly. An absent configuration or a mode with no enabled checks produces `not_configured` and exit 2 for standalone `plan`/`run`, never a successful test run. The main verifier simply has no optional checks to schedule in that case.

### Configuration contract

The top-level fields are exactly `schema_version: 1` and `checks`. Unknown fields, duplicate JSON keys and duplicate check IDs are errors.

| Check field | Meaning |
| --- | --- |
| `id` | Required unique identifier, 1–64 ASCII letters, digits, `_` or `-`; starts with a letter or digit |
| `tool` | Required catalog key from the example |
| `commands` | Required array of 1–4 argument arrays, executed sequentially without a shell; Stryker accepts exactly one command |
| `cwd` | Existing relative project directory, default `.`; no `..`, absolute path or symlink components |
| `timeout_seconds` | Combined command budget, integer 1–3600; default 300 |
| `enabled` | Boolean, default `true` |
| `modes` | Nonempty subset of `fast`, `pr`, `release`; default `pr` and `release` |
| `criteria` | Optional mapping of acceptance IDs to exact test IDs; every listed test must pass |

Arguments support `{report}`, `{output_dir}`, `{project}` and `{python}` substitutions. They are literal argument substitutions, not shell evaluation. `{project}` is the temporary source root for mutation and Schemathesis checks. `{python}` resolves the `.venv` in `cwd`, then the project root, then the running Python interpreter. The corresponding interpreter's directory is prepended to `PATH` for console scripts such as `mutmut` and `schemathesis`.

Do not put credentials in command arguments or config. Commands, bounded stdout/stderr and execution metadata are recorded as evidence. Tools inherit the process environment; configure authentication using the selected tool's supported environment mechanisms. The commands are trusted project code running with the current user's privileges.

### Bind an acceptance criterion

```json
{
  "schema_version": 1,
  "checks": [
    {
      "id": "payment-properties",
      "tool": "hypothesis",
      "commands": [["{python}", "-m", "pytest", "tests/properties", "-m", "hypothesis", "--junitxml={report}"]],
      "criteria": {
        "AC-PAYMENT-IDEMPOTENT": ["tests.properties.test_payments::test_retry_does_not_charge_twice"]
      }
    }
  ]
}
```

Read the actual IDs from `details[].report.tests` in `test-tools run --json`; JUnit identity is `classname::name` when a classname exists, otherwise `name`. Parameterized cases have their own IDs. Playwright identity combines file, nested suite titles, spec title and `[projectName]` when present. There is no substring or wildcard matching. A missing, duplicated, skipped or non-passing requested ID refuses the criterion.

Hypothesis and fast-check reports count test cases, not generated examples. JUnit cannot prove a case used a particular library; keep selectors narrow and inspect the tests. Testcontainers has no universal built-in pytest marker: the example deliberately selects your integration directory. A Docker availability check alone does not establish database behavior.

Schemathesis's aggregate report and mutation reports cannot bind individual acceptance criteria in this version. They remain additional checks alongside the concrete tests. This integration does not rewrite the active change specification or silently turn its free-text acceptance criteria into proven claims.

## Report and failure rules

- Every enabled check must finish its commands successfully and produce a new report in the current run. A missing executable, timeout, cleanup failure, absent/malformed/oversized report or nonzero command exit fails the check. A previous report cannot be reused.
- JUnit must contain actual cases and consistent counters. Failures, errors, skips and an empty suite refuse the check.
- Playwright requires successful actual attempts. Expected failures, skips, flaky results, global errors and inconsistent statistics refuse the check. `PLAYWRIGHT_JSON_OUTPUT_FILE` directs its JSON reporter to the fresh path.
- Schemathesis requires a completed run with checked cases and all selected operations tested. Errors, failures, skipped selected operations and incomplete execution refuse the check. Filtering is a project decision; unselected operations are not claimed as tested.
- mutmut uses `mutmut run`, then `mutmut export-cicd-stats`. Its fixed report is `mutants/mutmut-cicd-stats.json` in the check's working directory. Only a nonempty set with every mutant killed passes. The console executable is used, rather than `python -m mutmut`.
- Stryker uses its JSON reporter at `reports/mutation/mutation.json` in the check's working directory. Keep that default, or set `jsonReporter.fileName` to the supplied `{report}` path through an explicit wrapper. Getzilla appends `--force --incrementalFile <fresh-run-path>` to its one command, overriding incremental-cache reuse; wrappers must forward those options to Stryker. An end-of-options `--` separator is refused. Viable mutants must all be killed; compile errors are excluded and cannot form an all-green empty run. Survivors, no coverage, timeouts, runtime errors, pending and ignored mutants refuse the check, even when Stryker itself exits zero.

Reports are limited to 8 MiB and 10,000 cases/mutants. Configuration is limited to 128 KiB and 64 checks. Report parsing rejects duplicate JSON keys, unsupported structures and XML entity/declaration tricks. Unknown future report shapes fail explicitly; update an adapter after checking the new format, rather than treating a parser failure as success.

The normalized evidence includes command exit states, timings, report SHA-256, source commit when present, a source fingerprint, counters, observed test IDs and criterion results. Raw reports and temporary workspaces are removed after the check; use the normal verification JSON or standalone JSON output to retain the normalized evidence.

## Source copies and operational limits

Mutation tools and Schemathesis run on a fresh copy of current working files, including dirty and untracked source. This keeps Schemathesis's native cache writes inside the run while preserving the project's own configuration. Old mutation reports and the standard `.schemathesis/<project>/cache` subtree are excluded; other Schemathesis project files remain included. The original project is fingerprinted before and after execution; changed source refuses the result. Snapshots are capped at 20,000 files, 200 MiB total and 16 MiB per file. Source links, Windows junctions/reparse points and special files are refused for these copied runs.

The copy excludes Git metadata, Getzilla runtime/index data, dependency environments, common test caches/reports, mutation caches and secret-looking files such as `.env` and private keys. Example environment templates are retained. These exclusions also define the standalone source-fingerprint scope; the enclosing verifier keeps its existing repository fingerprint as an additional check.

Python dependencies are used from the original environment. Stryker's installed `node_modules` directories are linked for module resolution. These workspaces prevent normal mutation tools from editing the original source; they are not an OS sandbox and do not isolate shared dependencies, the network or external services. Use a container or CI worker when that isolation is required.

Provide a disposable API/database target and explicit service lifecycle. Use Testcontainers context managers or `yield` fixtures for teardown. The runner stops its owned process tree on timeout or interruption, but cannot guarantee cleanup of resources a test leaks to a remote Docker daemon. Do not run mutation tools or generated API traffic against production services.

The mutmut workflow requires its supported POSIX/fork environment; native Windows users need WSL or a suitable Linux worker. Browser binaries, Docker access, database images and tool-specific configuration remain project prerequisites. Rust, Go and C/C++ adapters are outside this implementation.
