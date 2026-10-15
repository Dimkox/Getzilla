from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))

import json
import unittest
from dataclasses import replace

from getzilla.language_quality.adapters import eslint
from getzilla.language_quality.models import AdapterRequest, ToolOutput


def request(**changes: object) -> AdapterRequest:
    base = AdapterRequest(
        tool_id="eslint", driver="cli", launcher=("/tools/eslint",),
        scope="changed", files=("src/app.ts",),
    )
    return replace(base, **changes)


def message(severity: int = 2, **changes: object) -> dict:
    value = {
        "ruleId": "no-unused-vars", "severity": severity,
        "message": "Unused variable.", "line": 3, "column": 7,
    }
    value.update(changes)
    return value


def report(*messages: dict, **changes: object) -> dict:
    value = {
        "filePath": "/workspace/src/app.ts", "messages": list(messages),
        "errorCount": sum(item["severity"] == 2 for item in messages),
        "warningCount": sum(item["severity"] == 1 for item in messages),
        "fatalErrorCount": sum(item.get("fatal") is True for item in messages),
        "fixableErrorCount": 0, "fixableWarningCount": 0,
    }
    value.update(changes)
    return value


def output(*reports: dict, code: int = 0) -> ToolOutput:
    return ToolOutput(returncode=code, stdout=json.dumps(list(reports)), stderr="")


class ESLintAdapterTests(unittest.TestCase):
    def test_capabilities_and_unknown_driver(self) -> None:
        supported = eslint.capabilities("eslint", "cli")
        self.assertTrue(supported.incremental)
        self.assertTrue(supported.full)
        for tool, driver in (("ktlint", "cli"), ("eslint", "gradle")):
            with self.subTest(tool=tool, driver=driver), self.assertRaises(ValueError):
                eslint.capabilities(tool, driver)

    def test_changed_plan_preserves_file_boundaries_and_never_fixes(self) -> None:
        planned = eslint.build_argv(request(
            launcher=("/tools/node", "node_modules/eslint/bin/eslint.js"),
            files=("src/a b.ts", "-unusual.js", "src/пример.js"),
        ))
        self.assertEqual(planned[:2], ("/tools/node", "node_modules/eslint/bin/eslint.js"))
        self.assertEqual(planned[planned.index("--format") + 1], "json")
        self.assertIn("--exit-on-fatal-error", planned)
        self.assertEqual(planned[planned.index("--cache-location") + 1], "/tmp/getzilla-eslint-cache")
        self.assertEqual(planned[planned.index("--") + 1:],
                         ("./src/a b.ts", "./-unusual.js", "./src/пример.js"))
        self.assertFalse({"--fix", "--fix-dry-run", "--cache", "--init"}.intersection(planned))

    def test_full_plan_uses_package_root_and_explicit_flat_config(self) -> None:
        planned = eslint.build_argv(request(scope="full", files=(), config_path="eslint.config.mjs"))
        self.assertEqual(planned[planned.index("--config") + 1], "./eslint.config.mjs")
        self.assertEqual(planned[planned.index("--") + 1:], (".",))

    def test_invalid_requests_are_rejected_before_execution(self) -> None:
        cases = (
            {"scope": "other"}, {"scope": []}, {"files": ()}, {"files": "src/app.ts"},
            {"files": ("../outside.js",)}, {"files": ("/etc/hosts",)},
            {"files": ("a/../../outside.js",)}, {"files": ("a\\b.js",)},
            {"files": ("a\x00.js",)}, {"files": ("a\n.js",)},
            {"files": ("a//b.js",)}, {"files": ("./a.js",)},
            {"files": (".",)}, {"files": ("a.js", "a.js")},
            {"config_path": "../eslint.config.js"}, {"config_path": ""},
            {"task": "lint"}, {"launcher": ()}, {"launcher": "eslint"},
            {"launcher": ("npx", "eslint")}, {"launcher": ("/tools/npm", "exec", "eslint")},
            {"launcher": ("/tools/eslint", "--fix")},
        )
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                eslint.build_argv(request(**changes))

    def test_clean_report_passes(self) -> None:
        result = eslint.normalize(request(), output(report()))
        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.diagnostics, ())

    def test_warning_is_preserved_without_changing_success_exit(self) -> None:
        result = eslint.normalize(request(), output(report(message(1))))
        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.diagnostics[0].severity, "warning")
        self.assertEqual(result.diagnostics[0].code, "no-unused-vars")
        self.assertEqual(result.diagnostics[0].path, "/workspace/src/app.ts")
        self.assertEqual((result.diagnostics[0].line, result.diagnostics[0].column), (3, 7))

    def test_lint_errors_and_warning_budget_are_failures(self) -> None:
        for severity in (1, 2):
            with self.subTest(severity=severity):
                result = eslint.normalize(request(), output(report(message(severity)), code=1))
                self.assertEqual(result.status, "FAIL")
                self.assertEqual(len(result.diagnostics), 1)

    def test_fatal_parse_error_is_not_a_lint_failure(self) -> None:
        fatal = message(fatal=True, ruleId=None, message="Parsing error.")
        for code in (0, 1, 2):
            with self.subTest(code=code):
                result = eslint.normalize(request(), output(report(fatal), code=code))
                self.assertEqual(result.status, "ERROR")

    def test_config_errors_and_unknown_exits_are_errors(self) -> None:
        for code, stdout in ((2, "Configuration is missing."), (127, ""), (-9, ""), (2, "[]")):
            with self.subTest(code=code, stdout=stdout):
                result = eslint.normalize(request(), ToolOutput(code, stdout, "tool stderr"))
                self.assertEqual(result.status, "ERROR")

    def test_exit_status_and_report_must_agree(self) -> None:
        for observed in (output(report(message())), output(report(), code=1)):
            with self.subTest(output=observed):
                self.assertEqual(eslint.normalize(request(), observed).status, "ERROR")

    def test_malformed_or_empty_json_never_passes(self) -> None:
        for stdout in ("", "not json", "{}", "[]", "null", "[null]", "[{}]", "[NaN]", "[true]"):
            for code in (0, 1):
                with self.subTest(stdout=stdout, code=code):
                    self.assertEqual(eslint.normalize(request(), ToolOutput(code, stdout, "")).status, "ERROR")

    def test_invalid_report_fields_and_counts_never_pass(self) -> None:
        cases = (
            report(errorCount=True), report(errorCount=-1), report(errorCount="0"),
            report(warningCount=1), report(fatalErrorCount=1),
            report(fixableErrorCount=1), report(messages={}), report(filePath=""),
            report(filePath="../../escape.ts"), report(filePath="/workspace/a\n.ts"),
            report(message(), errorCount=0), report(message(1), warningCount=0),
            report(message(severity=True)), report(message(severity=0)),
            report(message(message=[])), report(message(ruleId=3)),
            report(message(line=-1)), report(message(column=True)),
            report(message(fatal="true")), report(message(1, fatal=True)),
        )
        for item in cases:
            with self.subTest(report=item):
                self.assertEqual(eslint.normalize(request(), output(item)).status, "ERROR")

    def test_missing_required_fields_and_duplicate_reports_are_errors(self) -> None:
        for field in ("filePath", "messages", "errorCount", "warningCount", "fatalErrorCount"):
            item = report()
            del item[field]
            with self.subTest(field=field):
                self.assertEqual(eslint.normalize(request(), output(item)).status, "ERROR")
        self.assertEqual(eslint.normalize(request(), output(report(), report())).status, "ERROR")

    def test_unknown_metadata_is_ignored_and_location_can_be_absent(self) -> None:
        warning = {"ruleId": None, "severity": 1, "message": "Ignored file."}
        result = eslint.normalize(request(), output(report(warning, source="secret source", stats={"a": 1})))
        self.assertEqual(result.status, "PASS")
        self.assertIsNone(result.diagnostics[0].line)
        self.assertNotIn("secret source", repr(result))

    def test_multiple_files_are_aggregated(self) -> None:
        observed = output(report(), report(message(), filePath="/workspace/src/other.ts"), code=1)
        result = eslint.normalize(request(scope="full", files=()), observed)
        self.assertEqual(result.status, "FAIL")
        self.assertEqual(len(result.diagnostics), 1)

    def test_duplicate_json_fields_are_errors(self) -> None:
        stdout = json.dumps([report()]).replace('"errorCount": 0', '"errorCount": 1, "errorCount": 0')
        self.assertEqual(eslint.normalize(request(), ToolOutput(0, stdout, "")).status, "ERROR")

    def test_bad_output_types_are_errors(self) -> None:
        for value in (ToolOutput(True, "[]", ""), ToolOutput(0, None, ""), ToolOutput(0, "[]", None)):
            with self.subTest(value=value):
                self.assertEqual(eslint.normalize(request(), value).status, "ERROR")

    def test_invalid_request_still_raises_when_normalizing(self) -> None:
        with self.assertRaises(ValueError):
            eslint.normalize(request(files=()), output(report()))


if __name__ == "__main__":
    unittest.main()
