from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))

import json
import unittest
from dataclasses import replace

from getzilla.language_quality.adapters import kotlin
from getzilla.language_quality.models import AdapterRequest, ToolOutput


def request(**changes: object) -> AdapterRequest:
    return replace(
        AdapterRequest("ktlint", "cli", ("/opt/tools/ktlint",), "changed", ("src/Foo.kt",)),
        **changes,
    )


def findings(**changes: object) -> str:
    error = {"line": 2, "column": 3, "message": "Unexpected indentation", "rule": "standard:indent"}
    error.update(changes)
    return json.dumps([{"file": "src/Foo.kt", "errors": [error]}])


class KotlinAdapterTests(unittest.TestCase):
    def test_only_ktlint_cli_accepts_changed_scope(self) -> None:
        for tool, driver, incremental in (
            ("ktlint", "cli", True), ("detekt", "cli", False),
            ("ktlint", "gradle", False), ("detekt", "gradle", False),
        ):
            with self.subTest(tool=tool, driver=driver):
                self.assertEqual(kotlin.capabilities(tool, driver).incremental, incremental)
                self.assertTrue(kotlin.capabilities(tool, driver).full)
        for tool, driver in (("eslint", "cli"), ("ktlint", "dart"), ("detekt", "flutter")):
            with self.subTest(tool=tool, driver=driver), self.assertRaises(ValueError):
                kotlin.capabilities(tool, driver)

    def test_ktlint_uses_read_only_json_command_with_exact_files(self) -> None:
        self.assertEqual(kotlin.build_argv(request(files=("src/Foo.kt", "build.gradle.kts"))), (
            "/opt/tools/ktlint", "--reporter=json", "--log-level=none", "--relative",
            "--", "src/Foo.kt", "build.gradle.kts",
        ))

    def test_full_ktlint_uses_default_package_scan_not_changed_files(self) -> None:
        self.assertEqual(kotlin.build_argv(request(scope="full", config_path=".editorconfig")), (
            "/opt/tools/ktlint", "--reporter=json", "--log-level=none", "--relative",
            "--editorconfig=.editorconfig",
        ))

    def test_detekt_checks_full_package_and_forces_zero_issue_threshold(self) -> None:
        argv = kotlin.build_argv(request(
            tool_id="detekt", scope="full", launcher=("/opt/java/bin/java", "-jar", "/opt/detekt.jar"),
            config_path="config/detekt.yml",
        ))
        self.assertEqual(argv, (
            "/opt/java/bin/java", "-jar", "/opt/detekt.jar", "--input", ".", "--max-issues", "0",
            "--config", "config/detekt.yml",
        ))

    def test_detekt_rejects_incremental_plan_instead_of_silently_widening(self) -> None:
        with self.assertRaises(ValueError):
            kotlin.build_argv(request(tool_id="detekt"))

    def test_changed_files_reject_path_escape_glob_and_option_injection(self) -> None:
        for path in ("../Foo.kt", "/src/Foo.kt", "src/../Foo.kt", "src//Foo.kt", "./Foo.kt",
                     "--format", "!Foo.kt", "src/*.kt", "src/[ab].kt", "src/{a,b}.kt",
                     "src/Foo?.kt", "src\\Foo.kt", "C:/Foo.kt", "src/Foo\x00.kt", "src/Foo\n.kt",
                     "README.md", "."):
            with self.subTest(path=path), self.assertRaises(ValueError):
                kotlin.build_argv(request(files=(path,)))
        with self.assertRaises(ValueError):
            kotlin.build_argv(request(files=()))

    def test_changed_files_keep_spaces_and_unicode_literal(self) -> None:
        self.assertEqual(kotlin.build_argv(request(files=("src/пример file.kt",)))[-1], "src/пример file.kt")

    def test_bad_config_paths_cannot_add_detekt_configs_or_escape_package(self) -> None:
        for tool in ("detekt", "ktlint"):
            for path in ("../config.yml", "/config.yml", "a.yml,b.yml", "a.yml;b.yml", "--format", ""):
                with self.subTest(tool=tool, path=path), self.assertRaises(ValueError):
                    kotlin.build_argv(request(tool_id=tool, scope="full", config_path=path))

    def test_invalid_launcher_and_cli_task_are_rejected(self) -> None:
        for launcher in ((), ("",), ("ktlint\n",), ("ktlint", "--format"), ("detekt", "--auto-correct")):
            with self.subTest(launcher=launcher), self.assertRaises(ValueError):
                kotlin.build_argv(request(launcher=launcher))
        with self.assertRaises(ValueError):
            kotlin.build_argv(request(task=":app:ktlintFormat"))

    def test_gradle_command_is_offline_full_and_uses_only_named_check_task(self) -> None:
        argv = kotlin.build_argv(request(
            driver="gradle", launcher=("/opt/gradle/bin/gradle",), scope="full", task=":app:ktlintCheck",
        ))
        self.assertEqual(argv, (
            "/opt/gradle/bin/gradle", "--offline", "--no-daemon", "--console=plain",
            "--no-build-cache", "--rerun-tasks", "--no-parallel", "--max-workers=1", ":app:ktlintCheck",
        ))

    def test_gradle_rejects_wrapper_downloads_and_mutating_or_unbounded_tasks(self) -> None:
        base = request(driver="gradle", scope="full", task=":app:ktlintCheck")
        for changes in (
            {"task": None}, {"task": "check"}, {"task": "ktlintFormat"}, {"task": "ktlintCheck --scan"},
            {"task": ":app:ktlintCheck:clean"}, {"task": "--init-script=x"}, {"scope": "changed"},
            {"launcher": ("./gradlew",)}, {"config_path": ".editorconfig"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                kotlin.build_argv(replace(base, **changes))

    def test_gradle_supports_exact_detekt_task_names(self) -> None:
        for task in ("detekt", ":app:detekt", ":app:detektMain", ":app:detektTest"):
            with self.subTest(task=task):
                self.assertEqual(kotlin.build_argv(request(
                    tool_id="detekt", driver="gradle", scope="full", task=task,
                ))[-1], task)

    def test_ktlint_clean_json_is_pass(self) -> None:
        for output in (ToolOutput(0, "[]\n", ""), ToolOutput(0, "", "[]\n")):
            with self.subTest(output=output):
                result = kotlin.normalize(request(), output)
                self.assertEqual(result.status, "PASS")
                self.assertEqual(result.diagnostics, ())

    def test_ktlint_findings_preserve_structured_location(self) -> None:
        result = kotlin.normalize(request(), ToolOutput(1, findings(), ""))
        self.assertEqual(result.status, "FAIL")
        self.assertEqual(len(result.diagnostics), 1)
        item = result.diagnostics[0]
        self.assertEqual((item.path, item.line, item.column), ("src/Foo.kt", 2, 3))
        self.assertEqual((item.code, item.message, item.severity), ("standard:indent", "Unexpected indentation", "error"))

    def test_ktlint_invalid_output_never_passes(self) -> None:
        for body in ("", "not json", "{}", "null", '[{"file":"src/Foo.kt"}]',
                     '[{"file":"src/Foo.kt","errors":[]}]',
                     '[{"file":"src/Foo.kt","file":"../bad.kt","errors":[]}]',
                     findings(line=True), findings(column=-1), findings(message=None), findings(rule="")):
            with self.subTest(body=body):
                self.assertEqual(kotlin.normalize(request(), ToolOutput(0, body, "")).status, "ERROR")

    def test_ktlint_rejects_return_code_and_report_disagreement(self) -> None:
        for output in (ToolOutput(0, findings(), ""), ToolOutput(1, "[]", ""),
                       ToolOutput(2, "[]", ""), ToolOutput(-9, "[]", ""),
                       ToolOutput(True, "[]", ""), ToolOutput(0, "[]", findings()),
                       ToolOutput(0, "[]", "fatal error")):
            with self.subTest(output=output):
                self.assertEqual(kotlin.normalize(request(), output).status, "ERROR")

    def test_ktlint_unsafe_or_out_of_scope_report_path_is_error(self) -> None:
        for path in ("../Foo.kt", "/workspace/src/Foo.kt", "src/Other.kt", "src/../Foo.kt"):
            body = json.loads(findings())
            body[0]["file"] = path
            with self.subTest(path=path):
                self.assertEqual(kotlin.normalize(request(), ToolOutput(1, json.dumps(body), "")).status, "ERROR")

    def test_detekt_exit_codes_keep_fail_distinct_from_execution_error(self) -> None:
        for code, status in ((0, "PASS"), (2, "FAIL"), (1, "ERROR"), (3, "ERROR"), (9, "ERROR"), (-15, "ERROR")):
            with self.subTest(code=code):
                result = kotlin.normalize(request(tool_id="detekt", scope="full"), ToolOutput(code, "", ""))
                self.assertEqual(result.status, status)
                self.assertIn("exit", result.summary)

    def test_gradle_zero_exit_cannot_prove_lint_without_report_artifact(self) -> None:
        for tool in ("detekt", "ktlint"):
            for code in (0, 1):
                task = "detekt" if tool == "detekt" else "ktlintCheck"
                with self.subTest(tool=tool, code=code):
                    result = kotlin.normalize(
                        request(tool_id=tool, driver="gradle", scope="full", task=task),
                        ToolOutput(code, "BUILD SUCCESSFUL", ""),
                    )
                    self.assertEqual(result.status, "ERROR")
                    self.assertIn("report", result.summary)


if __name__ == "__main__":
    unittest.main()
