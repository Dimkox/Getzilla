"""Factory unit admission must execute new modules without inheriting database authority."""
from __future__ import annotations
import os
import json
import copy
import shutil
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".getzilla"))
from getzilla import verification

PASS = "import unittest\nclass Probe(unittest.TestCase):\n def test_probe(self): self.assertTrue(True)\n"
FAIL = "import unittest\nclass Probe(unittest.TestCase):\n def test_probe(self): self.fail('new module was executed')\n"


@unittest.skipUnless(sys.version_info >= (3, 11), "Factory controls require Python >=3.11")
class FactoryDiscoveryTests(unittest.TestCase):
    def test_pytest_consumer_cannot_bypass_factory_discovery(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.project(root, {"test_contracts.py": PASS})
            (root / "pyproject.toml").write_text("[project]\nname='probe'\n")
            (root / "tests").mkdir()
            with patch.object(verification, "command_exists", side_effect=lambda name: name == "pytest"), \
                    patch.object(verification, "_ruff", return_value=verification.CheckResult("ruff", "pass", "fixture")), \
                    patch.object(verification, "_bandit", return_value=verification.CheckResult("bandit", "pass", "fixture")), \
                    patch.object(verification, "_core_python_checks", return_value=[]), \
                    patch.object(verification, "_factory_unit", return_value=[]) as factory:
                verification._python_checks(root, "fast", None, [])
            factory.assert_called_once_with(root)

    def project(self, root, modules):
        directory = root / "factory/tests"
        directory.mkdir(parents=True)
        (root / "factory/pyproject.toml").write_text("[project]\nname='synthetic-factory'\n")
        (root / "factory/__init__.py").touch()
        (directory / "__init__.py").touch()
        for name, source in modules.items():
            (directory / name).write_text(source)

    def test_new_module_failure_cannot_hide_behind_legacy_contract_pass(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.project(root, {"test_contracts.py": PASS, "test_new_lifecycle.py": FAIL})
            result = verification._factory_unit(root)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0].status, "fail", result[0])
            self.assertIn("new module was executed", result[0].stderr)

    def test_dispatch_executes_a_tree_with_only_new_test_names(self):
        class Dispatch:
            def __init__(self):
                self.results = []
            def batch(self, _names, callback):
                self.results.extend(callback())
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.project(root, {"test_new_lifecycle.py": PASS})
            dispatch = Dispatch()
            verification._dispatch_factory_unit(root, dispatch)
            self.assertEqual(len(dispatch.results), 1)
            self.assertEqual(dispatch.results[0].status, "pass", dispatch.results)

    def test_an_applicable_empty_suite_never_passes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.project(root, {"test_contracts.py": "# no tests\n"})
            result = verification._factory_unit(root)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0].status, "fail", result[0])

    def test_an_entirely_skipped_unit_suite_never_passes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.project(root, {"test_contracts.py": "import unittest\n@unittest.skip('unavailable')\nclass Probe(unittest.TestCase):\n def test_skip(self): pass\n"})
            result = verification._factory_unit(root)
            self.assertEqual(result[0].status, "fail", result[0])

    def test_database_environment_is_scrubbed_before_test_import(self):
        source = (
            "import os,unittest\n"
            "names=('FACTORY_TEST_DATABASE_URL','FACTORY_FRESH_CLUSTER_DATABASE_URL',"
            "'FACTORY_TEST_POSTGRES_CONTAINER','FACTORY_TEST_POSTGRES_CONTAINER_ID',"
            "'FACTORY_TEST_POSTGRES_NONCE','FACTORY_TEST_POSTGRES_NETWORK_ID',"
            "'FACTORY_TEST_POSTGRES_NAMESPACE')\n"
            "assert not any(os.environ.get(name) for name in names), 'ambient DB authority reached import'\n"
            "class Probe(unittest.TestCase):\n def test_probe(self): self.assertTrue(True)\n"
        )
        with tempfile.TemporaryDirectory() as raw, patch.dict(os.environ, {
            "FACTORY_TEST_DATABASE_URL": "sentinel-not-a-real-database",
            "FACTORY_FRESH_CLUSTER_DATABASE_URL": "sentinel-fresh",
            "FACTORY_TEST_POSTGRES_CONTAINER": "sentinel",
            "FACTORY_TEST_POSTGRES_CONTAINER_ID": "1" * 64,
            "FACTORY_TEST_POSTGRES_NONCE": "2" * 32,
            "FACTORY_TEST_POSTGRES_NETWORK_ID": "3" * 64,
            "FACTORY_TEST_POSTGRES_NAMESPACE": "gz-sentinel",
        }):
            root = Path(raw)
            self.project(root, {"test_contracts.py": source})
            result = verification._factory_unit(root)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0].status, "pass", result[0])

    def test_import_errors_are_not_a_successful_empty_discovery(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.project(root, {"test_contracts.py": "import dependency_that_is_not_installed\n"})
            result = verification._factory_unit(root)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0].status, "fail", result[0])

    def test_collected_and_executed_identities_are_retained(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.project(root, {"test_new_lifecycle.py": PASS})
            result = verification._factory_unit(root)[0]
            self.assertEqual(result.status, "pass", result)
            self.assertTrue(result.details, "test identities must survive the subprocess")
            evidence = result.details[0]
            expected = ["factory.tests.test_new_lifecycle.Probe.test_probe"]
            self.assertEqual(evidence["collected_ids"], expected)
            self.assertEqual(evidence["executed"], expected)
            self.assertEqual(evidence["database_obligations"], "not_run_in_unit_mode")

    def test_mixed_required_skip_fails_and_is_not_executed(self):
        skipped = "import unittest\nclass Probe(unittest.TestCase):\n @unittest.skip('not available')\n def test_required(self): pass\n"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.project(root, {"test_contracts.py": PASS, "test_required.py": skipped})
            result = verification._factory_unit(root)[0]
            self.assertEqual(result.status, "fail", result)
            self.assertNotIn("factory.tests.test_required.Probe.test_required", result.details[0]["executed"])

    def test_borrowing_a_known_skip_reason_does_not_qualify_an_unknown_case(self):
        skipped = "import unittest\n@unittest.skip('FACTORY_TEST_DATABASE_URL must name a disposable database')\nclass Probe(unittest.TestCase):\n def test_required(self): pass\n"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.project(root, {"test_contracts.py": PASS, "test_unknown.py": skipped})
            self.assertEqual(verification._factory_unit(root)[0].status, "fail")

    def test_load_tests_cannot_remove_a_required_case(self):
        source = ("import unittest\nclass Probe(unittest.TestCase):\n"
                  " def test_pass(self): pass\n def test_required(self): self.fail('required')\n"
                  "def load_tests(loader, standard, pattern): return unittest.TestSuite([Probe('test_pass')])\n")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.project(root, {"test_contracts.py": source})
            self.assertEqual(verification._factory_unit(root)[0].status, "fail")

    def test_partial_pass_report_cannot_replace_executed_inventory(self):
        def partial(_root, name, command, *args, **kwargs):
            report = Path(command[command.index("--report") + 1])
            report.write_text(json.dumps({"schema_version": 1, "check_id": name, "status": "pass"}))
            return verification.CheckResult(name, "pass", "exit=0")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.project(root, {"test_contracts.py": PASS})
            with patch.object(verification, "_command_check", side_effect=partial):
                self.assertEqual(verification._factory_unit(root)[0].status, "fail")

    def test_known_database_cases_have_observed_unit_applicability(self):
        database = ("import os, unittest\n@unittest.skipUnless(os.environ.get('FACTORY_TEST_DATABASE_URL'), "
                    "'FACTORY_TEST_DATABASE_URL must name a disposable database')\n"
                    "class PostgresFactoryTests(unittest.TestCase):\n"
                    " def test_database(self): self.fail('unit mode reached a database case')\n")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.project(root, {"test_contracts.py": PASS, "test_postgres_integration.py": database})
            result = verification._factory_unit(root)[0]
            self.assertEqual(result.status, "pass", result)
            evidence = result.details[0]
            skipped = "factory.tests.test_postgres_integration.PostgresFactoryTests.test_database"
            self.assertEqual(evidence["skipped"], [{"id": skipped,
                             "reason": "FACTORY_TEST_DATABASE_URL must name a disposable database",
                             "applicability": "separate-disposable-postgres"}])
            self.assertNotIn(skipped, evidence["executed"])
            self.assertNotIn(skipped, evidence["required_ids"])
            self.assertEqual(evidence["tests_run"], 2)

    def test_complete_reports_require_current_binding_and_consistent_accounting(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.project(root, {"test_contracts.py": PASS})
            baseline = verification._factory_unit(root)[0]
            self.assertEqual(baseline.status, "pass", baseline)
            def invent_case(report):
                identifier = "factory.tests.test_invented.Probe.test_not_in_source"
                for field in ("collected_ids", "expected_ids", "required_ids", "started", "executed"):
                    report[field] = sorted([*report[field], identifier])
                report["collected"] += 1
                report["tests_run"] += 1
            mutations = [
                invent_case,
                lambda report: report.pop("executed"),
                lambda report: report.update(extra="unrecognized"),
                lambda report: report.update(collected=True),
                lambda report: report.update(tests_run=0),
                lambda report: report.update(executed=[]),
                lambda report: report.update(collected_ids=report["collected_ids"] * 2),
                lambda report: report["binding"].update(invocation_id="stale"),
                lambda report: report["binding"].update(source_inventory={}),
                lambda report: report.update(expected_ids=[]),
                lambda report: report.update(required_ids=[]),
                lambda report: report.update(missing_required=["omitted"]),
                lambda report: report.update(skipped=[{"id": "invented", "reason": "unavailable", "applicability": None}]),
            ]
            for index, mutate in enumerate([None, *mutations]):
                def complete(_root, name, command, *args, **kwargs):
                    report = copy.deepcopy(baseline.details[0])
                    request = Path(command[command.index("--request") + 1])
                    report["binding"] = json.loads(request.read_text())
                    if mutate is not None:
                        mutate(report)
                    Path(command[command.index("--report") + 1]).write_text(json.dumps(report))
                    return verification.CheckResult(name, "pass", "exit=0")
                with self.subTest(mutation=index), patch.object(verification, "_command_check", side_effect=complete):
                    result = verification._factory_unit(root)[0]
                    self.assertEqual(result.status, "pass" if mutate is None else "fail", result)

    def test_factory_marker_cannot_silently_lose_the_test_directory(self):
        class Dispatch:
            def __init__(self): self.results = []
            def batch(self, _names, callback): self.results.extend(callback())
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.project(root, {"test_contracts.py": PASS})
            shutil.rmtree(root / "factory/tests")
            dispatch = Dispatch()
            verification._dispatch_factory_unit(root, dispatch)
            self.assertEqual(len(dispatch.results), 1)
            self.assertEqual(dispatch.results[0].status, "fail")

    def test_consumer_package_cannot_shadow_the_selected_source_engine(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.project(root, {"test_contracts.py": PASS})
            (root / "getzilla").mkdir()
            (root / "getzilla/__init__.py").write_text("raise RuntimeError('consumer shadowed selected engine')\n")
            result = verification._factory_unit(root)[0]
            self.assertEqual(result.status, "pass", result)

    def test_factory_python_requirement_does_not_change_core_python_support(self):
        with tempfile.TemporaryDirectory() as raw, patch.object(sys, "version_info", (3, 10, 99)):
            root = Path(raw)
            self.assertEqual(verification._factory_unit(root), [])
            self.project(root, {"test_contracts.py": PASS})
            result = verification._factory_unit(root)[0]
            self.assertEqual(result.status, "fail", result)
            self.assertIn("Factory units require Python >=3.11", result.summary)

    def test_spawned_python_uses_the_same_candidate_package(self):
        source = (
            "import subprocess,sys,unittest\n"
            "class Probe(unittest.TestCase):\n"
            " def test_child(self):\n"
            "  subprocess.run([sys.executable,'-c','import candidate_probe; assert candidate_probe.VALUE == 7'],check=True)\n"
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.project(root, {"test_child.py": source})
            package = root / "factory/src"
            package.mkdir(parents=True)
            (package / "candidate_probe.py").write_text("VALUE = 7\n")
            result = verification._factory_unit(root)
            self.assertEqual(result[0].status, "pass", result[0])


if __name__ == "__main__":
    unittest.main()

