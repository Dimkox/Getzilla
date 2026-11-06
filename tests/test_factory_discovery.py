"""Factory unit admission must execute new modules without inheriting database authority."""
from __future__ import annotations
import os
import json
import copy
import importlib.util
import py_compile
import shutil
import subprocess
from types import SimpleNamespace
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".getzilla"))
from getzilla import verification, factory_tests, fsx

PASS = "import unittest\nclass Probe(unittest.TestCase):\n def test_probe(self): self.assertTrue(True)\n"
FAIL = "import unittest\nclass Probe(unittest.TestCase):\n def test_probe(self): self.fail('new module was executed')\n"


@unittest.skipUnless(sys.version_info >= (3, 11), "Factory controls require Python >=3.11")
class FactoryDiscoveryTests(unittest.TestCase):

    def test_readonly_source_binding_import_does_not_load_component_owner(self):
        source_root = Path(__file__).resolve().parents[1] / '.getzilla'
        script = (
            'import json,sys; '
            f'sys.path.insert(0,{str(source_root)!r}); '
            'import getzilla.factory_tests; '
            'print(json.dumps({"component_loaded":"getzilla.component_state" in sys.modules}))'
        )
        result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', script],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0)
        self.assertFalse(json.loads(result.stdout)['component_loaded'])

    def test_expected_failure_and_unexpected_success_keep_failure_evidence(self):
        source = ("import unittest\nclass Probe(unittest.TestCase):\n"
                  " @unittest.expectedFailure\n def test_expected(self): self.fail('public-sentinel')\n"
                  " @unittest.expectedFailure\n def test_unexpected(self): self.assertTrue(True)\n")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            self.project(root, {"test_problem.py": source})
            result = verification._factory_unit(root)[0]
            self.assertEqual(result.status, "fail")
            report = result.details[0]
            self.assertEqual(report["failures"], 2)
            self.assertEqual(sorted(row["kind"] for row in report["problems"]),
                             ["expected_failure", "unexpected_success"])
            self.assertNotIn("public-sentinel", json.dumps(report["problems"]))

    def test_complete_problem_inventory_keeps_class_and_module_fixture_errors(self):
        for phase in ("setUpClass", "tearDownClass", "setUpModule", "tearDownModule"):
            source = "import unittest\n"
            if phase.endswith("Module"):
                source += f"def {phase}(): raise RuntimeError('public-sentinel')\n"
            source += "class Probe(unittest.TestCase):\n"
            if phase.endswith("Class"):
                source += f" @classmethod\n def {phase}(cls): raise RuntimeError('public-sentinel')\n"
            source += " def test_probe(self): self.assertTrue(True)\n"
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve()
                self.project(root, {"test_problem.py": source})
                result = verification._factory_unit(root)[0]
                self.assertEqual(result.status, "fail")
                self.assertTrue(result.details, "fixture error lost its complete source-bound report")
                report = result.details[0]
                self.assertEqual(report["errors"], 1)
                self.assertEqual(len(report["problems"]), 1)
                problem = report["problems"][0]
                self.assertEqual(problem["phase"], phase)
                expected = "factory.tests.test_problem" + (".Probe" if phase.endswith("Class") else "")
                self.assertEqual(problem["id"], expected)
                self.assertNotIn("public-sentinel", json.dumps(problem))
                factory_tests.validate_report(report, report["binding"])

    def test_complete_problem_inventory_excludes_messages_and_subtest_values(self):
        source = (
            "import unittest\nclass Probe(unittest.TestCase):\n"
            " def test_subtests(self):\n"
            "  for value in (1,2):\n"
            "   with self.subTest(raw='public-sentinel',value=value): self.fail('public-sentinel')\n"
            " def test_error(self): raise ValueError('public-sentinel')\n"
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            self.project(root, {"test_problem.py": source})
            result = verification._factory_unit(root)[0]
            self.assertEqual(result.status, "fail")
            report = result.details[0]
            self.assertIn("problems", report, "complete safe failure inventory was discarded")
            problems = report["problems"]
            self.assertEqual(len(problems), 3)
            self.assertEqual(sorted(row["kind"] for row in problems), ["error", "failure", "failure"])
            self.assertEqual({row["id"] for row in problems}, set(report["executed"]))
            self.assertNotIn("public-sentinel", json.dumps(problems))
            self.assertNotIn(str(root), json.dumps(problems))
            self.assertTrue(all(row["frames"] for row in problems))
            for row in problems:
                for frame in row["frames"]:
                    self.assertEqual(frame["path"], "factory/tests/test_problem.py")
                    self.assertGreater(frame["line"], 0)
            for changed in ({**report, "problems": []},
                            {**report, "problems": [{**problems[0], "message": "untrusted"}, *problems[1:]]}):
                with self.assertRaises(ValueError):
                    factory_tests.validate_report(changed, report["binding"])

    def test_pytest_consumer_cannot_bypass_factory_discovery(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
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
            root = Path(raw).resolve()
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
            root = Path(raw).resolve()
            self.project(root, {"test_new_lifecycle.py": PASS})
            dispatch = Dispatch()
            verification._dispatch_factory_unit(root, dispatch)
            self.assertEqual(len(dispatch.results), 1)
            self.assertEqual(dispatch.results[0].status, "pass", dispatch.results)

    def test_an_applicable_empty_suite_never_passes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            self.project(root, {"test_contracts.py": "# no tests\n"})
            result = verification._factory_unit(root)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0].status, "fail", result[0])

    def test_an_entirely_skipped_unit_suite_never_passes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
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
            root = Path(raw).resolve()
            self.project(root, {"test_contracts.py": source})
            result = verification._factory_unit(root)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0].status, "pass", result[0])

    def test_import_errors_are_not_a_successful_empty_discovery(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            self.project(root, {"test_contracts.py": "import dependency_that_is_not_installed\n"})
            result = verification._factory_unit(root)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0].status, "fail", result[0])

    def test_collected_and_executed_identities_are_retained(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
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
            root = Path(raw).resolve()
            self.project(root, {"test_contracts.py": PASS, "test_required.py": skipped})
            result = verification._factory_unit(root)[0]
            self.assertEqual(result.status, "fail", result)
            self.assertNotIn("factory.tests.test_required.Probe.test_required", result.details[0]["executed"])

    def test_borrowing_a_known_skip_reason_does_not_qualify_an_unknown_case(self):
        skipped = "import unittest\n@unittest.skip('FACTORY_TEST_DATABASE_URL must name a disposable database')\nclass Probe(unittest.TestCase):\n def test_required(self): pass\n"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            self.project(root, {"test_contracts.py": PASS, "test_unknown.py": skipped})
            self.assertEqual(verification._factory_unit(root)[0].status, "fail")

    def test_load_tests_cannot_remove_a_required_case(self):
        source = ("import unittest\nclass Probe(unittest.TestCase):\n"
                  " def test_pass(self): pass\n def test_required(self): self.fail('required')\n"
                  "def load_tests(loader, standard, pattern): return unittest.TestSuite([Probe('test_pass')])\n")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            self.project(root, {"test_contracts.py": source})
            self.assertEqual(verification._factory_unit(root)[0].status, "fail")

    def test_partial_pass_report_cannot_replace_executed_inventory(self):
        def partial(_root, name, command, *args, **kwargs):
            report = Path(command[command.index("--report") + 1])
            report.write_text(json.dumps({"schema_version": 1, "check_id": name, "status": "pass"}))
            return verification.CheckResult(name, "pass", "exit=0")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            self.project(root, {"test_contracts.py": PASS})
            with patch.object(verification, "_command_check", side_effect=partial):
                self.assertEqual(verification._factory_unit(root)[0].status, "fail")

    def test_known_database_cases_have_observed_unit_applicability(self):
        database = ("import os, unittest\n@unittest.skipUnless(os.environ.get('FACTORY_TEST_DATABASE_URL'), "
                    "'FACTORY_TEST_DATABASE_URL must name a disposable database')\n"
                    "class PostgresFactoryTests(unittest.TestCase):\n"
                    " def test_database(self): self.fail('unit mode reached a database case')\n")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
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
            root = Path(raw).resolve()
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
            root = Path(raw).resolve()
            self.project(root, {"test_contracts.py": PASS})
            shutil.rmtree(root / "factory/tests")
            dispatch = Dispatch()
            verification._dispatch_factory_unit(root, dispatch)
            self.assertEqual(len(dispatch.results), 1)
            self.assertEqual(dispatch.results[0].status, "fail")

    def test_consumer_package_cannot_shadow_the_selected_source_engine(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            self.project(root, {"test_contracts.py": PASS})
            (root / "getzilla").mkdir()
            (root / "getzilla/__init__.py").write_text("raise RuntimeError('consumer shadowed selected engine')\n")
            result = verification._factory_unit(root)[0]
            self.assertEqual(result.status, "pass", result)

    def test_factory_python_requirement_does_not_change_core_python_support(self):
        with tempfile.TemporaryDirectory() as raw, patch.object(sys, "version_info", (3, 10, 99)):
            root = Path(raw).resolve()
            self.assertEqual(verification._factory_unit(root), [])
            self.project(root, {"test_contracts.py": PASS})
            result = verification._factory_unit(root)[0]
            self.assertEqual(result.status, "fail", result)
            self.assertIn("Factory units require Python >=3.11", result.summary)

    def _linked_source(self, *, selected, internal, junction=False):
        with tempfile.TemporaryDirectory() as raw:
            private = Path(raw).resolve()
            root = private / 'candidate'
            sentinel = private / 'imported-outside-source'
            source = "from pathlib import Path\nPath(" + repr(str(sentinel)) + ").touch()\n" + PASS
            self.project(root, {"test_contracts.py": source})
            link = root / selected
            target = (root if internal else private) / 'relocated'
            link.rename(target)
            if junction:
                created = subprocess.run(['cmd', '/c', 'mklink', '/J', str(link), str(target)],
                                         text=True, capture_output=True, timeout=10)
                self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
            else:
                try:
                    link.symlink_to(target, target_is_directory=True)
                except OSError as exc:
                    self.skipTest('directory links unavailable: ' + str(exc))
            try:
                result = verification._factory_unit(root)[0]
                self.assertFalse(sentinel.exists(), 'linked test source was imported before refusal')
                self.assertEqual(result.status, 'fail', result)
            finally:
                if junction:
                    link.rmdir()
                else:
                    link.unlink()

    def test_selected_test_root_and_factory_ancestor_links_refuse_before_import(self):
        for selected in ('factory/tests', 'factory'):
            for internal in (False, True):
                with self.subTest(selected=selected, internal=internal):
                    self._linked_source(selected=selected, internal=internal)

    @unittest.skipUnless(os.name == 'nt', 'native Windows junction qualification runs in CI')
    def test_native_windows_source_root_and_factory_junctions_refuse_before_import(self):
        for selected in ('factory/tests', 'factory'):
            for internal in (False, True):
                with self.subTest(selected=selected, internal=internal):
                    self._linked_source(selected=selected, internal=internal, junction=True)

    def test_candidate_root_and_parent_links_refuse_before_import(self):
        for ancestor in (False, True):
            with self.subTest(ancestor=ancestor), tempfile.TemporaryDirectory() as raw:
                private = Path(raw).resolve()
                root = private / 'real-parent/candidate'
                sentinel = private / 'imported-outside-source'
                self.project(root, {"test_contracts.py":
                    "from pathlib import Path\nPath(" + repr(str(sentinel)) + ").touch()\n" + PASS})
                alias = private / 'alias'
                try:
                    alias.symlink_to(root.parent if ancestor else root, target_is_directory=True)
                except OSError as exc:
                    self.skipTest('directory links unavailable: ' + str(exc))
                candidate = alias / 'candidate' if ancestor else alias
                result = verification._factory_unit(candidate)[0]
                self.assertFalse(sentinel.exists(), 'candidate ancestry was resolved before checking links')
                self.assertEqual(result.status, 'fail', result)

    def test_reparse_point_metadata_refuses_on_selected_roots(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            self.project(root, {"test_contracts.py": PASS})
            original = fsx.lstat_at
            def reparse(parent, name):
                metadata = original(parent, name)
                if name == 'tests':
                    return SimpleNamespace(st_mode=metadata.st_mode,
                                           st_file_attributes=fsx.FILE_ATTRIBUTE_REPARSE_POINT)
                return metadata
            with patch.object(fsx, 'lstat_at', side_effect=reparse):
                result = verification._factory_unit(root)[0]
            self.assertEqual(result.status, 'fail', result)

    def test_jsonl_and_binary_fixture_edits_are_refused_at_consumer_readback(self):
        for relative in ('fixtures/codex-0.152.1/success.jsonl', 'fixtures/pixels.bin'):
            with self.subTest(fixture=relative), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve()
                self.project(root, {"test_contracts.py": PASS})
                fixture = root / 'factory/tests' / relative
                fixture.parent.mkdir(parents=True, exist_ok=True)
                fixture.write_bytes(b'original\x00\xff')
                baseline = verification._factory_unit(root)[0]
                self.assertEqual(baseline.status, 'pass', baseline)
                original = verification._command_check
                def mutate(*args, **kwargs):
                    result = original(*args, **kwargs)
                    fixture.write_bytes(b'changed\x00\xff')
                    return result
                with patch.object(verification, '_command_check', side_effect=mutate):
                    result = verification._factory_unit(root)[0]
                self.assertEqual(result.status, 'fail', result)

    def test_fixture_edits_during_execution_cannot_claim_source_stable(self):
        for relative in ('fixtures/codex-0.152.1/success.jsonl', 'fixtures/pixels.bin'):
            with self.subTest(fixture=relative), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve()
                fixture = root / 'factory/tests' / relative
                source = ("from pathlib import Path\nimport unittest\nclass Probe(unittest.TestCase):\n"
                          " def test_fixture(self):\n"
                          "  path=Path(" + repr(str(fixture)) + ")\n"
                          "  self.assertEqual(path.read_bytes(), b'original')\n"
                          "  path.write_bytes(b'changed')\n")
                self.project(root, {"test_contracts.py": source})
                fixture.parent.mkdir(parents=True, exist_ok=True)
                fixture.write_bytes(b'original')
                documents = []
                original = verification._command_check
                def record(_root, name, command, *args, **kwargs):
                    result = original(_root, name, command, *args, **kwargs)
                    documents.append(json.loads(Path(command[command.index('--report') + 1]).read_text()))
                    return result
                with patch.object(verification, '_command_check', side_effect=record):
                    result = verification._factory_unit(root)[0]
                self.assertEqual(result.status, 'fail', result)
                self.assertFalse(documents[0]['source_stable'])

    def test_all_regular_fixture_inputs_are_bound_and_generated_caches_excluded(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            self.project(root, {"test_contracts.py": PASS})
            for relative in ('fixtures/success.jsonl', 'fixtures/pixels.bin', 'fixtures/readme.txt',
                             '__pycache__/generated.bin', '.pytest_cache/generated.bin', 'loose.pyc'):
                fixture = root / 'factory/tests' / relative
                fixture.parent.mkdir(parents=True, exist_ok=True)
                fixture.write_bytes(b'fixture bytes')
            result = verification._factory_unit(root)[0]
            self.assertEqual(result.status, 'pass', result)
            inventory = result.details[0]['binding']['source_inventory']
            for relative in ('fixtures/success.jsonl', 'fixtures/pixels.bin', 'fixtures/readme.txt'):
                self.assertIn('factory/tests/' + relative, inventory)
            self.assertFalse(any('__pycache__' in name or '.pytest_cache' in name or name.endswith('.pyc')
                                 for name in inventory))

    def test_declared_case_parser_rejects_a_linked_candidate_root(self):
        with tempfile.TemporaryDirectory() as raw:
            private = Path(raw).resolve()
            root = private / 'candidate'
            self.project(root, {"test_contracts.py": PASS})
            alias = private / 'alias'
            try:
                alias.symlink_to(root, target_is_directory=True)
            except OSError as exc:
                self.skipTest('directory links unavailable: ' + str(exc))
            with self.assertRaises(ValueError):
                factory_tests.declared_ids(alias)

    def test_equal_bytes_do_not_hide_replaced_source_directory_identity(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            self.project(root, {"test_contracts.py": PASS})
            original = verification._command_check
            def replace(*args, **kwargs):
                result = original(*args, **kwargs)
                source = root / 'factory/tests'
                retired = root / 'retired-tests'
                source.rename(retired)
                shutil.copytree(retired, source)
                return result
            with patch.object(verification, '_command_check', side_effect=replace):
                result = verification._factory_unit(root)[0]
            self.assertEqual(result.status, 'fail', result)

    def test_oversized_binary_fixture_refuses_before_test_import(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            sentinel = root / 'imported'
            source = "from pathlib import Path\nPath(" + repr(str(sentinel)) + ").touch()\n" + PASS
            self.project(root, {"test_contracts.py": source})
            with (root / 'factory/tests/oversized.bin').open('wb') as stream:
                stream.truncate(factory_tests.MAX_INPUT_BYTES + 1)
            result = verification._factory_unit(root)[0]
            self.assertEqual(result.status, 'fail', result)
            self.assertFalse(sentinel.exists())
            self.assertIn('size limit', result.summary)

    def _assert_source_wins_over_bytecode(self, mode):
        with tempfile.TemporaryDirectory() as raw, patch.dict(os.environ, {'PYTHONPYCACHEPREFIX': ''}):
            root = Path(raw).resolve()
            failing = "import unittest\nclass Probe(unittest.TestCase):\n def test_probe(self): self.fail('bound failing source ran')\n"
            size = max(len(PASS), len(failing))
            passing = PASS.rstrip('\n').ljust(size) + '\n'
            failing = failing.rstrip('\n').ljust(size) + '\n'
            self.assertEqual(len(passing), len(failing))
            self.project(root, {'test_contracts.py': passing})
            source = root / 'factory/tests/test_contracts.py'
            original = source.stat()
            with patch.object(sys, 'pycache_prefix', None):
                cache = Path(importlib.util.cache_from_source(str(source)))
            cache.parent.mkdir(parents=True, exist_ok=True)
            py_compile.compile(str(source), cfile=str(cache), doraise=True, invalidation_mode=mode)
            retained_cache = cache.read_bytes()
            positive = verification._factory_unit(root)[0]
            self.assertEqual(positive.status, 'pass', positive)
            self.assertEqual(cache.read_bytes(), retained_cache)
            source.write_text(failing)
            os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
            result = verification._factory_unit(root)[0]
            self.assertEqual(cache.read_bytes(), retained_cache, 'existing candidate cache must stay untouched')
            self.assertEqual(result.status, 'fail', result)
            self.assertIn('bound failing source ran', result.stderr)
            self.assertTrue(result.details[0]['source_stable'])
            self.assertEqual(result.details[0]['failures'], 1)

    def test_timestamp_valid_cache_cannot_replace_bound_failing_source(self):
        self._assert_source_wins_over_bytecode(py_compile.PycInvalidationMode.TIMESTAMP)

    def test_unchecked_hash_cache_cannot_replace_bound_failing_source(self):
        self._assert_source_wins_over_bytecode(py_compile.PycInvalidationMode.UNCHECKED_HASH)

    def test_factory_child_uses_fresh_private_cache_without_touching_ambient_cache(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            self.project(root, {'test_contracts.py': PASS})
            ambient = root / 'ambient-cache'
            ambient.mkdir()
            sentinel = ambient / 'retained.bin'
            sentinel.write_bytes(b'pre-existing cache bytes')
            observed = []
            original = verification._command_check
            def record(*args, **kwargs):
                environment = kwargs['env']
                self.assertIn('PYTHONPYCACHEPREFIX', environment)
                cache = Path(environment['PYTHONPYCACHEPREFIX'])
                self.assertNotEqual(cache, ambient)
                self.assertTrue(cache.is_dir())
                self.assertEqual(list(cache.iterdir()), [])
                if os.name == 'posix':
                    self.assertEqual(cache.stat().st_mode & 0o777, 0o700)
                observed.append(cache)
                return original(*args, **kwargs)
            with patch.dict(os.environ, {'PYTHONPYCACHEPREFIX': str(ambient)}), \
                    patch.object(verification, '_command_check', side_effect=record):
                result = verification._factory_unit(root)[0]
            self.assertEqual(result.status, 'pass', result)
            self.assertEqual(len(observed), 1)
            self.assertFalse(observed[0].exists(), 'only the owned cache namespace must be cleaned')
            self.assertEqual(sentinel.read_bytes(), b'pre-existing cache bytes')

    def test_spawned_python_uses_the_same_candidate_package(self):
        source = (
            "import subprocess,sys,unittest\n"
            "class Probe(unittest.TestCase):\n"
            " def test_child(self):\n"
            "  subprocess.run([sys.executable,'-c','import candidate_probe; assert candidate_probe.VALUE == 7'],check=True)\n"
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            self.project(root, {"test_child.py": source})
            package = root / "factory/src"
            package.mkdir(parents=True)
            (package / "candidate_probe.py").write_text("VALUE = 7\n")
            result = verification._factory_unit(root)
            self.assertEqual(result[0].status, "pass", result[0])


if __name__ == "__main__":
    unittest.main()

class Low336FixtureOwnerTests(unittest.TestCase):
    def report(self, owner, phase):
        ids = ['factory.tests.test_public.Probe.test_one', 'factory.tests.test_public.Probe.test_two']
        binding = {'declared_ids': ids, 'context': {}, 'source_inventory': {'factory/tests/test_public.py': 'a' * 64}}
        return {'schema_version': 3, 'check_id': 'factory-unit', 'status': 'fail', 'binding': binding,
            'collected': 2, 'collected_ids': ids, 'expected_ids': ids, 'required_ids': ids,
            'tests_run': 0, 'started': [], 'executed': [], 'failures': 0, 'errors': 1, 'loader_errors': 0,
            'skipped': [], 'unqualified_skips': [], 'missing_required': ids, 'source_stable': True,
            'database_obligations': 'not_run_in_unit_mode',
            'problems': [{'id': owner, 'phase': phase, 'kind': 'error', 'exception': 'RuntimeError', 'frames': []}]}

    def test_failed_report_binds_exact_class_and_module_not_package_prefix(self):
        for phase in ('setUpClass', 'tearDownClass', 'setUpModule', 'tearDownModule'):
            good = 'factory.tests.test_public' + ('.Probe' if phase.endswith('Class') else '')
            report = self.report(good, phase)
            factory_tests.validate_report(report, report['binding'])
            for bad in ('factory', 'factory.tests', good + '.extra',
                        'factory.tests.test_public' if phase.endswith('Class') else 'factory.tests.test_public.Probe'):
                with self.subTest(phase=phase, owner=bad):
                    value = self.report(bad, phase)
                    with self.assertRaises(ValueError):
                        factory_tests.validate_report(value, value['binding'])
