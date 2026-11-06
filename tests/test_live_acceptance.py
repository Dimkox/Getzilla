"""Public acceptance evidence and observer controls; no real Docker in unit cases."""

from __future__ import annotations
import hashlib
import importlib
import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))


class ComponentAdmissionTests(unittest.TestCase):
    def module(self):
        self.assertIsNotNone(
            importlib.util.find_spec("getzilla.live_acceptance"), "two isolated PostgreSQL cell observer must exist"
        )
        return importlib.import_module("getzilla.live_acceptance")

    def factory(self, root):
        from getzilla.factory_tests import source_census
        tests = root / "factory/tests"
        tests.mkdir(parents=True)
        (tests / "test_postgres_integration.py").write_text(
            "class FreshClusterArtifactAttestorMigrationTests:\n def test_fresh(self): pass\n"
            "class ApiTests:\n def test_runtime(self): pass\n")
        (tests / "test_other.py").write_text("class PublicOther:\n def test_other(self): pass\n")
        (tests / "test_landing_pdf_worker.py").write_text(
            "class PdfWorkerWithoutParser:\n def test_worker_executes_and_reports_parser_unavailable(self): pass\n")
        census = source_census(root)
        ids = census["declared_ids"]
        suite = {"schema_version": 2, "check_id": "factory-postgres-exit", "status": "pass", "census": census,
                 "collected_ids": ids, "started": ids, "tests_run": len(ids), "executed": ids,
                 "failures": 0, "errors": 0, "skipped": [], "loader_errors": 0, "source_stable": True}
        restart = {
            "status": "pass",
            "restarts": [
                {"before": "2026-01-01T00:00:00", "after": "2026-01-01T00:00:01"},
                {"before": "2026-01-01T00:00:01", "after": "2026-01-01T00:00:02"},
            ],
        }
        (root / "factory-suite.json").write_text(json.dumps(suite))
        (root / "factory-restart.json").write_text(json.dumps(restart))
        return suite, restart

    def test_factory_requires_counted_real_database_and_two_restarts(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            suite, restart = self.factory(root)
            self.assertTrue(module.validate_components(root, "factory", source_root=root))
            for change in ("missing", "skip", "zero", "partial", "duplicate", "restart"):
                with self.subTest(change=change):
                    s = json.loads(json.dumps(suite))
                    r = json.loads(json.dumps(restart))
                    if change == "missing":
                        s["executed"] = ["public.other"]
                        s["tests_run"] = 1
                    elif change == "skip":
                        s["skipped"] = [{"id": s["executed"][0], "reason": "required DB fixture missing"}]
                    elif change == "zero":
                        s["tests_run"] = 0
                    elif change == "partial":
                        s["tests_run"] = len(suite["executed"]) + 1
                    elif change == "duplicate":
                        s["executed"][1] = s["executed"][0]
                    else:
                        r["restarts"][1]["after"] = r["restarts"][1]["before"]
                    (root / "factory-suite.json").write_text(json.dumps(s))
                    (root / "factory-restart.json").write_text(json.dumps(r))
                    self.assertFalse(module.validate_components(root, "factory", source_root=root))

    def test_factory_conditional_skip_keeps_a_complete_disjoint_census(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            suite, _restart = self.factory(root)
            skipped = {
                "id": "factory.tests.test_landing_pdf_worker.PdfWorkerWithoutParser.test_worker_executes_and_reports_parser_unavailable",
                "reason": "pypdf present; unavailable branch cannot run",
            }
            suite["executed"] = [name for name in suite["executed"] if name != skipped["id"]]
            suite["skipped"] = [skipped]
            (root / "factory-suite.json").write_text(json.dumps(suite))
            self.assertTrue(module.validate_components(root, "factory", source_root=root))
            for change in ("duplicate", "overlap", "partial", "required", "unknown"):
                changed = json.loads(json.dumps(suite))
                if change == "duplicate":
                    changed["skipped"].append(skipped)
                    changed["tests_run"] = suite["tests_run"] + 1
                elif change == "overlap":
                    changed["executed"].append(skipped["id"])
                    changed["tests_run"] = suite["tests_run"] + 1
                elif change == "partial":
                    changed["tests_run"] = suite["tests_run"] + 1
                elif change == "required":
                    changed["skipped"][0]["id"] = "factory.tests.test_postgres_integration.Required.test_database"
                else:
                    changed["skipped"][0]["id"] = "factory.tests.public_unknown.test_skipped"
                with self.subTest(change=change):
                    (root / "factory-suite.json").write_text(json.dumps(changed))
                    self.assertFalse(module.validate_components(root, "factory", source_root=root))

    def test_trust_ci_requires_complete_ten_and_restart_identity(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            suite = {
                "status": "pass",
                "tests_run": 10,
                "executed": ["test_postgres_integration.PublicDb.test_" + str(i) for i in range(10)],
                "failures": 0,
                "errors": 0,
                "skipped": 0,
            }
            restart = {
                "status": "pass",
                "postmaster_before": "before",
                "postmaster_after": "after",
                "cluster_identity_preserved": True,
                "seed_verified": True,
            }
            for change in ("valid", "partial", "skip", "restart"):
                s = json.loads(json.dumps(suite))
                r = json.loads(json.dumps(restart))
                if change == "partial":
                    s["tests_run"] = 1
                    s["executed"] = s["executed"][:1]
                elif change == "skip":
                    s["skipped"] = 1
                elif change == "restart":
                    r["postmaster_after"] = r["postmaster_before"]
                (root / "trust-ci-suite.json").write_text(json.dumps(s))
                (root / "trust-ci-restart.json").write_text(json.dumps(r))
                self.assertEqual(module.validate_components(root, "trust-ci"), change == "valid")

    def test_unknown_or_missing_evidence_never_passes(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.assertFalse(module.validate_components(root, "factory"))
            self.assertFalse(module.validate_components(root, "trust-ci"))
            self.assertFalse(module.validate_components(root, "lifecycle"))


class ObserverControls(unittest.TestCase):
    def module(self):
        self.assertIsNotNone(
            importlib.util.find_spec("getzilla.live_acceptance"), "bounded PostgreSQL observer must exist"
        )
        return importlib.import_module("getzilla.live_acceptance")

    @unittest.skipUnless(sys.platform == "linux", "actual POSIX process session control")
    def test_missing_journal_blocks_even_when_child_exits_zero(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            result = module.observe(
                [sys.executable, "-c", "pass"],
                root=root,
                environment={},
                output=root,
                timeout=2,
                grace=1,
                namespace="gz-public",
                require_resources=True,
            )
            self.assertEqual(result["primary_outcome"], "passed")
            self.assertEqual(result["cleanup_outcome"], "unknown")
            self.assertEqual(result["status"], "fail")
            self.assertTrue(result["child_exit_confirmed"])

    @unittest.skipUnless(sys.platform == "linux", "actual POSIX process session control")
    def test_timeout_keeps_primary_and_reaps_after_cleanup_ack(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = "import signal,time,pathlib\ndef stop(*args):\n pathlib.Path('ack').write_text('done')\n raise SystemExit(130)\nsignal.signal(signal.SIGTERM,stop)\nwhile True:time.sleep(.01)\n"
            result = module.observe(
                [sys.executable, "-c", source], root=root, environment={}, output=root, timeout=0.25, grace=1
            )
            self.assertEqual(result["primary_outcome"], "timed_out")
            self.assertEqual((root / "ack").read_text(), "done")
            self.assertEqual(result["child_returncode"], 130)
            self.assertTrue(result["child_exit_confirmed"])

    def test_failed_subcommand_never_echoes_captured_output(self):
        module = self.module()
        command = ["docker", "exec", "public-argument-sentinel"]
        result = subprocess.CompletedProcess(command, 19, "public-output-sentinel", "public-error-sentinel")
        output = io.StringIO()
        with (
            patch.object(module.subprocess, "run", return_value=result),
            redirect_stderr(output),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            module._run(command)
        self.assertNotIn("sentinel", output.getvalue())

    def test_expired_main_budget_does_not_prepare_images(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with (
                patch.object(module, "_git", return_value="a" * 40),
                patch.object(module, "ensure_images") as prepare,
                self.assertRaises(ValueError),
            ):
                module.main(
                    [
                        "--cell",
                        "factory",
                        "--root",
                        str(root),
                        "--output",
                        str(root / "observations"),
                        "--timeout-seconds",
                        "0",
                    ]
                )
            prepare.assert_not_called()


class PublicWorkflowControls(unittest.TestCase):
    def test_counted_trust_ci_driver_is_a_separate_public_acceptance_harness(self):
        driver = ROOT / 'scripts/getzilla_trust_ci_postgres_suite.py'
        self.assertTrue(driver.is_file(), 'public acceptance orchestration belongs outside trust-ci product source')
        result = subprocess.run([sys.executable, '-B', str(driver), '--help'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--tests', result.stdout)

    def test_two_pg_cells_join_required_linux_without_replacing_native_jobs(self):
        import yaml

        document = yaml.safe_load((ROOT / ".github/workflows/getzilla.yml").read_text())
        jobs = document["jobs"]
        self.assertIn("postgres-acceptance", jobs)
        self.assertEqual(
            {v["cell"] for v in jobs["postgres-acceptance"]["strategy"]["matrix"]["include"]}, {"factory", "trust-ci"}
        )
        self.assertEqual(set(jobs["linux"]["needs"]), {"platform-install-results", "postgres-acceptance"})
        self.assertEqual(jobs["linux"]["if"], "always()")
        self.assertIn("windows", jobs)
        self.assertIn("macos", jobs)
        self.assertEqual(document["permissions"], {"contents": "read"})
        steps = jobs["postgres-acceptance"]["steps"]
        self.assertTrue(any("getzilla_live.py" in step.get("run", "") for step in steps))
        self.assertTrue(any("--live-source" in step.get("run", "") and step.get("if") == "always() && steps.source_checkout.outcome == 'success'" for step in steps))
        self.assertNotIn("workflow_dispatch", document.get("on", {}))

    def exporter(self):
        from getzilla import ci_evidence

        self.assertTrue(
            hasattr(ci_evidence, "export_live_evidence"), "bounded live observations must use the existing CI exporter"
        )
        return ci_evidence.export_live_evidence

    def manifest(self, root):
        data = b"public synthetic failure observation\n"
        (root / "observer.json").write_bytes(data)
        (root / "unrelated.txt").write_text("public data not selected for export")
        manifest = {
            "schema": "getzilla-live-acceptance-v1",
            "cell": "factory",
            "source": {"head": "a" * 40, "tree": "b" * 40},
            "run_id": "public-synthetic",
            "attempt": "1",
            "status": "fail",
            "files": [{"path": "observer.json", "sha256": hashlib.sha256(data).hexdigest()}],
        }
        (root / "manifest.json").write_text(json.dumps(manifest))
        return manifest

    def test_export_only_exact_hash_bound_public_observations(self):
        export = self.exporter()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.manifest(root)
            export(root, root / "export")
            self.assertEqual({p.name for p in (root / "export").iterdir()}, {"manifest.json", "observer.json"})
            self.assertEqual((root / "export/observer.json").read_bytes(), (root / "observer.json").read_bytes())

    def test_export_refuses_tampering_duplicates_and_unselected_paths_before_publication(self):
        export = self.exporter()
        for failure in ("tampered", "duplicate", "unselected", "traversal"):
            with tempfile.TemporaryDirectory() as raw, self.subTest(failure=failure):
                root = Path(raw)
                manifest = self.manifest(root)
                if failure == "tampered":
                    (root / "observer.json").write_text("different public bytes")
                elif failure == "duplicate":
                    manifest["files"] *= 2
                elif failure == "unselected":
                    manifest["files"][0]["path"] = "unrelated.txt"
                else:
                    manifest["files"][0]["path"] = "../public-other.txt"
                (root / "manifest.json").write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    export(root, root / "export")
                self.assertFalse((root / "export").exists())

class AcceptedPrefixBridgeControls(unittest.TestCase):
    def workflow(self):
        import yaml
        return yaml.safe_load((ROOT / '.github/workflows/getzilla.yml').read_text())

    def test_native_linux_body_and_checkout_guards_survive_postgres_join(self):
        jobs = self.workflow()['jobs']
        self.assertNotIn('linux-core', jobs)
        self.assertTrue({'platform-plan', 'platform-install', 'platform-install-results'} <= set(jobs))
        linux = jobs['linux']
        self.assertEqual(set(linux['needs']), {'platform-install-results', 'postgres-acceptance'})
        self.assertEqual(linux['if'], 'always()')
        self.assertTrue(any(step.get('name') == 'Require every supported native installer cell'
                            for step in linux['steps']))
        checkout = next(step for step in linux['steps'] if step.get('uses', '').startswith('actions/checkout@'))
        self.assertEqual((checkout['id'], checkout['if']), ('source_checkout', 'always()'))
        pg = jobs['postgres-acceptance']
        self.assertEqual({row['cell'] for row in pg['strategy']['matrix']['include']}, {'factory', 'trust-ci'})
        source = next(step for step in pg['steps'] if step.get('uses', '').startswith('actions/checkout@'))
        self.assertEqual((source['id'], source['if']), ('source_checkout', 'always()'))
        exports = [step for step in pg['steps'] if '--live-source' in step.get('run', '')
                   or step.get('uses', '').startswith('actions/upload-artifact@')]
        self.assertEqual(len(exports), 2)
        self.assertTrue(all(step['if'] == "always() && steps.source_checkout.outcome == 'success'" for step in exports))

    @unittest.skipUnless(shutil.which('bash'), 'fixed POSIX workflow guard requires bash')
    def test_postgres_result_guard_refuses_missing_failed_cancelled_and_skipped(self):
        steps = self.workflow()['jobs']['linux']['steps']
        guards = [step for step in steps if step.get('name') == 'Require both isolated PostgreSQL cells']
        self.assertEqual(len(guards), 1)
        command = guards[0]['run']
        self.assertEqual(command, 'test "$GETZILLA_POSTGRES_RESULT" = success')
        for value in ('success', 'failure', 'cancelled', 'skipped', ''):
            with self.subTest(result=value):
                result = subprocess.run([shutil.which('bash'), '--noprofile', '--norc', '-c', command],
                                        env={'GETZILLA_POSTGRES_RESULT': value}, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0 if value == 'success' else 1)

    def test_accepted_recorded_result_default_constructor_preserves_actual_events(self):
        # Inert unittest events only: no Factory/PG execution or component PASS.
        from getzilla.factory_tests import RecordedResult

        class PublicFixture(unittest.TestCase):
            def test_pass(self):
                self.assertEqual(2 + 2, 4)

            @unittest.skip('public fixture skip')
            def test_skip(self):
                pass

            def test_failure(self):
                self.fail('public fixed fixture failure')

        cases = [PublicFixture(name) for name in ('test_pass', 'test_skip', 'test_failure')]
        expected = [case.id() for case in cases]
        result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0, resultclass=RecordedResult).run(
            unittest.TestSuite(cases))
        self.assertIsInstance(result, RecordedResult)
        self.assertEqual(result.testsRun, 3)
        self.assertEqual(result.started, expected)
        self.assertEqual(result.executed, [expected[0], expected[2]])
        self.assertEqual((len(result.failures), len(result.errors), len(result.skipped)), (1, 0, 1))
        self.assertFalse(result.wasSuccessful())

class SourceCensusControls(unittest.TestCase):
    def fixture(self):
        from getzilla import factory_tests
        self.assertTrue(hasattr(factory_tests, 'source_census'), 'pure checked-source census must exist')
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        tests = root / 'factory/tests'
        tests.mkdir(parents=True)
        (tests / 'test_postgres_integration.py').write_text(
            'class FreshClusterArtifactAttestorMigrationTests:\n def test_public_fresh(self): pass\n'
            'class PublicApi:\n def test_public_api(self): pass\n')
        (tests / 'test_other.py').write_text('class PublicOther:\n def test_one(self): pass\n def test_two(self): pass\n')
        return root, factory_tests.source_census(root)

    def report(self, census):
        ids = census['declared_ids']
        return {'schema_version': 2, 'check_id': 'factory-postgres-exit', 'status': 'pass',
                'census': census, 'collected_ids': list(ids), 'started': list(ids), 'executed': list(ids),
                'skipped': [], 'tests_run': len(ids), 'failures': 0, 'errors': 0,
                'loader_errors': 0, 'source_stable': True}

    def test_census_is_pure_checked_and_consumer_derives_its_own_expected_set(self):
        from getzilla import factory_tests, live_acceptance
        root, census = self.fixture()
        with patch.object(factory_tests, 'observed_context', side_effect=AssertionError('no runtime probes')):
            self.assertEqual(factory_tests.source_census(root), census)
        self.assertEqual(set(census), {'source_inventory', 'source_bindings', 'declared_ids'})
        output = root / 'output'
        output.mkdir()
        (output / 'factory-restart.json').write_text(json.dumps({'status': 'pass', 'restarts': [
            {'before': 1, 'after': 2}, {'before': 2, 'after': 3}]}))
        full = self.report(census)
        suite = output / 'factory-suite.json'
        suite.write_text(json.dumps(full))
        self.assertTrue(live_acceptance.validate_components(output, 'factory', source_root=root))
        partial = json.loads(json.dumps(full))
        selected = [x for x in census['declared_ids'] if 'test_postgres_integration.' in x]
        partial.update(collected_ids=selected, started=selected, executed=selected, tests_run=len(selected))
        partial['census']['declared_ids'] = selected
        suite.write_text(json.dumps(partial))
        self.assertFalse(live_acceptance.validate_components(output, 'factory', source_root=root))
        self.assertFalse(live_acceptance.validate_components(output, 'factory'))

    def test_closed_sets_types_skips_and_changed_source_refuse(self):
        from getzilla import live_acceptance
        root, census = self.fixture()
        valid = self.report(census)
        for change in ('missing', 'extra', 'duplicate', 'boolean', 'loader', 'unstable', 'skip', 'unknown'):
            candidate = json.loads(json.dumps(valid))
            if change == 'missing':
                candidate['executed'].pop()
                candidate['started'].pop()
                candidate['collected_ids'].pop()
                candidate['tests_run'] -= 1
            elif change == 'extra':
                candidate['executed'].append('public.extra')
            elif change == 'duplicate':
                candidate['started'].append(candidate['started'][0])
            elif change == 'boolean':
                candidate['errors'] = False
            elif change == 'loader':
                candidate['loader_errors'] = 1
            elif change == 'unstable':
                candidate['source_stable'] = False
            elif change == 'skip':
                name = candidate['executed'].pop()
                candidate['skipped'] = [{'id': name, 'reason': 'not available'}]
            else:
                candidate['extra'] = 'unknown'
            with self.subTest(change=change):
                self.assertEqual(live_acceptance.factory_suite_status(candidate, census), 'fail')
        original = root / 'factory/tests/test_other.py'
        original.write_text(original.read_text() + '\n# current source changed\n')
        from getzilla import factory_tests
        self.assertFalse(factory_tests.source_matches(root, census))

    def test_producer_refuses_incomplete_collection_without_running_cases(self):
        from getzilla import live_acceptance
        root, census = self.fixture()
        spec = importlib.util.spec_from_file_location('public_live_producer', ROOT / 'factory/tests/run_live_suite.py')
        producer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(producer)
        output = root / 'output'
        output.mkdir()
        with patch.object(producer, 'ROOT', root), \
                patch.dict('os.environ', {'FACTORY_TEST_DATABASE_URL': 'public-fixture-not-a-DSN',
                                         'FACTORY_FRESH_CLUSTER_DATABASE_URL': 'public-fixture-not-a-DSN',
                                         'GETZILLA_LIVE_ARTIFACTS': str(output)}), \
                patch.object(producer.unittest.TestLoader, 'discover', return_value=unittest.TestSuite()), \
                patch.object(producer.unittest.TextTestRunner, 'run', side_effect=AssertionError('partial suite must not run')):
            self.assertNotEqual(producer.main(), 0)
        result = json.loads((output / 'factory-suite.json').read_text())
        self.assertEqual(live_acceptance.factory_suite_status(result, census), 'fail')



    def test_closed_scalar_and_list_types_and_duplicate_json_refuse(self):
        from getzilla import live_acceptance
        root, census = self.fixture()
        valid = self.report(census)
        for field, value in (("schema_version", True), ("tests_run", True), ("tests_run", -1),
                             ("executed", [None]), ("started", [["public"]]), ("skipped", [None]),
                             ("census", None), ("status", "unknown"), ("source_stable", 1)):
            candidate = json.loads(json.dumps(valid))
            candidate[field] = value
            with self.subTest(field=field, kind=type(value).__name__):
                self.assertEqual(live_acceptance.factory_suite_status(candidate, census), "fail")
        output = root / "output"
        output.mkdir()
        for raw in ('{"status":"fail","status":"pass"}', "[]", "null"):
            (output / "factory-suite.json").write_text(raw)
            self.assertFalse(live_acceptance.validate_components(output, "factory", source_root=root))

    def test_producer_complete_inert_result_and_discovery_rejections(self):
        from getzilla import factory_tests, live_acceptance
        from types import SimpleNamespace
        for change in ("complete", "missing", "extra", "duplicate", "loader", "changed", "failed", "expected_failure"):
            with self.subTest(change=change):
                root, census = self.fixture()
                spec = importlib.util.spec_from_file_location("public_live_producer", ROOT / "factory/tests/run_live_suite.py")
                producer = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(producer)
                ids = list(census["declared_ids"])
                if change == "missing":
                    ids.pop()
                elif change == "extra":
                    ids.append("public.extra")
                elif change == "duplicate":
                    ids.append(ids[0])
                suite = [SimpleNamespace(id=lambda name=name: name) for name in ids]
                loader = SimpleNamespace(discover=lambda *args, **kwargs: suite,
                                         errors=["public loader failure"] if change == "loader" else [])
                if change == "changed":
                    original = root / "factory/tests/test_other.py"
                    before = original.read_bytes()
                    def changed(*args, **kwargs):
                        original.write_bytes(before + b"\n# changed\n")
                        original.write_bytes(before)
                        return suite
                    loader.discover = changed
                result = SimpleNamespace(testsRun=len(ids), started=ids, executed=ids, skipped=[],
                    failures=[None] if change == "failed" else [], errors=[], unexpectedSuccesses=[],
                    expectedFailures=[None] if change == "expected_failure" else [])
                output = root / "output"
                output.mkdir()
                with patch.object(producer, "ROOT", root), \
                        patch.dict("os.environ", {"FACTORY_TEST_DATABASE_URL": "public-fixture-not-a-DSN",
                            "FACTORY_FRESH_CLUSTER_DATABASE_URL": "public-fixture-not-a-DSN",
                            "GETZILLA_LIVE_ARTIFACTS": str(output)}), \
                        patch.object(producer.unittest, "TestLoader", return_value=loader), \
                        patch.object(producer.unittest.TextTestRunner, "run", return_value=result) as run:
                    status = producer.main()
                should_run = change in ("complete", "failed", "expected_failure")
                self.assertEqual(run.call_count, int(should_run))
                self.assertEqual(status == 0, change == "complete")
                document = json.loads((output / "factory-suite.json").read_text())
                self.assertEqual(live_acceptance.factory_suite_status(document, census),
                                 "pass" if change == "complete" else "fail")
                self.assertEqual(factory_tests.source_census(root)["declared_ids"], census["declared_ids"])
