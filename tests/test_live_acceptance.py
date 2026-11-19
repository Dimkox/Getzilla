"""Owned synthetic producer/consumer controls. No live acceptance is claimed."""
from __future__ import annotations

import importlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / '.getzilla'), str(ROOT)]


class LiveSourceTests(unittest.TestCase):
    def setUp(self):
        for target in ('subprocess.Popen', 'socket.socket', 'socket.create_connection'):
            self.enterContext(patch(target, side_effect=AssertionError('unmocked transport forbidden')))

    def module(self):
        self.assertIsNotNone(importlib.util.find_spec('getzilla.live_acceptance'), 'live producer contract missing')
        return importlib.import_module('getzilla.live_acceptance')

    def binding(self):
        return {'head': 'a'*40, 'tree': 'b'*40, 'run_id': 'owned-test', 'attempt': '1',
                'cell': 'factory', 'namespace': 'gz-owned-test', 'nonce': 'c'*32,
                'producer_sha256': 'd'*64}

    def suite(self, skipped=False):
        class OwnedCase(unittest.TestCase):
            def test_owned(self):
                if skipped:
                    self.skipTest('required database absent')
        return unittest.defaultTestLoader.loadTestsFromTestCase(OwnedCase)

    def produce(self, module, skipped=False):
        suite = self.suite(skipped)
        ids = [case.id() for case in suite]
        return module.record_suite(suite, expected_ids=ids, required_ids=ids,
                                   loader_errors=(), binding=self.binding(), source_stable=lambda: True,
                                   stream=io.StringIO())

    def test_real_recorder_producer_consumes_complete_actual_identities(self):
        module = self.module()
        document = self.produce(module)
        self.assertTrue(module.accepted_suite(document, self.binding()))
        self.assertEqual(document['tests_run'], len(document['started']))
        self.assertEqual(document['started'], document['executed'])

    def test_factory_wrapper_reuses_recorder_without_unit_database_scrubbing(self):
        self.assertIsNotNone(importlib.util.find_spec('factory.tests.run_live_suite'), 'Factory live producer missing')
        from factory.tests import run_live_suite
        module = self.module()
        with patch.dict('os.environ', {'FACTORY_TEST_DATABASE_URL': 'owned-required-database'}):
            suite = self.suite()
            ids = [case.id() for case in suite]
            document = run_live_suite.produce(suite, expected_ids=ids, required_ids=ids, binding=self.binding(),
                source_stable=lambda: True, loader_errors=(), stream=io.StringIO())
            import os
            self.assertEqual(os.environ['FACTORY_TEST_DATABASE_URL'], 'owned-required-database')
        self.assertTrue(module.accepted_suite(document, self.binding()))

    def test_actual_skipped_required_case_refuses(self):
        module = self.module()
        document = self.produce(module, skipped=True)
        self.assertEqual(document['tests_run'], 1)
        self.assertEqual(document['executed'], [])
        self.assertFalse(module.accepted_suite(document, self.binding()))

    def test_missing_discovery_loader_error_and_source_mutation_refuse(self):
        module = self.module()
        for field, value in (('expected_ids', ['missing.case']), ('loader_errors', ['loader']),
                             ('source_stable', False), ('started', []), ('executed', [])):
            document = self.produce(module)
            document[field] = value
            self.assertFalse(module.accepted_suite(document, self.binding()), field)

    def test_wrong_source_attempt_namespace_nonce_and_producer_refuse(self):
        module = self.module()
        document = self.produce(module)
        for field in self.binding():
            foreign = dict(self.binding(), **{field: 'foreign'})
            self.assertFalse(module.accepted_suite(document, foreign), field)

    def test_boolean_or_untyped_counts_cannot_claim_complete_suite(self):
        module = self.module()
        for field, value in (('failures',False), ('errors',False), ('loader_errors',[])):
            document = self.produce(module)
            document[field] = value
            self.assertFalse(module.accepted_suite(document,self.binding()), field)

    def test_restart_producer_checks_actual_cluster_job_and_changed_postmaster(self):
        module = self.module()
        before = {'postmaster': '2026-11-01T00:00:00+00:00', 'cluster': '123'}
        after = {'postmaster': '2026-11-01T00:00:01+00:00', 'cluster': '123'}
        row = module.restart_observation(before, after, 'job1', 'job1')
        self.assertEqual(row['cluster'], '123')
        for changed, verified in ((before, 'job1'), (dict(after, cluster='foreign'), 'job1'), (after, 'job2')):
            with self.assertRaises(ValueError):
                module.restart_observation(before, changed, 'job1', verified)

    def test_held_reader_refuses_links_and_duplicate_keys(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / 'owned.json'
            path.write_text('{"status":1,"status":2}')
            with self.assertRaises(ValueError):
                module.read_document(path)
            path.unlink()
            path.symlink_to(Path(raw) / 'absent')
            with self.assertRaises((ValueError, OSError)):
                module.read_document(path)

    def test_native_observer_keeps_failure_and_refuses_unknown_cleanup(self):
        module = self.module()
        from getzilla.python_test_runner import ProcessResult, CleanupMetadata
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw)
            native = ProcessResult(['owned'], 124, stdout='postgresql://user:public-test-sentinel@owned/db', terminal_state='timeout')
            self.assertTrue(callable(getattr(module, 'observe', None)), 'native observer missing')
            with patch.object(module, 'execute', return_value=native) as execute:
                result = module.observe(['owned'], root=output, environment={}, output=output, timeout=1, require_resources=True)
            self.assertEqual(execute.call_args.kwargs, {'timeout': 1})
            self.assertEqual(result['primary_outcome'], 'timed_out')
            self.assertEqual(result['status'], 'fail')
            self.assertEqual(result['cleanup_outcome'], 'unknown')
            self.assertNotIn('public-test-sentinel', (output/'command.log').read_text())
            self.assertEqual(len(result['raw_log_sha256']), 64)

    def test_native_typed_cleanup_uncertainty_refuses_even_zero_exit(self):
        module = self.module()
        from getzilla.python_test_runner import ProcessResult, CleanupMetadata
        self.assertTrue(callable(getattr(module, 'observe', None)), 'native observer missing')
        for metadata in (CleanupMetadata(unavailable=True), CleanupMetadata(overflow=True)):
            with tempfile.TemporaryDirectory() as raw:
                native = ProcessResult(['owned'], 0, cleanup_metadata=metadata)
                with patch.object(module, 'execute', return_value=native):
                    result = module.observe(['owned'], root=Path(raw), environment={}, output=Path(raw), timeout=1)
                self.assertEqual(result['status'], 'fail')

    def test_binding_envelope_uses_actual_report_and_journal_bytes(self):
        module = self.module()
        self.assertTrue(callable(getattr(module, 'seal_component', None)), 'component envelope missing')
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw)
            report = self.produce(module)
            module._write(output/'factory-suite.json', report)
            module._write(output/'factory-resources.json', {'owned': 'synthetic parser control only'})
            module.seal_component(output, 'factory-suite.json', 'factory-resources.json', self.binding())
            self.assertEqual(module.read_component(output, 'factory-suite.json', self.binding()), report)
            (output/'factory-resources.json').write_text('{}')
            with self.assertRaises(ValueError):
                module.read_component(output, 'factory-suite.json', self.binding())

    def test_actual_owned_cleanup_producer_and_observer_require_bound_ack(self):
        module = self.module()
        self.assertTrue(callable(getattr(module, 'acknowledge_cleanup', None)), 'cleanup acknowledgement producer missing')
        from getzilla import disposable_resources as resources
        from getzilla.python_test_runner import ProcessResult
        from tests.test_isolated_resources import DockerDouble
        for acknowledged in (True, False):
            with self.subTest(acknowledged=acknowledged), tempfile.TemporaryDirectory() as raw:
                output = Path(raw)
                dead = [False]
                identity = lambda _pid: {'pid': 12345, 'boot': 'owned-boot', 'start': 'dead' if dead[0] else 'alive'}
                original_read = Path.read_text
                boot = lambda path,*a,**kw: 'owned-boot' if str(path) == '/proc/sys/kernel/random/boot_id' else original_read(path,*a,**kw)
                def child(*_args, **_kwargs):
                    owner = resources.OwnedDocker(output/'factory-resources.json', 'gz-owned-test')
                    owner.volume('data')
                    owner.cleanup()
                    if acknowledged:
                        module.acknowledge_cleanup(owner)
                    dead[0] = True
                    return ProcessResult(['owned'], 0)
                with patch.object(resources, '_execute', side_effect=DockerDouble()), \
                        patch.object(resources, '_process_identity', side_effect=identity), \
                        patch.object(Path, 'read_text', boot), patch.object(module, 'execute', side_effect=child):
                    observed = module.observe(['owned'], root=output, environment={}, output=output,
                        timeout=1, namespace='gz-owned-test', require_resources=True)
                self.assertEqual(observed['status'], 'pass' if acknowledged else 'fail')

    def test_absent_source_only_trust_fixtures_refuse_before_any_child(self):
        module = self.module()
        self.assertTrue(callable(getattr(module, 'main', None)), 'live entrypoint missing')
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaisesRegex(ValueError, 'Trust CI source'):
                module.main(['--root', raw, '--cell', 'trust-ci', '--output', str(Path(raw)/'output')])

    def test_trust_shell_live_branch_calls_the_structured_producer_before_compose(self):
        for name in ('postgres-integration.sh','postgres-restart-drill.sh'):
            source = (ROOT/'trust-ci/scripts'/name).read_text()
            self.assertIn('GETZILLA_LIVE_BINDING',source)
            self.assertLess(source.index('GETZILLA_LIVE_BINDING'),source.index('compose_file='))
            self.assertIn('--worker',source)

    def test_actual_trust_suite_resource_restart_producers_feed_consumer(self):
        module = self.module()
        from getzilla import disposable_resources as resources
        from getzilla.python_test_runner import ProcessResult
        from tests.test_isolated_resources import DockerDouble, PIN, IMAGE_ID
        import os
        import hashlib
        binding = dict(self.binding(), cell='trust-ci')
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            output = root/'output'
            output.mkdir(mode=0o700)
            for relative in ('.getzilla', 'trust-ci/postgres/init', 'wheelhouse'):
                (root/relative).mkdir(parents=True)
            source = root/'owned-suite.py'
            source.write_text('Owned source fixture. No live qualification.\n')
            restarted = [False]
            def transport(command, *_args, **_kwargs):
                if command[:3] == ['docker','container','inspect'] and '--format' in command:
                    content = json.dumps({'Running':False, 'ExitCode':0})
                elif command[:2] == ['docker','restart']:
                    restarted[0] = True
                    content = ''
                elif 'tests/run_postgres_suite.py' in command:
                    suite = self.suite()
                    ids = [case.id() for case in suite]
                    document = module.record_suite(suite, expected_ids=ids, required_ids=ids, binding=binding,
                        source_stable=lambda:True, loader_errors=(), stream=io.StringIO())
                    document['source_inventory'] = {'owned-suite.py':hashlib.sha256(source.read_bytes()).hexdigest()}
                    content = json.dumps(document)
                elif 'psql' in command:
                    content = ('2026-11-01T00:00:01+00:00' if restarted[0] else '2026-11-01T00:00:00+00:00')+'|123'
                elif 'tests.postgres_restart_probe' in command:
                    content = 'owned-synthetic-job'
                elif command[:2] == ['docker','exec'] and 'sh' in command:
                    content = ''
                else:
                    raise AssertionError('unadmitted owned transport operation')
                return ProcessResult(command, 0, stdout=content)
            pins = {'postgres':{'reference':PIN,'image_id':IMAGE_ID}, 'python':{'reference':PIN,'image_id':IMAGE_ID}}
            identity = {'pid':12345,'start':'owned','boot':'owned'}
            with patch.object(resources,'_execute',side_effect=DockerDouble()), \
                    patch.object(resources,'_process_identity',return_value=identity), \
                    patch.object(resources,'image_pins',return_value=pins), \
                    patch.object(module,'execute',side_effect=transport), \
                    patch.dict(os.environ, {'GETZILLA_LIVE_WHEELHOUSE':str(root/'wheelhouse')}):
                module._trust_ci(root, output, binding)
            self.assertTrue(module.validate_components(output,'trust-ci',binding))
            self.assertFalse(module.validate_components(output,'trust-ci',dict(binding,attempt='2')))
            journal = module.read_document(output/'trust-ci-resources.json')
            self.assertEqual(journal['cleanup_status'],'removed')
            self.assertTrue(all(row['status']=='removed' for row in journal['resources']))


if __name__ == '__main__':
    unittest.main()
