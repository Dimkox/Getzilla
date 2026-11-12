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
        with tempfile.TemporaryDirectory() as raw, patch.object(module,'_run',side_effect=AssertionError('Git or transport before refusal')) as run:
            with self.assertRaisesRegex(ValueError, 'Trust CI source'):
                module.main(['--root', raw, '--cell', 'trust-ci', '--output', str(Path(raw)/'output')])
            run.assert_not_called()

    def test_direct_trust_missing_producer_refuses_before_external_work(self):
        module = self.module()
        from getzilla import disposable_resources as resources
        with tempfile.TemporaryDirectory() as raw, \
                patch.object(module,'_run',side_effect=AssertionError('Git or transport before refusal')) as run, \
                patch.object(resources,'OwnedDocker',side_effect=AssertionError('Allocation before refusal')) as owner:
            with self.assertRaisesRegex(ValueError,'Trust CI source'):
                try:
                    module._trust_ci(Path(raw),Path(raw),dict(self.binding(),cell='trust-ci'))
                except KeyError:
                    self.fail('Missing producer was not checked before runtime configuration')
            run.assert_not_called()
            owner.assert_not_called()




class FactorySuiteGuardTests(unittest.TestCase):
    def test_both_owned_databases_are_guarded_before_discovery_or_mutation(self):
        from factory.tests import run_live_suite as suite_runner
        self.assertTrue(callable(getattr(suite_runner,'guard_databases',None)), 'central live preflight missing')
        from factory.tests import postgres_restart_probe as probe
        from getzilla import disposable_resources as resources
        from tests.test_isolated_resources import DockerDouble, PIN, IMAGE_ID
        from unittest.mock import MagicMock
        from urllib.parse import urlsplit
        import os
        cases = ('valid','missing-journal','wrong-endpoint','wrong-birth','wrong-cluster','same-container','same-cluster')
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as raw:
                root=Path(raw)
                docker=DockerDouble()
                process={'pid':12345,'start':'owned','boot':'owned'}
                with patch('subprocess.Popen',side_effect=AssertionError('unmocked child forbidden')), \
                        patch('socket.socket.connect',side_effect=AssertionError('unmocked network forbidden')), \
                        patch.object(resources,'_execute',side_effect=docker), \
                        patch.object(resources,'_process_identity',return_value=process):
                    owner=resources.OwnedDocker(root/'factory-resources.json','gz-owned-test')
                    network=owner.network('network')
                    primary=owner.container('primary',PIN,network=network)
                    fresh=owner.container('fresh',PIN,network=network)
                    for item,ip in ((primary,'172.28.0.2'),(fresh,'172.28.0.3')):
                        container=docker.items['container'][item['id']]
                        container['NetworkSettings']['Networks'][network['name']]['IPAddress']=ip
                        docker.items['network'][network['name']]['Containers'][item['id']]['IPv4Address']=ip+'/16'
                    environment={'FACTORY_TEST_DATABASE_URL':'postgresql://factory_exit:owned@172.28.0.2:5432/factory_exit',
                        'FACTORY_FRESH_CLUSTER_DATABASE_URL':'postgresql://factory_exit:owned@172.28.0.3:5432/factory_exit',
                        'FACTORY_TEST_POSTGRES_CONTAINER':primary['name'],'FACTORY_TEST_POSTGRES_CONTAINER_ID':primary['id'],
                        'FACTORY_FRESH_POSTGRES_CONTAINER':fresh['name'],'FACTORY_FRESH_POSTGRES_CONTAINER_ID':fresh['id'],
                        'FACTORY_TEST_POSTGRES_JOURNAL':str(owner.manifest),'FACTORY_TEST_POSTGRES_NAMESPACE':owner.namespace,
                        'FACTORY_TEST_POSTGRES_NETWORK_ID':network['identity']['Id'],'FACTORY_TEST_POSTGRES_NONCE':owner.nonce}
                    if case=='missing-journal':
                        environment['FACTORY_TEST_POSTGRES_JOURNAL']=''
                    elif case=='wrong-endpoint':
                        environment['FACTORY_FRESH_CLUSTER_DATABASE_URL']=environment['FACTORY_FRESH_CLUSTER_DATABASE_URL'].replace('172.28.0.3','172.28.0.99')
                    elif case=='wrong-birth':
                        docker.items['container'][fresh['id']]['Image']='sha256:'+'f'*64
                    elif case=='same-container':
                        environment['FACTORY_FRESH_POSTGRES_CONTAINER_ID']=primary['id']
                    queries=[]
                    def connect(url,**_kwargs):
                        connection=MagicMock()
                        cluster='111' if urlsplit(url).hostname=='172.28.0.2' else '222'
                        if case=='same-cluster':
                            cluster='111'
                        if case=='wrong-cluster':
                            cluster='333'
                        def query(sql):
                            self.assertTrue(sql.startswith('SELECT '))
                            queries.append(sql)
                            result=MagicMock()
                            result.fetchone.return_value=('factory_exit','factory_exit',170006,cluster)
                            return result
                        connection.__enter__.return_value.execute.side_effect=query
                        return connection
                    def command(argv,**_kwargs):
                        cluster='111' if argv[2]==primary['id'] else '222'
                        if case=='same-cluster':
                            cluster='111'
                        from subprocess import CompletedProcess
                        return CompletedProcess(argv,0,cluster if 'psql' in argv else '')
                    binding=LiveSourceTests.binding(self)
                    with patch.dict(os.environ,environment,clear=True), patch.object(probe,'POSTGRES',{'reference':PIN,'image_id':IMAGE_ID}), \
                            patch('psycopg.connect',side_effect=connect), patch.object(probe.subprocess,'run',side_effect=command), \
                            patch.object(suite_runner,'read_document',return_value=binding), \
                            patch.object(suite_runner.factory_tests,'_source_snapshot',side_effect=RuntimeError('owned discovery boundary')) as discovery:
                        os.environ['GETZILLA_LIVE_BINDING']='owned'
                        if case=='valid':
                            with self.assertRaisesRegex(RuntimeError,'owned discovery boundary'):
                                suite_runner.main()
                            discovery.assert_called_once()
                            self.assertEqual(len(queries),2)
                        else:
                            with self.assertRaises((ValueError,RuntimeError)):
                                suite_runner.main()
                            discovery.assert_not_called()
                            self.assertEqual(len(queries),1 if case=='wrong-cluster' else 2 if case=='same-cluster' else 0)


if __name__ == '__main__':
    unittest.main()
