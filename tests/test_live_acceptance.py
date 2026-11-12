"""Owned synthetic producer/consumer controls. No live acceptance is claimed."""
from __future__ import annotations

import importlib
import importlib.util
import ast
import copy
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
                            patch.object(suite_runner,'observe_parser_applicability',return_value=None), \
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


class ParserApplicabilityTests(unittest.TestCase):
    def test_exact_source_complementary_branches_keep_all_seven_cases(self):
        module=importlib.import_module('getzilla.live_acceptance')
        self.assertTrue(callable(getattr(module,'observe_parser_applicability',None)), 'measured parser applicability missing')
        from getzilla.python_test_runner import ProcessResult
        import types
        import tomllib
        original=(ROOT/'factory/tests/test_landing_pdf_worker.py').read_bytes()
        classes=[copy.deepcopy(node) for node in ast.parse(original).body if isinstance(node,ast.ClassDef)
                 and node.name in {'PdfWorkerWithoutParser','PdfWorkerWithPinnedParser'}]
        self.assertEqual(len(classes),2)
        for cls in classes:
            for method in cls.body:
                if isinstance(method,ast.FunctionDef):
                    identifier='factory.tests.test_landing_pdf_worker.'+cls.name+'.'+method.name
                    method.body=[ast.Expr(ast.Call(ast.Attribute(ast.Name('owned_executed',ast.Load()),'append',ast.Load()),[ast.Constant(identifier)],[]))]
        owned=ast.fix_missing_locations(ast.Module(body=classes,type_ignores=[]))
        metadata=(ROOT/'factory/pyproject.toml').read_bytes()
        pin=next(value.removeprefix('pypdf==') for value in tomllib.loads(metadata.decode())['project']['dependencies'] if value.startswith('pypdf=='))
        for version,actual,skipped in ((None,1,6),(pin,6,1)):
            with self.subTest(parser=version),tempfile.TemporaryDirectory() as raw:
                root=Path(raw); target=root/'factory/tests/test_landing_pdf_worker.py'
                target.parent.mkdir(parents=True)
                target.write_text(ast.unparse(owned)+'\n')
                (root/'factory/pyproject.toml').write_bytes(metadata)
                namespace=types.ModuleType('factory.tests.test_landing_pdf_worker')
                namespace.__file__=str(target)
                namespace.__dict__.update(unittest=unittest,CHILD_PYPDF_VERSION=version,owned_executed=[])
                exec(compile(owned,str(target),'exec'),namespace.__dict__)
                suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(getattr(namespace,cls.name)) for cls in classes)
                expected=[module.test_id(case) for case in module.cases(suite)]
                binding=LiveSourceTests.binding(self)
                def probe(command,*_args,**kwargs):
                    self.assertEqual(command[1:4],['-B','-I','-c'])
                    return ProcessResult(command,0,stdout=json.dumps({'pypdf_version':version}))
                with patch('subprocess.Popen',side_effect=AssertionError('unmocked child forbidden')), \
                        patch('socket.socket.connect',side_effect=AssertionError('unmocked network forbidden')), \
                        patch.object(module,'execute',side_effect=probe), \
                        patch.dict(sys.modules,{namespace.__name__:namespace}):
                    observation=module.observe_parser_applicability(root,binding,python=Path(sys.executable))
                    report=module.record_suite(suite,expected_ids=expected,required_ids=expected,loader_errors=(),
                        binding=binding,source_stable=lambda:True,stream=io.StringIO(),parser_observation=observation)
                    final=module.observe_parser_applicability(root,binding,python=Path(sys.executable))
                    self.assertTrue(module.accepted_suite(report,binding,parser_observation=final))
                    self.assertEqual(len(report['expected_ids']),7)
                    self.assertEqual(len(report['started']),7)
                    self.assertEqual(len(report['executed']),actual)
                    self.assertEqual(len(report['skipped']),skipped)
                    self.assertEqual(len(report['allowed_skips']),skipped)
                    self.assertEqual(set(namespace.owned_executed),set(report['executed']))
                    self.assertFalse(module.accepted_suite(report,binding))
                    self.assertFalse(module.accepted_suite(report,binding,parser_observation={'pypdf_version':version}))
                    changed=copy.deepcopy(report); changed['applicability']['observations'][0]['observed_ns']=0
                    self.assertFalse(module.accepted_suite(changed,binding,parser_observation=final))
                    changed=copy.deepcopy(report); changed['skipped'][0]['reason']='unsupported reason'
                    self.assertFalse(module.accepted_suite(changed,binding,parser_observation=final))
                    for dimension,value in (('python','/foreign/python'),('pypdf_version','foreign'),('policy_digest','0'*64)):
                        changed=copy.deepcopy(report)
                        changed['applicability']['observations'][1][dimension]=value
                        self.assertFalse(module.accepted_suite(changed,binding,parser_observation=final),dimension)
                    changed=copy.deepcopy(report); changed['applicability']['policy']['canonical_policy_sha256']='0'*64
                    self.assertFalse(module.accepted_suite(changed,binding,parser_observation=final))
                    changed=copy.deepcopy(report); changed['applicability']['observations'][0]['binding']['attempt']='foreign'
                    self.assertFalse(module.accepted_suite(changed,binding,parser_observation=final))
                    from getzilla.python_test_runner import CleanupMetadata
                    for invalid in (ProcessResult(['owned'],124,terminal_state='timeout'),
                            ProcessResult(['owned'],0,stdout=''),ProcessResult(['owned'],0,stdout='{}'),
                            ProcessResult(['owned'],0,stdout='{"pypdf_version":"foreign"}'),
                            ProcessResult(['owned'],0,stdout='{"pypdf_version":null}',cleanup_metadata=CleanupMetadata(unavailable=True))):
                        with patch.object(module,'execute',return_value=invalid),self.assertRaises(ValueError):
                            module.observe_parser_applicability(root,binding,python=Path(sys.executable))
                    if version is None:
                        with self.assertRaises(ValueError):
                            module.observe_parser_applicability(root,binding,python=Path(sys.executable),required=True)
                    else:
                        required=module.observe_parser_applicability(root,binding,python=Path(sys.executable),required=True)
                        self.assertTrue(required.policy['required_parser'])
                    applicable=getattr(namespace,'PdfWorkerWithoutParser' if version is None else 'PdfWorkerWithPinnedParser')
                    method=next(name for name in vars(applicable) if name.startswith('test_'))
                    original_method=getattr(applicable,method)
                    def conflicting(case):
                        original_method(case)
                        namespace.CHILD_PYPDF_VERSION='conflicting-after-body'
                    with patch.object(applicable,method,conflicting):
                        repeated=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(getattr(namespace,cls.name)) for cls in classes)
                        refused=module.record_suite(repeated,expected_ids=expected,required_ids=expected,loader_errors=(),
                            binding=binding,source_stable=lambda:True,stream=io.StringIO(),parser_observation=observation)
                        latest=module.observe_parser_applicability(root,binding,python=Path(sys.executable))
                        self.assertFalse(module.accepted_suite(refused,binding,parser_observation=latest),'after-body module fact conflict')
                    namespace.CHILD_PYPDF_VERSION=version
                    with patch.object(applicable,method,side_effect=RuntimeError('owned body did not return')):
                        repeated=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(getattr(namespace,cls.name)) for cls in classes)
                        refused=module.record_suite(repeated,expected_ids=expected,required_ids=expected,loader_errors=(),
                            binding=binding,source_stable=lambda:True,stream=io.StringIO(),parser_observation=observation)
                        latest=module.observe_parser_applicability(root,binding,python=Path(sys.executable))
                        self.assertFalse(module.accepted_suite(refused,binding,parser_observation=latest))

    def test_required_database_skip_and_forged_allowance_never_become_na(self):
        module=importlib.import_module('getzilla.live_acceptance')
        for skipped in (False,True):
            executed=[]
            class PostgresFactoryTests(unittest.TestCase):
                def test_required_database(self):
                    if skipped:
                        self.skipTest('FACTORY_TEST_DATABASE_URL must name a disposable database')
                    executed.append('body-returned')
            PostgresFactoryTests.__module__='factory.tests.test_postgres_integration'
            suite=unittest.defaultTestLoader.loadTestsFromTestCase(PostgresFactoryTests)
            expected=[case.id() for case in suite]
            report=module.record_suite(suite,expected_ids=expected,required_ids=expected,loader_errors=(),
                binding=LiveSourceTests.binding(self),source_stable=lambda:True,stream=io.StringIO(),
                allowed_skips={expected[0]:{'rule':'parser-absent','reason':'forged'}} if skipped else None)
            self.assertEqual(module.accepted_suite(report,LiveSourceTests.binding(self)),not skipped)
            self.assertEqual(executed,[] if skipped else ['body-returned'])
            if skipped:
                report.update(status='pass',required_ids=[],missing_required=[],inapplicable_ids=expected,
                              allowed_skips={expected[0]:{'rule':'parser-absent','reason':'forged'}})
                self.assertFalse(module.accepted_suite(report,LiveSourceTests.binding(self)))


class FactoryControllerTests(unittest.TestCase):
    def test_owned_interpreter_survives_final_measurement_and_cleanup_precedes_pass(self):
        module=importlib.import_module('getzilla.live_acceptance')
        self.assertTrue(callable(getattr(module,'_run_factory_cell',None)), 'outer interpreter lifetime missing')
        for primary,cleanup_failure,confirmed in (('passed',False,True),('failed',False,True),
                ('cancelled',False,True),('passed',True,True),('passed',False,False)):
            with self.subTest(primary=primary,cleanup_failure=cleanup_failure,confirmed=confirmed), tempfile.TemporaryDirectory() as raw:
                root=Path(raw); order=[]; paths=[]; token=object()
                def observed(_command,**kwargs):
                    path=Path(kwargs['environment']['UV_PROJECT_ENVIRONMENT'])
                    self.assertEqual(kwargs['environment']['GETZILLA_LIVE_PARSER_REQUIRED'],'1')
                    self.assertTrue(path.is_dir()); paths.append(path)
                    (path/'bin').mkdir()
                    (path/'bin/python').write_text('owned interpreter fixture, never executed')
                    order.append('observe')
                    return {'status':'pass' if primary=='passed' else 'fail','primary_outcome':primary,
                            'child_exit_confirmed':confirmed,'python':'/foreign/report-selected-python'}
                def measured(_root,_binding,*,python,**kwargs):
                    self.assertEqual(python,paths[0]/('Scripts/python.exe' if __import__('os').name=='nt' else 'bin/python'))
                    self.assertTrue(paths[0].is_dir()); order.append('final-measurement')
                    self.assertTrue(kwargs['required'])
                    return token
                def validated(_output,_cell,_binding,**kwargs):
                    self.assertIs(kwargs['parser_observation'],token)
                    self.assertTrue(paths[0].is_dir()); order.append('validate')
                    return True
                native_remove=module._remove_factory_environment
                def removed(path):
                    order.append('cleanup')
                    if cleanup_failure:
                        raise PermissionError('owned cleanup failure')
                    native_remove(path)
                with patch('subprocess.Popen',side_effect=AssertionError('unmocked child forbidden')), \
                        patch('socket.socket.connect',side_effect=AssertionError('unmocked network forbidden')), \
                        patch.object(module,'observe',side_effect=observed), \
                        patch.object(module,'observe_parser_applicability',side_effect=measured), \
                        patch.object(module,'validate_components',side_effect=validated), \
                        patch.object(module,'_remove_factory_environment',side_effect=removed):
                    result=module._run_factory_cell(['owned'],root=root,output=root,environment={},
                        binding=LiveSourceTests.binding(self),timeout=1,required_parser=True)
                self.assertEqual(result['primary_outcome'],primary)
                self.assertEqual(result['status'],'pass' if primary=='passed' and confirmed and not cleanup_failure else 'fail')
                self.assertEqual(paths[0].exists(),cleanup_failure or not confirmed)
                if primary=='passed' and confirmed:
                    self.assertEqual(order,['observe','final-measurement','validate','cleanup'])
                else:
                    self.assertNotIn('validate',order)

    def test_replaced_environment_birth_never_deletes_the_replacement(self):
        module=importlib.import_module('getzilla.live_acceptance')
        self.assertTrue(callable(getattr(module,'_FactoryEnvironment',None)), 'owned environment birth missing')
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw)
            owned=module._FactoryEnvironment(root)
            original=owned.path
            original.rename(root/'retained-original')
            original.mkdir(mode=0o700)
            (original/'foreign').write_text('retained')
            self.assertEqual(owned.cleanup(child_exit_confirmed=True)['status'],'unknown')
            self.assertEqual((original/'foreign').read_text(),'retained')


if __name__ == '__main__':
    unittest.main()
