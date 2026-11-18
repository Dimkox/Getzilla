"""Owned failure observations; no network, processes, scanners or project inventory."""
from contextlib import ExitStack, redirect_stdout, contextmanager
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import security_cli as cli, security_image_producer as producer
from getzilla import security_image_backend as native, security_oci as oci
from getzilla.security_artifacts import ArtifactError


class PreparationFaultControls(unittest.TestCase):
    def setUp(self):
        effects = ExitStack()
        self.addCleanup(effects.close)
        for port in ('socket.socket', 'socket.getaddrinfo', 'subprocess.Popen', 'subprocess.run'):
            effects.enter_context(mock.patch(port, side_effect=AssertionError('outside effects denied')))
        temporary = tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def marked(self, error=None, stage='package-artifacts'):
        self.assertTrue(callable(getattr(cli, '_preparation_step', None)), 'missing closed preparation boundary')
        error = error or ArtifactError('artifact-size', 'PRIVATE_MARKER /private https://private.invalid')
        caught_error = None
        try:
            with cli._preparation_step(stage):
                raise error
        except Exception as caught:
            caught_error = caught
        self.assertIs(caught_error, error, 'diagnostics must preserve original exception')
        return error

    def test_fixed_stage_kind_code_without_exception_text_or_replacement(self):
        error = self.marked()
        detail = cli._preparation_fault(error)
        self.assertEqual(detail, dict(stage='package-artifacts', error_kind='artifact',
                                      error_code='artifact-size', errno=None))
        with self.assertRaises(ArtifactError) as caught:
            with cli._preparation_step('prepare-result'):
                raise error
        self.assertIs(caught.exception, error)
        self.assertEqual(cli._preparation_fault(error), detail)
        self.assertNotIn('PRIVATE_MARKER', json.dumps(detail))

    def test_unsealed_unknown_or_malformed_facts_never_enter_fault(self):
        self.marked()
        forged = ArtifactError('artifact-size', 'PRIVATE_MARKER')
        forged._getzilla_preparation = dict(stage='package-artifacts', error_kind='artifact', error_code='artifact-size', errno=None)
        self.assertEqual(cli._preparation_fault(forged), {})
        forged._getzilla_preparation = (None, dict(forged._getzilla_preparation))
        self.assertEqual(cli._preparation_fault(forged), {})
        with mock.patch.object(producer.os, 'write') as write:
            producer._fault(forged)
        self.assertNotIn('preparation', json.loads(write.call_args.args[1])['fault'])
        native_forged = native.BackendUnavailable('owned', detail={'preparation': dict(
            stage='package-artifacts', error_kind='artifact', error_code='artifact-size', errno=None)})
        with mock.patch.object(producer.os, 'write') as write:
            producer._fault(native_forged)
        self.assertNotIn('preparation', json.loads(write.call_args.args[1])['fault'])
        for changes in (dict(secret='PRIVATE_MARKER'), dict(stage='PRIVATE_MARKER'),
                        dict(error_kind='PRIVATE_MARKER'), dict(error_code='PRIVATE_MARKER'),
                        dict(errno=True), dict(errno=2**100)):
            detail = dict(cli._preparation_fault(self.marked()), **changes)
            self.assertEqual(cli._preparation_detail(detail), {})
        marked = self.marked(ArtifactError('PRIVATE_MARKER', 'PRIVATE_MARKER'))
        self.assertEqual(cli._preparation_fault(marked)['error_code'], 'other')

    def test_actual_prepare_join_identifies_package_failure_and_stops_later_work(self):
        self.assertTrue(callable(getattr(cli, '_preparation_step', None)), 'missing closed preparation boundary')
        error = ArtifactError('artifact-origin', 'PRIVATE_MARKER')
        inventory = dict(dependencies=[dict(ecosystem='PyPI')], tools=[], images=[], digest='a'*64)
        source = dict(owned='source')
        with ExitStack() as ports:
            for name, value in (('read_image_selection', None), ('collect_inventory', inventory),
                                ('_policy_digest', 'a'*64), ('source_binding', source),
                                ('validate_input_profile', {}), ('provision_tools', []), ('refresh_feeds', [])):
                ports.enter_context(mock.patch.object(cli, name, return_value=value))
            ports.enter_context(mock.patch.object(cli, 'acquire_pypi', side_effect=error))
            later = ports.enter_context(mock.patch.object(cli, 'security_obligations'))
            with self.assertRaises(ArtifactError) as caught:
                cli.prepare_inputs(self.root, self.root/'db', self.root/'artifacts', self.root/'tools',
                                   profile={}, refresh=True, provision=True)
        self.assertIs(caught.exception, error)
        self.assertEqual(cli._preparation_fault(error)['stage'], 'package-artifacts')
        later.assert_not_called()

    def test_errno_and_existing_oci_bound_detail_survive_without_new_authority(self):
        error = self.marked(PermissionError(13, 'PRIVATE_MARKER'), stage='profile-validation')
        self.assertEqual(cli._preparation_fault(error), dict(stage='profile-validation',
            error_kind='os', error_code=None, errno=13))
        profile = dict(oci.LIMITS, max_storage_bytes=1, images=[], platform='linux/amd64')
        budget = oci._Budget(profile)
        try:
            with cli._preparation_step('image-artifacts'):
                budget.charge('storage', 2, phase='blob-storage')
        except oci.OCIError as error:
            fault = cli._input_fault(error)
            with mock.patch.object(producer.os, 'write') as write:
                producer._fault(error)
        self.assertEqual(fault['limit'], 1)
        self.assertEqual(fault['preparation']['error_kind'], 'oci')
        self.assertEqual(cli._input_fault_detail(fault), fault)
        emitted = json.loads(write.call_args.args[1])['fault']
        self.assertEqual(emitted['preparation'], fault['preparation'])
        self.assertEqual(emitted['attempted'], 2)
        with self.assertRaises(ValueError):
            cli._input_fault_detail(dict(fault, secret='PRIVATE_MARKER'))
        with cli._preparation_step('feeds'):
            pass
        self.assertEqual(cli._preparation_fault(RuntimeError('PRIVATE_MARKER')), {})

    def test_producer_and_public_refusal_forward_same_closed_observation(self):
        error = self.marked()
        with mock.patch.object(producer.os, 'write') as write:
            producer._fault(error)
        encoded = write.call_args.args[1]
        worker = json.loads(encoded)['fault']
        self.assertEqual(worker['preparation'], cli._preparation_fault(error))
        self.assertNotIn('PRIVATE_MARKER', encoded.decode())

        def collect(process, diagnostic, state, **options):
            diagnostic.extend(encoded)
            state['phase'] = 'prepare'
            raise native.BackendUnavailable('owned child failed')

        with mock.patch.object(native, '_collect_pipeline_inner', side_effect=collect):
            with self.assertRaises(native.BackendUnavailable) as caught:
                native._collect_pipeline(SimpleNamespace(poll=lambda: 1))
        fault = caught.exception.detail
        self.assertEqual(fault['worker_fault']['preparation'], worker['preparation'])
        output = self.root/'report.json'
        arguments = ['--produce-images', '--backend-tool-pins', str(self.root/'pins'),
                     '--input-profile', str(self.root/'profile'), '--json-out', str(output)]
        for key in ('root', 'database', 'artifacts', 'tools'):
            arguments += ['--'+key, str(self.root/key)]
        with mock.patch.object(producer, 'run_pipeline', side_effect=caught.exception):
            self.assertEqual(cli.main(arguments), 1)
        report = json.loads(output.read_bytes())
        self.assertEqual(report['fault']['worker_fault']['preparation'], worker['preparation'])
        self.assertEqual((report['status'], report['qualification']), ('fail', 'UNVERIFIED'))

    def test_actual_pipeline_prepare_publication_keeps_phase_and_original_refusal(self):
        self.assertTrue(callable(getattr(cli, '_preparation_step', None)))
        error = PermissionError(13, 'PRIVATE_MARKER')
        request = dict(root=str(self.root/'source'), database=str(self.root/'db'),
            artifacts=str(self.root/'artifacts'), tools=str(self.root/'tools'),
            profile=str(self.root/'profile'), preparation=str(self.root/'preparation'),
            report=str(self.root/'report'), run={})
        @contextmanager
        def produce(*arguments):
            yield {}, {}
        def atomic(path, raw):
            if path.name == 'preparation':
                raise error
        events = io.StringIO()
        with mock.patch.object(producer, 'produce', produce), \
                mock.patch.object(producer, '_pipeline_tools', return_value=self.root/'tools'), \
                mock.patch.object(cli, 'source_binding', return_value={}), \
                mock.patch.object(cli, 'validate_selection_authority'), \
                mock.patch.object(cli, 'prepare_inputs', side_effect=[{}, {'status': 'prepared'}]), \
                mock.patch.object(cli, '_atomic', side_effect=atomic), redirect_stdout(events):
            with self.assertRaises(PermissionError) as caught:
                producer._pipeline(request, self.root, object())
        self.assertIs(caught.exception, error)
        self.assertEqual(cli._preparation_fault(error)['stage'], 'prepare-result')
        self.assertEqual([json.loads(line)['stage'] for line in events.getvalue().splitlines()], ['declare', 'prepare'])

    def test_ordinary_completed_failed_child_requires_fresh_closed_output(self):
        error = self.marked()
        output = self.root/'report.json'
        arguments = []
        for key in ('root', 'database', 'artifacts', 'tools'):
            arguments += ['--'+key, str(self.root/key)]
        arguments += ['--json-out', str(output)]
        with mock.patch.object(cli, 'ci_run_context', return_value={}), \
                mock.patch.object(cli, 'evaluate', side_effect=error), redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(arguments), 1)
        child = json.loads(output.read_bytes())
        self.assertEqual(child['fault'], {'preparation': cli._preparation_fault(error)})
        args = SimpleNamespace(root=self.root, database=self.root/'db', artifacts=self.root/'artifacts',
            tools=self.root/'tools', input_profile=self.root/'profile', json_out=output,
            refresh=False, provision_tools=False, family_records=None)
        for variant in ('fresh', 'stale', 'unknown', 'timeout', 'cleanup', 'changed-read'):
            with self.subTest(variant=variant):
                cli._atomic(output, oci.canonical(child))

                def execute(*arguments, **options):
                    self.assertEqual(options['timeout'], 600)
                    if variant != 'stale':
                        value = copy.deepcopy(child)
                        if variant == 'unknown':
                            value['fault']['preparation']['secret'] = 'PRIVATE_MARKER'
                        cli._atomic(output, oci.canonical(value))
                    return SimpleNamespace(returncode=1, terminal_state='timeout' if variant == 'timeout' else 'completed',
                        cleanup_error='owned cleanup' if variant == 'cleanup' else None)

                real_read = cli.read_file
                def read(*arguments, **options):
                    raw = real_read(*arguments, **options)
                    if variant == 'changed-read':
                        cli._atomic(output, raw)
                    return raw
                with mock.patch.object(cli, 'execute', side_effect=execute), \
                        mock.patch.object(cli, '_environment', return_value={}), \
                        mock.patch.object(cli, 'read_file', side_effect=read):
                    report = cli._supervised_preparation(args, {})
                self.assertEqual(report.get('fault'), child['fault'] if variant == 'fresh' else None)
                self.assertEqual((report['status'], report['qualification']), ('unavailable', 'UNVERIFIED'))
                self.assertNotIn('PRIVATE_MARKER', json.dumps(report))
