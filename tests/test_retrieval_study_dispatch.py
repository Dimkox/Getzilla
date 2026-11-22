import builtins
import importlib
import time
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

from tests.test_retrieval_study_windows import InertLineCounter, function
from tests.test_retrieval_study_tokenizer import TinyTokenizer
from getzilla.retrieval.contracts import sha


class StudyDispatchTests(unittest.TestCase):
    def test_fixed_native_operations_report_scoped_process_measurements(self):
        owner = self.owner()
        result = owner.dispatch(self.request(op='release'), {'native_ready': True})
        measured = result['operation_measurements']
        self.assertGreaterEqual(measured['wall_seconds'], 0)
        self.assertGreaterEqual(measured['cpu_seconds'], 0)
        if owner.sys.platform == 'linux':
            self.assertGreater(measured['peak_rss_bytes'], 0)
            self.assertEqual(measured['scope'], 'native-child-process-lifetime-rusage-self-linux-kib-to-bytes')
        else:
            self.assertIsNone(measured['peak_rss_bytes'])
            self.assertEqual(measured['scope'], 'process-peak-rss-unavailable')

    def test_resource_import_is_lazy_linux_only_and_unknown_is_not_zero(self):
        owner = self.owner()
        original = builtins.__import__
        def guard(name, *args, **kwargs):
            if name == 'resource':
                self.fail('unsupported platform imported Linux measurement resource')
            return original(name, *args, **kwargs)
        with patch.object(owner.sys, 'platform', 'win32'), patch('builtins.__import__', side_effect=guard):
            result = owner.dispatch(self.request(op='release'), {'native_ready': True})
        self.assertIsNone(result['operation_measurements']['peak_rss_bytes'])
        self.assertEqual(result['operation_measurements']['scope'], 'process-peak-rss-unavailable')
        resource = SimpleNamespace(RUSAGE_SELF=0, getrusage=lambda scope: SimpleNamespace(ru_maxrss=7))
        with patch.object(owner.sys, 'platform', 'linux'), patch.dict('sys.modules', {'resource': resource}):
            result = owner.dispatch(self.request(op='release'), {'native_ready': True})
        self.assertEqual(result['operation_measurements']['peak_rss_bytes'], 7168)
        resource.getrusage = Mock(side_effect=OSError('counter unavailable'))
        with patch.object(owner.sys, 'platform', 'linux'), patch.dict('sys.modules', {'resource': resource}):
            result = owner.dispatch(self.request(op='release'), {'native_ready': True})
        self.assertIsNone(result['operation_measurements']['peak_rss_bytes'])

    def owner(self):
        try:
            return importlib.import_module('getzilla.retrieval.study_worker_dispatch')
        except ModuleNotFoundError:
            self.fail('fixed admitted worker dispatch missing')

    def request(self, **values):
        return {'nonce': 'a' * 64, 'sequence': 1, 'absolute_deadline': time.monotonic() + 2,
                **values}

    def test_default_import_and_unprepared_requests_do_not_import_native(self):
        original = builtins.__import__
        def guard(name, *args, **kwargs):
            if name.split('.')[0] in {'numpy', 'onnxruntime', 'tokenizers', 'tiktoken'}:
                self.fail('unprepared request imported native package')
            return original(name, *args, **kwargs)
        with patch('builtins.__import__', side_effect=guard):
            owner = importlib.reload(self.owner())
            for op in ('unknown', 'encode', 'load-model', 'load-tokenizer'):
                with self.subTest(op=op), self.assertRaises(ValueError):
                    owner.dispatch(self.request(op=op), {})

    def test_inert_admitted_source_window_maps_original_ids_no_model_import(self):
        owner = self.owner()
        raw = b'def choose(): ...\n'
        state = {'native_ready': True, 'window_counter': InertLineCounter()}
        result = owner.dispatch(self.request(op='windows', corpus='small', path='x.py',
                                             raw=raw.decode(), functions=[function(raw)]), state)
        self.assertEqual(result['windows'][0]['id'], 'x.py:1:choose@1-1')
        self.assertEqual(result['count'], 1)

    def test_caller_text_cannot_replace_a_captured_window(self):
        owner = self.owner()
        with self.assertRaises(ValueError):
            owner.dispatch(self.request(op='encode', kind='window', text='inert unlisted text'),
                           {'native_ready': True})

    def test_codec_has_one_fixed_local_path_no_provider_fallback(self):
        owner = self.owner()
        with self.assertRaises(ValueError):
            owner._codec_bytes('/other/codec')

    def test_warm_score_requires_prepared_index_and_cannot_rebuild_it(self):
        owner = self.owner()
        state = {'native_ready': True, 'query': ('q', 'small', 'inert', []), 'session': object()}
        with self.assertRaisesRegex(ValueError, 'study_index_incomplete'):
            owner.dispatch(self.request(op='score', corpus='small', query_id='q'), state)
        state.update(window_counter=InertLineCounter(), prepared={'small': object()})
        with self.assertRaisesRegex(ValueError, 'study_windows_unavailable'):
            owner.dispatch(self.request(op='windows', corpus='small', path='x.py', raw='', functions=[]), state)

    def test_tokenizer_identity_is_actual_held_bytes_not_access_time(self):
        owner = self.owner()
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'tiny.json'
            target.write_bytes(b'{}')
            target.chmod(0o444)
            os.utime(target, ns=(1000000000, 2000000000))
            native_open, native_stat = os.open, os.stat
            fixed = '/model/minilm/tokenizer.json'
            def redirect_open(path, *args, **kwargs):
                return native_open(target if path == fixed else path, *args, **kwargs)
            def redirect_stat(path, *args, **kwargs):
                return native_stat(target if path == fixed else path, *args, **kwargs)
            state = {'tokenizer_module': SimpleNamespace(Tokenizer=SimpleNamespace(
                     from_file=lambda path: TinyTokenizer()))}
            with patch('os.open', side_effect=redirect_open), patch('os.stat', side_effect=redirect_stat):
                result = owner._tokenizer('minilm', state)
            self.assertEqual(result['tokenizer_sha256'], sha(b'{}'))

    def test_packing_probe_uses_only_fixed_inert_bytes_and_complete_codec_count(self):
        from tests.test_retrieval_study_context import ByteCounter
        owner = self.owner()
        result = owner.dispatch(self.request(op='packing-probe'),
                                {'native_ready': True, 'codec': ByteCounter()})
        self.assertEqual(result['2048'], result['8192'])
        self.assertEqual(result['2048']['source_positions'], (1, 2))
        with self.assertRaises(ValueError):
            owner.dispatch(self.request(op='packing-probe', text='unlisted'),
                           {'native_ready': True, 'codec': ByteCounter()})
