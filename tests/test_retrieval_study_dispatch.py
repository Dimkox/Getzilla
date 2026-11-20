import builtins
import importlib
import time
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests.test_retrieval_study_windows import InertLineCounter, function
from tests.test_retrieval_study_tokenizer import TinyTokenizer
from getzilla.retrieval.contracts import sha


class StudyDispatchTests(unittest.TestCase):
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
