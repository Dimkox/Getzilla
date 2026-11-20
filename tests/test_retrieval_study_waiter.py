import builtins
import importlib
import io
import json
import unittest
from unittest.mock import Mock, patch


class StudyWaiterTests(unittest.TestCase):
    def test_failed_unavailable_emission_returns_failure_without_dispatch(self):
        owner = self.owner()
        outgoing = Mock()
        outgoing.write.side_effect = OSError('private broken pipe')
        with patch.object(owner, '_inside_readback', side_effect=ValueError('private readback')), \
                patch.object(owner, '_dispatch') as dispatch:
            self.assertEqual(owner.serve('a' * 64, io.BytesIO(), outgoing), 125)
        outgoing.write.assert_called_once_with(
            b'{"status":"unavailable","reason":"owned_worker_unavailable"}\n')
        outgoing.flush.assert_not_called()
        dispatch.assert_not_called()

    def owner(self):
        try:
            return importlib.import_module('getzilla.retrieval.study_worker_entry')
        except ModuleNotFoundError:
            self.fail('fixed stdlib-only waiting worker missing')

    def test_wait_then_stop_never_imports_native_packages(self):
        owner = self.owner()
        nonce = 'a' * 64
        incoming = io.BytesIO((json.dumps({'nonce': nonce, 'sequence': 1, 'op': 'stop'}) + '\n').encode())
        outgoing = io.BytesIO()
        original = builtins.__import__
        def guarded(name, *args, **kwargs):
            if name.split('.')[0] in {'numpy', 'onnxruntime', 'tokenizers', 'tiktoken'}:
                self.fail('waiting worker imported optional native package')
            return original(name, *args, **kwargs)
        with patch('builtins.__import__', side_effect=guarded), \
                patch.object(owner, '_inside_readback', return_value={'tiny': 'fixture'}):
            self.assertEqual(owner.serve(nonce, incoming, outgoing), 0)
        messages = [json.loads(line) for line in outgoing.getvalue().splitlines()]
        self.assertEqual(messages[0]['phase'], 'waiting')
        self.assertEqual(messages[0]['nonce'], nonce)
        self.assertEqual(messages[-1]['status'], 'stopped')

    def test_replayed_sequence_wrong_nonce_and_raw_boolean_never_dispatch(self):
        owner = self.owner()
        for request in ({'nonce': 'b' * 64, 'sequence': 1, 'op': 'native-import'},
                        {'nonce': 'a' * 64, 'sequence': 0, 'op': 'native-import'},
                        {'allow_execution': True}):
            with self.subTest(request=request), \
                    patch.object(owner, '_inside_readback', return_value={}), \
                    patch.object(owner, '_dispatch') as dispatch:
                self.assertEqual(owner.serve('a' * 64,
                    io.BytesIO((json.dumps(request) + '\n').encode()), io.BytesIO()), 125)
                dispatch.assert_not_called()
