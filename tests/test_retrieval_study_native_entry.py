import importlib
import io
import json
import unittest
from unittest.mock import patch


class StudyNativeEntryTests(unittest.TestCase):
    def owner(self):
        try:
            return importlib.import_module('getzilla.retrieval.study_native_entry')
        except ModuleNotFoundError:
            self.fail('separately owned native child entry missing')

    def test_wrong_nonce_or_repeat_never_dispatches_native_data_plane(self):
        owner = self.owner()
        for request in ({'nonce': 'b' * 64, 'sequence': 1, 'op': 'native-import'},
                        {'nonce': 'a' * 64, 'sequence': 0, 'op': 'native-import'}):
            with self.subTest(request=request), patch.object(owner, '_dispatch') as dispatch:
                incoming = io.BytesIO((json.dumps(request) + '\n').encode())
                self.assertEqual(owner.serve('a' * 64, incoming, io.BytesIO()), 125)
                dispatch.assert_not_called()

    def test_bootstrap_requires_two_exact_release_bytes_without_read_ahead(self):
        owner = self.owner()
        for chunks, expected in (([b'R', b'\n'], True), ([b'X'], False), ([b''], False)):
            with self.subTest(chunks=chunks), patch('os.read', side_effect=chunks):
                self.assertEqual(owner._released(), expected)
