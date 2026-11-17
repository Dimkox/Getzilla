"""Tiny compressed metadata fixtures; explicit mocked existing HTTP transport."""
import gzip
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'.getzilla'))
from getzilla import updater


class Response(io.BytesIO):
    def __init__(self, raw, encoding='gzip'):
        super().__init__(raw)
        self.headers = {'Content-Encoding': encoding}
    def geturl(self):
        return 'https://pypi.org/pypi/owned/json'


class ReleaseTransportTests(unittest.TestCase):
    def test_complete_compressed_catalog_and_truncated_stream_refusal(self):
        body = b'{"info":{"name":"owned"},"releases":{"1.0.0":[{}]}}'
        wire = gzip.compress(body)
        with patch.object(updater._RELEASE_OPENER, 'open', return_value=Response(wire)) as opened:
            self.assertEqual(updater._release_fetch('https://pypi.org/pypi/owned/json'), body)
            self.assertEqual(opened.call_args.args[0].get_header('Accept-encoding'), 'gzip')
        with patch.object(updater._RELEASE_OPENER, 'open', return_value=Response(wire[:-2])):
            with self.assertRaisesRegex(ValueError, 'truncated'):
                updater._release_fetch('https://pypi.org/pypi/owned/json')

    def test_unknown_origin_refuses_before_http_effect(self):
        with patch.object(updater._RELEASE_OPENER, 'open', side_effect=AssertionError('unexpected I/O')):
            with self.assertRaises(ValueError):
                updater._release_fetch('https://foreign.invalid/pypi/owned/json')

    def test_redirect_denied_before_delegate_and_official_forward_retained(self):
        guard = updater._ReleaseRedirect()
        with patch.object(updater.urllib.request.HTTPRedirectHandler, 'redirect_request', return_value='inert') as delegate:
            self.assertEqual(guard.redirect_request(None, None, 302, 'found', {}, 'https://release-assets.githubusercontent.com/owned'), 'inert')
            self.assertEqual(delegate.call_count, 1)
            with self.assertRaises(ValueError):
                guard.redirect_request(None, None, 302, 'found', {}, 'https://unknown.invalid/owned')
            self.assertEqual(delegate.call_count, 1)
