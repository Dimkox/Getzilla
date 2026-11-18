"""Tiny compressed metadata fixtures; explicit mocked existing HTTP transport."""
import gzip
import io
from email.message import Message
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

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
    def refusal(self, status, values=(), *, reason='private reason marker'):
        headers = Message()
        for name, value in values:
            headers[name] = value
        body = io.BytesIO(b'private body marker')
        error = HTTPError('https://private.invalid/private-url-marker', status, reason, headers, body)
        self.addCleanup(error.close)
        return error, body

    def observed_refusal(self, error, url='https://api.github.com/repos/owned/tool/releases/latest'):
        with patch.object(updater._RELEASE_OPENER, 'open', side_effect=error):
            with self.assertRaises((OSError, ValueError)) as caught:
                updater._release_fetch(url)
        return str(caught.exception)

    def test_opengrep_quota_refusal_keeps_numeric_evidence_and_stays_failed(self):
        error, body = self.refusal(403, (
            ('X-RateLimit-Remaining', '0'), ('X-RateLimit-Reset', '1795020000'), ('Retry-After', '120')))
        with tempfile.TemporaryDirectory(dir=ROOT/'.getzilla/runtime') as temporary:
            root = Path(temporary)
            with patch.object(updater._RELEASE_OPENER, 'open', side_effect=error) as opened:
                result = updater.update_opengrep(updater._release_fetch, root, ('linux', 'x86_64'),
                    run=lambda *_: self.fail('refused metadata must not run an artifact'))
            self.assertEqual(len(result), 1)
            self.assertEqual((result[0].component, result[0].status), ('tool:opengrep', 'fail'))
            self.assertEqual(result[0].detail, 'official release request refused: source=github-api status=403 reason=quota-exhausted endpoint=latest-release remaining=0 reset=1795020000 retry_after=120')
            self.assertEqual(opened.call_count, 1, 'refusals must not retry')
            self.assertFalse(list(root.iterdir()), 'refusal must not activate or cache anything')
        self.assertTrue(body.closed)

    def test_forbidden_is_not_exhausted_without_valid_zero_and_429_is_distinct(self):
        for status, headers, reason in (
            (403, (), 'forbidden'),
            (403, (('X-RateLimit-Remaining', '5'), ('Retry-After', '60')), 'forbidden'),
            (429, (), 'rate-limited'),
        ):
            with self.subTest(status=status, headers=headers):
                error, body = self.refusal(status, headers, reason='rate limit exceeded private reason marker')
                detail = self.observed_refusal(error)
                self.assertIn(f'status={status} reason={reason}', detail)
                self.assertNotIn('quota-exhausted', detail)
                for secret in ('private', 'rate limit exceeded', 'https://'):
                    self.assertNotIn(secret, detail)
                self.assertTrue(body.closed)
        error, body = self.refusal(403)
        detail = self.observed_refusal(error, 'https://github.com/owned/tool/releases/download/v1/owned')
        self.assertEqual(detail, 'official release request refused: source=official-release status=403 reason=forbidden endpoint=release-asset')
        self.assertTrue(body.closed)

    def test_invalid_duplicate_and_hostile_budget_headers_do_not_escape(self):
        for value in ('-1', '+1', ' 0', '0 ', '٠', 'private-header-marker', '9'*20, str(2**63)):
            with self.subTest(value=value):
                error, body = self.refusal(403, tuple((name, value) for name in (
                    'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'Retry-After')))
                self.assertEqual(self.observed_refusal(error), 'official release request refused: source=github-api status=403 reason=forbidden endpoint=latest-release')
                self.assertTrue(body.closed)
        error, body = self.refusal(403, (
            ('X-RateLimit-Remaining', '0'), ('x-ratelimit-remaining', '5'),
            ('X-RateLimit-Reset', '10'), ('X-RateLimit-Reset', '20'),
            ('Retry-After', '1'), ('retry-after', '2')))
        self.assertEqual(self.observed_refusal(error), 'official release request refused: source=github-api status=403 reason=forbidden endpoint=latest-release')
        self.assertTrue(body.closed)
        error, body = self.refusal(403, (('X-RateLimit-Reset', str(2**63-1)),))
        self.assertIn(f'reset={2**63-1}', self.observed_refusal(error))
        self.assertTrue(body.closed)

    def test_unpublished_tag_404_keeps_original_exception_semantics(self):
        error, body = self.refusal(404)
        with patch.object(updater._RELEASE_OPENER, 'open', side_effect=error):
            with self.assertRaises(HTTPError) as caught:
                updater._release_fetch('https://api.github.com/repos/owned/tool/releases/tags/v2.0.0')
        self.assertIs(caught.exception, error)
        self.assertEqual(caught.exception.code, 404)
        error.close()
        self.assertTrue(body.closed)

        from getzilla.latest_releases import github_release
        error, body = self.refusal(404)

        def fetch(url):
            if url.endswith('/releases/latest'):
                return json.dumps(dict(tag_name='v1.0.0', draft=False, prerelease=False)).encode()
            if url.endswith('/git/matching-refs/tags/'):
                return json.dumps([dict(ref='refs/tags/v1.0.0'), dict(ref='refs/tags/v2.0.0')]).encode()
            return updater._release_fetch(url)

        with patch.object(updater._RELEASE_OPENER, 'open', side_effect=error) as opened:
            self.assertEqual(github_release('owned/tool', fetch)['version'], '1.0.0')
            self.assertEqual(opened.call_count, 1)
        error.close()
        self.assertTrue(body.closed)

    def test_endpoint_kinds_are_closed_and_never_echo_request_data(self):
        for url, endpoint in (
            ('https://api.github.com/repos/owned/tool/releases/latest', 'latest-release'),
            ('https://api.github.com/repos/owned/tool/git/matching-refs/tags/', 'tag-refs'),
            ('https://api.github.com/repos/owned/tool/releases/tags/v1.0.0', 'tagged-release'),
            ('https://github.com/owned/tool/releases/download/v1.0.0/owned', 'release-asset'),
            ('https://api.github.com/private-path-marker?private-query-marker=private-token-marker', 'other'),
            ('https://api.github.com/repos/owned/tool/releases/latest/private-suffix-marker', 'other'),
        ):
            with self.subTest(endpoint=endpoint, url=url):
                error, body = self.refusal(403)
                detail = self.observed_refusal(error, url)
                self.assertIn('endpoint=' + endpoint, detail)
                for marker in ('private', 'https://', 'owned', 'v1.0.0'):
                    self.assertNotIn(marker, detail)
                self.assertTrue(body.closed)

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
