from __future__ import annotations

import unittest
import time
import sys
import tempfile
import os
import io
import json
from pathlib import Path
import urllib.error
from types import SimpleNamespace
from unittest import mock

from adaptive_trust_ci.github import GitHubError, UrllibTransport
from adaptive_trust_ci.http_response import MAX_RESPONSE_BYTES, ResponseLimitError, read_response, exchange, _run_owned, request_bytes, _worker


class SizedStream:
    """Owned bytes only. No network or executable effects; unbounded reads fail."""

    status = 200

    def __init__(self, payload: bytes):
        self.payload = payload
        self.closed = False
        self.fp = SimpleNamespace(raw=SimpleNamespace(_sock=SimpleNamespace(
            settimeout=lambda value: None, shutdown=lambda how: None)))

    def read(self, size=-1):
        if size < 0:
            raise AssertionError('unbounded transport read')
        return self.read1(size)

    def read1(self, size):
        if size <= 0:
            raise AssertionError('invalid read bound')
        block, self.payload = self.payload[:size], self.payload[size:]
        return block

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class HttpResponseLimitTests(unittest.TestCase):
    def test_fixed_worker_ignores_pythonpath_startup_code(self):
        import urllib.request

        runtime = Path(__file__).resolve().parents[2] / '.getzilla/runtime'
        runtime.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=runtime) as directory:
            canary = Path(directory) / 'startup-executed'
            (Path(directory) / 'sitecustomize.py').write_text(
                f'from pathlib import Path; Path({str(canary)!r}).write_text("executed")\n')

            def empty_input_worker(command, payload, *, deadline):
                # Real owned worker launch, but invalid input stops before urllib.
                return _run_owned(command, b'', deadline=deadline)

            with mock.patch.dict(os.environ, {'PYTHONPATH': directory}), \
                    mock.patch('adaptive_trust_ci.http_response._run_owned',
                               side_effect=empty_input_worker), \
                    self.assertRaisesRegex(ResponseLimitError, 'worker failed'):
                request_bytes(urllib.request.Request('https://fixture.invalid'))
            self.assertFalse(canary.exists(), 'ambient sitecustomize ran before the fixed worker')

    def error_exchange(self, request, error):
        def opener(*args, **kwargs):
            raise error
        return exchange(request, opener=opener, deadline=time.monotonic() + 30)

    def test_owned_worker_open_stall_is_killed_and_reaped(self):
        runtime = Path(__file__).resolve().parents[2] / '.getzilla/runtime'
        runtime.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=runtime) as directory:
            pid_file = Path(directory) / 'pid'
            command = [sys.executable, '-c',
                       'import os,sys,time; open(sys.argv[1], "w").write(str(os.getpid())); time.sleep(5)',
                       str(pid_file)]
            started = time.monotonic()
            with self.assertRaisesRegex(ResponseLimitError, 'effect unknown'):
                _run_owned(command, b'{}', deadline=started + 0.5)
            self.assertLess(time.monotonic() - started, 1.5)
            pid = int(pid_file.read_text())
            with self.assertRaises(ChildProcessError):
                os.waitpid(pid, os.WNOHANG)

    def test_owned_worker_small_output_and_failure(self):
        command = [sys.executable, '-c', 'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read(8))']
        self.assertEqual(_run_owned(command, b'owned', deadline=time.monotonic() + 2), b'owned')
        with self.assertRaisesRegex(ResponseLimitError, 'effect unknown'):
            _run_owned([sys.executable, '-c', 'raise SystemExit(1)'], b'', deadline=time.monotonic() + 2)

    def test_parent_validates_bounded_worker_status_and_body(self):
        import urllib.request
        request = urllib.request.Request('https://fixture.invalid')
        with mock.patch('adaptive_trust_ci.http_response._run_owned', return_value=b'{"status":200,"body":"e30="}'):
            self.assertEqual(request_bytes(request), (200, b'{}'))
        with mock.patch('adaptive_trust_ci.http_response._run_owned', return_value=b'{"status":true,"body":"e30="}'), \
                self.assertRaisesRegex(ResponseLimitError, 'IPC'):
            request_bytes(request)

    def test_fixed_worker_request_and_reply_protocol_without_network(self):
        payload = json.dumps({'method': 'POST', 'url': 'https://fixture.invalid',
                              'headers': {'X-Fixture': 'owned'}, 'body': 'e30=',
                              'seconds': 1}).encode()
        output = io.BytesIO()

        def owned_exchange(request, *, deadline):
            self.assertEqual(request.get_method(), 'POST')
            self.assertEqual(request.full_url, 'https://fixture.invalid')
            self.assertEqual(request.data, b'{}')
            self.assertEqual(request.get_header('X-fixture'), 'owned')
            self.assertGreater(deadline, time.monotonic())
            return 201, b'{"ok":true}'

        with mock.patch.object(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(payload))), \
                mock.patch.object(sys, 'stdout', SimpleNamespace(buffer=output)):
            self.assertEqual(_worker(exchange_request=owned_exchange), 0)
        self.assertEqual(json.loads(output.getvalue()), {'status': 201, 'body': 'eyJvayI6dHJ1ZX0='})

    def test_small_success_never_uses_unbounded_read(self):
        response = SizedStream(b'{"ok":true}')
        with mock.patch('adaptive_trust_ci.github.request_bytes', side_effect=lambda req, **kw: exchange(req, opener=lambda *a, **k: response, deadline=time.monotonic() + 30)):
            self.assertEqual(UrllibTransport().request('GET', 'https://fixture.invalid', {}),
                             (200, {'ok': True}))
        self.assertTrue(response.closed)

    def test_exact_limit_and_limit_plus_one_without_content_length(self):
        self.assertEqual(read_response(SizedStream(b'12345678'), deadline=100,
                                       maximum=8, clock=lambda: 0), b'12345678')
        with self.assertRaisesRegex(ResponseLimitError, 'byte budget'):
            read_response(SizedStream(b'123456789'), deadline=100, maximum=8, clock=lambda: 0)

    def test_chunked_reader_accounts_for_all_bytes(self):
        class Fragments(SizedStream):
            def read1(self, size):
                return super().read1(min(size, 2))

        self.assertEqual(read_response(Fragments(b'12345678'), deadline=100,
                                       maximum=8, clock=lambda: 0), b'12345678')
        with self.assertRaisesRegex(ResponseLimitError, 'byte budget'):
            read_response(Fragments(b'123456789'), deadline=100, maximum=8, clock=lambda: 0)

    def test_http_error_small_body_decodes_and_closes(self):
        response = SizedStream(b'{"message":"denied"}')
        error = urllib.error.HTTPError('https://fixture.invalid', 403, 'denied', {}, response)
        with mock.patch('adaptive_trust_ci.github.request_bytes', side_effect=lambda req, **kw: self.error_exchange(req, error)):
            self.assertEqual(UrllibTransport().request('GET', 'https://fixture.invalid', {}),
                             (403, {'message': 'denied'}))
        self.assertTrue(response.closed)

    def test_http_error_oversize_keeps_primary_status(self):
        response = SizedStream(b'x' * (MAX_RESPONSE_BYTES + 1))
        error = urllib.error.HTTPError('https://fixture.invalid', 429, 'limited', {}, response)
        with mock.patch('adaptive_trust_ci.github.request_bytes', side_effect=lambda req, **kw: self.error_exchange(req, error)):
            status, payload = UrllibTransport().request('GET', 'https://fixture.invalid', {})
        self.assertEqual(status, 429)
        self.assertIn('byte budget', payload)
        self.assertTrue(response.closed)

    def test_success_oversize_fails_and_closes(self):
        response = SizedStream(b'x' * (MAX_RESPONSE_BYTES + 1))
        with mock.patch('adaptive_trust_ci.github.request_bytes', side_effect=lambda req, **kw: exchange(req, opener=lambda *a, **k: response, deadline=time.monotonic() + 30)), \
                self.assertRaisesRegex(GitHubError, 'byte budget'):
            UrllibTransport().request('GET', 'https://fixture.invalid', {})
        self.assertTrue(response.closed)

    def test_small_success_empty_array_and_text_decoding(self):
        for body, want in ((b'', {}), (b'[1]', {'value': [1]}), (b'bad JSON', 'bad JSON')):
            with self.subTest(body=body), \
                    mock.patch('adaptive_trust_ci.github.request_bytes',
                               side_effect=lambda req, **kw: exchange(req, opener=lambda *a, **k: SizedStream(body), deadline=time.monotonic() + 30)):
                self.assertEqual(UrllibTransport().request('GET', 'https://fixture.invalid', {}),
                                 (200, want))

    def test_slow_fragments_exhaust_one_total_budget(self):
        elapsed = [0.0]

        class SlowFragments(SizedStream):
            def read1(self, size):
                elapsed[0] += 0.4
                return super().read1(min(size, 1))

        with self.assertRaisesRegex(ResponseLimitError, 'elapsed budget'):
            read_response(SlowFragments(b'12345678'), deadline=1, maximum=8,
                          clock=lambda: elapsed[0])

    def test_deadline_interrupts_blocking_chunk_framing(self):
        elapsed, stopped = [0.0], []
        callbacks = []

        class OwnedTimer:
            def __init__(self, delay, callback):
                callbacks.append(callback)

            def start(self):
                pass

            def cancel(self):
                pass

            def join(self):
                pass

        class FramingStream(SizedStream):
            def read1(self, size):
                # A chunk framing read may perform several receives internally.
                elapsed[0] = 1
                callbacks[0]()
                return b''

        response = FramingStream(b'')
        response.fp.raw._sock.shutdown = lambda how: stopped.append(how)
        with mock.patch('adaptive_trust_ci.http_response.threading.Timer', OwnedTimer), \
                self.assertRaisesRegex(ResponseLimitError, 'elapsed budget'):
            read_response(response, deadline=1, clock=lambda: elapsed[0])
        self.assertEqual(len(stopped), 1)

    def test_unqualified_stream_refused_before_read(self):
        response = SizedStream(b'unchanged')
        response.fp = None
        with self.assertRaisesRegex(ResponseLimitError, 'capability'):
            read_response(response, deadline=100, clock=lambda: 0)
        self.assertEqual(response.payload, b'unchanged')

    def test_already_elapsed_deadline_refuses_before_read(self):
        response = SizedStream(b'unchanged')
        with self.assertRaisesRegex(ResponseLimitError, 'elapsed budget'):
            read_response(response, deadline=1, clock=lambda: 1)
        self.assertEqual(response.payload, b'unchanged')


if __name__ == '__main__':
    unittest.main()
