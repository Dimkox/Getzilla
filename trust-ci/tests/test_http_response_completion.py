"""Production exchange framing against a bounded owned HTTP/1.0 loopback server."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import threading
import time
import unittest
import urllib.request
from unittest import mock

from adaptive_trust_ci.http_response import ResponseLimitError, exchange


class ResponseCompletionTests(unittest.TestCase):
    def read(self, body, advertised):
        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.0'

            def log_message(self, *args):
                pass

            def do_GET(self):
                self.send_response(200)
                if advertised is not None:
                    self.send_header('Content-Length', str(advertised))
                self.end_headers()
                self.wfile.write(body)
                self.wfile.flush()
                self.close_connection = True

        with HTTPServer(('127.0.0.1', 0), Handler) as server:
            server.timeout = 2
            worker = threading.Thread(target=server.handle_request)
            worker.start()
            try:
                request = urllib.request.Request('http://127.0.0.1:'+str(server.server_port)+'/owned')
                proxies = {key: '' for key in ('http_proxy', 'https_proxy', 'all_proxy',
                                               'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY')}
                proxies.update(NO_PROXY='127.0.0.1,localhost', no_proxy='127.0.0.1,localhost')
                with mock.patch.dict(os.environ, proxies):
                    status, result = exchange(request, deadline=time.monotonic()+2)
                self.assertEqual(status, 200)
                return result
            finally:
                worker.join(3)
                self.assertFalse(worker.is_alive(), 'owned one-request server did not stop')

    def test_completed_length_closes_socket_before_the_final_eof_read(self):
        body = b'{"owned":true}'
        self.assertEqual(self.read(body, len(body)), body)

    def test_truncated_length_never_admits_complete_looking_json(self):
        body = b'{"owned":true}'
        with self.assertRaisesRegex(ResponseLimitError, 'truncated'):
            self.read(body, len(body)+9)

    def test_close_delimited_response_still_accepts_real_eof(self):
        self.assertEqual(self.read(b'{"owned":true}', None), b'{"owned":true}')
