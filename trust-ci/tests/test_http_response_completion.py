"""Real HTTPResponse framing over owned memory; no network or external process."""
import errno
import http.client
import io
import time
import unittest
from types import SimpleNamespace

from adaptive_trust_ci.http_response import ResponseLimitError, read_response


class MemorySocket:
    def __init__(self, wire):
        self.closed = False
        owner = self
        class Stream(io.BytesIO):
            raw = SimpleNamespace(_sock=owner)
            def close(self):
                owner.closed = True
                super().close()
        self.stream = Stream(wire)

    def makefile(self, *args, **kwargs):
        return self.stream

    def settimeout(self, value):
        if self.closed:
            raise OSError(errno.EBADF, 'owned closed socket')

    def shutdown(self, how):
        self.closed = True


class ResponseCompletionTests(unittest.TestCase):
    def read(self, body, advertised):
        length = b'' if advertised is None else b'Content-Length: '+str(advertised).encode()+b'\r\n'
        sock = MemorySocket(b'HTTP/1.0 200 OK\r\n'+length+b'\r\n'+body)
        with http.client.HTTPResponse(sock) as response:
            response.begin()
            return read_response(response, deadline=time.monotonic()+2)

    def test_completed_length_closes_socket_before_the_final_eof_read(self):
        body = b'{"owned":true}'
        self.assertEqual(self.read(body, len(body)), body)

    def test_truncated_length_never_admits_complete_looking_json(self):
        body = b'{"owned":true}'
        with self.assertRaisesRegex(ResponseLimitError, 'truncated'):
            self.read(body, len(body)+9)

    def test_close_delimited_response_still_accepts_real_eof(self):
        self.assertEqual(self.read(b'{"owned":true}', None), b'{"owned":true}')
