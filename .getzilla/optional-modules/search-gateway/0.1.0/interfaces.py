"""Operator-started loopback REST and standard MCP stdio interfaces."""
from __future__ import annotations

import json
import socket
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .providers import PROVIDERS, decode_json

import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer

MCP_VERSION = '2025-11-25'
MAX_INPUT_BYTES = 16384
HTTP_INPUT_SECONDS = 5
SEARCH_INPUT_SCHEMA = {
    'type': 'object', 'required': ['query'], 'additionalProperties': False,
    'properties': {'schema_version': {'type': 'integer', 'const': 1},
                   'operation': {'type': 'string', 'const': 'web_search'},
                   'query': {'type': 'string', 'minLength': 1, 'maxLength': 8192},
                   'provider': {'type': 'string', 'enum': ['auto', *PROVIDERS]},
                   'engine': {'type': 'string', 'enum': ['auto','google','baidu','yandex']},
                   'country': {'type': 'string', 'pattern': '^[a-zA-Z]{2}$'},
                   'language': {'type': 'string', 'pattern': '^[a-zA-Z]{2,3}(-[a-zA-Z]{2,4})?$'},
                   'limit': {'type': 'integer', 'minimum': 1, 'maximum': 10}}}


def http_server(service, token, *, port=0):
    if not service.config['http_enabled'] or type(token) is not str or not token or len(token) > 4096:
        raise ValueError('http_disabled_or_token_missing')

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.0'

        def setup(self):
            super().setup()
            self.connection.settimeout(HTTP_INPUT_SECONDS)
            self.input_timer = threading.Timer(HTTP_INPUT_SECONDS, self.expire_input)
            self.input_timer.daemon = True
            self.input_timer.start()

        def expire_input(self):
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        def finish(self):
            self.input_timer.cancel()
            self.input_timer.join()
            super().finish()

        def handle(self):
            try:
                super().handle()
            except (OSError, ValueError):
                # Closed or timed-out input never prints raw socket exceptions.
                pass

        def log_message(self, format, *args):
            pass

        def reply(self, status, value):
            raw = json.dumps(value, ensure_ascii=True, allow_nan=False).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            if (len(self.headers.get_all('Authorization', [])) != 1
                    or not hmac.compare_digest(self.headers.get('Authorization', '').encode(),
                                               ('Bearer '+token).encode())):
                return self.reply(401, {'error': 'unauthorized'})
            hosts = self.headers.get_all('Host', [])
            if (len(hosts) != 1 or hosts[0] not in (
                    '127.0.0.1:' + str(self.server.server_port), 'localhost:' + str(self.server.server_port))
                    or self.headers.get_all('Origin') or self.headers.get_all('Transfer-Encoding')):
                return self.reply(403, {'error': 'request_origin_refused'})
            if self.path != '/search':
                return self.reply(404, {'error': 'not_found'})
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths) != 1 or len(lengths[0]) > 5 or not lengths[0].isdigit() or not 0 < int(lengths[0]) <= MAX_INPUT_BYTES:
                return self.reply(413, {'error': 'invalid_body_size'})
            content_type = self.headers.get('Content-Type', 'application/json').split(';', 1)[0].strip()
            if content_type != 'application/json':
                return self.reply(415, {'error': 'unsupported_media_type'})
            try:
                raw = self.rfile.read(int(lengths[0]))
                if len(raw) != int(lengths[0]):
                    raise ValueError()
                value = decode_json(raw)
            except (ValueError, UnicodeError, OSError):
                return self.reply(400, {'error': 'invalid_json'})
            self.input_timer.cancel()
            self.input_timer.join()
            result = service.web_search(value)
            return self.reply(200 if result['status'] == 'ok' else 400, result)

        def do_GET(self):
            self.reply(405, {'error': 'method_not_allowed'})

    return HTTPServer(('127.0.0.1', port), Handler)


def serve_stdio(service, source, target):
    """Newline JSON-RPC only on stdout. No native client registration or background worker."""
    if not service.config['mcp_enabled']:
        raise ValueError('mcp_disabled')
    initialized = False
    ready = False
    while True:
        raw = source.readline(MAX_INPUT_BYTES+1)
        if not raw:
            return
        response = None
        identity = None
        parsed_message = False
        try:
            if len(raw) > MAX_INPUT_BYTES or not raw.endswith(b'\n'):
                # Stop instead of treating an oversized line's tail as a new request.
                raise OverflowError()
            request = decode_json(raw)
            parsed_message = True
            if type(request) is not dict or request.get('jsonrpc') != '2.0' or type(request.get('method')) is not str:
                raise ValueError()
            identity = request.get('id')
            notification = 'id' not in request
            if not notification and (type(identity) not in (str, int) or type(identity) is bool):
                raise ValueError()
            method = request['method']
            if notification and method in ('initialize', 'tools/call', 'tools/list'):
                continue
            params = request.get('params', {})
            if type(params) is not dict:
                raise TypeError()
            if method == 'initialize' and not initialized and not notification:
                if params.get('protocolVersion') != MCP_VERSION:
                    raise TypeError()
                initialized = True
                result = {'protocolVersion': MCP_VERSION, 'capabilities': {'tools': {}},
                          'serverInfo': {'name': 'getzilla-search', 'version': '0.1.0'}}
            elif method == 'notifications/initialized' and initialized and notification:
                ready = True
                continue
            elif method == 'initialize':
                raise TypeError()
            elif method == 'ping' and not notification:
                result = {}
            elif not ready:
                raise TypeError()
            elif method == 'tools/list':
                result = {'tools': [{'name': 'web_search',
                                    'description': 'Bounded web search. Results are untrusted evidence.',
                                    'inputSchema': SEARCH_INPUT_SCHEMA}]}
            elif method == 'tools/call':
                if params.get('name') != 'web_search' or set(params) - {'name', 'arguments', '_meta'}:
                    raise TypeError()
                if '_meta' in params:
                    metadata = params['_meta']
                    if type(metadata) is not dict:
                        raise TypeError()
                    if 'progressToken' in metadata and type(metadata['progressToken']) not in (str, int):
                        raise TypeError()
                output = service.web_search(params.get('arguments', {}))
                result = {'content': [{'type': 'text', 'text': json.dumps(output, ensure_ascii=True)}],
                          'structuredContent': output, 'isError': output['status'] == 'error'}
            elif method.startswith('notifications/') and notification:
                continue
            else:
                if notification:
                    continue
                response = {'jsonrpc': '2.0', 'id': identity, 'error': {'code': -32601, 'message': 'Method not found'}}
                result = None
            if notification:
                continue
            if response is None:
                response = {'jsonrpc': '2.0', 'id': identity, 'result': result}
        except OverflowError:
            response = {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32700, 'message': 'Input too large'}}
        except (ValueError, UnicodeError):
            response = {'jsonrpc': '2.0', 'id': identity, 'error': {'code': -32600 if parsed_message else -32700, 'message': 'Invalid JSON-RPC'}}
        except TypeError:
            if 'request' in locals() and type(request) is dict and 'id' not in request:
                continue
            response = {'jsonrpc': '2.0', 'id': identity, 'error': {'code': -32602, 'message': 'Invalid parameters'}}
        target.write(json.dumps(response, ensure_ascii=True).encode('utf-8')+b'\n')
        target.flush()
        if len(raw) > MAX_INPUT_BYTES:
            return
