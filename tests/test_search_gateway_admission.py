"""Real module-ledger, CLI, transport and installer tests with public local fixtures only."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

from tests.test_search_gateway import ROOT, ARTIFACT, engine, policy, payload

sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.component_state import MANIFEST, V2, encode_manifest, record_owned
from getzilla.optional_modules import admit_module, manage_modules


def wrapper():
    path = ROOT / 'scripts/getzilla_search_gateway.py'
    if not path.is_file():
        raise AssertionError('admitted search wrapper is missing')
    spec = importlib.util.spec_from_file_location('search_wrapper_fixture', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AdmissionAndPackaging(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'project'
        core = self.root / '.getzilla/getzilla/__init__.py'
        core.parent.mkdir(parents=True)
        core.write_bytes(b'# public fixture core\n')
        manifest = {'schema_version': V2, 'agents': [], 'components': {}}
        record_owned(manifest, '.getzilla/getzilla/__init__.py', core.read_bytes(), 0o644)
        (self.root / MANIFEST).write_bytes(encode_manifest(manifest))
        self.w = wrapper()

    def install(self):
        return manage_modules(self.root, 'install', {'search-gateway': '0.1.0'}, source=ROOT)

    def enable(self):
        self.install()
        manage_modules(self.root, 'enable', {'search-gateway': None}, grants=['search.web'])

    def test_installs_disabled_without_loading_and_preserves_native_client_bytes(self):
        native = self.root / '.mcp.json'
        native.write_bytes(b'{"mcpServers":{"foreign":{}}}\n')
        self.install()
        with patch.object(self.w, '_load', side_effect=AssertionError('must not load')):
            with self.assertRaises(ValueError):
                self.w.create_gateway(self.root, policy())
        self.assertEqual(native.read_bytes(), b'{"mcpServers":{"foreign":{}}}\n')
        self.assertFalse(admit_module(self.root, 'search-gateway')['allowed'])

    def test_admitted_wrapper_checks_tamper_and_revocation_before_cached_result(self):
        self.enable()
        calls = []
        def send(r,t):
            calls.append(r['provider'])
            return 200, {}, json.dumps(payload()).encode()
        service = self.w.create_gateway(self.root, policy(), transport=send)
        self.assertEqual(service.web_search({'query':'a'})['status'], 'ok')
        manage_modules(self.root, 'disable', {'search-gateway': None})
        self.assertEqual(service.web_search({'query':'a'})['error'], 'module_unavailable')
        self.assertEqual(calls, ['serper'])
        manage_modules(self.root, 'enable', {'search-gateway': None}, grants=['search.web'])
        target = self.root / '.getzilla/modules/search-gateway/providers.py'
        target.write_bytes(target.read_bytes()+b'\n# tampered\n')
        self.assertEqual(service.web_search({'query':'b'})['error'], 'module_unavailable')
        with self.assertRaises(ValueError):
            self.w.create_gateway(self.root, policy())

    def test_default_core_payload_excludes_artifacts_and_explicit_bundle_roundtrips(self):
        spec = importlib.util.spec_from_file_location('search_install_fixture', ROOT / 'scripts/install_into.py')
        install = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = install
        spec.loader.exec_module(install)
        selection = install.PayloadSelection(('codex',))
        self.assertFalse(selection.includes('.getzilla/optional-modules/search-gateway/0.1.0/providers.py'))
        selection = install.PayloadSelection(('codex',), search_gateway=True)
        self.assertTrue(selection.includes('.getzilla/optional-modules/search-gateway/0.1.0/providers.py'))
        entries = install.build_payload(ROOT, selection=selection)
        actual = {item.path: item.content for item in entries}
        self.assertEqual(actual['.getzilla/optional-modules/search-gateway/0.1.0/providers.py'], (ARTIFACT / 'providers.py').read_bytes())

    def test_cli_and_stdio_subprocess_make_only_real_loopback_search_requests(self):
        self.enable()
        calls = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                calls.append(self.path)
                raw = json.dumps(payload('searxng')).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            def log_message(self, *args):
                pass
        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            config = policy(('searxng',), mcp_enabled=True)
            config['providers'][0]['endpoint'] = 'http://127.0.0.1:' + str(server.server_port) + '/search'
            path = self.root / 'operator-search.json'
            path.write_text(json.dumps(config), encoding='utf-8')
            os.chmod(path, 0o600)
            command = [sys.executable, str(ROOT / 'scripts/getzilla_search_gateway.py'), '--root', str(self.root)]
            cli = subprocess.run([*command, 'query', '--policy', str(path), '--query', '任何代理 missing context'],
                                 capture_output=True, timeout=10)
            self.assertEqual(cli.returncode, 0, cli.stderr)
            self.assertEqual(json.loads(cli.stdout)['status'], 'ok')
            messages = [{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25'}},
                        {'jsonrpc':'2.0','method':'notifications/initialized'},
                        {'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'web_search','arguments':{'query':'any question'}}}]
            process = subprocess.run([*command, 'mcp-stdio', '--policy', str(path)],
                                     input=b''.join(json.dumps(r).encode()+b'\n' for r in messages),
                                     capture_output=True, timeout=10)
            self.assertEqual(process.returncode, 0, process.stderr)
            replies = [json.loads(line) for line in process.stdout.splitlines()]
            self.assertEqual(replies[1]['result']['structuredContent']['status'], 'ok')
            self.assertEqual(len(calls), 2)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)


class RealGuardedTransport(unittest.TestCase):
    def test_slow_trickle_headers_stop_at_total_deadline_and_keep_reservation(self):
        m = engine()
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                try:
                    for byte in b'HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}':
                        self.connection.sendall(bytes([byte]))
                        time.sleep(0.02)
                except OSError:
                    pass
            def log_message(self, *args):
                pass
        server = HTTPServer(('127.0.0.1',0),Handler)
        thread = threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            config = policy(('searxng',), timeout_seconds=0.15)
            config['providers'][0]['endpoint'] = 'http://127.0.0.1:'+str(server.server_port)+'/search'
            started = time.monotonic()
            result = m.Gateway(config, admission=lambda:True).web_search({'query':'a'})
            self.assertLess(time.monotonic()-started,0.7)
            self.assertEqual(result['usage']['attempted_calls'],1)
            self.assertEqual(result['usage']['reserved_estimated_cost_microusd'],10)
            self.assertEqual(result['attempts'][0]['outcome'],'timeout')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)

    def test_resolution_after_deadline_sends_no_provider_bytes(self):
        m = engine()
        sent = []
        class Connection:
            sock = None
            def __init__(self,*args,**kwargs):
                pass
            def connect(self):
                time.sleep(0.08)
            def request(self,*args,**kwargs):
                sent.append(args)
            def close(self):
                pass
        request = m.provider_request(policy(('searxng',))['providers'][0], m.validate_request({'query':'a'}))
        with patch.object(m.http.client, 'HTTPConnection', Connection):
            with self.assertRaises(TimeoutError):
                m.guarded_transport(request,0.02)
        self.assertEqual(sent,[])

    def test_slow_trickle_body_stops_at_deadline(self):
        m = engine()
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length','100')
                self.end_headers()
                try:
                    for _ in range(100):
                        self.wfile.write(b' ')
                        self.wfile.flush()
                        time.sleep(0.02)
                except OSError:
                    pass
            def log_message(self,*args):
                pass
        server = HTTPServer(('127.0.0.1',0),Handler)
        thread = threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            config = policy(('searxng',), timeout_seconds=0.15)
            config['providers'][0]['endpoint'] = 'http://127.0.0.1:'+str(server.server_port)+'/search'
            started = time.monotonic()
            result = m.Gateway(config,admission=lambda:True).web_search({'query':'a'})
            self.assertLess(time.monotonic()-started,0.7)
            self.assertEqual(result['attempts'][0]['outcome'],'timeout')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)

    def test_refuses_redirect_and_oversized_reply_without_second_request(self):
        m = engine()
        for mode in ('redirect', 'large', '500', '429'):
            calls = []
            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    calls.append(self.path)
                    self.send_response(302 if mode == 'redirect' else int(mode) if mode.isdigit() else 200)
                    if mode == 'redirect':
                        self.send_header('Location', 'http://127.0.0.1:1/key-leak')
                    if mode == 'large':
                        self.send_header('Content-Length', str(m.MAX_RESPONSE_BYTES+1))
                    else:
                        self.send_header('Content-Length', '2')
                    self.end_headers()
                    if mode != 'large':
                        self.wfile.write(b'{}')
                def log_message(self, *args):
                    pass
            server = HTTPServer(('127.0.0.1', 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                config = policy(('searxng',))
                config['providers'][0]['endpoint'] = 'http://127.0.0.1:'+str(server.server_port)+'/search'
                service = m.Gateway(config, admission=lambda:True)
                result = service.web_search({'query':'a'})
                self.assertEqual(result['attempts'][0]['outcome'],
                                 {'redirect':'redirect_refused','large':'response_too_large','500':'upstream_error','429':'rate_limited'}[mode])
                self.assertEqual(calls, ['/search?q=a&format=json'])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(3)
