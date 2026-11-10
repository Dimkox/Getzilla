"""Offline contracts and real local interfaces for optional universal search."""
from __future__ import annotations

import io
import json
from pathlib import Path
import socket
import threading
import types
import unittest
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / '.getzilla/optional-modules/search-gateway/0.1.0'


def engine():
    module = types.ModuleType('search_fixture')
    for name in ('providers.py', 'gateway.py', 'interfaces.py'):
        path = ARTIFACT / name
        if not path.exists():
            raise AssertionError('universal search implementation is missing: ' + name)
        exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


def policy(names=('serper',), **updates):
    value = {'schema_version': 1, 'live_enabled': True, 'project': 'public-test',
             'max_attempts': 2, 'max_estimated_cost_microusd': 20, 'timeout_seconds': 5,
             'cache_ttl_seconds': 60, 'cache_entries': 4, 'cache_bytes': 100000,
             'http_enabled': False, 'mcp_enabled': False,
             'providers': [{'id': name, 'credential': 'synthetic-key',
                            'estimated_unit_cost_microusd': 10,
                            **({'endpoint': 'http://127.0.0.1:18765/search'} if name == 'searxng' else {})}
                           for name in names]}
    value.update(updates)
    return value


def payload(name='serper', rows=None):
    rows = rows if rows is not None else [{'title': 'Evidence', 'url': 'https://example.org/a',
                                          'link': 'https://example.org/a', 'snippet': 'untrusted text',
                                          'content': 'untrusted text', 'description': 'untrusted text'}]
    return {'searxng': {'results': rows}, 'serper': {'organic': rows}, 'serpapi': {'organic_results': rows},
            'brave': {'web': {'results': rows}}, 'tavily': {'results': rows},
            'firecrawl': {'success': True, 'data': {'web': rows}}, 'scrapingdog': {'organic_results': rows}}[name]


class SearchBehavior(unittest.TestCase):
    def setUp(self):
        self.m = engine()
        self.calls = []
        self.allowed = True
        self.now = 100.0

    def send(self, request, timeout):
        self.calls.append((request, timeout))
        return 200, {}, json.dumps(payload(request['provider'])).encode()

    def service(self, config=None, send=None):
        return self.m.Gateway(config or policy(), admission=lambda: self.allowed,
                              transport=send or self.send, clock=lambda: self.now)

    def test_arbitrary_multilingual_queries_preserve_text_and_provenance(self):
        for query in ('Python traceback\nValueError: bad token', '为什么连接失败', 'Поиск документации', 'भारत में खोज'):
            with self.subTest(query=query):
                result = self.service().web_search({'query': query})
                self.assertEqual(result['status'], 'ok')
                self.assertEqual(result['query'], query)
                source = result['results'][0]['provenance'][0]
                self.assertEqual(source['query'], query)
                self.assertTrue(source['untrusted'])
                self.assertEqual(source['engine'], 'google')
                self.assertIsNone(result['usage']['actual_cost_microusd'])

    def test_authority_and_invalid_input_are_rejected_before_transport(self):
        for request in ({'query': 'a', 'endpoint': 'https://evil.invalid'}, {'query': 'a', 'project': 'other'},
                        {'query': 'a', 'budget': {}}, {'query': 'a', 'credential': 'x'},
                        {'query': ''}, {'query': 'a\x00b'}, {'query': 'x'*8193},
                        {'query': 'a', 'limit': True}, {'query': 'a', 'engine': 'bing'},
                        {'query': 'a', 'schema_version': 2}):
            with self.subTest(request=request):
                self.assertEqual(self.service().web_search(request)['error'], 'invalid_request')
        self.assertEqual(self.calls, [])

    def test_engine_selection_never_widens_and_unsupported_locale_fails(self):
        service = self.service(policy(('serper', 'brave')))
        self.assertEqual(service.web_search({'query': 'a', 'engine': 'baidu'})['error'], 'no_eligible_provider')
        self.assertEqual(service.web_search({'query': 'a', 'engine': 'yandex'})['error'], 'no_eligible_provider')
        self.assertEqual(service.web_search({'query': 'a', 'country': 'in', 'language': 'hi', 'provider': 'brave'})['error'], 'no_eligible_provider')
        self.assertEqual(self.calls, [])

    def test_serpapi_engine_specific_query_and_india_hindi_parameters(self):
        for selected, query_key in (('google', 'q'), ('baidu', 'q'), ('yandex', 'text')):
            with self.subTest(engine=selected):
                service = self.service(policy(('serpapi',)))
                result = service.web_search({'query': 'Тест 中文', 'engine': selected})
                self.assertEqual(result['status'], 'ok')
                params = parse_qs(urlsplit(self.calls[-1][0]['url']).query)
                self.assertEqual(params['engine'], [selected])
                self.assertEqual(params[query_key], ['Тест 中文'])
                self.assertEqual(result['results'][0]['provenance'][0]['engine'], selected)
        self.service(policy(('serpapi',))).web_search({'query': 'भारत', 'engine': 'google', 'country': 'in', 'language': 'hi'})
        params = parse_qs(urlsplit(self.calls[-1][0]['url']).query)
        self.assertEqual(params['gl'], ['in'])
        self.assertEqual(params['hl'], ['hi'])

    def test_engine_specific_locale_contracts_and_unknown_locales(self):
        for selected, arguments, expected in (
                ('baidu', {'language':'zh-cn'}, {'ct':'2', 'rn':'5'}),
                ('yandex', {'language':'ru'}, {'lang':'ru'})):
            result = self.service(policy(('serpapi',))).web_search({'query':'多语言 поиск','engine':selected,**arguments})
            self.assertEqual(result['status'],'ok')
            params = parse_qs(urlsplit(self.calls[-1][0]['url']).query)
            for field,value in expected.items():
                self.assertEqual(params[field],[value])
        self.calls.clear()
        for request in ({'query':'a','country':'zz'}, {'query':'a','language':'zz'},
                        {'query':'a','engine':'baidu','language':'hi'},
                        {'query':'a'*401,'engine':'yandex'}):
            result = self.service(policy(('serpapi',))).web_search(request)
            self.assertEqual(result.get('error'),'no_eligible_provider')
        self.assertEqual(self.calls,[])

    def test_provider_query_caps_never_truncate_or_send_unsupported_text(self):
        for provider,query in (('brave','x'*601), ('brave',' '.join(['word']*76)),
                               ('firecrawl','x'*501), ('serpapi',' '.join(['word']*41))):
            with self.subTest(provider=provider):
                request = {'query':query,'provider':provider}
                if provider == 'serpapi':
                    request['engine']='yandex'
                result = self.service(policy((provider,))).web_search(request)
                self.assertEqual(result.get('error'),'no_eligible_provider')
        self.assertEqual(self.calls,[])
        result = self.service(policy(('brave','serper'))).web_search({'query':'x'*601})
        self.assertEqual(result['status'],'ok')
        self.assertEqual(result['query'],'x'*601)
        self.assertEqual(self.calls[-1][0]['provider'],'serper')

    def test_each_adapter_retains_reservations_on_http_failures(self):
        for provider in self.m.PROVIDERS:
            for status in (429,500):
                with self.subTest(provider=provider,status=status):
                    service = self.service(policy((provider,)), lambda r,t:(status,{},b'{}'))
                    result = service.web_search({'query':'a'})
                    self.assertEqual(result['attempts'][0]['http_status'],status)
                    self.assertEqual(result['usage']['reserved_estimated_cost_microusd'],10)

    def test_all_seven_adapters_send_and_normalize_allowlisted_results(self):
        for name in ('searxng', 'serper', 'serpapi', 'brave', 'tavily', 'firecrawl', 'scrapingdog'):
            with self.subTest(provider=name):
                result = self.service(policy((name,))).web_search({'query': 'any question', 'provider': name, 'limit': 1})
                self.assertEqual(result['status'], 'ok')
                self.assertEqual(result['results'][0]['title'], 'Evidence')
                self.assertEqual(result['results'][0]['provenance'][0]['provider'], name)
                request = self.calls[-1][0]
                self.assertNotIn('synthetic-key', repr(request))
                if name == 'tavily':
                    body = json.loads(request['body'])
                    self.assertFalse(body['include_raw_content'])
                    self.assertFalse(body['auto_parameters'])
                if name == 'firecrawl':
                    self.assertNotIn('scrapeOptions', json.loads(request['body']))

    def test_failed_attempts_share_reservations_and_do_not_retry_provider(self):
        def fail(request, timeout):
            self.calls.append(request['provider'])
            return 500, {}, b'{}'
        result = self.service(policy(('serper', 'brave', 'tavily')), fail).web_search({'query': 'error'})
        self.assertEqual(self.calls, ['serper', 'brave'])
        self.assertEqual(result['usage']['attempted_calls'], 2)
        self.assertEqual(result['usage']['reserved_estimated_cost_microusd'], 20)
        self.assertEqual(result['error'], 'budget_exhausted')

    def test_timeout_malformed_and_empty_results_have_truthful_cost(self):
        for mode in ('timeout', 'malformed', 'empty'):
            def send(request, timeout):
                if mode == 'timeout':
                    raise TimeoutError('synthetic-key')
                return 200, {}, b'no json' if mode == 'malformed' else b'{"organic":[]}'
            result = self.service(send=send).web_search({'query': 'a'})
            self.assertEqual(result['usage']['reserved_estimated_cost_microusd'], 10)
            self.assertIsNone(result['usage']['actual_cost_microusd'])
            self.assertNotIn('synthetic-key', json.dumps(result))
            self.assertEqual(result['status'], 'ok' if mode == 'empty' else 'error')

    def test_missing_price_or_credentials_does_not_send(self):
        for field in ('credential', 'estimated_unit_cost_microusd'):
            config = policy()
            del config['providers'][0][field]
            result = self.service(config).web_search({'query': 'a'})
            self.assertEqual(result['error'], 'no_eligible_provider')
        self.assertEqual(self.calls, [])

    def test_deadline_and_estimated_cost_stop_before_send(self):
        service = self.service(policy(max_estimated_cost_microusd=9))
        result = service.web_search({'query': 'a'})
        self.assertEqual(result['error'], 'budget_exhausted')
        self.assertEqual(result['usage']['attempted_calls'], 0)
        self.assertEqual(self.calls, [])

    def test_status_specific_health_and_retry_after(self):
        for status, code in ((401, 'invalid_credentials'), (402, 'quota_exhausted'),
                             (403, 'forbidden'), (429, 'rate_limited'), (500, 'upstream_error')):
            self.calls.clear()
            def send(request, timeout):
                self.calls.append(request['provider'])
                return status, {'Retry-After': '120'}, b'private upstream body synthetic-key'
            service = self.service(send=send)
            first = service.web_search({'query': 'a'})
            self.assertEqual(first['attempts'][0]['outcome'], code)
            service.web_search({'query': 'b'})
            self.assertEqual(len(self.calls), 2 if status == 403 else 1)
            self.assertNotIn('synthetic-key', json.dumps(first))

    def test_cache_keeps_evidence_time_and_checks_revocation_before_lookup(self):
        service = self.service()
        first = service.web_search({'query': 'a'})
        self.now += 2
        second = service.web_search({'query': 'a'})
        self.assertTrue(second['cache']['hit'])
        self.assertEqual(first['results'], second['results'])
        self.assertNotEqual(first['request_id'], second['request_id'])
        self.assertEqual(second['usage']['attempted_calls'], 0)
        self.assertEqual(second['usage']['reserved_estimated_cost_microusd'], 0)
        self.allowed = False
        self.assertEqual(service.web_search({'query': 'a'})['error'], 'module_unavailable')
        self.assertEqual(len(self.calls), 1)

    def test_large_duplicate_evidence_has_independent_output_bound(self):
        rows = [{'title':'a', 'link':'https://example.org/a#'+str(i), 'snippet':'文'} for i in range(1000)]
        result = self.service(send=lambda r,t:(200,{},json.dumps(payload(rows=rows)).encode())).web_search({'query':'文'*2000})
        self.assertEqual(result['status'],'ok')
        self.assertLess(len(json.dumps(result).encode()),600000)
        self.assertIn('result_truncated',result['warnings'])

    def test_live_policy_is_distinct_from_admission_and_cache(self):
        result = self.service(policy(live_enabled=False)).web_search({'query': 'a'})
        self.assertEqual(result['error'], 'live_policy_disabled')
        self.assertEqual(self.calls, [])

    def test_cache_locale_scope_expiry_and_capacity(self):
        service = self.service(policy(cache_entries=1))
        for country in ('in', 'us', 'in'):
            service.web_search({'query': 'a', 'country': country})
        self.assertEqual(len(self.calls), 3)
        self.now += 61
        service.web_search({'query': 'a', 'country': 'in'})
        self.assertEqual(len(self.calls), 4)

    def test_invalid_rows_are_dropped_and_duplicates_keep_provenance(self):
        rows = [{'title': 'a', 'link': 'https://example.org/a#one'},
                {'title': 'b', 'link': 'https://example.org/a#two'},
                {'title': 'secret', 'link': 'file:///etc/passwd'}, 17]
        result = self.service(send=lambda r,t: (200, {}, json.dumps(payload(rows=rows)).encode())).web_search({'query': 'a'})
        self.assertEqual(len(result['results']), 1)
        self.assertEqual(len(result['results'][0]['provenance']), 2)
        self.assertTrue(result['warnings'])

    def test_plain_string_query_uses_universal_defaults(self):
        result = self.service().web_search('an arbitrary context gap')
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['requested_engine'], 'auto')

    def test_operator_policy_cannot_be_escalated_after_startup(self):
        service = self.service(policy(live_enabled=False))
        service.config['live_enabled'] = True
        self.assertEqual(service.web_search({'query':'a'})['error'], 'live_policy_changed')
        self.assertEqual(self.calls, [])

    def test_policy_disable_blocks_cached_evidence_and_fallback_rechecks_module(self):
        service = self.service()
        service.web_search({'query':'a'})
        service.config['live_enabled'] = False
        self.assertEqual(service.web_search({'query':'a'})['error'], 'live_policy_disabled')
        self.calls.clear()
        self.allowed = True
        def revoke(request, timeout):
            self.calls.append(request['provider'])
            self.allowed = False
            return 500, {}, b'{}'
        result = self.service(policy(('serper','brave')), revoke).web_search({'query':'a'})
        self.assertEqual(result['error'], 'module_unavailable')
        self.assertEqual(self.calls, ['serper'])
        self.assertEqual(result['usage']['reserved_estimated_cost_microusd'], 10)

    def test_concurrent_requests_each_keep_their_own_aggregate_cap(self):
        results = []
        service = self.service(policy(('serper','brave','tavily')), lambda r,t:(403,{},b'{}'))
        threads = [threading.Thread(target=lambda i=i:results.append(service.web_search({'query':'q'+str(i)}))) for i in range(4)]
        for worker in threads:
            worker.start()
        for worker in threads:
            worker.join(3)
        self.assertEqual(len(results),4)
        for result in results:
            self.assertEqual(result['usage']['attempted_calls'],2)
            self.assertEqual(result['usage']['reserved_estimated_cost_microusd'],20)
            self.assertEqual(result['error'],'budget_exhausted')

    def test_monotonic_deadline_stops_fallback_after_failed_attempt(self):
        def slow(request, timeout):
            self.calls.append(timeout)
            self.now += 6
            return 500, {}, b'{}'
        result = self.service(policy(('serper','brave')), slow).web_search({'query':'a'})
        self.assertEqual(result['error'], 'deadline_exhausted')
        self.assertEqual(self.calls, [5])
        self.assertEqual(result['usage']['reserved_estimated_cost_microusd'], 10)


class InterfaceBehavior(unittest.TestCase):
    def setUp(self):
        self.m = engine()
        self.service = self.m.Gateway(policy(http_enabled=True, mcp_enabled=True), admission=lambda: True,
                                     transport=lambda r,t: (200, {}, json.dumps(payload()).encode()))

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaises(ValueError):
            self.m.decode_json(b'{"query":"a","query":"b"}')

    def test_stdio_initialize_tools_and_call_use_real_shared_handler(self):
        messages = [{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'test','version':'1'}}},
                    {'jsonrpc':'2.0','method':'notifications/initialized'},
                    {'jsonrpc':'2.0','id':2,'method':'tools/list'},
                    {'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'web_search','arguments':{'query':'anything'}}},
                    {'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':'bad','arguments':{}}}]
        source = io.BytesIO(b''.join(json.dumps(row).encode()+b'\n' for row in messages))
        target = io.BytesIO()
        self.m.serve_stdio(self.service, source, target)
        replies = [json.loads(line) for line in target.getvalue().splitlines()]
        self.assertEqual(len(replies), 4)
        self.assertEqual(replies[0]['result']['protocolVersion'], '2025-11-25')
        self.assertEqual(replies[1]['result']['tools'][0]['name'], 'web_search')
        self.assertEqual(replies[2]['result']['structuredContent']['status'], 'ok')
        self.assertEqual(replies[3]['error']['code'], -32602)

    def test_mcp_search_notifications_and_uninitialized_calls_never_search(self):
        calls = []
        service = self.m.Gateway(policy(mcp_enabled=True), admission=lambda:True,
                                 transport=lambda r,t: calls.append(r))
        messages = [{'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'web_search','arguments':{'query':'a'}}},
                    {'jsonrpc':'2.0','id':2,'method':'initialize','params':{'protocolVersion':'2025-11-25'}},
                    {'jsonrpc':'2.0','method':'notifications/initialized'},
                    {'jsonrpc':'2.0','method':'tools/call','params':{'name':'web_search','arguments':{'query':'a'}}},
                    {'jsonrpc':'2.0','id':3,'method':'initialize','params':{'protocolVersion':'2025-11-25'}}]
        source = io.BytesIO(b''.join(json.dumps(row).encode()+b'\n' for row in messages))
        target = io.BytesIO()
        self.m.serve_stdio(service, source, target)
        self.assertEqual(calls, [])
        replies = [json.loads(line) for line in target.getvalue().splitlines()]
        self.assertIn('error', replies[0])
        self.assertIn('error', replies[-1])

    def test_http_real_loopback_auth_host_origin_and_body_limits(self):
        from http.client import HTTPConnection
        server = self.m.http_server(self.service, 'test-token', port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for headers, status in (({}, 401), ({'Authorization':'Bearer test-token','Origin':'https://evil.invalid'},403),
                                    ({'Authorization':'Bearer test-token','Host':'evil.invalid'},403),
                                    ({'Authorization':'Bearer test-token'},200)):
                conn = HTTPConnection('127.0.0.1', server.server_port, timeout=3)
                conn.request('POST','/search',json.dumps({'query':'generic error'}), headers)
                response = conn.getresponse()
                self.assertEqual(response.status,status)
                data = response.read()
                if status == 200:
                    self.assertEqual(json.loads(data)['status'],'ok')
                conn.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)

    def test_http_rejects_duplicate_lengths_json_keys_and_oversized_body(self):
        from http.client import HTTPConnection
        server = self.m.http_server(self.service,'test-token',port=0)
        thread = threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            for body,status in ((b'{"query":"a","query":"b"}',400), (b'x'*16385,413)):
                connection = HTTPConnection('127.0.0.1',server.server_port,timeout=3)
                connection.request('POST','/search',body,{'Authorization':'Bearer test-token'})
                response = connection.getresponse()
                self.assertEqual(response.status,status)
                response.read()
                connection.close()
            connection = socket.create_connection(server.server_address,timeout=3)
            request = ('POST /search HTTP/1.0\r\nHost: 127.0.0.1:'+str(server.server_port)+
                       '\r\nAuthorization: Bearer test-token\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}')
            connection.sendall(request.encode())
            self.assertIn(b' 413 ',connection.recv(4096))
            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)

    def test_http_slow_header_trickle_has_total_input_deadline(self):
        import time
        self.m.HTTP_INPUT_SECONDS = 0.15
        server = self.m.http_server(self.service,'test-token',port=0)
        thread = threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        connection = socket.create_connection(server.server_address,timeout=1)
        try:
            started = time.monotonic()
            closed = False
            for _ in range(20):
                try:
                    connection.sendall(b'P')
                except OSError:
                    closed = True
                    break
                time.sleep(0.025)
            self.assertTrue(closed)
            self.assertLess(time.monotonic()-started,0.6)
        finally:
            connection.close()
            server.shutdown()
            server.server_close()
            thread.join(3)

    def test_http_requires_token_and_explicit_policy(self):
        with self.assertRaises(ValueError):
            self.m.http_server(self.service, '', port=0)
        self.service.config['http_enabled'] = False
        with self.assertRaises(ValueError):
            self.m.http_server(self.service, 'token', port=0)


if __name__ == '__main__':
    unittest.main()
