"""Synthetic-only Codex protocol probe. Run only in a no-network disposable container.

This fixture is not a production adapter or proof of tool/effect fencing.
"""
import json
import os
import selectors
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

observed = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        if self.path != '/v1/responses':
            self.send_error(404)
            return
        size = int(self.headers.get('Content-Length', '0'))
        if size > 2000000:
            self.send_error(413)
            return
        body = json.loads(self.rfile.read(size))
        tools = body.get('tools', [])
        observed.append({'model': body.get('model'), 'tool_names': [x.get('name', x.get('type')) for x in tools],
                         'tool_count': len(tools)})
        if body.get('model') == 'fixture-a':
            payload = json.dumps({'error': {'message': 'synthetic rate limit', 'type': 'rate_limit_error',
                                            'code': 'rate_limit_exceeded'}}).encode()
            self.send_response(429)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        frames = [
            {'type': 'response.created', 'response': {'id': 'r1'}},
            {'type': 'response.output_item.done', 'item': {'type': 'message', 'role': 'assistant', 'id': 'm1',
                                                           'content': [{'type': 'output_text', 'text': 'synthetic-ok'}]}},
            {'type': 'response.completed', 'response': {'id': 'r1', 'usage': {'input_tokens': 1,
             'input_tokens_details': None, 'output_tokens': 1, 'output_tokens_details': None, 'total_tokens': 2}}},
        ]
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Connection', 'close')
        self.end_headers()
        for frame in frames:
            self.wfile.write(('event: ' + frame['type'] + '\ndata: ' + json.dumps(frame) + '\n\n').encode())
        self.wfile.flush()


server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
port = server.server_port
config = [
    'model_provider="local_fixture"', 'model="fixture-a"',
    f'model_providers.local_fixture={{name="Local fixture",base_url="http://127.0.0.1:{port}/v1",wire_api="responses",requires_openai_auth=false,supports_websockets=false,request_max_retries=0,stream_max_retries=0}}',
    'sandbox_mode="read-only"', 'approval_policy="never"', 'features.shell_tool=false',
    'agents.enabled=false', 'web_search="disabled"',
]
args = ['/fixture-codex', 'app-server', '--stdio']
Path(os.environ.get('CODEX_HOME', '/tmp/codex')).mkdir(mode=0o700, parents=True, exist_ok=True)
for item in config:
    args += ['-c', item]
process = subprocess.Popen(args, cwd='/work', stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, bufsize=0)
selector = selectors.DefaultSelector()
selector.register(process.stdout, selectors.EVENT_READ)
buffer = b''
methods = []
item_types = []
retry_flags = []
event_shapes = []
error_infos = []
server_requests = []
event_frames = []


def send(value):
    process.stdin.write((json.dumps(value) + '\n').encode())
    process.stdin.flush()


def host_gate(value):
    if os.environ.get('GETZILLA_CONTROLLED_GATE') != '1':
        return
    nonce = os.environ.get('GETZILLA_FIXTURE_NONCE', '')
    value.update(version=1, nonce=nonce)
    print(json.dumps(value, separators=(',', ':')), flush=True)
    if json.loads(sys.stdin.readline(4096)) != {'allow': True, 'nonce': nonce}:
        raise ValueError('host refused')


def receive(deadline):
    global buffer
    while b'\n' not in buffer:
        if not selector.select(max(0, deadline - time.monotonic())):
            raise TimeoutError('protocol timeout')
        chunk = os.read(process.stdout.fileno(), 65536)
        if not chunk:
            raise ValueError('closed response')
        buffer += chunk
        if len(buffer) > 2000000:
            raise ValueError('oversized response')
    line, buffer = buffer.split(b'\n', 1)
    value = json.loads(line)
    if 'method' in value:
        event_frames.append(value)
        if len(event_frames) > 128:
            raise ValueError('too many events')
        methods.append(value['method'])
        if 'id' in value:
            server_requests.append(value['method'])
        params = value.get('params') or {}
        event_shapes.append({'method': value['method'], 'keys': sorted(params),
                             'item_type': (params.get('item') or {}).get('type') if isinstance(params.get('item'), dict) else None})
        if value['method'] in ('item/started', 'item/completed'):
            item_types.append((params.get('item') or {}).get('type'))
        if value['method'] == 'error':
            retry_flags.append(params.get('willRetry'))
            error_infos.append((params.get('error') or {}).get('codexErrorInfo'))
    return value


def response(number):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        event = receive(deadline)
        if event.get('id') == number:
            if 'error' in event:
                raise ValueError('rpc refused: ' + str(event['error'].get('code')))
            return event['result']
    raise TimeoutError('response timeout')


try:
    send({'id': 1, 'method': 'initialize', 'params': {'clientInfo': {'name': 'getzilla-fixture', 'version': '1'}}})
    response(1)
    send({'method': 'initialized', 'params': {}})
    send({'id': 2, 'method': 'thread/start', 'params': {'cwd': '/work', 'model': 'fixture-a',
         'modelProvider': 'local_fixture', 'sandbox': 'read-only', 'approvalPolicy': 'never'}})
    thread = response(2)['thread']['id']
    host_gate({'type': 'before_a'})
    send({'id': 3, 'method': 'turn/start', 'params': {'threadId': thread, 'model': 'fixture-a',
         'input': [{'type': 'text', 'text': 'Reply with synthetic-ok.', 'text_elements': []}]}})
    turn = response(3)['turn']['id']
    def wait_turn(turn_id):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            event = receive(deadline)
            params = event.get('params', {})
            if event.get('method') == 'turn/completed' and params.get('threadId') == thread and params.get('turn', {}).get('id') == turn_id:
                error = params['turn'].get('error') or {}
                return {'status': params['turn'].get('status'), 'error_info': error.get('codexErrorInfo'),
                        'items': params['turn'].get('items', [])}
        return {'status': 'timeout'}

    first = wait_turn(turn)
    second = None
    error_info = first.get('error_info')
    rate = (isinstance(error_info, dict) and set(error_info) == {'responseTooManyFailedAttempts'}
            and error_info['responseTooManyFailedAttempts'].get('httpStatusCode') == 429)
    no_effect_items = (all(item in ('userMessage', 'agentMessage', 'reasoning') for item in item_types)
                       and isinstance(first['items'], list)
                       and all(isinstance(item, dict) and item.get('type') in ('userMessage', 'agentMessage', 'reasoning')
                               for item in first['items']))
    if first['status'] == 'failed' and rate and retry_flags == [False] and no_effect_items and not server_requests:
        host_gate({'type': 'before_b', 'thread': thread, 'turn': turn, 'first': first,
                   'retry_flags': retry_flags, 'item_types': item_types, 'server_requests': server_requests,
                   'events': event_frames})
        send({'id': 4, 'method': 'turn/start', 'params': {'threadId': thread, 'model': 'fixture-b',
             'input': [{'type': 'text', 'text': 'Reply with synthetic-ok.', 'text_elements': []}]}})
        second_turn = response(4)['turn']['id']
        second = wait_turn(second_turn)
    if (second is None or second['status'] != 'completed' or len(observed) != 2
            or [item['model'] for item in observed] != ['fixture-a', 'fixture-b'] or server_requests):
        raise ValueError('fixture continuation failed')
    print(json.dumps({'initialize': 'ok', 'thread_start': 'ok', 'first_turn': first, 'second_turn': second,
                      'request_count': len(observed), 'synthetic_requests': observed,
                      'event_methods': methods, 'event_shapes': event_shapes, 'item_types': item_types, 'retry_flags': retry_flags,
                      'error_infos': error_infos, 'server_requests': server_requests,
                      'network': 'container-none-loopback', 'provider': 'synthetic-local',
                      'version': 1, 'nonce': os.environ.get('GETZILLA_FIXTURE_NONCE', ''),
                      'thread': thread, 'turn': turn, 'second_turn_id': second_turn,
                      'events': event_frames}))
except Exception as exc:
    print(json.dumps({'result': 'not_qualified', 'failure_type': type(exc).__name__,
                      'request_count': len(observed), 'synthetic_requests': observed, 'event_methods': methods}))
    sys.exit(1)
finally:
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)
    server.shutdown()
