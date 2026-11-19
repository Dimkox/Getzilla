"""Optional MCP 2025-11-25 stdio framing. HTTP/modern profiles are unsupported.

All process ownership is supplied by the existing managed execution boundary.
This module does not spawn, register, authenticate or reconnect on import.
"""
from dataclasses import dataclass
import json
import os
import selectors
import time

CAP = 1_048_576


class TransportError(ValueError):
    pass


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise TransportError('malformed')
        result[key] = value
    return result


def _constant(value):
    raise TransportError('malformed')


class Frames:
    def __init__(self):
        self.pending = bytearray()
        self.observed = 0

    def feed(self, chunk):
        # Bound bytes before accumulating, decoding, JSON parsing or base64 use.
        if len(chunk) > CAP - self.observed:
            raise TransportError('oversize')
        self.observed += len(chunk)
        self.pending.extend(chunk)
        messages = []
        while b'\n' in self.pending:
            raw, _, rest = self.pending.partition(b'\n')
            self.pending = bytearray(rest)
            try:
                value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs, parse_constant=_constant)
            except (ValueError, UnicodeError, RecursionError):
                raise TransportError('malformed') from None
            if not isinstance(value, dict) or value.get('jsonrpc') != '2.0':
                raise TransportError('malformed')
            messages.append(value)
        return messages


@dataclass(frozen=True)
class Reply:
    status: str
    value: object = None
    reason: str | None = None
    remote_task_id: str | None = None
    remote_confirmed: bool = False
    sent: bool = False


def native_bypass():
    return {'management': 'unmanaged', 'limits_enforced': False, 'remote_termination_confirmed': False}


class Session:
    def __init__(self, process, *, deadline, watch, request_id, clock=time.monotonic, on_remote_task=None, expected_server_version=None):
        self.process, self.deadline, self.watch = process, deadline, watch
        self.request_id, self.clock, self.on_remote_task = request_id, clock, on_remote_task
        self.expected_server_version = expected_server_version
        self.frames = Frames()
        self.remote_task = None
        self.tasks = False
        self.sent = False
        self.selector = selectors.DefaultSelector()
        for stream in (process.stdin, process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
        self.selector.register(process.stdout, selectors.EVENT_READ, 'out')
        self.selector.register(process.stderr, selectors.EVENT_READ, 'err')

    def close(self):
        self.selector.close()

    def _send(self, value):
        raw = json.dumps(value, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode() + b'\n'
        if len(raw) > CAP:
            raise TransportError('request_oversize')
        offset = 0
        while offset < len(raw):
            state = self.watch()
            if self.clock() >= self.deadline or state == 'deadline':
                raise TransportError('hard_deadline')
            if state != 'running':
                raise TransportError('cancelled_before_send')
            try:
                count = os.write(self.process.stdin.fileno(), raw[offset:offset + 4096])
                if count == 0:
                    raise TransportError('disconnect')
                offset += count
            except BlockingIOError:
                time.sleep(min(.005, max(0, self.deadline - self.clock())))
            except (BrokenPipeError, OSError):
                raise TransportError('disconnect') from None

    def _receive(self, wanted):
        while True:
            state = self.watch()
            if self.clock() >= self.deadline:
                return Reply('deadline', reason='hard_deadline', remote_task_id=self.remote_task, sent=self.sent)
            if state != 'running':
                return self._cancel(state)
            for key, _ in self.selector.select(min(.02, max(0, self.deadline - self.clock()))):
                try:
                    chunk = os.read(key.fd, min(65536, CAP - self.frames.observed + 1) if key.data == 'out' else 4096)
                except BlockingIOError:
                    continue
                if not chunk:
                    self.selector.unregister(key.fileobj)
                    if key.data == 'out':
                        raise TransportError('disconnect')
                    continue
                if key.data == 'err':
                    continue  # stderr is not a response, receipt or health failure.
                for message in self.frames.feed(chunk):
                    if message.get('id') == wanted:
                        # Parsing/progress does not extend admission or revive a
                        # request whose cancel/deadline won before acceptance.
                        current = self.watch()
                        if self.clock() >= self.deadline:
                            return Reply('deadline', reason='hard_deadline', remote_task_id=self.remote_task, sent=self.sent)
                        if current != 'running':
                            return self._cancel(current)
                        return message
                    if 'id' in message:
                        # A stale/late response never satisfies another request.
                        continue

    def _cancel(self, state):
        # Cancellation submission is not remote confirmation. This nonblocking
        # best effort cannot extend the hard deadline or leave a polling worker.
        if self.remote_task is not None and self.tasks:
            value = {'jsonrpc': '2.0', 'id': 'cancel-' + self.request_id,
                     'method': 'tasks/cancel', 'params': {'taskId': self.remote_task}}
        else:
            value = {'jsonrpc': '2.0', 'method': 'notifications/cancelled',
                     'params': {'requestId': self.request_id, 'reason': state}}
        try:
            raw = json.dumps(value, separators=(',', ':')).encode() + b'\n'
            os.write(self.process.stdin.fileno(), raw)
        except (OSError, BlockingIOError):
            pass
        return Reply(state, reason='remote_cancel_unconfirmed', remote_task_id=self.remote_task, sent=self.sent)

    def call(self, tool, arguments):
        try:
            self._send({'jsonrpc': '2.0', 'id': 'init-' + self.request_id, 'method': 'initialize',
                        'params': {'protocolVersion': '2025-11-25', 'capabilities': {},
                                   'clientInfo': {'name': 'getzilla-optional-mcp', 'version': '0.1.0'}}})
            initialized = self._receive('init-' + self.request_id)
            if isinstance(initialized, Reply):
                return initialized
            if not isinstance(initialized.get('result'), dict) or not isinstance(initialized['result'].get('capabilities', {}), dict):
                raise TransportError('malformed')
            if initialized['result'].get('protocolVersion') != '2025-11-25':
                return Reply('unsupported', reason='protocol_profile_unqualified')
            if not isinstance(initialized['result'].get('serverInfo', {}), dict):
                raise TransportError('malformed')
            if self.expected_server_version is not None and initialized['result'].get('serverInfo', {}).get('version') != self.expected_server_version:
                return Reply('unsupported', reason='server_version_changed')
            self.tasks = isinstance(initialized['result'].get('capabilities', {}).get('tasks'), dict)
            self._send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
            cursor = None
            selected = None
            for page in range(4):
                list_id = 'tools-' + str(page) + '-' + self.request_id
                self._send({'jsonrpc': '2.0', 'id': list_id, 'method': 'tools/list',
                            'params': {} if cursor is None else {'cursor': cursor}})
                catalog = self._receive(list_id)
                if isinstance(catalog, Reply):
                    return catalog
                result = catalog.get('result')
                if not isinstance(result, dict) or not isinstance(result.get('tools'), list) or len(result['tools']) > 128:
                    raise TransportError('malformed')
                for item in result['tools']:
                    if isinstance(item, dict) and item.get('name') == tool:
                        if selected is not None:
                            raise TransportError('malformed')
                        selected = item
                cursor = result.get('nextCursor')
                if cursor is None:
                    break
                if not isinstance(cursor, str) or len(cursor) > 4096:
                    raise TransportError('malformed')
            if cursor is not None:
                return Reply('unsupported', reason='capability_pagination_limit')
            if selected is not None and not isinstance(selected.get('annotations', {}), dict):
                raise TransportError('malformed')
            if (selected is None or not isinstance(selected.get('inputSchema'), dict)
                    or selected.get('annotations', {}).get('readOnlyHint') is not True):
                return Reply('unsupported', reason='read_capability_unqualified')
            self._send({'jsonrpc': '2.0', 'id': self.request_id, 'method': 'tools/call',
                        'params': {'name': tool, 'arguments': arguments}})
            self.sent = True
            message = self._receive(self.request_id)
            if isinstance(message, Reply):
                return message
            if 'error' in message:
                return Reply('domain', message['error'], sent=True, remote_confirmed=True)
            result = message.get('result')
            if not isinstance(result, dict):
                raise TransportError('malformed')
            task = result.get('task')
            if task is not None:
                if not isinstance(task, dict) or not isinstance(task.get('taskId'), str) or not 1 <= len(task['taskId']) <= 128:
                    raise TransportError('remote_task_unqualified')
                self.remote_task = task['taskId']
                if self.on_remote_task:
                    try:
                        self.on_remote_task(self.remote_task)
                    except ValueError:
                        return Reply('unsupported', reason='remote_task_identity_unrecordable', remote_task_id=self.remote_task, sent=True)
                if not self.tasks:
                    return Reply('unsupported', reason='remote_task_profile_unqualified', remote_task_id=self.remote_task, sent=True)
                # Task polling is not qualified by this stdio profile. Preserve
                # its identity and uncertainty instead of inventing completion.
                return self._cancel('unsupported')
            return Reply('domain' if result.get('isError') is True else 'success', result,
                         remote_task_id=self.remote_task, remote_confirmed=True, sent=True)
        except TransportError as error:
            if str(error) == 'hard_deadline':
                return Reply('deadline', reason='hard_deadline', remote_task_id=self.remote_task, sent=self.sent)
            if str(error) == 'cancelled_before_send':
                return Reply('cancelled', reason=str(error), sent=self.sent)
            return Reply('infra', reason=str(error), remote_task_id=self.remote_task, sent=self.sent)
