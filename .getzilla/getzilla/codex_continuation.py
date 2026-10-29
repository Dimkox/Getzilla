"""Correlate Codex app-server turn events without granting dispatch authority.

Protocol observations do not prove that a process or its effects are fenced.
"""
from __future__ import annotations

import asyncio
import json
import re

from . import model_continuation_state as journal

LIVE_QUALIFIED = False
_ELIGIBLE = {'rateLimitExceeded', 'usageLimitExceeded', 'serverOverloaded', 'internalServerError'}
_SAFE_ITEMS = {'agentMessage', 'reasoning', 'userMessage'}
MAX_FRAME = 65536


class ProtocolError(ValueError):
    """Fixed diagnostic without peer output or caller content."""


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError('invalid_frame')
        result[key] = value
    return result


class OwnedJsonlPeer:
    """Own a bounded stdio process. Stopping it is not an effect fence."""

    def __init__(self, process, timeout):
        self._process = process
        self._timeout = timeout

    @classmethod
    async def start(cls, executable: str, *args: str, timeout: float = 10):
        if not executable or not 0 < timeout <= 60:
            raise ProtocolError('invalid_configuration')
        process = await asyncio.create_subprocess_exec(
            executable, *args, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, limit=MAX_FRAME + 1)
        return cls(process, timeout)

    @property
    def returncode(self):
        return self._process.returncode

    async def send(self, value: dict):
        try:
            data = json.dumps(value, separators=(',', ':'), allow_nan=False).encode('utf-8') + b'\n'
            if not isinstance(value, dict) or len(data) > MAX_FRAME:
                raise ProtocolError('invalid_frame')
            self._process.stdin.write(data)
            await asyncio.wait_for(self._process.stdin.drain(), self._timeout)
        except (OSError, TypeError, ValueError, asyncio.TimeoutError):
            raise ProtocolError('send_failed') from None

    async def read(self):
        try:
            data = await asyncio.wait_for(self._process.stdout.readline(), self._timeout)
            if not data or len(data) > MAX_FRAME or not data.endswith(b'\n'):
                raise ProtocolError('invalid_frame')
            value = json.loads(data, object_pairs_hook=_pairs)
            if not isinstance(value, dict):
                raise ProtocolError('invalid_frame')
            return value
        except (OSError, ValueError, UnicodeError, asyncio.TimeoutError, RecursionError):
            raise ProtocolError('invalid_frame') from None

    async def close(self):
        if self._process.returncode is None:
            try:
                self._process.terminate()
            except ProcessLookupError:
                await self._process.wait()
                return
            try:
                await asyncio.wait_for(self._process.wait(), self._timeout)
            except asyncio.TimeoutError:
                try:
                    self._process.kill()
                except ProcessLookupError:
                    pass
                await self._process.wait()


async def initialize(peer: OwnedJsonlPeer) -> None:
    """Negotiate the documented app-server protocol without starting a turn."""
    await peer.send({'id': 1, 'method': 'initialize',
                     'params': {'clientInfo': {'name': 'getzilla', 'version': '1'}}})
    response = await peer.read()
    if response.get('id') != 1 or not isinstance(response.get('result'), dict) or 'error' in response:
        raise ProtocolError('initialization_failed')
    await peer.send({'method': 'initialized', 'params': {}})


class TurnObserver:
    """Observe a single owned turn. Unknown and effectful events fail closed."""

    def __init__(self, thread_id: str, turn_id: str):
        if not thread_id or not turn_id:
            raise ValueError('invalid_turn_binding')
        self._thread = thread_id
        self._turn = turn_id
        self._error = None
        self._complete = False
        self._unsafe = False
        self._native_retry = False

    def observe(self, event: object) -> None:
        if not isinstance(event, dict) or not isinstance(event.get('method'), str):
            self._unsafe = True
            return
        method = event['method']
        params = event.get('params')
        if not isinstance(params, dict):
            self._unsafe = True
            return
        if 'id' in event:
            # Approval and other server requests cannot prove effects were fenced.
            self._unsafe = True
            return
        if method == 'error':
            error = params.get('error')
            if (params.get('threadId') != self._thread or params.get('turnId') != self._turn
                    or type(params.get('willRetry')) is not bool or not isinstance(error, dict)):
                self._unsafe = True
                return
            value = error.get('codexErrorInfo')
            if self._error is not None and self._error != value:
                self._unsafe = True
            self._error = value
            self._native_retry |= params['willRetry']
        elif method == 'turn/completed':
            turn = params.get('turn')
            if (params.get('threadId') != self._thread or not isinstance(turn, dict)
                    or turn.get('id') != self._turn or turn.get('status') != 'failed'):
                self._unsafe = True
                return
            self._complete = True
        elif method in {'item/started', 'item/completed'}:
            item = params.get('item')
            if (params.get('threadId') != self._thread or params.get('turnId') != self._turn
                    or not isinstance(item, dict) or item.get('type') not in _SAFE_ITEMS):
                self._unsafe = True
        else:
            self._unsafe = True

    @property
    def eligible(self) -> bool:
        return (self._complete and not self._unsafe and not self._native_retry
                and isinstance(self._error, str) and self._error in _ELIGIBLE)

    @property
    def dispatch_permitted(self) -> bool:
        return False


async def observe_and_reserve(peer: OwnedJsonlPeer, root, binding, generation: int, event_id: str,
                              thread_id: str, turn_id: str, usage, *, timeout: float = 60, max_events: int = 128):
    """Observe an owned turn, then ask the durable journal for admission.

    No event proves effect fencing. The current journal qualification boundary
    denies every reservation; this function never sends a successor turn.
    """
    if (not isinstance(event_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,61}', event_id)
            or type(max_events) is not int or not 1 <= max_events <= 1024 or not 0 < timeout <= 300):
        raise ProtocolError('invalid_configuration')
    observer = TurnObserver(thread_id, turn_id)

    async def receive():
        for _ in range(max_events):
            event = await peer.read()
            observer.observe(event)
            if observer._unsafe:
                return {'state': 'denied', 'reason': 'unreconciled_effect', 'dispatch_permitted': False}
            if observer._complete:
                if not observer.eligible:
                    return {'state': 'denied', 'reason': 'not_eligible', 'dispatch_permitted': False}
                # An arbitrary stdio peer is not proof of model-event provenance.
                # Persist an unknown outcome so a future adapter cannot reuse this
                # observation as a trusted eligible failure.
                terminal = journal.record_terminal(root, binding, generation, event_id, 'unknown')
                if terminal['state'] != 'terminal_unknown':
                    return terminal
                return journal.reserve_next(root, binding, terminal['revision'], event_id + '_r', usage)
        return {'state': 'denied', 'reason': 'event_limit', 'dispatch_permitted': False}

    try:
        return await asyncio.wait_for(receive(), timeout)
    except asyncio.TimeoutError:
        return {'state': 'denied', 'reason': 'observation_timeout', 'dispatch_permitted': False}
