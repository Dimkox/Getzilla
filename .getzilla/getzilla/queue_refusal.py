"""Immutable bounded queue refusal diagnostics, with no analyzer dependency."""
from __future__ import annotations

import json
import re
import os
import sys
from typing import NamedTuple

class QueueRefusalCapture(NamedTuple):
    owner: Exception
    message: str
    payload: str


# The observer bootstrap loads the same authenticated source under a private
# package. Share only its immutable type when both loader origins are identical.
_peer = sys.modules.get('getzilla.queue_refusal')
_run = os.environ.get('GETZILLA_JOURNAL_RUN', '')
if __package__ == 'getzilla' and re.fullmatch(r'[0-9a-f]{32}', _run):
    _peer = sys.modules.get('_getzilla_observer_' + _run + '.queue_refusal')
if ((getattr(_peer, '__file__', None), getattr(getattr(_peer, '__spec__', None), 'origin', None),
     getattr(__spec__, 'origin', None)) == (__file__,) * 3
        and isinstance(getattr(_peer, 'QueueRefusalCapture', None), type)):
    QueueRefusalCapture = _peer.QueueRefusalCapture


def queue_refusal_text(error: Exception) -> str:
    """Retain only the bound internal capture, never a mutable public sidecar.

    This protects optional diagnostic serialization, not arbitrary same-process
    execution. Invalid optional metadata must not mask the original refusal.
    """
    original = str(error)
    capture = getattr(error, '_queue_refusal_capture', None)
    if (getattr(error, 'code', None) != 'limit' or type(capture) is not QueueRefusalCapture or capture.owner is not error
            or type(capture.message) is not str or capture.message != original or type(capture.payload) is not str):
        return original
    text = original + '; ' + capture.payload
    try:
        if len(text.encode('utf-8')) > 2048:
            return original
        detail = json.loads(capture.payload)
        fields = {'version', 'kind', 'side', 'category', 'limit', 'observed', 'site', 'witness_scope',
                  'active', 'cached', 'active_omitted', 'cached_omitted', 'cached_witness_unavailable'}
        if (type(detail) is not dict or set(detail) != fields or type(detail['version']) is not int
                or detail['version'] != 1 or detail['kind'] != 'queue-analysis-refusal'
                or detail['side'] not in ('head', 'base', 'unknown')
                or detail['category'] not in ('depth', 'work', 'bytes', 'nodes', 'modules', 'other')
                or detail['site'] not in ('budget', 'cached', 'active', 'declaration', 'resolver')
                or detail['witness_scope'] != 'ordered-module-request-frames'
                or type(detail['cached_witness_unavailable']) is not bool):
            return original
        for key in ('limit', 'observed', 'active_omitted', 'cached_omitted'):
            if not (detail[key] is None and key in ('limit', 'observed')) and (
                    type(detail[key]) is not int or detail[key] < 0):
                return original
        for key in ('active', 'cached'):
            if type(detail[key]) is not list or any(type(value) is not str or not re.fullmatch(
                    r'(?:[A-Za-z_][A-Za-z0-9_.]{0,255}|sha256:[0-9a-f]{64})', value) for value in detail[key]):
                return original
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        return original
    return text
