"""Verification claims need a receipt: "all tests pass" without a current verification receipt is unsupported.

The stop gate reads the agent's last message. Claim phrases come from the risk vocabulary
(`verification-claim`, English base plus language packs). When the message claims tests or
checks passed and no passing verification receipt matches the current tree fingerprint, the stop
gate warns, or in strict mode blocks the stop where the agent supports it (Claude Code, Codex).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping

from .risk_terms import load_vocabulary

CLAIM_ID = 'verification-claim'
BLOCKING_HARNESSES = frozenset({'claude', 'codex'})
MAX_TRANSCRIPT_BYTES = 8 * 1024 * 1024


def _text_of(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return '\n'.join(part.get('text', '') for part in content
                         if isinstance(part, dict) and part.get('type') in (None, 'text', 'output_text'))
    return ''


def last_assistant_text(payload: Mapping[str, Any]) -> str | None:
    """The agent's final message: from the payload when the agent sends it, else from the transcript."""
    for key in ('last_assistant_message', 'lastAssistantMessage', 'last-assistant-message'):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    path = payload.get('transcript_path') or payload.get('transcriptPath')
    if not isinstance(path, str) or not path:
        return None
    try:
        file = Path(path)
        size = file.stat().st_size
        with file.open('rb') as handle:
            if size > MAX_TRANSCRIPT_BYTES:
                handle.seek(size - MAX_TRANSCRIPT_BYTES)
            lines = handle.read().decode('utf-8', 'replace').splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict):
            continue
        message = entry.get('message') if isinstance(entry.get('message'), dict) else entry
        role = message.get('role') or entry.get('type')
        if role == 'assistant':
            text = _text_of(message.get('content'))
            if text.strip():
                return text
    return None


def claims_verification(text: str) -> bool:
    return CLAIM_ID in load_vocabulary().matched_ids(text)


def has_current_verification(root: Path, route: Mapping[str, Any]) -> bool:
    from .receipts import get_receipt
    from .continuity import receipt_context_current
    from .util import tree_fingerprint
    try:
        receipt = get_receipt(root, str(route.get('route_id')), 'verification')
    except RuntimeError:
        return False
    return isinstance(receipt, dict) and receipt.get('status') == 'pass' and not receipt.get('stale') and \
        receipt.get('tree_fingerprint') == tree_fingerprint(root) and receipt_context_current(root, dict(route), receipt)


def effective_risk(root: Path, route: Mapping[str, Any]) -> str:
    """The route's risk, raised by the diff risk the latest verification recorded."""
    from .receipts import get_receipt
    risk = str(route.get('risk') or 'low')
    try:
        receipt = get_receipt(root, str(route.get('route_id')), 'verification')
    except RuntimeError:
        receipt = None
    from .continuity import receipt_context_current
    if receipt is not None and not receipt_context_current(root, dict(route), receipt):
        receipt = None
    details = receipt.get('details') if isinstance(receipt, dict) and isinstance(receipt.get('details'), dict) else {}
    diff = details.get('diff_risk') if isinstance(details.get('diff_risk'), dict) else {}
    return 'high' if 'high' in (risk, diff.get('effective_risk')) else risk


def stop_mode(root: Path, route: Mapping[str, Any]) -> str:
    """soft warns, strict blocks; GETZILLA_STOP_GATE_MODE overrides, high effective risk is strict."""
    override = os.environ.get('GETZILLA_STOP_GATE_MODE', '').strip().lower()
    if override in {'soft', 'strict'}:
        return override
    return 'strict' if effective_risk(root, route) == 'high' else 'soft'


def unsupported_claim(root: Path, route: Mapping[str, Any] | None, payload: Mapping[str, Any]) -> str | None:
    """A message when the last answer claims a passing verification that no current receipt backs."""
    if not route:
        return None
    text = last_assistant_text(payload)
    if not text or not claims_verification(text):
        return None
    if has_current_verification(root, route):
        return None
    return ('the last message says tests or checks passed, but there is no passing verification receipt for the '
            'current tree; run `getzilla verify` (python3 scripts/getzilla_verify.py) and report its result instead')
