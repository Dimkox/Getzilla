"""Passive hook integration through the existing optional-module lifecycle.

Enablement is feature selection, never current source or sink authorization.
There is no index open/build, worker, model, network or raw-reader fallback.
"""
from __future__ import annotations

from ..optional_modules import admit_module

MODULE = 'context-retrieval'
MAX_HOOK_BYTES = 16384


def enabled(root):
    return admit_module(root, MODULE).get('allowed') is True


def startup_note(root):
    if not enabled(root):
        return ('Code context: disabled. Optional context-retrieval uses the shared graph; '
                'getzilla context --help describes access.')
    try:
        from ..state import require_route_owner
        from ..trace_storage import native_root
        with native_root(root) as anchor:
            require_route_owner(root, anchor=anchor)
            present = anchor.exists('.getzilla/index/graph.sqlite')
        return ('Code context: index ' + ('present' if present else 'missing') +
                '; freshness unverified until task retrieval. Use getzilla context query. '
                'Native local source/selected-hook transport only; backend and private-egress confinement are unverified.')
    except (ValueError, OSError):
        return ('Code context: authority_unavailable; index freshness is unverified. '
                'Use authorized ordinary search/reads or getzilla context query.')



def append_note(mandatory, note, *, max_bytes=MAX_HOOK_BYTES):
    """Optional code context cannot displace any mandatory handoff byte."""
    if not note:
        return mandatory
    combined = mandatory + '\n\n' + note
    return combined if len(combined.encode('utf-8')) <= max_bytes else mandatory
