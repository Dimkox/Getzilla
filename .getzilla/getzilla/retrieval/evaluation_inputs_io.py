"""Read-only public benchmark-artifact adapter using existing anchored readers.

This adapter does not authorize a protected project, principal or source. It
audits the fixed public research catalog; private/native query ingestion keeps
using the separate current-authority retrieval port.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..component_state import BoundRoot
from .budget import RetrievalError
from .evaluation_inputs import ISSUE_162_PROFILE, audit_draft_inputs, source_references

INPUTS = ('function-universes.json', 'partition.json', 'queries.json', 'full-qrels.json')
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_TOTAL_JSON_BYTES = 16 * 1024 * 1024


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise RetrievalError('invalid_input_json')
        value[key] = item
    return value


def _constant(_value):
    raise RetrievalError('invalid_input_json')


def _json(raw):
    try:
        if raw.startswith(b'\xef\xbb\xbf'):
            raise RetrievalError('invalid_input_json')
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs, parse_constant=_constant)
        if type(value) is not dict:
            raise RetrievalError('invalid_input_json')
        pending, nodes = [(value, 0)], 0
        while pending:
            item, depth = pending.pop()
            nodes += 1
            if nodes > 200000 or depth > 32:
                raise RetrievalError('input_structure_exceeded')
            if type(item) is dict:
                pending.extend((child, depth + 1) for child in item.values())
            elif type(item) is list:
                pending.extend((child, depth + 1) for child in item)
        return value
    except RetrievalError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise RetrievalError('invalid_input_json') from None


def audit_directory(candidate: Path, public_sources: Path, *, profile=ISSUE_162_PROFILE):
    """Audit source observations; no writes, models, ranks or source-access permits."""
    try:
        with BoundRoot(candidate) as inputs:
            documents, snapshots, total = [], {}, 0
            for name in INPUTS:
                observed = inputs.read(name, limit=MAX_JSON_BYTES)
                if observed is None:
                    raise RetrievalError('input_missing')
                total += len(observed.content)
                if total > MAX_TOTAL_JSON_BYTES:
                    raise RetrievalError('input_bytes_exceeded')
                snapshots[name] = observed
                documents.append(_json(observed.content))
            references = source_references(documents[0], profile=profile)
            # A mismatched full-profile catalog never reaches the source reader.
            with BoundRoot(public_sources) as sources:
                source_bytes, observed_sources, source_total = {}, {}, 0
                for corpus, path in references:
                    name = corpus + '/' + path
                    observed = sources.read(name, limit=1048576)
                    if observed is None:
                        raise RetrievalError('source_file_mismatch')
                    source_total += len(observed.content)
                    if source_total > 32 * 1024 * 1024:
                        raise RetrievalError('source_inventory_exceeded')
                    source_bytes[corpus, path] = observed.content
                    observed_sources[name] = observed
                result = audit_draft_inputs(*documents, source_bytes, profile=profile)
                for name, observed in observed_sources.items():
                    if sources.read(name, limit=1048576) != observed:
                        raise RetrievalError('source_changed')
                sources.check()
            for name, observed in snapshots.items():
                if inputs.read(name, limit=MAX_JSON_BYTES) != observed:
                    raise RetrievalError('input_changed')
            inputs.check()
            return result
    except RetrievalError:
        raise
    except (OSError, ValueError, TypeError, KeyError):
        raise RetrievalError('input_unavailable') from None
