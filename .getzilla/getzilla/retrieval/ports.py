"""Native composition boundary. No default authority, raw reader or model fallback.

Protocols describe the future qualified host adapter; a Python implementation of
one does not authenticate its caller or qualify an actual source/sink channel.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .budget import Budget, RetrievalError
from .contracts import Generation, SourceSnapshot
from .engine import pack_context, search


class NativeRetrievalPort(Protocol):
    def current(self, request: object, budget: Budget): ...
    def recheck(self, request: object, source, budget: Budget) -> None: ...
    def prepare(self, request: object, source, packed, budget: Budget) -> str: ...


@dataclass(frozen=True)
class PreparedResult:
    prepared_ref: str
    generation_id: str
    status: str
    qualification: str = 'native_adapter_required'


class RetrievalService:
    def __init__(self, *, port: NativeRetrievalPort | None = None, token_counter=None):
        self.port, self.token_counter = port, token_counter

    def query(self, request, query, *, token_budget=2048, budget=None):
        if self.port is None:
            raise RetrievalError('authority_unavailable')
        if self.token_counter is None:
            raise RetrievalError('tokenizer_unavailable')
        budget = Budget() if budget is None else budget
        budget.check()
        def call(method, *args):
            try:
                value = method(*args)
                budget.check()
                return value
            except Exception as exc:
                code = exc.args[0] if exc.args and type(exc.args[0]) is str else None
                allowed = {'source_unavailable', 'authority_unavailable', 'deadline_exceeded'}
                raise RetrievalError(code if code in allowed else 'adapter_unavailable') from None

        current = call(self.port.current, request, budget)
        if not isinstance(current, tuple) or len(current) != 2:
            raise RetrievalError('adapter_unavailable')
        source, generation = current
        if type(source) is not SourceSnapshot or type(generation) is not Generation:
            raise RetrievalError('adapter_unavailable')
        if (generation.repository != source.repository or generation.source_snapshot != source.source_identity
                or generation.representation_ids != tuple(sorted(d.representation_identity for d in source.documents))):
            raise RetrievalError('current_index_unavailable')
        if call(self.port.recheck, request, source, budget) is not None:
            raise RetrievalError('adapter_unavailable')
        budget.check()
        result = search(generation, query, budget=budget)
        packed = pack_context(source, result.rankings['rrf'], self.token_counter, token_budget, budget=budget)
        if call(self.port.recheck, request, source, budget) is not None:
            raise RetrievalError('adapter_unavailable')
        budget.check()
        reference = call(self.port.prepare, request, source, packed, budget)
        budget.check()
        if not isinstance(reference, str) or not reference or len(reference) > 128 or not reference.isprintable():
            raise RetrievalError('invalid_prepared_reference')
        return PreparedResult(reference, generation.identity, result.status)
