"""Pure algorithms over native-adapter-selected bytes; no source/permission I/O."""
from __future__ import annotations

from dataclasses import dataclass, field

from .budget import Budget, RetrievalError
from .contracts import sha
from .ranking import rank


@dataclass(frozen=True)
class SearchResult:
    rankings: dict = field(repr=False)
    component_status: dict
    status: str = 'degraded'
    answerability: str = 'unknown'
    billed_tokens: None = None


def search(generation, query, *, budget=None):
    budget = Budget() if budget is None else budget
    budget.check()
    return SearchResult(rank(generation.chunks, query, budget),
        {'exact_symbol': 'available', 'bm25': 'available', 'semantic': 'unavailable', 'rrf': 'degraded'})


def verify_citation(source, chunk, *, budget=None):
    budget = Budget() if budget is None else budget
    budget.check()
    document = next((d for d in source.documents if d.key == chunk.key and d.path == chunk.path), None)
    if document is None or document.version != chunk.version or document.representation_identity != chunk.representation_identity:
        raise RetrievalError('stale_citation')
    lines = document.original.splitlines(keepends=True)
    represented = document.representation.splitlines(keepends=True)
    if (type(chunk.start) is not int or type(chunk.end) is not int or not 1 <= chunk.start <= chunk.end <= len(lines)
            or document.original_sha256 != chunk.file_sha256
            or sha(b''.join(lines[chunk.start - 1:chunk.end])) != chunk.chunk_sha256
            or sha(b''.join(represented[chunk.start - 1:chunk.end])) != chunk.transformed_sha256
            or sha(chunk.text.encode()) != chunk.transformed_sha256):
        raise RetrievalError('stale_citation')
    budget.charge('query_source_bytes', len(b''.join(lines[chunk.start - 1:chunk.end]))
        + len(b''.join(represented[chunk.start - 1:chunk.end])))
    return {'source_key': chunk.key.parts(), 'path': chunk.path, 'start': chunk.start, 'end': chunk.end,
        'file_sha256': chunk.file_sha256, 'chunk_sha256': chunk.chunk_sha256,
        'transformed_sha256': chunk.transformed_sha256, 'representation_identity': chunk.representation_identity,
        'source_version': chunk.version, 'source_snapshot': source.source_identity}


@dataclass(frozen=True)
class PackedContext:
    text: str = field(repr=False)
    proxy_tokens: int
    dependencies: tuple
    citations: tuple = field(repr=False)


def pack_context(source, hits, token_counter, token_budget, *, mandatory='', budget=None):
    budget = Budget() if budget is None else budget
    if token_budget not in (2048, 8192) or type(token_budget) is not int:
        raise RetrievalError('invalid_context_budget')
    if not isinstance(mandatory, str) or len(mandatory.encode()) > 262144:
        raise RetrievalError('context_bytes_exceeded')

    def count(text):
        budget.check()
        try:
            result = token_counter(text)
        except Exception:
            raise RetrievalError('tokenizer_unavailable') from None
        if type(result) is not int or result < 0:
            raise RetrievalError('invalid_token_count')
        budget.check()
        return result

    used = count(mandatory)
    if used > token_budget:
        raise RetrievalError('mandatory_budget_exceeded')
    context, citations, dependencies, seen = mandatory, [], set(), set()
    for hit in hits[:100]:
        budget.check()
        chunk = hit.chunk
        citation = verify_citation(source, chunk, budget=budget)
        lines = chunk.text.splitlines(keepends=True)
        fresh = [(number, line) for number, line in enumerate(lines, chunk.start)
            if (chunk.key, chunk.path, number) not in seen]
        if not fresh:
            continue
        header = f'[{chunk.path}:{chunk.start}-{chunk.end} sha256={chunk.file_sha256} source-lines='
        header += ','.join(str(number) for number, _ in fresh) + ']\n'
        piece = header + ''.join(line for _, line in fresh) + '\n---\n'
        prospective = context + piece
        if len(prospective.encode()) > 262144 or count(prospective) > token_budget:
            continue
        if chunk.key not in dependencies:
            budget.charge('dependencies', 1)
        context = prospective
        used = count(context)
        citations.append(citation)
        dependencies.add(chunk.key)
        seen.update((chunk.key, chunk.path, number) for number, _ in fresh)
    return PackedContext(context, used, tuple(sorted(dependencies)), tuple(citations))
