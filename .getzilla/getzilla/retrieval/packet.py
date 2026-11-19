"""Provider-neutral computation over an already-authorized current source cut.

Packets are unadmitted values. Native source/sink authority remains at the ports;
constructing one is not permission to read a source or deliver it to a client.
"""
from __future__ import annotations

from .budget import Budget, RetrievalError
from .engine import pack_context, search


def prepare_packet(source, generation, query, *, mandatory='', token_budget=8192,
                   token_counter=None, tokenizer_identity=None, graph_hits=(), budget=None):
    budget = Budget() if budget is None else budget
    budget.check()
    if (generation.repository != source.repository or generation.source_snapshot != source.source_identity
            or generation.representation_ids != tuple(sorted(d.representation_identity for d in source.documents))):
        raise RetrievalError('current_index_unavailable')
    if token_counter is not None and (type(tokenizer_identity) is not str or not tokenizer_identity
                                     or len(tokenizer_identity) > 256):
        raise RetrievalError('tokenizer_identity_required')
    # Counting bytes imposes a conservative hard size bound. It is not a claim
    # about a selected model's tokenization or its actual provider usage.
    counter = token_counter or (lambda text: len(text.encode('utf-8')))
    result = search(generation, query, budget=budget)
    hits, seen = [], set()
    for hit in (*graph_hits, *result.rankings['rrf']):
        budget.check()
        if hit.chunk.id not in seen:
            hits.append(hit)
            seen.add(hit.chunk.id)
    packed = pack_context(source, hits, counter, token_budget, mandatory=mandatory, budget=budget)
    components = {name: {hit.chunk.id: (hit.rank, hit.score) for hit in rows}
                  for name, rows in result.rankings.items()}
    cited = {(row['path'], row['start'], row['end'], row['chunk_sha256']) for row in packed.citations}
    ranking_components = []
    for hit in hits[:100]:
        chunk = hit.chunk
        if (chunk.path, chunk.start, chunk.end, chunk.chunk_sha256) not in cited:
            continue
        ranking_components.append({'chunk_id': chunk.id,
            'ranks': {name: rows.get(chunk.id, (None, None))[0] for name, rows in components.items()},
            'scores': {name: rows.get(chunk.id, (None, None))[1] for name, rows in components.items()},
            'claim': 'ranking_components_not_confidence'})
    return {'schema': 'getzilla-context-packet-v1', 'qualification': 'unadmitted_source_packet',
            'generation_id': generation.identity, 'source_identity': source.source_identity,
            'text': packed.text, 'citations': list(packed.citations),
            'component_status': result.component_status, 'ranking_components': ranking_components, 'coverage_gaps': list(generation.gaps),
            'answerability': 'unknown', 'status': 'selected' if packed.citations else 'no_fitting_fragments',
            'token_accounting': {'kind': 'utf8_bytes_upper_bound_estimate' if token_counter is None else
                                'supplied_tokenizer_count', 'tokenizer': tokenizer_identity,
                                'count': packed.proxy_tokens, 'budget': token_budget,
                                'actual_input_tokens': None, 'cached_input_tokens': None,
                                'output_tokens': None, 'billed_tokens': None},
            'counters': dict(budget.counts)}
