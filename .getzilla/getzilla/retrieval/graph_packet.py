"""Compose the existing graph and retrieval owners over a native-selected cut.

No root discovery, credential lookup or authority fallback lives here. The host
must recheck its current cut and own final admission after this computation.
"""
from __future__ import annotations

from ..code_graph.context import query_graph
from ..code_graph.models import EXTRACTOR
from .budget import Budget, RetrievalError
from .observation import stage
from .contracts import Chunk, sha
from .lines import physical_lines
from .packet import prepare_packet
from .ranking import RankedHit


def current_graph(graph_input, store):
    """The graph store remains the only persistent index owner.

    The caller already owns authorized bounded input bytes and cache custody.
    Reuse an identical generation without parsing or relinking. Changed source
    uses the existing incremental path and its transactional publication.
    """
    with stage('cache_lookup') as measured:
        previous = store.read_active()
        reused = previous is not None and previous.input_identity == graph_input.identity
        measured.result('cache_hit' if reused else 'cache_miss')
    if reused:
        return previous, {'generation_reused': True, 'parsed_files': 0, 'link_resolution_runs': 0}
    from ..code_graph.incremental import update_index
    from ..code_graph.store import build_full_index
    graph = build_full_index(graph_input, store) if previous is None else update_index(previous, graph_input, store)
    return graph, {'generation_reused': False, 'parsed_files': graph.counters.get('parsed', 0),
                   'link_resolution_runs': 1}


def prepare_graph_packet(source, generation, graph, query, *, depth=1, max_nodes=32, budget=None, **options):
    budget = Budget() if budget is None else budget
    budget.check()
    actual = {document.path: document.original_sha256 for document in source.documents}
    indexed = {node.path: node.sha256 for node in graph.files}
    graph_source = graph.graph_input.get('source', {})
    # A graph identity must match the whole authorized representation cut. A
    # matching selected fragment cannot make a stale surrounding graph current.
    if (actual != indexed or len(actual) != len(source.documents)
            or graph.graph_input.get('config', {}).get('extractor') != EXTRACTOR
            or source.head_sha is not None and graph_source.get('commit_oid') != source.head_sha
            or source.head_sha is None and graph_source.get('source_kind') != 'folder'):
        raise RetrievalError('current_graph_unavailable')
    with stage('structural') as measured:
        selection = query_graph(graph, query, depth=depth, max_nodes=max_nodes, budget=budget)
        measured.result('succeeded' if selection['node_ids'] else 'empty',
                        candidate_count=len(selection['node_ids']))
    selected = set(selection['node_ids'])
    paths = {node['path'] for node in selection['nodes'] if node['id'].startswith('file:')}
    chunks = [chunk for chunk in generation.chunks if 'sym:' + chunk.path + '::' + chunk.symbol in selected
              or chunk.path in paths]
    references, fragment_gaps = [], set()
    documents = {document.path: document for document in source.documents}
    for node in selection['nodes']:
        if node.get('kind') != 'class' and not node['id'].startswith('file:'):
            continue
        document = documents[node['path']]
        lines = physical_lines(document.original)
        represented = physical_lines(document.representation)
        start, end = (node['span'][0], node['span'][2]) if 'span' in node else (1, min(128, len(lines)))
        if not 1 <= start <= end <= len(lines):
            raise RetrievalError('stale_citation')
        raw = b''.join(lines[start - 1:end])
        transformed = b''.join(represented[start - 1:end])
        if max(len(raw), len(transformed)) > 65536:
            fragment_gaps.add('graph_fragment_bytes_exceeded')
            continue
        references.append(Chunk(document.key, document.path, document.version, node.get('qualname', '<file>'),
                                start, end, document.original_sha256, sha(raw),
                                document.representation_identity, sha(transformed), transformed.decode('utf-8')))
        if node['id'].startswith('file:') and end < len(lines):
            fragment_gaps.add('file_fragment_line_limit')
    hits = tuple(RankedHit(chunk, 1.0, index + 1)
                 for index, chunk in enumerate((*references, *chunks)[:100]))
    packet = prepare_packet(source, generation, query, graph_hits=hits, budget=budget, **options)
    packet['coverage_gaps'] = sorted(set(packet['coverage_gaps']) | fragment_gaps)
    packet['graph'] = selection
    return packet
