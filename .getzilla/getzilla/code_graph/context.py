"""Bounded metadata selection over the project's existing code graph.

This selects references only. It does not read source, authorize a principal,
prove complete analysis or qualify a destination for source text.
"""
from __future__ import annotations

from ..retrieval.budget import Budget
from .models import GraphError


def query_graph(generation, query, *, depth=1, max_nodes=32, budget=None):
    if (type(query) is not str or not query.strip() or len(query.encode('utf-8')) > 4096
            or type(depth) is not int or not 0 <= depth <= 3
            or type(max_nodes) is not int or not 1 <= max_nodes <= 128):
        raise GraphError('INVALID_CONTEXT_QUERY')
    budget = Budget() if budget is None else budget
    budget.check()
    symbols = {symbol.id: symbol for symbol in generation.symbols}
    files = {node.id: node for node in generation.files}
    nodes = {**files, **symbols}
    if len(nodes) > 100_000 or len(generation.calls) + len(generation.imports) > 200_000:
        raise GraphError('CONTEXT_GRAPH_LIMIT')
    query = query.strip()
    exact = sorted(key for key, node in nodes.items() if query in {key, node.path}
                   or key in symbols and query in {node.qualname, node.qualname.rsplit('.', 1)[-1]})
    ambiguous = len([key for key in exact if key in symbols]) > 1 and not query.startswith(('file:', 'sym:'))
    adjacency = {key: set() for key in nodes}
    for edge in generation.calls:
        budget.check()
        for target in edge.targets:
            if edge.caller in nodes and target in nodes:
                adjacency[edge.caller].add(target)
                adjacency[target].add(edge.caller)
    for edge in generation.imports:
        budget.check()
        origin, target = 'file:' + edge.source_file, 'file:' + str(edge.target_file)
        if origin in nodes and target in nodes:
            adjacency[origin].add(target)
            adjacency[target].add(origin)
    # Symbols inherit the import references of their containing file. File queries
    # select contained symbols without pretending that every file is one symbol.
    for key, symbol in symbols.items():
        budget.check()
        owner = 'file:' + symbol.path
        adjacency[key].update(adjacency.get(owner, ()))
        adjacency[owner].add(key)
    selected = exact[:max_nodes]
    truncated = len(exact) > max_nodes
    frontier = list(selected)
    seen = set(selected)
    for _ in range(depth):
        pending = sorted({target for key in frontier for target in adjacency[key]} - seen)
        room = max_nodes - len(selected)
        truncated |= len(pending) > room
        frontier = pending[:room]
        selected.extend(frontier)
        seen.update(frontier)
        budget.check()
        if not frontier:
            break
    reason = 'no_graph_match' if not exact else ('node_budget_exceeded' if truncated else
                                               'ambiguous_symbol' if ambiguous else 'selected')
    return {'schema': 'getzilla-graph-context-v1', 'generation_id': generation.generation_id,
            'input_identity': generation.input_identity, 'node_ids': selected,
            'nodes': [nodes[key].to_dict() for key in selected], 'depth': depth,
            'truncated': truncated, 'reason': reason, 'coverage': generation.coverage.to_dict(),
            'qualification': 'source_selection_only'}
