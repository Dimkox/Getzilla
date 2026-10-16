"""Conservative impact: reverse dependencies over old and new edges, widened by every gap.

Traversal follows reverse imports (file -> importing files) and reverse calls (callee -> caller)
from both generations, so a deleted target still reaches its former dependents. Files with
unresolved or candidate calls, unresolved internal imports or dynamic gaps may reach any change
and are added with their dependents. An incomplete generation, an unsupported code language in
scope, a changed node the graph does not know, or a traversal limit widens the scope to the whole
configured project. Security checks are always required; an empty set never means "nothing to test".
"""
from __future__ import annotations

from collections import deque
from typing import Iterable

from .incremental import change_set
from .models import GraphConfig, GraphGeneration, ImpactReport

ALWAYS_REQUIRED = ('security_checks',)


def _reverse_edges(generations: Iterable[GraphGeneration]) -> dict[str, set[str]]:
    reverse: dict[str, set[str]] = {}
    for generation in generations:
        for edge in generation.imports:
            if edge.target_file is not None:
                reverse.setdefault(f'file:{edge.target_file}', set()).add(f'file:{edge.source_file}')
        for edge in generation.calls:
            if edge.resolution in ('exact', 'candidate'):
                caller_file = 'file:' + edge.caller.split(':', 1)[1].split('::', 1)[0]
                for target in edge.targets:
                    reverse.setdefault(target, set()).update({edge.caller, caller_file})
        for symbol in generation.symbols:
            reverse.setdefault(symbol.id, set()).add(f'file:{symbol.path}')
            reverse.setdefault(f'file:{symbol.path}', set()).add(symbol.id)
    return reverse


ANY_TARGET = frozenset({'REFLECTION', 'DYNAMIC_CALLEE'})


def _gap_files(generation: GraphGeneration, names: set[str]) -> dict[str, str]:
    """Files whose unresolved calls could reach a symbol named in `names` (or anything, for reflection)."""
    gaps: dict[str, str] = {}
    for edge in generation.calls:
        if edge.resolution != 'unresolved':
            continue
        if edge.reason in ANY_TARGET or edge.expression.rsplit('.', 1)[-1] in names:
            path = edge.caller.split(':', 1)[1].split('::', 1)[0]
            gaps.setdefault(f'file:{path}', f'UNRESOLVED_CALL_MAY_REACH_CHANGE:{edge.reason}')
    for edge in generation.imports:
        if edge.resolution == 'unresolved':
            gaps.setdefault(f'file:{edge.source_file}', f'UNRESOLVED_IMPORT:{edge.reason}')
    for path, parsed in generation.parsed.items():
        if parsed.dynamic_gaps:
            gaps.setdefault(f'file:{path}', f'DYNAMIC_GAP:{parsed.dynamic_gaps[0][0]}')
    return gaps


def calculate_impact(previous: GraphGeneration | None, current: GraphGeneration,
                     changed_nodes: Iterable[str] | None = None, *, config: GraphConfig | None = None) -> ImpactReport:
    config = config or current.config
    generations = [current] if previous is None else [previous, current]
    if changed_nodes is None:
        if previous is None:
            changed = sorted(f'file:{item.path}' for item in current.files)
        else:
            delta = change_set(previous, current)
            changed = sorted(f'file:{path}' for paths in delta.values() for path in paths)
    else:
        changed = sorted({node if node.startswith(('file:', 'sym:')) else f'file:{node}' for node in changed_nodes})
    known = {f'file:{f.path}' for g in generations for f in g.files} | {s.id for g in generations for s in g.symbols}
    graph_nodes = {f'file:{f.path}' for g in generations for f in g.files if f.language == 'python'} | \
                  {s.id for g in generations for s in g.symbols}
    reasons: dict[str, set[str]] = {}
    gaps: list[str] = []
    for node in changed:
        reasons.setdefault(node, set()).add('CHANGED')
        if node not in known:
            gaps.append(f'CHANGED_NODE_NOT_IN_GRAPH:{node}')
        elif node not in graph_nodes:
            gaps.append(f'CHANGED_FILE_NOT_ANALYSED:{node}')
    reverse = _reverse_edges(generations)
    queue = deque(changed)
    seen = set(changed)
    limit_hit = False

    def visit(start: Iterable[str], why: str) -> None:
        nonlocal limit_hit
        for node in start:
            if node not in seen:
                seen.add(node)
                reasons.setdefault(node, set()).add(why)
                queue.append(node)
        while queue:
            node = queue.popleft()
            for dependent in sorted(reverse.get(node, ())):
                if dependent in seen:
                    reasons.setdefault(dependent, set()).add(f'DEPENDS_ON:{node}')
                    continue
                if len(seen) >= config.max_impact_nodes:
                    limit_hit = True
                    queue.clear()
                    return
                seen.add(dependent)
                reasons.setdefault(dependent, set()).add(f'DEPENDS_ON:{node}')
                queue.append(dependent)

    visit((), 'CHANGED')
    if changed:
        while not limit_hit:  # widen until no new gap file joins
            names = {node.rsplit('::', 1)[-1].rsplit('.', 1)[-1] for node in seen if node.startswith('sym:')}
            added = False
            for generation in generations:
                for node, why in sorted(_gap_files(generation, names).items()):
                    if node not in seen:
                        visit([node], why)
                        added = True
                    else:
                        reasons[node].add(why)
            if not added:
                break
    for generation in generations:
        coverage = generation.coverage
        gaps.extend(f'INCOMPLETE_PARSE:{path}:{why}' for path, why in coverage.incomplete)
        gaps.extend(f'UNSUPPORTED_LANGUAGE:{path}:{language}' for path, language in coverage.unsupported_language)
        gaps.extend(f'OMITTED:{path}:{why}' for path, why in coverage.omitted)
    if limit_hit:
        gaps.append('TRAVERSAL_LIMIT_REACHED')
    gaps = sorted(set(gaps))
    complete = not gaps
    fallback = 'none' if complete else 'configured_project'
    if not changed:
        gaps_note = ('NO_CHANGE_DETECTED',)
    else:
        gaps_note = ()
    required = (*ALWAYS_REQUIRED, 'affected_tests' if complete else 'full_test_suite', 'review')
    affected_files = tuple(sorted(node[5:] for node in seen if node.startswith('file:')))
    affected_symbols = tuple(sorted(node for node in seen if node.startswith('sym:')))
    return ImpactReport(None if previous is None else previous.generation_id, current.generation_id, tuple(changed),
                        affected_files, affected_symbols,
                        {node: tuple(sorted(why)) for node, why in reasons.items()}, complete,
                        tuple(gaps) + gaps_note, fallback, required, current.graph_input.get('source', {}))
