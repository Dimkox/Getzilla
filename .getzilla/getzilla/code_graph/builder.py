"""Build one generation from a GraphInput; parsing may reuse earlier ParsedFiles of identical bytes and path."""
from __future__ import annotations

from typing import Mapping

from .models import SUPPORTED, FileNode, GraphGeneration, GraphInput, ParsedFile, build_coverage
from .python_calls import resolve_python_calls
from .python_resolver import ModuleIndex, import_bindings, resolve_file_imports
from .python_parser import parse_python


def build_generation(graph_input: GraphInput, reuse: Mapping[tuple[str, str], ParsedFile] | None = None) -> GraphGeneration:
    reuse = reuse or {}
    parsed: dict[str, ParsedFile] = {}
    counters = {'parsed': 0, 'reused': 0, 'resolved_files': 0}
    for item in graph_input.files:
        if item.language not in SUPPORTED:
            continue
        cached = reuse.get((item.path, item.sha256))
        if cached is not None:
            parsed[item.path] = cached
            counters['reused'] += 1
        else:
            parsed[item.path] = parse_python(item.path, graph_input.contents[item.path], graph_input.config)
            counters['parsed'] += 1
    complete = [entry for entry in parsed.values() if entry.status == 'complete']
    index = ModuleIndex([item.path for item in graph_input.files], graph_input.config)
    imports = []
    for entry in complete:
        imports.extend(resolve_file_imports(entry, index)[0])
        counters['resolved_files'] += 1
    calls = resolve_python_calls(complete, index, graph_input.config, import_bindings(complete, index))
    coverage = build_coverage(graph_input, list(parsed.values()),
                              sum(edge.resolution == 'unresolved' for edge in imports),
                              sum(edge.resolution in ('unresolved', 'candidate') for edge in calls))
    files = tuple(FileNode(item.path, item.language, item.sha256) for item in graph_input.files)
    unique: dict[str, object] = {}
    for entry in complete:
        for symbol in entry.symbols:
            unique.setdefault(symbol.id, symbol)  # a redefinition keeps one node; calls to it are REBOUND_NAME
    symbols = tuple(unique.values())
    return GraphGeneration(graph_input.identity, graph_input.to_dict(), files, symbols, tuple(imports), tuple(calls),
                           coverage, parsed, counters)
