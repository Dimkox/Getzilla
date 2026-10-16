"""Helpers for the code graph tests: in-memory scopes and the fixed fixture corpus."""
from __future__ import annotations

import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.code_graph.builder import build_generation  # noqa: E402
from getzilla.code_graph.models import GraphConfig, make_graph_input  # noqa: E402

FIXTURES = ROOT / 'tests' / 'fixtures' / 'code_graph' / 'python'
FOLDER = {'source_kind': 'folder', 'source_digest': '0' * 64}


def scope(files: dict[str, str]) -> dict[str, bytes]:
    return {path: textwrap.dedent(text).encode('utf-8') for path, text in files.items()}


def graph_input(files: dict[str, str], config: GraphConfig | None = None, baseline=None, **kwargs):
    return make_graph_input(baseline or FOLDER, scope(files), config or GraphConfig(), **kwargs)


def generation(files: dict[str, str], config: GraphConfig | None = None, **kwargs):
    return build_generation(graph_input(files, config, **kwargs))


BROKEN = b'def oops(:\n    pass\n'  # kept in memory so repository linters never see invalid syntax


def fixture_scope() -> dict[str, bytes]:
    files = {path.relative_to(FIXTURES).as_posix(): path.read_bytes()
             for path in sorted(FIXTURES.rglob('*')) if path.is_file()}
    return {**files, 'shop/broken.py': BROKEN}


def calls_by_expression(gen, caller_suffix: str = '') -> dict[str, object]:
    return {edge.expression: edge for edge in gen.calls if edge.caller.endswith(caller_suffix)}
