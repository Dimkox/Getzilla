"""Fixed current reviewed worker source closure, not execution permission."""
from __future__ import annotations

import ast
from pathlib import Path

from .budget import RetrievalError
from .contracts import sha

WORKER_FILES = tuple(sorted(('getzilla/__init__.py', 'getzilla/retrieval/__init__.py',
    *(f'getzilla/retrieval/{name}.py' for name in (
        'budget', 'contracts', 'lines', 'evaluation_inputs', 'study_windows',
        'study_tokenizer', 'study_onnx_worker', 'study_codec', 'study_context',
        'study_vectors', 'study_metrics', 'study_lexical', 'study_worker_entry',
        'study_native_entry', 'study_worker_dispatch', 'study_waiter_process',
        'study_waiter_kernel', 'study_kernel', 'study_resources')))))


def _check_imports(path, raw):
    package = path.removesuffix('.py').split('/')[:-1]
    known = {item.removesuffix('.py').replace('/', '.') for item in WORKER_FILES}
    known |= {'getzilla', 'getzilla.retrieval'}
    try:
        tree = ast.parse(raw)
        for node in ast.walk(tree):
            modules = []
            if isinstance(node, ast.Import):
                modules = [item.name for item in node.names if item.name.startswith('getzilla')]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    base = package[:len(package) - node.level + 1]
                    modules = ['.'.join(base + node.module.split('.'))] if node.module else [
                        '.'.join(base + [item.name]) for item in node.names]
                elif node.module and node.module.startswith('getzilla'):
                    modules = [node.module]
            if any(module not in known for module in modules):
                raise RetrievalError('worker_source_closure_unavailable')
    except (SyntaxError, RecursionError):
        raise RetrievalError('worker_source_closure_unavailable') from None


def worker_source_files(root):
    from ..fsx import ReadOnlyBoundRoot
    root = Path(root).resolve(strict=True)
    rows, total, snapshots = [], 0, {}
    with ReadOnlyBoundRoot(root) as anchor:
        for path in WORKER_FILES:
            relative = '.getzilla/' + path
            observed = anchor.read(relative, limit=1048576)
            if observed is None or observed.mode not in {0o444, 0o644}:
                raise RetrievalError('worker_source_closure_unavailable')
            raw = observed.content
            total += len(raw)
            if total > 4 * 1024 * 1024:
                raise RetrievalError('worker_source_closure_unavailable')
            _check_imports(path, raw)
            snapshots[relative] = observed
            rows.append((path, len(raw), sha(raw)))
        for relative, original in snapshots.items():
            if anchor.read(relative, limit=1048576) != original:
                raise RetrievalError('worker_source_closure_unavailable')
        anchor.check()
    return tuple(rows)
