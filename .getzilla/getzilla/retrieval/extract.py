"""Implementation-inclusive source spans; no model or project code is executed."""
from __future__ import annotations

import ast

from .budget import Budget, RetrievalError
from .contracts import Chunk, Generation, hex_digest, sha


def build_generation(source, *, budget=None, window_counter=None):
    budget = Budget() if budget is None else budget
    budget.charge('files', len(source.documents))
    budget.charge('source_bytes', sum(len(d.original) + len(d.representation) for d in source.documents))
    chunks, gaps, overloads = [], set(), 0
    if window_counter is not None and not hex_digest(getattr(window_counter, 'identity', None)):
        raise RetrievalError('window_tokenizer_unavailable')

    def count(text):
        budget.check()
        try:
            result = window_counter.count(text)
        except Exception:
            raise RetrievalError('window_tokenizer_unavailable') from None
        budget.check()
        if type(result) is not int or not 0 <= result <= 1_048_576:
            raise RetrievalError('window_tokenizer_unavailable')
        return result

    for document in sorted(source.documents, key=lambda d: (d.key, d.path)):
        budget.check()
        if not document.path.endswith('.py'):
            gaps.add('language_unavailable')
            continue
        try:
            tree = ast.parse(document.original)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            gaps.add('python_parse_unavailable')
            continue
        original = document.original.splitlines(keepends=True)
        representation = document.representation.splitlines(keepends=True)

        def visit(node, parents=()):
            nonlocal overloads
            budget.check()
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    names = parents + (child.name,)
                    if not isinstance(child, ast.ClassDef):
                        is_overload = any(isinstance(d, ast.Name) and d.id == 'overload'
                            or isinstance(d, ast.Attribute) and d.attr == 'overload' for d in child.decorator_list)
                        if is_overload:
                            overloads += 1
                        else:
                            start = min([child.lineno] + [d.lineno for d in child.decorator_list])
                            end = child.end_lineno
                            cursor = start
                            while cursor <= end:
                                stop = end if window_counter is None else cursor
                                if window_counter is not None:
                                    while stop < end and count(b''.join(representation[cursor - 1:stop + 1]).decode()) <= 254:
                                        stop += 1
                                raw = b''.join(original[cursor - 1:stop])
                                transformed = b''.join(representation[cursor - 1:stop])
                                if max(len(raw), len(transformed)) > 65_536:
                                    raise RetrievalError('window_tokenizer_unavailable')
                                encoded = None if window_counter is None else count(transformed.decode())
                                budget.charge('index_bytes', len(raw) + len(transformed))
                                budget.charge('chunks', 1)
                                chunks.append(Chunk(document.key, document.path, document.version, '.'.join(names),
                                    cursor, stop, document.original_sha256, sha(raw), document.representation_identity,
                                    sha(transformed), transformed.decode('utf-8'), encoded,
                                    None if encoded is None else encoded > 256))
                                if stop == end:
                                    break
                                cursor = max(cursor + 1, stop - 1)
                    visit(child, names)
                else:
                    visit(child, parents)

        try:
            visit(tree)
        except RecursionError:
            raise RetrievalError('ast_depth_exceeded') from None
    profile = 'function_no_encoder_v1' if window_counter is None else 'token_window254_overlap2_v1:' + window_counter.identity
    return Generation(source.repository, source.source_identity, tuple(sorted(chunks, key=lambda c: c.id)),
        tuple(sorted(d.representation_identity for d in source.documents)), overloads, tuple(sorted(gaps)), profile)
