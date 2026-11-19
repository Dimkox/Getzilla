"""Pure published context serialization over already admitted study windows.

The result contains source bytes. Native callers must keep it behind the same
current source/operation/resource fences as encoder inputs and final release.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from concurrent.futures import CancelledError

from .budget import Budget, RetrievalError
from .contracts import hex_digest, sha
from .evaluation_inputs import checked_relative
from .study_windows import StudyWindow


@dataclass(frozen=True)
class PackedContext:
    text: str = field(repr=False)
    tokens: int
    functions: tuple[str, ...]
    included_positions: tuple[int, ...]
    unavailable_positions: tuple[int, ...]
    skipped_positions: tuple[int, ...]


def pack_context(ranking, windows, counter, token_budget, *, budget=None):
    budget = Budget() if budget is None else budget
    budget.check()
    if (type(ranking) not in {tuple, list} or len(ranking) > 100
            or any(type(key) is not str or not key for key in ranking)
            or type(windows) is not dict or len(windows) > 8192
            or type(token_budget) is not int or token_budget not in {2048, 8192}
            or not hex_digest(getattr(counter, 'identity', None))):
        raise RetrievalError('invalid_context_request')
    context, functions, included, unavailable, skipped = [], [], [], [], []
    seen_lines, corpus, used = set(), None, 0
    for position, key in enumerate(ranking, 1):
        budget.check()
        row = windows.get(key)
        if row is None:
            unavailable.append(position)
            continue
        if (type(row) is not StudyWindow or row.id != key or type(row.text) is not str
                or row.corpus not in {'small', 'large'}
                or type(row.start) is not int or type(row.end) is not int
                or not 1 <= row.start <= row.end or not hex_digest(row.file_sha256)
                or sha(row.text.encode()) != row.sha256
                or len(row.text.encode()) > 65536
                or len(row.text.splitlines()) != row.end - row.start + 1
                or (corpus is not None and row.corpus != corpus)):
            raise RetrievalError('invalid_context_window')
        checked_relative(row.path)
        corpus = row.corpus
        fresh = [(number, line) for number, line in enumerate(
                 row.text.splitlines(keepends=True), row.start)
                 if (row.path, number) not in seen_lines]
        if not fresh:
            skipped.append(position)
            continue
        header = (f'[{row.corpus} {row.path}:{row.start}-{row.end} '
                  f'sha256={row.file_sha256} source-lines='
                  + ','.join(str(number) for number, _ in fresh) + ']\n')
        piece = header + ''.join(line for _, line in fresh) + '\n---\n'
        prospective = ''.join(context) + piece
        budget.check()
        try:
            count = counter.count(prospective)
        except CancelledError:
            raise
        except Exception:
            raise RetrievalError('context_codec_unavailable') from None
        budget.check()
        if type(count) is not int or not 0 <= count <= 1048576:
            raise RetrievalError('context_codec_unavailable')
        if count > token_budget:
            skipped.append(position)
            continue
        used = count
        context.append(piece)
        functions.append(row.function_id)
        included.append(position)
        seen_lines.update((row.path, number) for number, _ in fresh)
    return PackedContext(''.join(context), used, tuple(functions), tuple(included),
                         tuple(unavailable), tuple(skipped))
