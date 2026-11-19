"""Fixed historical study windows over already admitted public bytes.

Pure computation. A counter identity, manifest row or returned window grants no
source, model, ranking or output permission. Native admission remains separate.
"""
from __future__ import annotations

from concurrent.futures import CancelledError
from dataclasses import dataclass, field

from .budget import Budget, RetrievalError
from .contracts import hex_digest, sha
from .evaluation_inputs import checked_relative
from .lines import physical_lines

FUNCTION_FIELDS = frozenset({'id', 'path', 'symbol', 'start', 'end', 'sha256',
                             'file_sha256', 'overload_stub'})
MAX_WINDOW_BYTES = 65536


@dataclass(frozen=True)
class StudyWindow:
    corpus: str
    path: str
    symbol: str
    function_id: str
    start: int
    end: int
    file_sha256: str
    sha256: str
    text: str = field(repr=False)
    encoder_tokens: int
    encoder_truncated: bool
    tokenizer_digest: str

    @property
    def id(self):
        return f'{self.function_id}@{self.start}-{self.end}'


def windows_for_file(corpus, path, raw, functions, counter, *, budget=None):
    """Preserve original greedy254/two-line overlap and immutable function IDs.

The original Protocol ellipsis declarations remain ordinary rows. Only the
original explicit overload_stub flag excludes a declaration; no AST reinterpretation
or post-review data correction occurs here.
"""
    budget = Budget() if budget is None else budget
    budget.check()
    if (type(corpus) is not str or corpus not in {'small', 'large'}
            or type(raw) is not bytes or len(raw) > 1048576
            or type(functions) not in {tuple, list} or len(functions) > 8192
            or not hex_digest(getattr(counter, 'identity', None))):
        raise RetrievalError('invalid_study_source')
    checked_relative(path)
    budget.charge('files', 1)
    budget.charge('source_bytes', len(raw))
    try:
        raw.decode('utf-8')
    except UnicodeError:
        raise RetrievalError('invalid_study_source') from None
    lines, source_hash, selected, seen = physical_lines(raw), sha(raw), [], set()

    def count(data):
        budget.check()
        try:
            value = counter.count(data.decode('utf-8'))
        except CancelledError:
            raise
        except Exception:
            raise RetrievalError('window_tokenizer_unavailable') from None
        budget.check()
        if type(value) is not int or not 0 <= value <= 1048576:
            raise RetrievalError('window_tokenizer_unavailable')
        return value

    for function in functions:
        budget.check()
        if type(function) is not dict or set(function) != FUNCTION_FIELDS:
            raise RetrievalError('invalid_study_function')
        start, stop, symbol = function['start'], function['end'], function['symbol']
        if (function['path'] != path or type(start) is not int or type(stop) is not int
                or not 1 <= start <= stop <= len(lines) or type(symbol) is not str
                or not 0 < len(symbol) <= 1024 or not symbol.isprintable()
                or type(function['overload_stub']) is not bool
                or function['id'] != f'{path}:{start}:{symbol}'
                or function['id'] in seen or function['file_sha256'] != source_hash
                or function['sha256'] != sha(b''.join(lines[start - 1:stop]))):
            raise RetrievalError('stale_study_source')
        seen.add(function['id'])
        if function['overload_stub']:
            continue
        while start <= stop:
            budget.check()
            end = start
            while end < stop and count(b''.join(lines[start - 1:end + 1])) <= 254:
                end += 1
            data = b''.join(lines[start - 1:end])
            if len(data) > MAX_WINDOW_BYTES:
                raise RetrievalError('source_window_bytes_exceeded')
            encoded = count(data)
            budget.charge('chunks', 1)
            budget.charge('index_bytes', len(data))
            selected.append(StudyWindow(corpus, path, symbol, function['id'], start, end,
                source_hash, sha(data), data.decode('utf-8'), encoded, encoded > 256, counter.identity))
            if end == stop:
                break
            start = max(start + 1, end - 1)
    return tuple(sorted(selected, key=lambda row: row.id))
