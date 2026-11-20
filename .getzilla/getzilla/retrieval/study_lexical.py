"""Published162 ASCII lexical formulas over fixed shared study windows.

This pure research index is not a production source reader or ranking permit.
Unlike the Core no-encoder path, it precomputes exactly the published index
statistics once; native study admission and current lineage remain mandatory.
"""
from __future__ import annotations

from collections import Counter
import math
import re

from .budget import Budget, RetrievalError


def tokens(text):
    out = []
    for full in re.findall(r'[A-Za-z_][A-Za-z_0-9]*|[0-9]+', text):
        pieces = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', full).replace('_', ' ').lower().split()
        out.append(full.lower())
        out.extend(piece for piece in pieces if piece != full.lower())
    return out


class LexicalIndex:
    def __init__(self, windows, *, budget=None):
        budget = Budget() if budget is None else budget
        budget.check()
        if type(windows) not in {tuple, list} or not 1 <= len(windows) <= 8192:
            raise RetrievalError('invalid_study_index')
        self.windows, self.counts, self.symbols = tuple(windows), [], []
        ids = set()
        for row in self.windows:
            budget.check()
            if row.id in ids:
                raise RetrievalError('invalid_study_index')
            ids.add(row.id)
            budget.charge('index_bytes', len(row.text.encode()))
            self.counts.append(Counter(tokens(row.text)))
            self.symbols.append(set(re.findall(r'[A-Za-z_][A-Za-z_0-9]*', row.symbol)) | {row.symbol})
        self.lengths = tuple(sum(row.values()) for row in self.counts)
        self.average = sum(self.lengths) / len(self.lengths)
        df = Counter(term for row in self.counts for term in row)
        self.idf = {term: math.log(1 + (len(self.windows) - count + .5) / (count + .5))
                    for term, count in df.items()}

    def _rank(self, scores):
        return tuple((self.windows[index].id, float(scores[index])) for index in
            sorted(range(len(scores)), key=lambda index: (-float(scores[index]), self.windows[index].id))
            if scores[index] > 0)[:100]

    def query(self, text, *, budget=None):
        budget = Budget() if budget is None else budget
        if type(text) is not str or len(text.encode()) > 4096:
            raise RetrievalError('invalid_query')
        terms = tokens(text)
        if len(terms) > 64:
            raise RetrievalError('query_terms_exceeded')
        budget.charge('query_source_bytes', sum(len(row.text.encode()) for row in self.windows))
        budget.charge('scoring_units', len(self.windows) * max(1, len(terms)))
        exact = set(re.findall(r'[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*', text))
        exact |= {part for item in tuple(exact) for part in item.split('.')}
        symbol = self._rank([len(exact & names) for names in self.symbols])
        scores = [0.0] * len(self.windows)
        if self.average:
            for term in terms:
                idf = self.idf.get(term, 0)
                for index, row in enumerate(self.counts):
                    if index % 256 == 0:
                        budget.check()
                    tf = row.get(term, 0)
                    scores[index] += idf * tf * 2.2 / (tf + 1.2 *
                        (.25 + .75 * self.lengths[index] / self.average))
        budget.check()
        return {'exact_symbol': symbol, 'bm25': self._rank(scores)}
