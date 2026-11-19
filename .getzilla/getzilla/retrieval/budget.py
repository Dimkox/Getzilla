"""One caller-independent deadline and aggregate limits across retrieval stages."""
from __future__ import annotations

import time

LIMITS = {'files': 4000, 'source_bytes': 32 * 1024 * 1024, 'index_bytes': 32 * 1024 * 1024, 'chunks': 8192,
    'query_source_bytes': 8 * 1024 * 1024, 'scoring_units': 1_048_576,
    'authorization_calls': 32, 'authorization_checks': 8192, 'dependencies': 128}


class RetrievalError(ValueError):
    """Diagnostics contain fixed codes, never source content or adapter errors."""


class Budget:
    def __init__(self, *, clock=time.monotonic, seconds=2.0):
        if type(seconds) not in (int, float) or not 0 < seconds <= 2:
            raise RetrievalError('invalid_deadline')
        self.clock = clock
        self.deadline = clock() + seconds
        self.counts = {key: 0 for key in LIMITS}

    def check(self):
        if self.clock() >= self.deadline:
            raise RetrievalError('deadline_exceeded')

    def charge(self, kind, count):
        self.check()
        if kind not in LIMITS or type(count) is not int or count < 0:
            raise RetrievalError('invalid_work')
        if self.counts[kind] + count > LIMITS[kind]:
            raise RetrievalError(kind + '_exceeded')
        self.counts[kind] += count

    def remaining(self):
        self.check()
        return self.deadline - self.clock()
