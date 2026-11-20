"""Immutable data files using the existing private runtime/par artifact owner.

This adapter grants no source/model/output admission and creates no journal or
permission store. The fixed driver must check current native release before IO.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re

from .budget import RetrievalError
from .contracts import sha


@dataclass(frozen=True)
class RunArtifact:
    path: str
    bytes: int
    sha256: str


class RunArtifacts:
    def __init__(self, root, *, byte_limit):
        if type(byte_limit) is not int or not 1 <= byte_limit <= 12 * 1024**3:
            raise RetrievalError('study_artifact_budget_unavailable')
        self.root, self.limit, self.used = Path(root), byte_limit, 0
        self._files, self._context, self._directory = {}, None, None

    def __enter__(self):
        from ..parallel import _log_folder
        self._context = _log_folder(self.root)
        self._folder, self._directory = self._context.__enter__()
        return self

    def write(self, name, payload):
        from ..parallel import _create_log
        if (self._directory is None or type(name) is not str
                or not re.fullmatch('[a-z0-9_-]{1,160}\\.json', name) or name in self._files):
            raise RetrievalError('study_artifact_name_unavailable')
        try:
            raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, allow_nan=False,
                             separators=(',', ':')).encode() + b'\n'
        except (ValueError, TypeError, UnicodeError):
            raise RetrievalError('study_artifact_payload_unavailable') from None
        if len(raw) > 16 * 1024**2 or self.used + len(raw) > self.limit:
            raise RetrievalError('study_artifact_bytes_exceeded')
        with _create_log(self._directory, name) as output:
            offset = 0
            while offset < len(raw):
                count = output.write(raw[offset:])
                if not count:
                    raise RetrievalError('study_artifact_write_unavailable')
                offset += count
        self.used += len(raw)
        observed = RunArtifact((self._folder / name).relative_to(self.root).as_posix(), len(raw), sha(raw))
        self._files[name] = observed
        return observed

    def manifest(self):
        return tuple(self._files[name] for name in sorted(self._files))

    def __exit__(self, *arguments):
        self._directory = None
        return self._context.__exit__(*arguments)
