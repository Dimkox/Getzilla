"""Narrow POSIX local reader using the existing native-root and Read policy.

The current OS owner, route owner and held source resources define this local
profile. It is not an enterprise ACL or permission to send bytes to a provider.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

from .. import policy, state
from ..source_admission import sensitive_class
from ..source_secrets import rules_digest, scan_bytes
from .budget import RetrievalError
from .contracts import SourceDocument, SourceKey, SourceSnapshot, digest

MAX_FILES = 112
MAX_BYTES = 8 * 1024 * 1024 - 65536
SKIP = {'.git', '.getzilla/runtime', '.getzilla/index', '.getzilla/config', '.getzilla/modules',
        '.getzilla/managed-components.json', '.venv', 'node_modules', '__pycache__'}


class NativeSource:
    def __init__(self, root, anchor, resources, budget, *, extra_metadata=()):
        self.root, self.anchor, self.resources, self.budget = root, anchor, resources, budget
        self.held, self.gaps = [], set()
        self.counters = {'source_file_opens': 0, 'source_recheck_reads': 0,
                         'local_read_bytes': 0, 'policy_checks': 0}
        self.route = state.require_route_owner(root, anchor=anchor)
        if not state.current_session() or self.route.get('workspace') != str(root):
            raise RetrievalError('authority_unavailable')
        self.metadata = {path: self._read(path) for path in ('.getzilla/config/policy.json',
                                                          '.getzilla/managed-components.json', *extra_metadata)}
        declared = json.loads(self.metadata['.getzilla/config/policy.json'])
        if (type(declared) is not dict or declared.get('schema_version') != 2
                or type(declared.get('secret_read_paths')) is not list
                or any(type(item) is not str for item in declared['secret_read_paths'])):
            raise RetrievalError('policy_unavailable')
        self.policy_digest = digest([hashlib.sha256(raw).hexdigest() for raw in self.metadata.values()])
        self.git = self._git()
        self.paths = self._paths()
        documents, total = [], 0
        repository = anchor.binding['repository_digest']
        for path in self.paths:
            budget.check()
            if sensitive_class(path) is not None or not self.allowed(path):
                self.gaps.add('source_policy_exclusion')
                continue
            if Path(path).suffix not in {'.py', '.pyi'}:
                self.gaps.add('language_or_content_not_indexed')
                continue
            if len(documents) >= MAX_FILES:
                raise RetrievalError('source_file_limit')
            try:
                raw = self._read(path)
                raw.decode('utf-8')
            except (OSError, ValueError, UnicodeError):
                self.gaps.add('source_unavailable')
                continue
            findings, unsupported = scan_bytes(path, raw)
            if findings or unsupported:
                self.gaps.add('source_secret_or_container_exclusion')
                continue
            total += len(raw)
            if total > MAX_BYTES:
                raise RetrievalError('source_bytes_exceeded')
            key = SourceKey('os-' + str(os.getuid()), repository, 'native-local', repository,
                            hashlib.sha256(path.encode()).hexdigest())
            documents.append(SourceDocument(key, path, 'sha256:' + hashlib.sha256(raw).hexdigest(),
                                            raw, raw, rules_digest(), 'identity-scanned-v1'))
        self.source = SourceSnapshot.create('os-' + str(os.getuid()), repository, repository, documents,
            base_sha=None if self.git is None else self.git['head'],
            head_sha=None if self.git is None else self.git['head'])

    def _read(self, path):
        self.budget.check()
        descriptor, parent = self.resources.enter_context(self.anchor.file(path, source=True))
        expected = os.fstat(descriptor)
        chunks, size = [], 0
        while True:
            self._held_unchanged(path, descriptor, parent, expected)
            block = os.read(descriptor, min(65536, 1048577 - size))
            if not block:
                break
            size += len(block)
            if size > 1048576:
                raise RetrievalError('source_file_exceeded')
            chunks.append(block)
            self.budget.check()
        raw = b''.join(chunks)
        self.counters['source_file_opens'] += 1
        self.counters['local_read_bytes'] += len(raw)
        self.held.append((path, descriptor, parent, expected, hashlib.sha256(raw).hexdigest()))
        return raw

    def allowed(self, path):
        self.counters['policy_checks'] += 1
        event = {'tool_name': 'Read', 'tool_input': {'file_path': str(self.root / path)}}
        return policy.evaluate_pre_tool(self.root, event, execution_cwd=self.root)[0] is True

    def _git(self):
        return self.anchor.git_source() if self.anchor.exists('.git', source=True) else None

    def _paths(self):
        result, entries = [], 0
        def visit(descriptor, prefix=''):
            nonlocal entries
            with os.scandir(descriptor) as iterator:
                names = []
                for entry in iterator:
                    self.budget.check()
                    entries += 1
                    if entries > 4096:
                        raise RetrievalError('source_inventory_exceeded')
                    names.append(entry.name)
            for name in sorted(names):
                path = prefix + name
                if path in SKIP or name == '__pycache__':
                    continue
                info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    try:
                        with self.anchor.parent(path + '/.context-probe', source=True) as (child, _):
                            visit(child, path + '/')
                    except RetrievalError:
                        raise
                    except (OSError, ValueError):
                        self.gaps.add('source_directory_exclusion')
                elif stat.S_ISREG(info.st_mode):
                    result.append(path)
                else:
                    self.gaps.add('source_link_or_special_exclusion')
        descriptor = self.anchor.duplicate_root_fd()
        try:
            visit(descriptor)
        finally:
            os.close(descriptor)
        return tuple(result)

    def _held_unchanged(self, path, descriptor, parent, expected):
        self.anchor.check_parent(parent)
        opened = os.fstat(descriptor)
        named = os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False)
        self.anchor._regular(opened, source=True)
        self.anchor._regular(named, source=True)
        def identity(info):
            return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
                    info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if identity(opened) != identity(expected) or identity(named) != identity(expected):
            raise RetrievalError('source_or_authority_changed')

    def recheck(self):
        self.budget.check()
        self.anchor.check_cwd()
        if state.require_route_owner(self.root, anchor=self.anchor) != self.route or self._git() != self.git:
            raise RetrievalError('source_or_authority_changed')
        if self._paths() != self.paths:
            raise RetrievalError('source_or_authority_changed')
        for path, descriptor, parent, expected, expected_sha in self.held:
            self._held_unchanged(path, descriptor, parent, expected)
            os.lseek(descriptor, 0, os.SEEK_SET)
            raw = os.read(descriptor, 1048577)
            self.counters['source_recheck_reads'] += 1
            self.counters['local_read_bytes'] += len(raw)
            if hashlib.sha256(raw).hexdigest() != expected_sha:
                raise RetrievalError('source_or_authority_changed')
            if path not in self.metadata and not self.allowed(path):
                raise RetrievalError('source_or_authority_changed')
            self.budget.check()
