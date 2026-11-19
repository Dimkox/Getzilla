"""Finite history derived only from format-aware, independently hashed Git objects.

Git resolves literal refs and supplies object bytes. It does not choose parents, dates,
range membership or tree differences: grafts, shallow cutoffs and replace interpretation
therefore cannot silently rewrite the numerical evidence.
"""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass

from .history_git import GitReader, HistoryReadError


@dataclass(frozen=True)
class Commit:
    oid: str
    tree: str
    parents: tuple[str, ...]
    timestamp: int


class VerifiedObjects:
    def __init__(self, reader: GitReader, object_format: str, max_commits: int):
        if object_format not in ('sha1', 'sha256'):
            raise HistoryReadError('UNSUPPORTED_OBJECT_FORMAT')
        self.reader, self.format = reader, object_format
        self.oid_bytes = 20 if object_format == 'sha1' else 32
        self.commit_limit = max_commits + 1  # existing finite commit lookahead
        self.objects: dict[str, tuple[str, bytes]] = {}
        self.commits: dict[str, Commit] = {}
        self.trees: dict[str, dict[str, tuple[str, str]]] = {}

    def check_time(self):
        if time.monotonic() >= self.reader.deadline:
            raise HistoryReadError('TIME_BUDGET')

    def valid_oid(self, oid):
        return isinstance(oid, str) and len(oid) == self.oid_bytes * 2 and re.fullmatch('[a-f0-9]+', oid) is not None

    def object(self, oid: str, expected: str | None = None) -> tuple[str, bytes]:
        self.check_time()
        if not self.valid_oid(oid):
            raise HistoryReadError('INVALID_OBJECT_ID')
        if oid not in self.objects:
            _, kind_bytes = self.reader.read('cat-file', '-t', oid, bare=True)
            kind = kind_bytes.decode('ascii').strip()
            if kind not in ('blob', 'tree', 'commit', 'tag'):
                raise HistoryReadError('OBJECT_TYPE_MISMATCH')
            _, contents = self.reader.read('cat-file', kind, oid, bare=True)
            digest = hashlib.new(self.format, usedforsecurity=False)
            digest.update(kind.encode('ascii') + b' ' + str(len(contents)).encode('ascii') + b'\0')
            digest.update(contents)
            if digest.hexdigest() != oid:
                raise HistoryReadError('OBJECT_ID_MISMATCH')
            self.objects[oid] = (kind, contents)
        kind, contents = self.objects[oid]
        if expected is not None and kind != expected:
            raise HistoryReadError('OBJECT_TYPE_MISMATCH')
        return kind, contents

    def resolve(self, value: str) -> str:
        # Expressions such as HEAD~N would let unverified Git ancestry choose a
        # different range before admission. Literal refs/tags and full OIDs suffice.
        if not isinstance(value, str) or not value or len(value) > 256 or '\0' in value or value.startswith('-'):
            raise HistoryReadError('INVALID_REVISION')
        if not self.valid_oid(value):
            code, _ = self.reader.read('check-ref-format', '--allow-onelevel', value, allowed_codes=(0, 1))
            if code:
                raise HistoryReadError('INVALID_REVISION')
        code, raw = self.reader.read('rev-parse', '--verify', '--end-of-options', value, allowed_codes=(0, 128))
        if code:
            raise HistoryReadError('INVALID_REVISION')
        oid = raw.decode('ascii').strip()
        seen = set()
        while len(seen) < 64:
            if oid in seen:
                raise HistoryReadError('INVALID_TAG_CHAIN')
            seen.add(oid)
            kind, contents = self.object(oid)
            if kind == 'commit':
                return oid
            if kind != 'tag':
                raise HistoryReadError('INVALID_REVISION')
            headers = contents.partition(b'\n\n')[0].split(b'\n')
            targets = [line[7:].decode('ascii') for line in headers if line.startswith(b'object ')]
            declared = [line[5:].decode('ascii') for line in headers if line.startswith(b'type ')]
            if len(targets) != 1 or len(declared) != 1 or declared[0] not in ('tag', 'commit'):
                raise HistoryReadError('INVALID_TAG_CHAIN')
            oid = targets[0]
            self.object(oid, declared[0])
        raise HistoryReadError('TAG_CHAIN_BUDGET')

    def commit(self, oid: str) -> Commit:
        if oid in self.commits:
            return self.commits[oid]
        if len(self.commits) >= self.commit_limit:
            raise HistoryReadError('COMMIT_BUDGET')
        _, raw = self.object(oid, 'commit')
        header, separator, _ = raw.partition(b'\n\n')
        if not separator:
            raise HistoryReadError('INVALID_COMMIT')
        lines = header.split(b'\n')
        if not lines[0].startswith(b'tree ') or any(b'\0' in line for line in lines):
            raise HistoryReadError('INVALID_COMMIT')
        for line in lines:
            if line.startswith(b' '):
                continue  # continuation of an optional header, never a parent/date
            key, space, _value = line.partition(b' ')
            if not space or not re.fullmatch(rb'[a-zA-Z0-9-]+', key):
                raise HistoryReadError('INVALID_COMMIT')
        trees = [line[5:].decode('ascii') for line in lines if line.startswith(b'tree ')]
        parents = tuple(line[7:].decode('ascii') for line in lines if line.startswith(b'parent '))
        committers = [line for line in lines if line.startswith(b'committer ')]
        authors = [line for line in lines if line.startswith(b'author ')]
        if len(parents) > self.commit_limit:
            raise HistoryReadError('COMMIT_BUDGET')
        if len(trees) != 1 or not self.valid_oid(trees[0]) or len(committers) != 1 or len(authors) != 1 or any(
                not self.valid_oid(parent) or parent == oid for parent in parents):
            raise HistoryReadError('INVALID_COMMIT')
        timestamp = re.search(rb' (-?[0-9]{1,12}) [+-][0-9]{4}$', committers[0])
        if timestamp is None:
            raise HistoryReadError('INVALID_COMMIT')
        result = Commit(oid, trees[0], parents, int(timestamp[1]))
        self.commits[oid] = result
        return result

    def range(self, end: str, base: str | None, maximum: int) -> tuple[list[Commit], set[str]]:
        errors: set[str] = set()
        base_commit = self.commit(base) if base else None
        cut = set(base_commit.parents) | {base} if base_commit else set()
        pending, visited, records = [end], set(), []
        base_seen = end == base
        while pending:
            self.check_time()
            oid = pending.pop()
            if oid in visited or oid in cut:
                continue
            visited.add(oid)
            try:
                record = self.commit(oid)
            except HistoryReadError as error:
                errors.add(error.reason)
                if error.reason in ('COMMIT_BUDGET', 'TIME_BUDGET', 'BYTE_BUDGET'):
                    break
                continue
            records.append(record)
            if base in record.parents:
                base_seen = True
            pending.extend(reversed(record.parents))
        if len(records) > maximum or pending:
            errors.add('COMMIT_BUDGET')
        records = records[:maximum]
        if base is None:
            return records, errors
        if not base_seen:
            if not errors:
                errors.add('NON_ANCESTOR_RANGE')
            return [], errors
        parent_cut = set(base_commit.parents)
        # A candidate reaching every parent of base cannot be an ancestor of
        # any of them in this content-addressed DAG. A direct path to base also
        # supplies that proof. This closes ordinary small ranges without reading
        # the repository's irrelevant pre-base history.
        reached = {base: parent_cut, **{oid: {oid} for oid in parent_cut}}
        for start in records:
            stack = [(start.oid, False)]
            active = set()
            while stack:
                self.check_time()
                oid, exiting = stack.pop()
                if oid in reached:
                    continue
                record = self.commits.get(oid)
                if record is None:
                    reached[oid] = set()
                    continue
                if exiting:
                    reached[oid] = set().union(*(reached.get(parent, set()) for parent in record.parents))
                    active.discard(oid)
                else:
                    if oid in active:
                        raise HistoryReadError('INVALID_COMMIT_GRAPH')
                    active.add(oid)
                    stack.append((oid, True))
                    stack.extend((parent, False) for parent in reversed(record.parents) if parent not in reached)
        proven = {record.oid for record in records if reached[record.oid] >= parent_cut}
        if len(proven) == len(records):
            return records, errors
        ancestors, frontier = {base}, list(base_commit.parents)
        while frontier:
            self.check_time()
            oid = frontier.pop()
            if oid in ancestors:
                continue
            ancestors.add(oid)
            try:
                frontier.extend(self.commit(oid).parents)
            except HistoryReadError as error:
                errors.add(error.reason)
                return [record for record in records if record.oid in proven], errors
        return [record for record in records if record.oid not in ancestors], errors

    def tree(self, oid: str) -> dict[str, tuple[str, str]]:
        if oid in self.trees:
            return self.trees[oid]
        _, raw = self.object(oid, 'tree')
        position, entries = 0, {}
        while position < len(raw):
            self.check_time()
            space, nul = raw.find(b' ', position), raw.find(b'\0', position)
            if space < position or nul < space or nul + 1 + self.oid_bytes > len(raw):
                raise HistoryReadError('INVALID_TREE')
            mode = raw[position:space].decode('ascii')
            name = raw[space + 1:nul].decode('utf-8', 'surrogateescape')
            if mode not in ('40000', '040000', '100644', '100755', '120000', '160000') or not name or name in ('.', '..') or '/' in name:
                raise HistoryReadError('INVALID_TREE')
            target = raw[nul + 1:nul + 1 + self.oid_bytes].hex()
            if name in entries or set(target) == {'0'}:
                raise HistoryReadError('INVALID_TREE')
            entries[name] = ('40000' if mode == '040000' else mode, target)
            position = nul + 1 + self.oid_bytes
        self.trees[oid] = entries
        return entries

    def changes(self, old: str | None, new: str, maximum: int) -> dict[str, tuple[str, str]]:
        zero = '0' * (self.oid_bytes * 2)
        pending, result = [(old, new, '', 0)], {}
        while pending:
            self.check_time()
            old_tree, new_tree, prefix, depth = pending.pop()
            if depth > 256:
                raise HistoryReadError('TREE_DEPTH_BUDGET')
            if old_tree == new_tree:
                continue
            before = self.tree(old_tree) if old_tree else {}
            after = self.tree(new_tree) if new_tree else {}
            for name in sorted(before.keys() | after.keys()):
                left, right = before.get(name), after.get(name)
                if left == right:
                    continue
                path = prefix + name
                if len(path) > 4096:
                    raise HistoryReadError('TREE_PATH_BUDGET')
                if any(item and item[0] == '160000' for item in (left, right)):
                    raise HistoryReadError('UNSUPPORTED_GITLINK')
                left_dir, right_dir = bool(left and left[0] == '40000'), bool(right and right[0] == '40000')
                if left_dir or right_dir:
                    pending.append((left[1] if left_dir else None, right[1] if right_dir else None, path + '/', depth + 1))
                if left and not left_dir or right and not right_dir:
                    if len(result) >= maximum:
                        raise HistoryReadError('FILE_TOUCH_BUDGET')
                    result[path] = (left[1] if left and not left_dir else zero, right[1] if right and not right_dir else zero)
        return result
