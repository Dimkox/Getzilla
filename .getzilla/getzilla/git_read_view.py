"""Private Git metadata for observations; repository configuration never reaches Git."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
import zlib

from . import fsx

MAX_BYTES = 20_000_000
MAX_ENTRIES = 4096
MAX_DIRECTORIES = 256
_READ = frozenset({'rev-parse', 'symbolic-ref', 'config', 'status', 'diff', 'show', 'log',
                   'rev-list', 'merge-base', 'cat-file', 'ls-tree', 'ls-files', 'for-each-ref', 'check-ignore'})


def validate_arguments(arguments):
    values = list(arguments)
    if values[:2] == ['-c', 'protocol.allow=never']:
        values = values[2:]
    if values[:1] == ['--literal-pathspecs']:
        values = values[1:]
    if (not values or values[0] not in _READ
            or any(v.startswith(('--output', '--ext-diff', '--textconv', '--exec', '--open-files-in-pager', '--no-index', '--filters'))
                   for v in values[1:])):
        raise ValueError('Git read arguments unavailable')
    if values[0] == 'config' and (not any(v in {'--get', '--get-all', '--get-regexp', '--list', '-l'} for v in values[1:]) or any(v in {'-f', '-e'} or v.startswith(('-f', '--add', '--unset', '--replace', '--remove', '--rename', '--edit', '--file', '--global', '--system', '--local', '--worktree', '--includes', '--blob')) for v in values[1:])):
        raise ValueError('Git configuration mutation is not an observation')
    if values[0] == 'symbolic-ref' and (len([v for v in values[1:] if not v.startswith('-')]) != 1 or any(v in {'--delete', '-d'} for v in values[1:])):
        raise ValueError('Git reference mutation is not an observation')


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


class GitReadView:
    def __init__(self, binding, parse_config, deadline, guard=None):
        self.binding, self.parse_config, self.deadline, self.guard = binding, parse_config, deadline, guard
        self.stack = ExitStack()
        self.directories, self.files, self.listings = {}, [], []
        self.total = self.entries = 0

    def tick(self):
        if time.monotonic() >= self.deadline:
            raise ValueError('Git read view deadline exceeded')

    def directory(self, path):
        path = Path(path)
        if path not in self.directories:
            self.tick()
            if len(self.directories) >= MAX_DIRECTORIES:
                raise ValueError('Git read view directory bound exceeded')
            if path == Path(path.anchor):
                handle = fsx.open_dir(path, flags=fsx.O_CLOEXEC)
                parent = None
            else:
                parent = self.directory(path.parent)
                if len(self.directories) >= MAX_DIRECTORIES:
                    raise ValueError('Git read view directory bound exceeded')
                handle = fsx.open_dir_at(parent, path.name, flags=fsx.O_CLOEXEC)
            self.stack.callback(fsx.close_dir, handle)
            self.directories[path] = (handle, _identity(fsx.fstat_dir(handle)), parent)
        return self.directories[path][0]

    def read(self, path, limit=MAX_BYTES):
        self.tick()
        parent = self.directory(path.parent)
        try:
            before = fsx.lstat_at(parent, path.name)
        except FileNotFoundError:
            self.files.append((parent, path.name, None))
            return None
        if fsx.is_link(before) or not stat.S_ISREG(before.st_mode) or before.st_size > min(limit, MAX_BYTES-self.total):
            raise ValueError('Git read metadata unavailable')
        descriptor = fsx.open_at(parent, path.name, os.O_RDONLY | fsx.O_NOFOLLOW | fsx.O_NONBLOCK | fsx.O_CLOEXEC)
        try:
            identity = _identity(os.fstat(descriptor))
            if identity != _identity(before):
                raise ValueError('Git read metadata changed')
            body = bytearray()
            while True:
                self.tick()
                chunk = os.read(descriptor, min(65536, limit-len(body)+1))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > limit or self.total + len(body) > MAX_BYTES:
                    raise ValueError('Git read metadata bound exceeded')
            if (_identity(os.fstat(descriptor)) != identity
                    or _identity(fsx.lstat_at(parent, path.name)) != identity):
                raise ValueError('Git read metadata changed')
            self.files.append((parent, path.name, identity))
            self.total += len(body)
            return bytes(body)
        finally:
            os.close(descriptor)

    def tree(self, source, destination, depth=0):
        self.tick()
        if depth > 16:
            raise ValueError('Git reference depth exceeded')
        try:
            handle = self.directory(source)
        except FileNotFoundError:
            self.files.append((self.directory(source.parent), source.name, None))
            return
        names = []
        with fsx.scandir(handle) as entries:
            for entry in entries:
                self.tick()
                self.entries += 1
                if self.entries > MAX_ENTRIES:
                    raise ValueError('Git reference entry bound exceeded')
                names.append(entry.name)
        self.listings.append((handle, tuple(sorted(names))))
        destination.mkdir(mode=0o700, exist_ok=True)
        for name in sorted(names):
            info = fsx.lstat_at(handle, name)
            if stat.S_ISDIR(info.st_mode) and not fsx.is_link(info):
                self.tree(source/name, destination/name, depth+1)
            else:
                body = self.read(source/name, 4096)
                text = body.rstrip(b'\n')
                if not (re.fullmatch(b'[0-9a-f]{40}|[0-9a-f]{64}', text)
                        or text.startswith(b'ref: refs/') and all(p not in {b'', b'.', b'..'} for p in text[5:].split(b'/'))
                        and not any(c < 33 or c == 127 for c in text[5:]) and b'\\' not in text[5:]):
                    raise ValueError('Git reference topology unavailable')
                (destination/name).write_bytes(body)

    def check(self):
        self.tick()
        self.binding.verify(self.guard, strict_directories=True)
        for path, (handle, expected, parent) in self.directories.items():
            current = _identity(fsx.fstat_dir(handle))
            named = _identity(fsx.lstat_at(parent, path.name)) if parent is not None else current
            # Namespace-history qualification remains with the existing guard.
            if current[:3] != expected[:3] or named[:3] != expected[:3]:
                raise ValueError('Git read directory custody changed')
        for parent, name, expected in self.files:
            try:
                current = _identity(fsx.lstat_at(parent, name))
            except FileNotFoundError:
                current = None
            if current != expected:
                raise ValueError('Git read metadata changed')
        for handle, names in self.listings:
            if tuple(sorted(fsx.listdir(handle))) != names:
                raise ValueError('Git reference membership changed')

    def __enter__(self):
        try:
            if not fsx.WINDOWS and (not getattr(os, 'O_NOFOLLOW', 0)
                    or not {os.open, os.stat}.issubset(getattr(os, 'supports_dir_fd', set()))):
                raise ValueError('Git read directory capabilities unavailable')
            self.path = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix='getzilla-git-read-')))
            self.path.chmod(0o700)
            records = []
            for directory in dict.fromkeys((self.binding.common_directory, self.binding.git_directory)):
                for name in ('config', 'config.worktree'):
                    raw = self.read(directory/name, MAX_BYTES)
                    if raw is not None:
                        records.extend(self.parse_config(raw))
            object_format = 'sha1'
            config = ['[core]', '\tbare = false', '\tfilemode = true', '\tsymlinks = true']
            for key, value in records:
                if (key.startswith(('include.', 'includeif.')) or key == 'core.worktree'
                        or key == 'core.bare' and value.lower() != 'false'
                        or key == 'core.repositoryformatversion' and value not in {'0', '1'}):
                    raise ValueError('Git structural configuration unavailable')
                if key == 'extensions.objectformat':
                    if value not in {'sha1', 'sha256'}:
                        raise ValueError('Git object format unavailable')
                    object_format = value
                elif key.startswith('extensions.') and key != 'extensions.worktreeconfig':
                    raise ValueError('Git extension unsupported by read view')
                elif key in {'core.filemode', 'core.symlinks'}:
                    if value.lower() not in {'true', 'false'}:
                        raise ValueError('Git boolean metadata unavailable')
                    config.append('\t'+key.split('.')[1]+' = '+value.lower())
                elif re.fullmatch(r'(remote\.[A-Za-z0-9_./-]+\.(url|fetch)|branch\.[A-Za-z0-9_./-]+\.(remote|merge))', key):
                    section, middle, field = key.split('.', 1)[0], key.rsplit('.', 1)[0].split('.', 1)[1], key.rsplit('.', 1)[1]
                    config.extend(('['+section+' '+json.dumps(middle, ensure_ascii=False)+']', '\t'+field+' = '+json.dumps(value, ensure_ascii=False), '[core]'))
            config.extend(('[core]', '\trepositoryformatversion = '+('1' if object_format == 'sha256' else '0')))
            if object_format == 'sha256':
                config.extend(('[extensions]', '\tobjectformat = sha256'))
            (self.path/'config').write_text('\n'.join(config)+'\n', encoding='utf-8', newline='\n')
            for name in ('HEAD', 'index', 'packed-refs', 'shallow'):
                source = self.binding.git_directory/name if name in {'HEAD', 'index'} else self.binding.common_directory/name
                raw = self.read(source, 4096 if name == 'HEAD' else MAX_BYTES)
                if raw is not None:
                    (self.path/name).write_bytes(raw)
                    if name == 'index':
                        recorded = self.files[-1][2]
                        os.utime(self.path/name, ns=(recorded[4], recorded[4]))
            for directory in dict.fromkeys((self.binding.common_directory, self.binding.git_directory)):
                self.tree(directory/'refs', self.path/'refs')
            (self.path/'info').mkdir(mode=0o700)
            raw = self.read(self.binding.common_directory/'info'/'exclude', 65_536)
            if raw is not None:
                (self.path/'info'/'exclude').write_bytes(raw)
            (self.path/'objects/info').mkdir(parents=True, mode=0o700)
            objects = self.directory(self.binding.objects_directory)
            for name in ('alternates', 'http-alternates'):
                if self.read(self.binding.objects_directory/'info'/name, 4096) is not None:
                    raise ValueError('Git alternate object stores unsupported')
            pointer = f'/proc/self/fd/{objects}' if isinstance(objects, int) and Path('/proc/self/fd').is_dir() else str(self.binding.objects_directory)
            (self.path/'objects/info/alternates').write_text(json.dumps(pointer, ensure_ascii=False)+'\n', encoding='utf-8', newline='\n')
            raw = b'tree 0\0'
            self.empty_tree = ('4b825dc642cb6eb9a060e54bf8d69288fbee4904' if object_format == 'sha1' else hashlib.sha256(raw).hexdigest())
            object_path = self.path/'objects'/self.empty_tree[:2]/self.empty_tree[2:]
            object_path.parent.mkdir(mode=0o700)
            object_path.write_bytes(zlib.compress(raw))
            self.pass_fds = (objects,) if pointer.startswith('/proc/self/fd/') else ()
            self.check()
            return self
        except BaseException:
            self.stack.close()
            raise

    def __exit__(self, kind, value, traceback):
        try:
            self.check()
        finally:
            self.stack.close()
