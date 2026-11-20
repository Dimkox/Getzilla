"""Source-bound OpenGrep component. Unsupported custody/grammar stays incomplete."""
from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager, ExitStack
import hashlib
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import sys
import time

from . import fsx
from .opengrep_contract import OpenGrepError, targets, decode_report, project_core_report
from .python_test_runner import execute

MAX_ENTRIES = 200_000
MAX_FILES = 100_000
MAX_DEPTH = 64
MAX_SOURCE_FILE = 16 * 1024 * 1024
MAX_SOURCE_TOTAL = 256 * 1024 * 1024
SUFFIXES = {'.py', '.php', '.js', '.jsx', '.ts', '.tsx', '.java', '.go', '.rb', '.rs', '.c', '.cc', '.cpp', '.cs'}
_NATIVE_EXCLUDED = {'tests', 'fixtures', 'node_modules', 'vendor'}
_EXPANDED_EXCLUDED = {'tests', 'fixtures', 'engineering', 'examples', 'dist', 'packages', 'vendor', 'node_modules'}
_PUBLIC_MODES = {0o444, 0o644, 0o555, 0o755}


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _public(info, uid, maximum):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) not in _PUBLIC_MODES or info.st_size > maximum):
        raise OpenGrepError('source_unavailable')


def _read_at(directory, name, uid, maximum):
    named = os.stat(name, dir_fd=directory, follow_symlinks=False)
    _public(named, uid, maximum)
    descriptor = fsx.open_at(directory, name, os.O_RDONLY | fsx.O_NOFOLLOW | fsx.O_NONBLOCK | fsx.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        _public(before, uid, maximum)
        if _identity(before) != _identity(named):
            raise OpenGrepError('source_changed')
        chunks, total = [], 0
        while True:
            raw = os.read(descriptor, min(65536, maximum + 1 - total))
            if not raw:
                break
            total += len(raw)
            if total > maximum:
                raise OpenGrepError('source_limit')
            chunks.append(raw)
            if _identity(os.fstat(descriptor)) != _identity(before):
                raise OpenGrepError('source_changed')
        if (_identity(os.fstat(descriptor)) != _identity(before)
                or _identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) != _identity(before)):
            raise OpenGrepError('source_changed')
        return b''.join(chunks), _identity(before)
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class SourceEntry:
    path: str
    digest: str
    identity: tuple
    raw: bytes


class SourceCut:
    """Held public root and complete bounded roster; no receipt/customer authority."""

    def __init__(self, root: Path, profile: str, *, _handle=None):
        self.root = Path(root).absolute()
        self.handle = None
        if (profile not in {'native', 'expanded', 'rules'} or fsx.WINDOWS or not fsx.O_NOFOLLOW
                or os.open not in os.supports_dir_fd):
            raise OpenGrepError('source_profile_unavailable')
        self.excluded = _NATIVE_EXCLUDED if profile == 'native' else (_EXPANDED_EXCLUDED if profile == 'expanded' else set())
        self.suffixes = {'.yaml', '.yml'} if profile == 'rules' else SUFFIXES
        try:
            self.handle = os.dup(_handle) if _handle is not None else fsx.open_dir(self.root, flags=fsx.O_CLOEXEC)
            self.root_identity = _identity(fsx.fstat_dir(self.handle))
            if _identity(self.root.lstat()) != self.root_identity:
                raise OpenGrepError('source_changed')
            self.uid = os.getuid()
            if self.root_identity[3] != self.uid:
                raise OpenGrepError('source_unavailable')
            self.entries, self.directories = self._walk()
        except (OSError, ValueError):
            self.close()
            raise OpenGrepError('source_unavailable') from None

    def _walk(self):
        entries, directories = [], []
        count, total = 0, 0

        def visit(directory, prefix, depth):
            nonlocal count, total
            if depth > MAX_DEPTH:
                raise OpenGrepError('source_limit')
            before = _identity(fsx.fstat_dir(directory))
            if before[3] != self.uid:
                raise OpenGrepError('source_unavailable')
            names = sorted(fsx.listdir(directory))
            count += len(names)
            if count > MAX_ENTRIES:
                raise OpenGrepError('source_limit')
            for name in names:
                relative = f'{prefix}/{name}' if prefix else name
                if (name == '.git' or name in self.excluded or relative in {'.getzilla/runtime', '.getzilla/sast'}):
                    continue
                targets([relative])  # no traversal, control, alias or nonportable path
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    child = fsx.open_dir_at(directory, name, flags=fsx.O_CLOEXEC)
                    try:
                        if _identity(fsx.fstat_dir(child)) != _identity(info):
                            raise OpenGrepError('source_changed')
                        visit(child, relative, depth + 1)
                        if _identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) != _identity(info):
                            raise OpenGrepError('source_changed')
                    finally:
                        fsx.close_dir(child)
                elif stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                    raise OpenGrepError('source_unavailable')
                elif Path(name).suffix.lower() in self.suffixes:
                    if Path(name).suffix != Path(name).suffix.lower():
                        raise OpenGrepError('source_profile_unavailable')
                    raw, identity = _read_at(directory, name, self.uid, MAX_SOURCE_FILE)
                    total += len(raw)
                    if len(entries) >= MAX_FILES or total > MAX_SOURCE_TOTAL:
                        raise OpenGrepError('source_limit')
                    entries.append(SourceEntry(relative, hashlib.sha256(raw).hexdigest(), identity, raw))
            if _identity(fsx.fstat_dir(directory)) != before:
                raise OpenGrepError('source_changed')
            directories.append((prefix, before, tuple(names)))

        visit(self.handle, '', 0)
        ordered = tuple(sorted(entries, key=lambda row: row.path))
        if ordered:
            targets([row.path for row in ordered])
        return ordered, tuple(sorted(directories))

    def assert_current(self):
        try:
            if self.handle is None or _identity(self.root.lstat()) != self.root_identity:
                raise OpenGrepError('source_changed')
            entries, directories = self._walk()
            if entries != self.entries or directories != self.directories:
                raise OpenGrepError('source_changed')
        except (OSError, ValueError):
            raise OpenGrepError('source_changed') from None

    def close(self):
        fsx.close_dir(self.handle)
        self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_exception):
        self.close()


_FRONTENDS = {
    'python': ('/usr/bin/python3.12', ('-I', '-S', '--version'), 'Python 3.12.', 'python3.12'),
    'php': ('/usr/bin/php8.3', ('-n', '-v'), 'PHP 8.3.', 'php8.3-default-tags'),
    'javascript': ('/usr/bin/node', ('--version',), 'v24.', 'node24-module'),
}
_ENVIRONMENT = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
_COMPILE_HELPER = (
    'import pathlib,sys\n'
    'raw=pathlib.Path(sys.argv[1]).read_bytes()\n'
    'if len(raw)>16777216: raise SystemExit(2)\n'
    'try: compile(raw,sys.argv[1],"exec",dont_inherit=True)\n'
    'except (SyntaxError,ValueError): raise SystemExit(1)\n'
)


def _timeout(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise OpenGrepError('scanner_timeout')
    return min(30, remaining)


def _run(command, root, environment, deadline, *, inherited_fds=(), stdin_fd=None):
    options = {}
    if inherited_fds:
        options['inherited_fds'] = inherited_fds
    if stdin_fd is not None:
        options['stdin_fd'] = stdin_fd
    result = execute(command, root, environment, timeout=_timeout(deadline), **options)
    if result.terminal_state == 'timeout':
        raise OpenGrepError('scanner_timeout')
    if result.terminal_state != 'completed' or result.cleanup_error:
        raise OpenGrepError('execution_incomplete')
    return result


@dataclass
class SyntaxFrontend:
    path: Path
    descriptor: int
    identity: tuple
    digest: str
    language: str
    grammar: str

    def assert_current(self):
        if (_identity(os.fstat(self.descriptor)) != self.identity
                or _identity(self.path.lstat()) != self.identity):
            raise OpenGrepError('syntax_frontend_changed')

    def __enter__(self):
        return self

    def __exit__(self, *_exception):
        os.close(self.descriptor)


def syntax_frontend(language: str, *, deadline=None) -> SyntaxFrontend:
    """Local OS custody, not customer identity or protection from host privilege.

    Never admit PATH/per-user markers or a self-reported version/hash as trust.
    A root-running process cannot claim this nonprivileged-source boundary.
    """
    if (language not in _FRONTENDS or fsx.WINDOWS or not hasattr(os, 'geteuid')
            or os.geteuid() == 0 or os.geteuid() != os.getuid()):
        raise OpenGrepError('syntax_frontend_unavailable')
    selected, arguments, version, grammar = _FRONTENDS[language]
    descriptor, directory = None, None
    deadline = time.monotonic() + 30 if deadline is None else deadline
    try:
        canonical = Path(fsx.system_canonical(selected))
        directory = fsx.open_dir('/', flags=fsx.O_CLOEXEC)
        for part in canonical.parts[1:-1]:
            current = fsx.fstat_dir(directory)
            if current.st_uid != 0 or current.st_mode & 0o022:
                raise OpenGrepError('syntax_frontend_unavailable')
            child = fsx.open_dir_at(directory, part, flags=fsx.O_CLOEXEC)
            fsx.close_dir(directory)
            directory = child
        current = fsx.fstat_dir(directory)
        if current.st_uid != 0 or current.st_mode & 0o022:
            raise OpenGrepError('syntax_frontend_unavailable')
        raw, identity = _read_at(directory, canonical.name, 0, MAX_SOURCE_TOTAL)
        if not identity[2] & 0o111:
            raise OpenGrepError('syntax_frontend_unavailable')
        descriptor = fsx.open_at(directory, canonical.name, os.O_RDONLY | fsx.O_NOFOLLOW | fsx.O_CLOEXEC)
        if _identity(os.fstat(descriptor)) != identity:
            raise OpenGrepError('syntax_frontend_changed')
        result = _run([str(canonical), *arguments], Path('/'), dict(_ENVIRONMENT), deadline)
        if result.returncode or not result.stdout.startswith(version):
            raise OpenGrepError('syntax_frontend_incompatible')
        frontend = SyntaxFrontend(canonical, descriptor, identity, hashlib.sha256(raw).hexdigest(), language, grammar)
        frontend.assert_current()
        descriptor = None
        return frontend
    except (OSError, ValueError):
        raise OpenGrepError('syntax_frontend_unavailable') from None
    finally:
        fsx.close_dir(directory)
        if descriptor is not None:
            os.close(descriptor)


def syntax_check(frontend: SyntaxFrontend, raw: bytes, run_root: Path, *, deadline=None):
    """Parse immutable public bytes. Never evaluate/import candidate source."""
    deadline = time.monotonic() + 30 if deadline is None else deadline
    if len(raw) > MAX_SOURCE_FILE:
        raise OpenGrepError('source_limit')
    frontend.assert_current()
    with sealed_tool(raw, executable=False) as source:
        inherited = (source.descriptor,)
        if frontend.language == 'python':
            with sealed_tool(_COMPILE_HELPER.encode('utf-8'), executable=False) as helper:
                result = _run([str(frontend.path), '-I', '-S', helper.path, source.path], run_root,
                              dict(_ENVIRONMENT), deadline, inherited_fds=(source.descriptor, helper.descriptor))
        elif frontend.language == 'php':
            # PHP default-tag grammar cannot silently treat a short-tag program as HTML.
            import re
            if re.search(br'<\?(?!php(?:\s|$)|=)', raw, re.IGNORECASE):
                raise OpenGrepError('syntax_incomplete')
            result = _run([str(frontend.path), '-n', '-l', source.path], run_root,
                          dict(_ENVIRONMENT), deadline, inherited_fds=inherited)
        elif frontend.language == 'javascript':
            # Parsing needs no JIT code range; reserving it can exhaust a bounded
            # worker's address space before Node ever examines the sealed bytes.
            result = _run([str(frontend.path), '--jitless', '--input-type=module', '--check'], run_root,
                          dict(_ENVIRONMENT), deadline, stdin_fd=source.descriptor)
        else:
            raise OpenGrepError('syntax_frontend_unavailable')
        frontend.assert_current()
        source.assert_current()
        if result.returncode:
            raise OpenGrepError('syntax_incomplete')


@dataclass
class SealedTool:
    descriptor: int
    digest: str
    size: int
    seals: int

    @property
    def path(self):
        return f'/proc/self/fd/{self.descriptor}'

    def assert_current(self):
        import fcntl
        info = os.fstat(self.descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_size != self.size
                or fcntl.fcntl(self.descriptor, fcntl.F_GET_SEALS) & self.seals != self.seals
                or (os.stat(self.path).st_dev, os.stat(self.path).st_ino) != (info.st_dev, info.st_ino)):
            raise OpenGrepError('tool_custody_unavailable')


@contextmanager
def sealed_tool(raw: bytes, *, executable=True):
    """Immutable public executable bytes only; not runtime/customer containment."""
    descriptor = None
    try:
        if not sys.platform.startswith('linux') or not hasattr(os, 'memfd_create') or not 0 < len(raw) <= MAX_SOURCE_TOTAL:
            raise OpenGrepError('tool_custody_unavailable')
        import fcntl
        descriptor = os.memfd_create('getzilla-public-tool', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:offset + 65536])
        os.fchmod(descriptor, 0o500 if executable else 0o400)
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
        os.lseek(descriptor, 0, os.SEEK_SET)
        tool = SealedTool(descriptor, hashlib.sha256(raw).hexdigest(), len(raw), seals)
        tool.assert_current()
        yield tool
        tool.assert_current()
    except OSError:
        raise OpenGrepError('tool_custody_unavailable') from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


@dataclass(frozen=True)
class RuleMetadata:
    identifier: str
    languages: tuple[str, ...]
    severity: str
    message: str


def rule_catalog(raw: bytes) -> tuple[RuleMetadata, ...]:
    """Admit current metadata headers; same core parses untouched pattern/YAML bytes."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 1024 * 1024:
        raise OpenGrepError('rule_header_unavailable')
    try:
        lines = raw.decode('utf-8').splitlines()
    except UnicodeError:
        raise OpenGrepError('rule_header_unavailable') from None
    rules, fields, root_seen, seen = [], None, False, set()

    def finish():
        if fields is None or set(fields) != {'id', 'languages', 'severity', 'message'}:
            raise OpenGrepError('rule_header_unavailable')
        languages = fields['languages']
        if not re.fullmatch(r'\[[a-z]+(?:, *[a-z]+)*\]', languages):
            raise OpenGrepError('rule_header_unavailable')
        selected = tuple(value.strip() for value in languages[1:-1].split(','))
        if (len(set(selected)) != len(selected) or not set(selected) <= {'python', 'php', 'go', 'javascript', 'typescript'}
                or fields['severity'] not in {'ERROR', 'WARNING', 'INFO'}):
            raise OpenGrepError('rule_header_unavailable')
        message = fields['message']
        if not message or message[0] in '&*!|>{[\'"' or len(message) > 4096:
            raise OpenGrepError('rule_header_unavailable')
        rules.append(RuleMetadata(fields['id'], selected, fields['severity'], message))

    for line in lines:
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if '\t' in line or len(line) > 65536:
            raise OpenGrepError('rule_header_unavailable')
        indent = len(line) - len(line.lstrip(' '))
        if indent == 0:
            if line != 'rules:' or root_seen or fields is not None:
                raise OpenGrepError('rule_header_unavailable')
            root_seen = True
        elif indent == 2:
            match = re.fullmatch(r'  - id: ([A-Za-z0-9][A-Za-z0-9_.-]{0,255})', line)
            if not root_seen or not match:
                raise OpenGrepError('rule_header_unavailable')
            if fields is not None:
                finish()
            fields = {'id': match[1]}
            seen = {'id'}
        elif indent == 4:
            match = re.fullmatch(r'    ([A-Za-z][A-Za-z0-9_-]*):(?: (.*))?', line)
            if fields is None or not match:
                raise OpenGrepError('rule_header_unavailable')
            key, value = match[1], match[2] or ''
            if key in seen or key not in {'languages', 'severity', 'message', 'mode', 'metadata', 'pattern', 'pattern-either',
                                          'pattern-sources', 'pattern-sinks', 'pattern-sanitizers'}:
                raise OpenGrepError('rule_header_unavailable')
            seen.add(key)
            if key == 'mode' and value != 'taint':
                raise OpenGrepError('rule_header_unavailable')
            if key == 'metadata' and (not value.startswith('{') or not value.endswith('}')):
                raise OpenGrepError('rule_header_unavailable')
            if key in {'languages', 'severity', 'message'}:
                if key in fields:
                    raise OpenGrepError('rule_header_unavailable')
                fields[key] = value
        elif indent < 6 or fields is None:
            raise OpenGrepError('rule_header_unavailable')
    finish()
    if not rules or len(rules) > 512 or len({rule.identifier.casefold() for rule in rules}) != len(rules):
        raise OpenGrepError('rule_header_unavailable')
    return tuple(rules)


def resolved_rules(raw: bytes) -> dict:
    """Current YAML data/aliases, plus ONLY pinned transport language aliases."""
    from .spec import MAX_SPEC_BYTES, SpecError, parse_yaml_subset
    catalog = rule_catalog(raw)
    try:
        value = parse_yaml_subset(raw.decode('utf-8'), rules_profile=True)
    except (SpecError, UnicodeError):
        raise OpenGrepError('rule_resolution_unavailable') from None
    if (not isinstance(value, dict) or set(value) != {'rules'} or not isinstance(value['rules'], list)
            or len(value['rules']) != len(catalog)):
        raise OpenGrepError('rule_resolution_unavailable')
    aliases = {'javascript': 'js', 'typescript': 'ts'}
    for item, metadata in zip(value['rules'], catalog):
        if (not isinstance(item, dict) or item.get('id') != metadata.identifier
                or item.get('languages') != list(metadata.languages)
                or item.get('severity') != metadata.severity or item.get('message') != metadata.message):
            raise OpenGrepError('rule_metadata_changed')
        item['languages'] = [aliases.get(language, language) for language in metadata.languages]
    import json
    if len(json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')) > MAX_SPEC_BYTES:
        raise OpenGrepError('rule_resolution_limit')
    return value


def _directory_object(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid


class OwnedRun:
    """FD-addressed new public run resources, never an authentication boundary."""

    def __init__(self, rules_root: Path):
        self.handles = []
        self.fd = self.runtime = self.project = self.rules = None
        self.name = None
        self.pid = os.getpid()
        if (not sys.platform.startswith('linux') or not hasattr(os, 'getuid')
                or tuple(rules_root.parts[-3:]) != ('.getzilla', 'sast', 'rules')):
            raise OpenGrepError('run_profile_unavailable')
        self.project_path = rules_root.parents[2]
        try:
            self.project = fsx.open_dir(self.project_path, flags=fsx.O_CLOEXEC)
            self.handles.append(self.project)
            if fsx.fstat_dir(self.project).st_uid != os.getuid():
                raise OpenGrepError('run_profile_unavailable')
            getzilla = self._child(self.project, '.getzilla')
            sast = self._child(getzilla, 'sast')
            self.rules = self._child(sast, 'rules')
            # Connect storage to the same checker/rules root BEFORE creating resources.
            if _identity(fsx.fstat_dir(self.rules)) != _identity(rules_root.lstat()):
                raise OpenGrepError('source_changed')
            try:
                self.runtime = self._child(getzilla, 'runtime')
            except FileNotFoundError:
                fsx.mkdir_at(getzilla, 'runtime', 0o700)
                self.runtime = self._child(getzilla, 'runtime')
            self.name = 'opengrep-' + secrets.token_hex(12)
            fsx.mkdir_at(self.runtime, self.name, 0o700)
            self.fd = self._child(self.runtime, self.name, private=True)
            self.identity = _directory_object(fsx.fstat_dir(self.fd))
            self.path = Path(f'/proc/{self.pid}/fd/{self.fd}')
            self.assert_current()
            for name in ('cache', 'settings', 'tmp'):
                fsx.mkdir_at(self.fd, name, 0o700)
        except (OSError, ValueError):
            self.close()
            raise OpenGrepError('run_profile_unavailable') from None

    def _child(self, parent, name, *, private=False):
        child = fsx.open_dir_at(parent, name, flags=fsx.O_CLOEXEC)
        self.handles.append(child)
        info = fsx.fstat_dir(child)
        if info.st_uid != os.getuid() or info.st_mode & 0o022 or (private and stat.S_IMODE(info.st_mode) != 0o700):
            raise OpenGrepError('run_profile_unavailable')
        return child

    def assert_current(self):
        if (self.pid != os.getpid() or self.fd is None
                or _directory_object(fsx.fstat_dir(self.fd)) != self.identity
                or _directory_object(self.path.stat()) != self.identity
                or _directory_object(os.stat(self.name, dir_fd=self.runtime, follow_symlinks=False)) != self.identity):
            raise OpenGrepError('run_custody_changed')

    def environment(self):
        self.assert_current()
        return {**_ENVIRONMENT, 'XDG_CACHE_HOME': str(self.path / 'cache'),
                'XDG_CONFIG_HOME': str(self.path / 'settings'), 'TMPDIR': str(self.path / 'tmp'),
                'OPENGREP_SETTINGS_FILE': str(self.path / 'settings/settings.yml'),
                'SEMGREP_SETTINGS_FILE': str(self.path / 'settings/settings.yml'),
                'OPENGREP_LOG_FILE': str(self.path / 'scanner.log'),
                'SEMGREP_LOG_FILE': str(self.path / 'scanner.log'),
                'OPENGREP_SEND_METRICS': 'off', 'SEMGREP_SEND_METRICS': 'off',
                'OPENGREP_ENABLE_VERSION_CHECK': '0', 'SEMGREP_ENABLE_VERSION_CHECK': '0'}

    def close(self):
        try:
            if self.name is not None and self.fd is not None:
                # Children have ended before cleanup. Refuse a changed named root;
                # this sole-owner temporary cleanup is not an inode-CAS/OS sandbox claim.
                self.assert_current()
                if not shutil.rmtree.avoids_symlink_attacks:
                    raise OpenGrepError('run_cleanup_unavailable')
                shutil.rmtree(self.name, dir_fd=self.runtime)
        finally:
            for handle in reversed(self.handles):
                fsx.close_dir(handle)
            self.handles = []
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_exception):
        self.close()


def _launcher_bytes(executable: Path) -> bytes:
    from .updater import OPENGREP_ASSETS, OPENGREP_VERSION, _platform_key
    if OPENGREP_VERSION != '1.30.1':
        raise OpenGrepError('tool_profile_unavailable')
    pin = OPENGREP_ASSETS.get(_platform_key())
    if pin is None:
        raise OpenGrepError('tool_profile_unavailable')
    directory = fsx.open_dir(executable.parent, flags=fsx.O_CLOEXEC)
    try:
        info = os.stat(executable.name, dir_fd=directory, follow_symlinks=False)
        if info.st_uid not in {0, os.getuid()}:
            raise OpenGrepError('tool_custody_unavailable')
        raw, _binding = _read_at(directory, executable.name, info.st_uid, MAX_SOURCE_TOTAL)
        if hashlib.sha256(raw).hexdigest() != pin[1]:
            raise OpenGrepError('tool_sha256_mismatch')
        return raw
    finally:
        fsx.close_dir(directory)


def _bootstrap_core(launcher: SealedTool, run: OwnedRun, deadline) -> bytes:
    """Derive bundled core from a fresh pinned launcher; do not claim sealed CLI chain."""
    run.assert_current()
    result = _run([launcher.path, '--version'], run.path, run.environment(), deadline,
                  inherited_fds=(launcher.descriptor,))
    if result.returncode or result.stdout.strip() != '1.30.1':
        raise OpenGrepError('core_extraction_incomplete')
    run.assert_current()
    handles = []
    directory = run.fd
    try:
        for name in ('cache', 'opengrep', 'v1.30.1', 'semgrep', 'bin'):
            child = fsx.open_dir_at(directory, name, flags=fsx.O_CLOEXEC)
            handles.append(child)
            info = fsx.fstat_dir(child)
            if info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise OpenGrepError('core_custody_unavailable')
            directory = child
        named = os.stat('opengrep-core', dir_fd=directory, follow_symlinks=False)
        if (not stat.S_ISREG(named.st_mode) or named.st_uid != os.getuid() or named.st_nlink != 1
                or stat.S_IMODE(named.st_mode) not in {0o745, 0o755, 0o555} or named.st_size > MAX_SOURCE_TOTAL):
            raise OpenGrepError('core_custody_unavailable')
        descriptor = fsx.open_at(directory, 'opengrep-core', os.O_RDONLY | fsx.O_NOFOLLOW | fsx.O_NONBLOCK | fsx.O_CLOEXEC)
        try:
            before = _identity(os.fstat(descriptor))
            if before != _identity(named):
                raise OpenGrepError('core_custody_unavailable')
            chunks, total = [], 0
            while True:
                raw = os.read(descriptor, 65536)
                if not raw:
                    break
                total += len(raw)
                if total > MAX_SOURCE_TOTAL or _identity(os.fstat(descriptor)) != before:
                    raise OpenGrepError('core_custody_unavailable')
                chunks.append(raw)
            if (_identity(os.fstat(descriptor)) != before
                    or _identity(os.stat('opengrep-core', dir_fd=directory, follow_symlinks=False)) != before):
                raise OpenGrepError('core_custody_unavailable')
            result = b''.join(chunks)
            if not result.startswith(b'\x7fELF'):
                raise OpenGrepError('core_profile_unavailable')
            run.assert_current()
            return result
        finally:
            os.close(descriptor)
    finally:
        for handle in reversed(handles):
            fsx.close_dir(handle)


def legacy_rule_prefix(profile: str, rules_root: Path) -> str:
    # Exact pinned CLI rule_lang.convert_config_id_to_prefix, fixed BEFORE scan.
    directory = Path('.getzilla/sast/rules') if profile == 'native' else rules_root
    if profile not in {'native', 'expanded'}:
        raise OpenGrepError('rule_profile_unavailable')
    prefix = '.'.join(directory.parts).lstrip('./').lstrip('.')
    return re.sub(r'[^a-zA-Z0-9._-]', '', prefix + '.')


_LANGUAGE = {'.py': 'python', '.php': 'php', '.js': 'javascript'}


def _expanded_absence(root: Path, deadline) -> bool:
    # An empty applicable roster needs no installed checker/tool. Release a
    # nonempty preliminary cut before the existing operative cut/OwnedRun;
    # internal runtime initialization must not alter its source metadata cut.
    with SourceCut(root, 'expanded') as source:
        _timeout(deadline)
        if source.entries:
            return False
        source.assert_current()
        _timeout(deadline)
        return True


def scan_source(root: Path, *, rules_root: Path, executable: Path, profile: str) -> dict:
    """Real local component. No imported inventory, result or local hash grants trust."""
    deadline = time.monotonic() + 900
    root, rules_root, executable = (Path(value).absolute() for value in (root, rules_root, executable))
    command = None
    try:
        if profile not in {'native', 'expanded'}:
            raise OpenGrepError('source_profile_unavailable')
        if profile == 'expanded' and _expanded_absence(root, deadline):
            return {'outcome': 'not_applicable', 'summary': 'complete census contains no required source targets',
                    'coverage': {'expected': [], 'observed': []}, 'findings': [], 'finding_count': 0}
        with ExitStack() as stack:
            run = stack.enter_context(OwnedRun(rules_root))
            if profile == 'native' and _directory_object(root.stat()) != _directory_object(fsx.fstat_dir(run.project)):
                raise OpenGrepError('source_changed')
            source = stack.enter_context(SourceCut(root, profile, _handle=run.project if profile == 'native' else None))
            rule_source = stack.enter_context(SourceCut(rules_root, 'rules', _handle=run.rules))
            if {entry.path for entry in rule_source.entries} != {'go.yaml', 'javascript.yaml', 'php.yaml', 'python.yaml'}:
                raise OpenGrepError('rule_profile_unavailable')
            catalogs = {entry.path: rule_catalog(entry.raw) for entry in rule_source.entries}
            import json
            resolved = {entry.path: json.dumps(resolved_rules(entry.raw), ensure_ascii=False,
                                              sort_keys=True, separators=(',', ':')).encode('utf-8')
                        for entry in rule_source.entries}
            identifiers = [rule.identifier for rows in catalogs.values() for rule in rows]
            if len(set(identifiers)) != len(identifiers):
                raise OpenGrepError('rule_header_unavailable')
            languages = {_LANGUAGE.get(Path(entry.path).suffix) for entry in source.entries}
            if None in languages:
                raise OpenGrepError('syntax_frontend_unavailable')
            frontends = {language: stack.enter_context(syntax_frontend(language, deadline=deadline)) for language in sorted(languages)}
            if not source.entries:
                source.assert_current()
                rule_source.assert_current()
                run.assert_current()
                return {'outcome': 'not_applicable', 'summary': 'complete census contains no required source targets',
                        'coverage': {'expected': [], 'observed': []}, 'findings': [], 'finding_count': 0}
            raw_launcher = _launcher_bytes(executable)
            prefix = legacy_rule_prefix(profile, rules_root)
            launcher = stack.enter_context(sealed_tool(raw_launcher))
            core = stack.enter_context(sealed_tool(_bootstrap_core(launcher, run, deadline)))
            observations = []
            for entry in source.entries:
                target_deadline = min(deadline, time.monotonic() + 30)
                language = _LANGUAGE[Path(entry.path).suffix]
                syntax_check(frontends[language], entry.raw, run.path, deadline=target_deadline)
                with sealed_tool(entry.raw, executable=False) as target:
                    applicable = 0
                    for rule_entry in rule_source.entries:
                        selected = [rule for rule in catalogs[rule_entry.path] if language in rule.languages]
                        if not selected:
                            continue
                        applicable += len(selected)
                        metadata = {rule.identifier: {'id': prefix + rule.identifier, 'severity': rule.severity,
                                                       'message': rule.message} for rule in selected}
                        with sealed_tool(rule_entry.raw, executable=False) as original_rules, \
                                sealed_tool(resolved[rule_entry.path], executable=False) as rules:
                            run.assert_current()
                            core.assert_current()
                            target.assert_current()
                            rules.assert_current()
                            original_rules.assert_current()
                            command = [core.path, '-json_nodots', '-rules', rules.path, '-lang', language,
                                       '-strict', '-taint_intrafile', '-timeout', '30', '-j', '1', target.path]
                            result = _run(command, run.path, run.environment(), target_deadline,
                                          inherited_fds=(core.descriptor, rules.descriptor, target.descriptor))
                            observations.append(project_core_report(decode_report(result.stdout),
                                                {target.path: entry.path}, metadata, result.returncode))
                    if not applicable:
                        raise OpenGrepError('rule_coverage_incomplete')
            source.assert_current()
            rule_source.assert_current()
            run.assert_current()
            for frontend in frontends.values():
                frontend.assert_current()
            _timeout(deadline)
            findings = [finding for observation in observations for finding in observation['findings']]
            expected = list(targets([entry.path for entry in source.entries]))
            count = sum(observation['finding_count'] for observation in observations)
            return {'outcome': 'finding' if count else 'pass', 'summary': f'{len(expected)} source targets; {count} findings',
                    'findings': findings[:200], 'finding_count': count, 'coverage': {'expected': expected, 'observed': expected},
                    'command': command, 'tool_sha256': launcher.digest, 'core_sha256': core.digest,
                    'source_sha256': hashlib.sha256(repr([(entry.path, entry.digest) for entry in source.entries]).encode()).hexdigest(),
                    'rules_sha256': hashlib.sha256(repr([(entry.path, entry.digest) for entry in rule_source.entries]).encode()).hexdigest(),
                    'grammars': sorted(frontend.grammar for frontend in frontends.values()),
                    'assurance': 'local-pinned-core-source-integrity; no customer/OS containment or external acceptance'}
    except (OSError, ValueError, TypeError, RecursionError) as error:
        reason = str(error) if isinstance(error, OpenGrepError) else 'scanner_unavailable'
        return {'outcome': 'blocked', 'summary': 'OpenGrep 1.30.1 incomplete: ' + reason, 'findings': [],
                'finding_count': None, 'coverage': None, 'command': command}
