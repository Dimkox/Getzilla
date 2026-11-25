"""Narrow, source-bound review records for exact verification observations.

These records classify findings. They are not authenticated approvals.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path

CONFIG_PATH = 'engineering/verification-dispositions.json'
MAX_CONFIG_BYTES = 131_072
MAX_FILE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 32_000_000
MAX_ENTRIES = 128

SECRET_PATTERNS = {
    'private-key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'aws-access-key': re.compile(r'AKIA[0-9A-Z]{16}'),
    'generic-secret': re.compile(r'(?i)(?:api[_-]?key|secret|password|token)\s*[:=]\s*["\'][^"\']{12,}["\']'),
}
# Reviewed test inputs for #461. The file digest also binds multiline PEM context.
_REVIEWED_SECRET_INPUTS = {
    ('factory/tests/test_retrieval_access.py',
     'b93d7b3bc60976803f1751a6934f372c5a8f8c4d1646e12a651c5689073de66c'): {
        (100, 19, 'generic-secret'): (
            'fe7e066ecc72e9e9b970e6980b1039358e34128dcc9a2c3d80c559258a807cf4',
            'test-fixture', 'Test input for redaction before retrieval ranking.'),
    },
    ('tests/test_entire_adapter.py',
     'f7a7ba907d94dc6102a662c67f62ed6b835a235c13f9af6df8b44c175fe77671'): {
        (146, 47, 'generic-secret'): (
            '89c4b8b02d73827c6b2b9959c07bc9b107e66b01363ba275c21c315dc459b2b6',
            'test-fixture', 'Mock child environment used to test token filtering.'),
        (146, 74, 'generic-secret'): (
            '89c4b8b02d73827c6b2b9959c07bc9b107e66b01363ba275c21c315dc459b2b6',
            'test-fixture', 'Second mock token in the same environment filtering test.'),
    },
    ('tests/test_execution_public_certificate.py',
     '758d15a9446c3e0c57cd2d46daf1db3eace994d07e8aaf66689ab2da7991eaad'): {
        (63, 20, 'private-key'): (
            'd66506534fe62e42a0b1667376590e9ea6e2765eac2d85b632f03084b4e1de5e',
            'test-fixture', 'PEM header alone exercises public certificate rejection.'),
    },
    ('tests/test_native_context.py',
     '062ee8fd871b879371f8399f61a8081da8850c2504c6137aa94143a62b221129'): {
        (96, 64, 'generic-secret'): (
            'ac5fac16cd75f6df62320b5bf185acd1c46dbf0983ec244d203b8abeb59ad929',
            'test-fixture', 'Synthetic secret for a denied native context read.'),
    },
    ('tests/test_reverse_engineering.py',
     '9ee0499514a7b698103c7ca765b0b5d4b304cf6f2156b0367c6bd1b7e2856583'): {
        (180, 27, 'private-key'): (
            '34adba61dcbb56a3363035880c881fc679b1680fcb427d19c104facdd0e0dc69',
            'test-fixture', 'PEM header sentinel in the native addon refusal test.'),
    },
    ('tests/test_security_oci_budget_faults.py',
     'e4a6b307f584fa2b2af5565bf3736e1633ad54a69e69c5d454ea05d392e1e91d'): {
        (170, 18, 'generic-secret'): (
            '112c4c1f9a175a87dc00f83fc1f038f4e1c79cac168d44ecb80aaf0be1b50fc0',
            'test-fixture', 'Marker in an intentionally invalid budget fault.'),
    },
    ('tests/test_security_oci_transport.py',
     '9bfc695559c0e6793f11f7b5990da9d2ab659926811e0186a6d49a52ca24d312'): {
        (353, 9, 'generic-secret'): (
            'c5797b9774f92f1d977a338c63c5fb8b3c25ebf26562bece2f78425feb7a2d12',
            'test-fixture', 'Transport canary for the token persistence assertion.'),
    },
    ('tests/test_security_preparation_faults.py',
     'a46e625bcbda155640169d19f0d52375ae9eddfbc96cccc92aa6da848c975d56'): {
        (69, 30, 'generic-secret'): (
            '4d40d6c119f445ce57e9ae2ff40678c33fc011855e5a3faccf9233d90e266ac8',
            'test-fixture', 'Marker in a malformed preparation fault.'),
        (116, 49, 'generic-secret'): (
            'd02b2d2c5a6b78118d1177a667848d9c2d560cb4e42e43a2aec7ebed298375c7',
            'test-fixture', 'Marker in the preparation error redaction test.'),
    },
    ('tests/test_security_tools.py',
     '83c2975cf347f697917cc898496f1fe506732d5a7c8fcdb5ad02752fea929766'): {
        (452, 23, 'generic-secret'): (
            '4249a1e9d3f0ebf349246ba02be849c75f9d48fc212a29b414d50ad85010acae',
            'false-positive', 'Pattern spans Python concatenation in the encoding test.'),
        (483, 24, 'generic-secret'): (
            '36acc2a1da13a9369b7874e218b5f827759a1865d91ddfcd4ee73dd074892c0b',
            'test-fixture', 'Byte-view fixture exercises scanning of binary input.'),
    },
    ('tests/test_source_admission.py',
     '45eef56e5d14f1a0024615efb2464b9764ec59fabc39c508cc2c6a440b9eefae'): {
        (63, 64, 'generic-secret'): (
            '0302fe7324916fc678d57a5ea05ba6663810999a8a2e3ff7188aff80b6b5d44e',
            'test-fixture', 'Constructed fake token for an admission redaction test.'),
        (140, 64, 'generic-secret'): (
            '0302fe7324916fc678d57a5ea05ba6663810999a8a2e3ff7188aff80b6b5d44e',
            'test-fixture', 'Constructed fake token for the no-spool assertion.'),
        (149, 70, 'generic-secret'): (
            '4e3dbfeb2641907066d10e70e7d542b550ea62c2e610cc285283b1e66e662b65',
            'test-fixture', 'Fixed synthetic password for the narrow exception test.'),
        (156, 51, 'generic-secret'): (
            '0fe6b946ee9d9bb46d2ea4e2f5506e74e0ed054bb4d337b659318081dc82a133',
            'test-fixture', 'Modified synthetic password tests rejection of a stale exception.'),
    },
    ('tests/test_trust_ci_setup.py',
     'd1b304a95307e9fba4f2f1521ee5e9ae1da61ad9589ab8ac5c415a76b35e2d91'): {
        (29, 13, 'private-key'): (
            'f83bc3864721adcaa3c7e1dc108de2953868a872793c341cd4d9213cb2d2d450',
            'test-fixture', 'Short dummy PEM fixture without a usable key payload.'),
        (156, 31, 'private-key'): (
            '5eb951515bb61e5e52ddd682ef4cdcc8c414d0a1fbe414de777e044278ea6dd2',
            'test-fixture', 'Fake host writes a synthetic PEM marker.'),
        (668, 29, 'private-key'): (
            '0c53e47a1c3089ca397425095defdced26ac0904a2df919cd9976347540a0fc3',
            'test-fixture', 'Damaged PEM input exercises private-key rejection.'),
    },
    ('tests/test_verification_dispositions.py',
     'e2b80e1a35b705a11e5592fb0f22e3a28ad9bf99ea84f0208e85ef12fb873bc9'): {
        (93, 23, 'generic-secret'): (
            '4249a1e9d3f0ebf349246ba02be849c75f9d48fc212a29b414d50ad85010acae',
            'false-positive', 'Pattern spans Python concatenation in the file encoding test.'),
    },
}

_PUBLIC_TOKEN = re.compile(r'token\s*[:=]\s*(["\'])0x[0-9a-fA-F]{40}\1')
_HASH = re.compile(r'[0-9a-f]{64}')
_COMMON_FIELDS = {'id', 'check', 'kind', 'rule', 'path', 'sha256', 'line', 'reason', 'evidence'}


class DispositionError(ValueError):
    """The optional review configuration is present but not safe to use."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_path(value: object) -> str:
    if (not isinstance(value, str) or len(value) > 512
            or not re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', value)
            or any(part in {'.', '..', '.git'} for part in value.split('/'))
            or value.startswith(('.getzilla/runtime/', '.qwen/tmp/'))):
        raise DispositionError('disposition paths must be canonical source paths')
    return value


def _fields(value: object, expected: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise DispositionError('disposition object has missing or unknown fields')
    return value


def _hash(value: object) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise DispositionError('disposition SHA-256 must be 64 lowercase hex digits')
    return value


def _positive(value: object) -> int:
    if type(value) is not int or not 1 <= value <= MAX_FILE_BYTES:
        raise DispositionError('disposition positions must be positive bounded integers')
    return value


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise DispositionError('duplicate disposition JSON key')
        result[key] = value
    return result


def location(text: str, offset: int) -> tuple[int, int]:
    return text.count('\n', 0, offset) + 1, offset - text.rfind('\n', 0, offset)


def _standalone_context(text: str, end: int) -> bool:
    # The entire prefix must be ASCII, including strings and comments: Unicode
    # line terminators must never conceal code behind an apparent comment.
    if not text[:end].isascii():
        return False
    whitespace = ' \t\r\n\f\v'
    if end and text[end - 1] not in whitespace + '{[(,;':
        return False
    index = 0
    previous = ''
    while index < end:
        char = text[index]
        if char in whitespace:
            index += 1
            continue
        if text.startswith('//', index):
            stops = [pos for mark in '\r\n' if (pos := text.find(mark, index + 2, end)) >= 0]
            if not stops:
                return False
            index = min(stops) + 1
            continue
        if text.startswith('/*', index):
            close = text.find('*/', index + 2, end)
            if close < 0:
                return False
            index = close + 2
            continue
        if char in '\'"':
            quote = char
            index += 1
            while index < end:
                char = text[index]
                index += 1
                if char == '\\':
                    index += 1
                elif char == quote:
                    break
                elif char in '\r\n':
                    return False
            else:
                return False
            previous = quote
            continue
        # Only ordinary ASCII code characters are supported. Legacy HTML
        # comments, regex/division, templates, escapes and unknown constructs
        # cannot establish a safe context without language-specific parsing.
        if (text.startswith(('<!--', '-->'), index)
                or not (char.isalnum() or char in '_$()[]{}.,:;=+-*!&|%?^~<>')):
            return False
        previous = char
        index += 1
    return previous not in {'.', ':', '?', '>'}


def public_token(text: str, match: re.Match) -> bool:
    return bool(_PUBLIC_TOKEN.fullmatch(match.group()) and _standalone_context(text, match.start()))


def eof_blank_line(data: bytes) -> int | None:
    if b'\0' in data or not data.endswith(b'\n'):
        return None
    lines = data.split(b'\n')[:-1]
    end = len(lines)
    while end and not lines[end - 1].strip(b' \t\r'):
        end -= 1
    return end + 1 if 0 < end < len(lines) else None


def _git(root: Path, *arguments: str) -> bytes:
    try:
        result = subprocess.run(['git', *arguments], cwd=root, capture_output=True,
                                timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DispositionError('cannot establish disposition source identity') from exc
    if result.returncode or result.stderr:
        raise DispositionError('cannot establish disposition source identity')
    return result.stdout


def _index(root: Path, relative: str) -> tuple[str, str]:
    raw = _git(root, 'ls-files', '-v', '--stage', '-z', '--', relative)
    match = re.fullmatch(rb'H (100644|100755) ([0-9a-f]{40,64}) 0\t' + re.escape(relative.encode()) + b'\0', raw)
    if not match:
        raise DispositionError('disposition sources must be tracked regular files without hidden index flags')
    return match[1].decode(), match[2].decode()


def _regular_path(root: Path, relative: str, *, optional: bool = False) -> Path | None:
    path = root
    for part in canonical_path(relative).split('/'):
        path = path / part
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            if optional:
                return None
            raise DispositionError('disposition source is missing') from None
        if stat.S_ISLNK(mode):
            raise DispositionError('disposition source paths cannot contain symlinks')
    if not stat.S_ISREG(mode):
        raise DispositionError('disposition source must be a regular file')
    return path


class Dispositions:
    def __init__(self, root: Path):
        self.root = root
        self.config_sha256: str | None = None
        self.entries: list[dict] = []
        self.sources: dict[str, tuple[bytes, int, str]] = {}
        self._total = 0
        self._vendor_sources: set[str] = set()
        self._archived: set[str] = set()
        if _regular_path(root, CONFIG_PATH, optional=True) is None:
            return
        raw = self._read(CONFIG_PATH, limit=MAX_CONFIG_BYTES, nonexecutable=True)
        self.config_sha256 = sha256(raw)
        try:
            document = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object)
        except (UnicodeError, ValueError, RecursionError) as exc:
            raise DispositionError('invalid disposition JSON') from exc
        _fields(document, {'schema_version', 'dispositions'})
        if type(document['schema_version']) is not int or document['schema_version'] != 1:
            raise DispositionError('unsupported disposition schema version')
        entries = document['dispositions']
        if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
            raise DispositionError('disposition entries must be a bounded list')
        ids, identities = set(), set()
        for entry in entries:
            self._validate_entry(entry)
            identity = (entry['check'], entry['rule'], entry['path'], entry['line'], entry.get('column'))
            if entry['id'] in ids or identity in identities:
                raise DispositionError('duplicate disposition identity')
            ids.add(entry['id'])
            identities.add(identity)
            self.entries.append(entry)

    def _read(self, relative: str, *, limit: int = MAX_FILE_BYTES, nonexecutable: bool = False) -> bytes:
        relative = canonical_path(relative)
        if relative in self._archived:
            raw = self._vendor_read(relative)
            if len(raw) > limit:
                raise DispositionError('disposition source exceeds the size limit')
            return raw
        return self._read_file(relative, limit=limit, nonexecutable=nonexecutable)

    def _read_file(self, relative: str, *, limit: int = MAX_FILE_BYTES, nonexecutable: bool = False) -> bytes:
        path = _regular_path(self.root, relative)
        assert path is not None
        index_mode, _oid = _index(self.root, relative)
        before = path.stat()
        if nonexecutable and (before.st_mode & 0o111 or index_mode != '100644'):
            raise DispositionError('review evidence, configuration and immutable Markdown cannot be executable')
        if before.st_nlink != 1:
            raise DispositionError('disposition sources cannot have foreign hard links')
        if before.st_size > limit:
            raise DispositionError('disposition source exceeds the size limit')
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(descriptor, 'rb') as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_mode) != (before.st_dev, before.st_ino, before.st_mode):
                raise DispositionError('disposition source changed while opening')
            raw = stream.read(limit + 1)
        _regular_path(self.root, relative)
        after = path.stat()
        if len(raw) > limit or (before.st_ino, before.st_mtime_ns, before.st_size, before.st_mode) != (
                after.st_ino, after.st_mtime_ns, after.st_size, after.st_mode):
            raise DispositionError('disposition source changed while reading')
        previous = self.sources.get(relative)
        value = (raw, stat.S_IMODE(before.st_mode), index_mode)
        if previous is not None and previous != value:
            raise DispositionError('disposition source changed during verification')
        if previous is None:
            self._total += len(raw)
            if self._total > MAX_TOTAL_BYTES:
                raise DispositionError('disposition sources exceed the total size limit')
            self.sources[relative] = value
        return raw

    def _vendor_read(self, relative: str) -> bytes:
        """Only immutable vendor blobs can derive bytes from a separately proved container."""
        from .baseline_assets import ENGINE_ARCHIVE, ARCHIVE_LIMIT, archive_entries, validate_resources
        if (not re.fullmatch(r'\.getzilla/templates/baseline/blobs/[a-f0-9]{64}\.txt', relative)
                or _regular_path(self.root, ENGINE_ARCHIVE, optional=True) is None):
            return self._read(relative, nonexecutable=True)
        container = self._read(ENGINE_ARCHIVE, limit=ARCHIVE_LIMIT, nonexecutable=True)
        members = archive_entries(container)
        validate_resources(members, lambda path: self._read(path, nonexecutable=True))
        member = members.get(relative)
        if member is None:
            if relative in self._archived:
                raise DispositionError('archived disposition source disappeared')
            return self._read(relative, nonexecutable=True)
        raw, mode = member
        if len(raw) > MAX_FILE_BYTES or mode != 0o644:
            raise DispositionError('disposition source exceeds the size or mode limit')
        loose = _regular_path(self.root, relative, optional=True)
        if loose is not None:
            if self._read_file(relative, nonexecutable=True) != raw:
                raise DispositionError('conflicting loose/archive disposition source')
        previous = self.sources.get(relative)
        value = (raw, mode, '100644')  # Logical member mode; backing Git identity is separate below.
        if previous is not None and previous != value:
            raise DispositionError('archived disposition source changed')
        if previous is None:
            self._total += len(raw)
            if self._total > MAX_TOTAL_BYTES:
                raise DispositionError('disposition sources exceed the total size limit')
        self.sources[relative] = value
        self._archived.add(relative)
        self._vendor_sources.add(ENGINE_ARCHIVE)
        return raw

    def _validate_entry(self, entry: object) -> None:
        secret = isinstance(entry, dict) and entry.get('kind') == 'public-token-address'
        vendor = isinstance(entry, dict) and entry.get('kind') == 'immutable-vendored-whitespace'
        _fields(entry, _COMMON_FIELDS | ({'column', 'match_sha256'} if secret else {'mode', 'catalog'} if vendor else set()))
        if not isinstance(entry['id'], str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,63}', entry['id']):
            raise DispositionError('invalid disposition ID')
        expected = ('secret-scan', 'generic-secret', 'public-token-address') if secret else (
            'git-diff-check', 'new-blank-line-at-eof', 'immutable-markdown-whitespace')
        if not vendor and (entry['check'], entry['rule'], entry['kind']) != expected:
            raise DispositionError('unsupported disposition check, rule or kind')
        reason = entry['reason']
        if (not isinstance(reason, str) or not 1 <= len(reason) <= 2000 or reason.strip() != reason
                or any(ord(char) < 32 or ord(char) == 127 for char in reason)):
            raise DispositionError('disposition reason must be bounded nonempty single-line text')
        _positive(entry['line'])
        path = canonical_path(entry['path'])
        _hash(entry['sha256'])
        if vendor:
            from . import vendored_whitespace
            if (entry['check'] != 'git-diff-check' or entry['rule'] not in vendored_whitespace.KINDS
                    or entry['mode'] != '100644'):
                raise DispositionError('unsupported vendored whitespace observation')

            def read_source(relative):
                previous = self.sources.get(relative)
                raw = previous[0] if previous is not None else self._vendor_read(relative)
                from .component_state import mode_matches
                if not mode_matches(self.sources[relative][1], 0o644) or self.sources[relative][2] != '100644':
                    raise DispositionError('vendored custody sources require exact nonexecutable modes')
                self._vendor_sources.add(relative)
                return raw

            try:
                raw = read_source(path)
                if sha256(raw) != entry['sha256']:
                    raise DispositionError('disposition file hash is stale')
                vendored_whitespace.validate(entry, raw, read_source, canonical_path)
            except (ValueError, TypeError, KeyError, RecursionError) as exc:
                raise DispositionError('invalid exact vendored whitespace proof') from exc
            self._vendor_sources.add(CONFIG_PATH)
            return
        evidence = _fields(entry['evidence'], {'path', 'sha256'})
        evidence_path = canonical_path(evidence['path'])
        _hash(evidence['sha256'])
        if not evidence_path.endswith('.md') or evidence_path == path:
            raise DispositionError('review evidence must be a separate Markdown source')
        if sha256(self._read(evidence_path, nonexecutable=True)) != evidence['sha256']:
            raise DispositionError('review evidence hash is stale')
        raw = self._read(path, nonexecutable=not secret)
        if sha256(raw) != entry['sha256']:
            raise DispositionError('disposition file hash is stale')
        if not secret:
            if not path.endswith('.md') or eof_blank_line(raw) != entry['line']:
                raise DispositionError('disposition does not identify a Markdown EOF blank line')
            return
        _positive(entry['column'])
        _hash(entry['match_sha256'])
        try:
            text = raw.decode('utf-8')
        except UnicodeError as exc:
            raise DispositionError('public-token source must be UTF-8') from exc
        if b'\0' in raw:
            raise DispositionError('public-token source must be text')
        for match in SECRET_PATTERNS['generic-secret'].finditer(text):
            if location(text, match.start()) == (entry['line'], entry['column']):
                if public_token(text, match) and sha256(match.group().encode()) == entry['match_sha256']:
                    return
        raise DispositionError('disposition does not identify an eligible public-token occurrence')

    def assert_current(self) -> None:
        if self.config_sha256 is None:
            if _regular_path(self.root, CONFIG_PATH, optional=True) is not None:
                raise DispositionError('disposition configuration appeared during verification')
            return
        for relative in tuple(self.sources):
            from .baseline_assets import ENGINE_ARCHIVE, ARCHIVE_LIMIT
            limit = ARCHIVE_LIMIT if relative == ENGINE_ARCHIVE and self._archived else (
                MAX_CONFIG_BYTES if relative == CONFIG_PATH else MAX_FILE_BYTES)
            self._read(relative, limit=limit)

    def secret(self, path: str, file_hash: str, text: str, match: re.Match, rule: str = 'generic-secret') -> dict | None:
        line, column = location(text, match.start())
        reviewed = _REVIEWED_SECRET_INPUTS.get((path, file_hash), {}).get((line, column, rule))
        if reviewed:
            line_hash, kind, reason = reviewed
            start = match.start() - column + 1
            end = text.find('\n', match.start())
            raw_line = text[start:end if end >= 0 else len(text)].removesuffix('\r')
            if sha256(raw_line.encode('utf-8')) == line_hash:
                identity = sha256(f'{path}:{line}:{column}'.encode())[:20]
                return {'id': f'reviewed-461-{identity}', 'kind': kind, 'reason': reason,
                        'sha256': file_hash, 'line_sha256': line_hash}
        if rule != 'generic-secret':
            return None
        return next((entry for entry in self.entries if entry['check'] == 'secret-scan'
                     and (entry['path'], entry['sha256'], entry['line'], entry['column'], entry['match_sha256'])
                     == (path, file_hash, line, column, sha256(match.group().encode()))
                     and public_token(text, match)), None)

    def snapshots(self, layer: str) -> dict[str, tuple[bytes, str]]:
        result = {}
        paths = {entry['path'] for entry in self.entries if entry['check'] == 'git-diff-check'}
        paths.update(self._vendor_sources)
        for path in sorted(paths):
            from .baseline_assets import ENGINE_ARCHIVE, ARCHIVE_LIMIT, archive_entries
            backing = ENGINE_ARCHIVE if path in self._archived else path
            if layer == 'worktree':
                raw = self._read(path, limit=ARCHIVE_LIMIT if path == ENGINE_ARCHIVE and self._archived else MAX_FILE_BYTES,
                                 nonexecutable=True)
                result[path] = (raw, '100644')
                continue
            if layer == 'index':
                mode, oid = _index(self.root, backing)
            else:
                record = _git(self.root, 'ls-tree', '-z', 'HEAD', '--', backing)
                found = re.fullmatch(rb'(100644|100755) blob ([0-9a-f]{40,64})\t' + re.escape(backing.encode()) + b'\0', record)
                if not found:
                    # A new worktree/index file has no HEAD blob and grants no HEAD coverage.
                    result[path] = (b'', 'missing')
                    continue
                mode, oid = found[1].decode(), found[2].decode()
            size = _git(self.root, 'cat-file', '-s', oid).strip()
            limit = ARCHIVE_LIMIT if backing == ENGINE_ARCHIVE and self._archived else MAX_FILE_BYTES
            if not size.isdigit() or int(size) > limit:
                raise DispositionError('disposition Git blob exceeds the size limit')
            raw = _git(self.root, 'cat-file', 'blob', oid)
            if len(raw) != int(size):
                raise DispositionError('disposition Git blob size is inconsistent')
            if path in self._archived:
                member = archive_entries(raw).get(path)
                if member is None:
                    result[path] = (b'', 'missing')
                    continue
                raw = member[0]
                if len(raw) > MAX_FILE_BYTES:
                    raise DispositionError('disposition Git member exceeds the size limit')
            result[path] = (raw, mode)
        return result

    def whitespace(self, path: str, line: int, snapshots: dict, rule='new-blank-line-at-eof') -> dict | None:
        raw, mode = snapshots.get(path, (b'', 'missing'))
        for entry in self.entries:
            if (entry['check'] != 'git-diff-check' or entry['rule'] != rule
                    or (entry['path'], entry['line'], entry['sha256']) != (path, line, sha256(raw))
                    or mode != '100644'):
                continue
            if entry['kind'] == 'immutable-vendored-whitespace':
                # Every proof/configuration byte must exist unchanged in the exact
                # layer being classified. Worktree claims never cover absent HEAD
                # or stale staged evidence/catalog/consumer inventory bytes.
                if all(snapshots.get(source) == (self.sources[source][0], self.sources[source][2])
                       for source in self._vendor_sources):
                    return entry
            elif rule == 'new-blank-line-at-eof' and eof_blank_line(raw) == line:
                return entry
        return None

    def apply(self, finding: dict, entry: dict | None) -> None:
        finding['effective_severity'] = finding['severity']
        if entry is not None:
            finding['effective_severity'] = 'info'
            if 'line_sha256' in entry:
                finding['disposition'] = {'id': entry['id'], 'kind': entry['kind'], 'reason': entry['reason'],
                                          'line_sha256': entry['line_sha256'], 'file_sha256': entry['sha256']}
                return
            finding['disposition'] = {
                'id': entry['id'], 'kind': entry['kind'], 'reason': entry['reason'],
                'evidence': entry['evidence'], 'config_path': CONFIG_PATH,
                'config_sha256': self.config_sha256, 'file_sha256': entry['sha256'],
            }
            finding['message'] += f" Reviewed disposition: {entry['id']}."


def invalid_finding() -> dict:
    # Never include parser exceptions: they can contain untrusted source bytes.
    return {'severity': 'error', 'effective_severity': 'error', 'code': 'disposition-config-invalid',
            'path': CONFIG_PATH, 'message': 'Reviewed dispositions are invalid, stale or changed during verification.'}


def diff_findings(stdout: str, policy: Dispositions | None, snapshots: dict, label: str) -> tuple[list[dict], bool]:
    """Classify only exact supported diagnostics; retain every raw observation."""
    if not stdout or not stdout.endswith('\n') or len(stdout) > MAX_FILE_BYTES:
        return [], False
    lines = stdout[:-1].split('\n')
    findings = []
    complete = True
    cursor = 0
    while cursor < len(lines):
        found = re.fullmatch(r'([^\r\n]+):([1-9][0-9]{0,9}): ([^\r\n]+)', lines[cursor])
        cursor += 1
        if not found:
            complete = False
            continue
        path, line, diagnostic = found[1], int(found[2]), found[3]
        eof = diagnostic == 'new blank line at EOF.'
        finding = {'severity': 'error', 'effective_severity': 'error', 'observation': True,
                   'code': 'new-blank-line-at-eof' if eof else 'diff-whitespace',
                   'path': path, 'line': line, 'layer': label, 'message': diagnostic}
        rule = {'new blank line at EOF.': 'new-blank-line-at-eof',
                'trailing whitespace.': 'trailing-whitespace',
                'space before tab in indent.': 'space-before-tab',
                'trailing whitespace, space before tab in indent.': 'trailing-whitespace-and-space-before-tab'}.get(diagnostic)
        entry = policy.whitespace(path, line, snapshots, rule) if rule and policy else None
        if policy:
            policy.apply(finding, entry)
        findings.append(finding)
        if not eof:
            # Git's non-EOF whitespace observations include the added source line.
            if diagnostic not in {'trailing whitespace.', 'space before tab in indent.',
                                  'trailing whitespace, space before tab in indent.'}:
                complete = False
            if cursor < len(lines) and lines[cursor].startswith('+'):
                cursor += 1
            else:
                complete = False
    return findings, complete


def summary(policy: Dispositions | None, findings: list[dict]) -> dict:
    observations = [item for item in findings if item.get('observation')]
    disposed = sum(item.get('effective_severity') == 'info' for item in observations)
    return {'severity': 'info', 'code': 'disposition-summary', 'path': CONFIG_PATH,
            'message': 'Raw findings remain visible; effective outcomes include reviewed dispositions.',
            'config_sha256': policy.config_sha256 if policy else None,
            'configured': len(policy.entries) if policy else 0, 'observed': len(observations),
            'disposed': disposed,
            'unresolved': sum(item.get('severity') == 'error' and item.get('effective_severity') != 'info'
                              for item in findings)}
