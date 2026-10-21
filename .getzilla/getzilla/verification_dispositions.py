"""Narrow, source-bound review records for two verification observations.

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
        path = _regular_path(self.root, relative)
        assert path is not None
        index_mode, _oid = _index(self.root, relative)
        before = path.stat()
        if nonexecutable and (before.st_mode & 0o111 or index_mode != '100644'):
            raise DispositionError('review evidence, configuration and immutable Markdown cannot be executable')
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

    def _validate_entry(self, entry: object) -> None:
        secret = isinstance(entry, dict) and entry.get('kind') == 'public-token-address'
        _fields(entry, _COMMON_FIELDS | ({'column', 'match_sha256'} if secret else set()))
        if not isinstance(entry['id'], str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,63}', entry['id']):
            raise DispositionError('invalid disposition ID')
        expected = ('secret-scan', 'generic-secret', 'public-token-address') if secret else (
            'git-diff-check', 'new-blank-line-at-eof', 'immutable-markdown-whitespace')
        if (entry['check'], entry['rule'], entry['kind']) != expected:
            raise DispositionError('unsupported disposition check, rule or kind')
        reason = entry['reason']
        if (not isinstance(reason, str) or not 1 <= len(reason) <= 2000 or reason.strip() != reason
                or any(ord(char) < 32 or ord(char) == 127 for char in reason)):
            raise DispositionError('disposition reason must be bounded nonempty single-line text')
        _positive(entry['line'])
        path = canonical_path(entry['path'])
        _hash(entry['sha256'])
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
            self._read(relative, limit=MAX_CONFIG_BYTES if relative == CONFIG_PATH else MAX_FILE_BYTES)

    def secret(self, path: str, file_hash: str, text: str, match: re.Match) -> dict | None:
        line, column = location(text, match.start())
        return next((entry for entry in self.entries if entry['check'] == 'secret-scan'
                     and (entry['path'], entry['sha256'], entry['line'], entry['column'], entry['match_sha256'])
                     == (path, file_hash, line, column, sha256(match.group().encode()))
                     and public_token(text, match)), None)

    def snapshots(self, layer: str) -> dict[str, tuple[bytes, str]]:
        result = {}
        for entry in self.entries:
            if entry['check'] != 'git-diff-check':
                continue
            path = entry['path']
            if layer == 'worktree':
                raw = self._read(path, nonexecutable=True)
                result[path] = (raw, '100644')
                continue
            if layer == 'index':
                mode, oid = _index(self.root, path)
            else:
                record = _git(self.root, 'ls-tree', '-z', 'HEAD', '--', path)
                found = re.fullmatch(rb'(100644|100755) blob ([0-9a-f]{40,64})\t' + re.escape(path.encode()) + b'\0', record)
                if not found:
                    # A new worktree/index file has no HEAD blob and grants no HEAD coverage.
                    result[path] = (b'', 'missing')
                    continue
                mode, oid = found[1].decode(), found[2].decode()
            size = _git(self.root, 'cat-file', '-s', oid).strip()
            if not size.isdigit() or int(size) > MAX_FILE_BYTES:
                raise DispositionError('disposition Git blob exceeds the size limit')
            raw = _git(self.root, 'cat-file', 'blob', oid)
            if len(raw) != int(size):
                raise DispositionError('disposition Git blob size is inconsistent')
            result[path] = (raw, mode)
        return result

    def whitespace(self, path: str, line: int, snapshots: dict) -> dict | None:
        raw, mode = snapshots.get(path, (b'', 'missing'))
        return next((entry for entry in self.entries if entry['check'] == 'git-diff-check'
                     and (entry['path'], entry['line'], entry['sha256']) == (path, line, sha256(raw))
                     and mode == '100644' and eof_blank_line(raw) == line), None)

    def apply(self, finding: dict, entry: dict | None) -> None:
        finding['effective_severity'] = finding['severity']
        if entry is not None:
            finding['effective_severity'] = 'info'
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
    """Only an exact EOF diagnostic can be covered; retain all other observations."""
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
        entry = policy.whitespace(path, line, snapshots) if eof and policy else None
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
