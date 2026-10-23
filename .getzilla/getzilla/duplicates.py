"""Read-only, source-only duplication analysis. Never install or load project config."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time

from .manifest import _open_regular_at, _open_root
from .util import find_tool

VERSION = '4.0.5'
EXTENSIONS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.php', '.go', '.rs',
              '.java', '.c', '.h', '.cpp', '.hpp', '.cs', '.rb', '.sh', '.vue', '.svelte'}
EXCLUDED = {'.git', '.grok', '.qwen', '.claude', '.codex', '.gemini', '.github',
            '.agents', 'docs', 'engineering', 'reports', 'evidence', 'packages', 'vendor',
            'node_modules', 'build', 'dist', '__pycache__', '.venv', 'venv', '.cache',
            '.pytest_cache', '.ruff_cache', 'coverage', 'htmlcov', 'generated'}
MAX_FILE = 1024 * 1024
MAX_BYTES = 32 * 1024 * 1024
MAX_REPORT = 8 * 1024 * 1024
MAX_FILES = 4000


def _identity(value: os.stat_result) -> tuple:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns


def inventory(root: Path, *, include_tests: bool = False) -> dict[str, bytes]:
    """Apply path policy before opening bytes; refuse incomplete or changing input."""
    root, descriptor = _open_root(root)
    result: dict[str, bytes] = {}
    total = entries = 0
    excluded = EXCLUDED | (set() if include_tests else {'test', 'tests', '__tests__', 'fixtures'})
    try:
        def failed(error):
            raise error
        for directory, folders, files in os.walk(root, topdown=True, followlinks=False, onerror=failed):
            folders[:] = sorted(name for name in folders if name.lower() not in excluded
                                and not (Path(directory) / name).is_symlink())
            if Path(directory).name == '.getzilla':
                folders[:] = [name for name in folders if name == 'getzilla']
                files = []
            entries += len(folders) + len(files)
            if entries > 20000:
                raise ValueError('source inventory entry limit')
            for name in sorted(files):
                path = Path(directory) / name
                if path.suffix.lower() not in EXTENSIONS or name.startswith('.'):
                    continue
                if not include_tests and (name.startswith('test_') or '.test.' in name or '.spec.' in name):
                    continue
                before = path.lstat()
                if not stat.S_ISREG(before.st_mode):
                    continue
                if before.st_size > MAX_FILE or len(result) >= MAX_FILES:
                    raise ValueError('source inventory file limit')
                relative = path.relative_to(root).as_posix()
                fd = _open_regular_at(descriptor, tuple(path.relative_to(root).parts), relative)
                with os.fdopen(fd, 'rb') as handle:
                    opened = os.fstat(handle.fileno())
                    data = handle.read(MAX_FILE + 1)
                    after = os.fstat(handle.fileno())
                if _identity(opened) != _identity(after) or _identity(before) != _identity(opened):
                    raise ValueError('source changed while reading')
                if len(data) > MAX_FILE:
                    raise ValueError('source inventory file limit')
                data.decode('utf-8')
                total += len(data)
                if total > MAX_BYTES:
                    raise ValueError('source inventory byte limit')
                result[relative] = data
    finally:
        if isinstance(descriptor, int):
            os.close(descriptor)
    return result


def _execute(argv: list[str], cwd: Path, report: Path | None = None, timeout: int = 120):
    """Keep subprocess output on owned disk and stop on time/output limits."""
    with tempfile.TemporaryFile() as output:
        with subprocess.Popen(argv, cwd=cwd, stdout=output, stderr=subprocess.STDOUT) as process:
            started = time.monotonic()
            try:
                while process.poll() is None:
                    if time.monotonic() - started > timeout:
                        raise ValueError('jscpd timeout')
                    if os.fstat(output.fileno()).st_size > MAX_REPORT or (
                            report is not None and report.exists() and report.stat().st_size > MAX_REPORT):
                        raise ValueError('jscpd output limit')
                    time.sleep(0.02)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
            output.seek(0)
            data = output.read(MAX_REPORT + 1)
            if len(data) > MAX_REPORT:
                raise ValueError('jscpd output limit')
            return process.returncode, data.decode('utf-8', 'replace')


def _scratch(root: Path) -> Path:
    """Reject existing linked output ancestors before creating snapshot directories.

    This is a local path guard, not isolation from concurrent hostile renames.
    """
    current = root
    for name in ('.getzilla', 'runtime', 'scratch'):
        current = current / name
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            pass
        metadata = current.lstat()
        reparse = getattr(metadata, 'st_file_attributes', 0) & 0x400
        if not stat.S_ISDIR(metadata.st_mode) or reparse:
            raise ValueError('unsafe snapshot scratch ancestor')
    return current


def _span(value: object, source: Path, files: dict[str, bytes]) -> dict:
    if not isinstance(value, dict) or not isinstance(value.get('name'), str):
        raise ValueError('invalid clone file')
    name = value['name']
    if '\\' in name:
        raise ValueError('invalid clone path')
    path = Path(name)
    if '..' in path.parts:
        raise ValueError('invalid clone path')
    resolved = (path if path.is_absolute() else source.parent / path).resolve()
    relative = resolved.relative_to(source).as_posix()
    if relative not in files:
        raise ValueError('clone outside source inventory')
    start, end = value.get('start'), value.get('end')
    lines = len(files[relative].decode('utf-8').splitlines())
    if type(start) is not int or type(end) is not int or not 1 <= start <= end <= lines:
        raise ValueError('invalid clone span')
    return {'path': relative, 'start': start, 'end': end,
            'sha256': hashlib.sha256(files[relative]).hexdigest()}


def scan(root: Path, *, include_tests: bool = False, min_tokens: int = 50,
         min_lines: int = 5, timeout: int = 120) -> dict:
    result = {'schema_version': 1, 'status': 'unavailable', 'pairs': None, 'version': None,
              'advisory': True, 'reason': '', 'options': {'include_tests': include_tests,
              'min_tokens': min_tokens, 'min_lines': min_lines}}
    binary = find_tool('jscpd')
    if not binary:
        result['reason'] = 'jscpd missing; run getzilla update --only jscpd'
        return result
    try:
        if not 1 <= min_tokens <= 10000 or not 1 <= min_lines <= 10000 or not 1 <= timeout <= 120:
            raise ValueError('invalid scan bounds')
        files = inventory(root, include_tests=include_tests)
        hashes = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
        result['source_hashes'] = hashes
        result['inventory_digest'] = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
        scratch = _scratch(root)
        with tempfile.TemporaryDirectory(prefix='duplicates-', dir=scratch) as temporary:
            work = Path(temporary)
            source = work / 'source'
            source.mkdir()
            for name, data in files.items():
                target = source / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            config = work / 'controlled.json'
            config.write_text('{}', encoding='utf-8', newline='\n')
            code, version = _execute([binary, '--version'], work, timeout=10)
            result['version'] = version.strip()
            if code or version.strip() != VERSION:
                result['reason'] = f'unsupported jscpd version; require {VERSION}'
                return result
            report = work / 'report/jscpd-report.json'
            argv = [binary, 'source', '--config', str(config), '--reporters', 'json',
                    '--output', str(report.parent), '--min-tokens', str(min_tokens),
                    '--min-lines', str(min_lines), '--max-lines', '1000000', '--max-size', '2mb',
                    '--absolute', '--noSymlinks', '--silent']
            code, _ = _execute(argv, work, report, timeout)
            if code:
                raise ValueError('jscpd failed')
            if not report.is_file() or report.stat().st_size > MAX_REPORT:
                raise ValueError('missing or oversized jscpd report')
            payload = json.loads(report.read_text(encoding='utf-8'))
            clones = payload.get('duplicates') if isinstance(payload, dict) else None
            if not isinstance(clones, list) or len(clones) > 10000:
                raise ValueError('invalid jscpd report')
            pairs = []
            rejected = 0
            for clone in clones:
                try:
                    first = _span(clone['firstFile'], source, files)
                    second = _span(clone['secondFile'], source, files)
                    tokens = clone.get('tokens')
                    pairs.append({'first': first, 'second': second,
                                  'tokens': tokens if type(tokens) is int and tokens > 0 else None})
                except (KeyError, TypeError, ValueError):
                    rejected += 1
            if inventory(root, include_tests=include_tests) != files:
                raise ValueError('source changed during scan')
            result.update(status='partial' if rejected else 'complete', pairs=pairs,
                          rejected_pairs=rejected, reason='invalid clone pairs' if rejected else '')
    except (OSError, ValueError, UnicodeError, RuntimeError) as exc:
        result.update(status='error', pairs=None, reason=str(exc)[:200])
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--include-tests', action='store_true')
    parser.add_argument('--min-tokens', type=int, default=50)
    parser.add_argument('--min-lines', type=int, default=5)
    args = parser.parse_args(argv)
    result = scan(args.root.resolve(), include_tests=args.include_tests,
                  min_tokens=args.min_tokens, min_lines=args.min_lines)
    print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
    return 0 if result['status'] == 'complete' else 2
