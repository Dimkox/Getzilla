"""Resolve current direct tools, qualify the complete wheel graph, then activate it.

Only Getzilla's own environment changes. No customer requirements or sdist code run.
The isolated resolver uses public PyPI without user configuration or credentials.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from .latest_releases import metadata, pypi_version
from .managed_runtime import directory

PROJECTS = ('pip', 'pytest', 'pytest-xdist', 'pytest-cov', 'coverage', 'jsonschema', 'ruff', 'bandit', 'uv')


def execute(command, cwd=None, *, env=None):
    from .architecture_diff import _run_capped
    code, stdout, stderr = _run_capped(command, cwd=Path(cwd or Path.cwd()),
        env=dict(os.environ) if env is None else env, stdout_limit=2*1024*1024,
        stderr_limit=1024*1024, timeout=900)
    return subprocess.CompletedProcess(command, code, stdout.decode('utf-8', 'replace'), stderr.decode('utf-8', 'replace'))



def _name(value):
    if type(value) is not str or not re.fullmatch('[A-Za-z0-9_.-]+', value):
        raise ValueError('invalid quality dependency name')
    return re.sub('[-_.]+', '-', value).lower()


def _wheel(row, fetch):
    name, version = _name(row['metadata']['name']), row['metadata']['version']
    if type(version) is not str or not re.fullmatch('[A-Za-z0-9_.+!-]+', version):
        raise ValueError('invalid quality dependency exact version')
    info = row['download_info']
    url = info['url']
    parsed = urlsplit(url)
    filename = parsed.path.rsplit('/', 1)[-1]
    if (parsed.scheme != 'https' or parsed.netloc != 'files.pythonhosted.org' or parsed.query or parsed.fragment
            or not re.fullmatch(r'[A-Za-z0-9_.+-]+\.whl', filename)):
        raise ValueError('quality resolver requires an official wheel; no sdist/build fallback')
    catalog = metadata(fetch, f'https://pypi.org/pypi/{name}/{version}/json')
    if _name(catalog.get('info', {}).get('name')) != name or catalog.get('info', {}).get('version') != version:
        raise ValueError('quality wheel metadata identity differs from PyPI')
    matches = [f for f in catalog.get('urls', []) if f.get('url') == url and f.get('filename') == filename
               and f.get('yanked') is False and f.get('packagetype') == 'bdist_wheel']
    if len(matches) != 1:
        raise ValueError('quality wheel missing/ambiguous/yanked in exact official release')
    sha = matches[0].get('digests', {}).get('sha256', '')
    if not re.fullmatch('[a-f0-9]{64}', sha) or info.get('archive_info', {}).get('hashes', {}).get('sha256') != sha:
        raise ValueError('quality resolver wheel hash differs from official PyPI digest')
    raw = fetch(url)
    if len(raw) > 128*1024*1024 or hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError('quality wheel integrity mismatch')
    return name, version, filename, sha, raw


class EnvironmentFailure(ValueError):
    """An incomplete operation with bounded private diagnostic data, never admission credit."""
    def __init__(self, message, report=None):
        super().__init__(message)
        self._diagnostic = json.dumps(report, ensure_ascii=False, sort_keys=True) if report is not None else None


def failure_details(error):
    if type(error) is not EnvironmentFailure or type(error._diagnostic) is not str:
        return None
    if len(error._diagnostic.encode('utf-8')) > 65536:
        return None
    try:
        value = json.loads(error._diagnostic)
    except (ValueError, RecursionError):
        return None
    return value if type(value) is dict else None


def _redact_urls(text):
    def redact(match):
        try:
            parsed = urlsplit(match.group())
        except ValueError:
            return '[invalid URL redacted]'
        authority = parsed.netloc.rsplit('@', 1)[-1]
        suffix = '?[redacted]' if parsed.query else ''
        suffix += '#[redacted]' if parsed.fragment else ''
        return parsed.scheme+'://'+authority+parsed.path+suffix
    return re.sub(r'https?://[^\s\'"<>]+', redact, str(text))


def _failure_record(stage, command, phase, result):
    """Private bounded first/last output; no ambient environment or credentials."""
    report = {'schema_version': 1, 'phase': phase,
              'command': [_redact_urls(value) for value in command], 'returncode': result.returncode,
              'environment_policy': {'ambient_pip_overrides': False, 'config_file': 'disabled',
                                     'keyring': 'disabled', 'private_home': True}}
    for key in ('stdout', 'stderr'):
        original = str(getattr(result, key) or '').encode('utf-8', 'replace')
        safe = _redact_urls(original.decode('utf-8', 'replace')).encode('utf-8')
        kept = safe if len(safe) <= 8192 else safe[:4096]+b'\n[output omitted]\n'+safe[-4096:]
        report[key] = {'retained': kept.decode('utf-8', 'replace'), 'bytes': len(original),
                       'sha256': hashlib.sha256(original).hexdigest(),
                       'omitted_bytes': max(0, len(safe)-8192), 'urls_redacted': safe != original}
    raw = (json.dumps(report, ensure_ascii=False, sort_keys=True)+'\n').encode('utf-8')
    # Remain below a fixed diagnostic bound without changing process/output limits.
    while len(raw) > 65536 and any(len(report[key]['retained']) > 512 for key in ('stdout', 'stderr')):
        for key in ('stdout', 'stderr'):
            text = report[key]['retained']
            if len(text) > 512:
                report[key]['retained'] = text[:128]+'\n[output omitted]\n'+text[-128:]
                report[key]['omitted_bytes'] += max(0, len(text.encode('utf-8'))-256)
        raw = (json.dumps(report, ensure_ascii=False, sort_keys=True)+'\n').encode('utf-8')
    if len(raw) > 65536:
        raise ValueError('managed failure diagnostic exceeds bound')
    path = stage/'failure.json'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
    return path, report


def install_environment(home: Path, python: str, *, fetch, run=execute, projects=PROJECTS) -> Path:
    targets = {_name(name): pypi_version(name, fetch) for name in projects}
    base = home/'.getzilla/runtime/environments'
    directory(base)
    if any(p.is_symlink() for p in (home, home/'.getzilla', home/'.getzilla/runtime', base)):
        raise ValueError('linked Getzilla environment root')
    stage = Path(tempfile.mkdtemp(prefix='current-', dir=base))
    private = stage/'resolver-home'
    private.mkdir(mode=0o700)
    environment = {k: v for k, v in os.environ.items() if k in ('PATH', 'SystemRoot', 'WINDIR', 'COMSPEC', 'PATHEXT', 'LD_LIBRARY_PATH')}
    environment.update(HOME=str(private), USERPROFILE=str(private), APPDATA=str(private), LOCALAPPDATA=str(private),
                       TMPDIR=str(private), TEMP=str(private), TMP=str(private), NETRC=str(private/'absent-netrc'),
                       PIP_CONFIG_FILE=os.devnull, PIP_NO_INPUT='1', PIP_KEYRING_PROVIDER='disabled')

    def checked(command, phase):
        result = run(command, home, env=environment)
        if result.returncode:
            try:
                path, details = _failure_record(stage, command, phase, result)
                diagnostic = str(path.relative_to(home))
            except (OSError, ValueError):
                diagnostic, details = 'unavailable', None
            cause = _redact_urls(result.stderr or result.stdout)[-500:]
            raise EnvironmentFailure(f'{phase}: latest exact targets incompatible or operation failed: {cause}; diagnostic={diagnostic}', details)
        return result

    checked([python, '-m', 'venv', str(stage)], 'create managed environment')
    executable = stage/('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    if not executable.is_file():
        raise ValueError('managed interpreter was not created')
    report = stage/'resolved-wheels.json'
    prefix = [str(executable), '-m', 'pip', '--isolated', '--disable-pip-version-check']
    checked([*prefix, 'install', '--dry-run', '--ignore-installed', '--only-binary=:all:', '--no-input',
             '--keyring-provider', 'disabled', '--retries', '0', '--timeout', '20',
             '--index-url', 'https://pypi.org/simple', '--report', str(report),
             *[name+'=='+version for name, version in targets.items()]], 'resolve exact wheel closure')
    if report.stat().st_size > 2*1024*1024:
        raise ValueError('quality dependency report exceeds byte bound')
    graph = json.loads(report.read_text())
    rows = graph.get('install')
    if type(rows) is not list or not 0 < len(rows) <= 512:
        raise ValueError('quality dependency graph is incomplete or exceeds bound')
    wheelhouse = stage/'verified-wheels'
    wheelhouse.mkdir(mode=0o700)
    exact, total, lock = {}, 0, []
    for row in rows:
        name, version, filename, sha, raw = _wheel(row, fetch)
        if name in exact or (wheelhouse/filename).exists():
            raise ValueError('duplicate quality dependency identity')
        exact[name] = version
        total += len(raw)
        if total > 512*1024*1024:
            raise ValueError('quality wheel batch exceeds byte bound')
        (wheelhouse/filename).write_bytes(raw)
        lock.append(f'{name}=={version} --hash=sha256:{sha}')
    if any(exact.get(name) != version for name, version in targets.items()):
        raise ValueError('resolver selected an older/different direct target')
    requirements = stage/'verified-requirements.txt'
    requirements.write_text('\n'.join(lock)+'\n')
    checked([*prefix, 'install', '--no-index', '--find-links', str(wheelhouse), '--only-binary=:all:',
             '--require-hashes', '--no-input', '-r', str(requirements)], 'install verified exact wheel closure')
    checked([*prefix, 'check'], 'check dependency compatibility')
    probe = 'import importlib.metadata,json,sys;print(json.dumps({n:importlib.metadata.version(n) for n in json.loads(sys.argv[1])}))'
    actual = checked([str(executable), '-I', '-c', probe, json.dumps(sorted(exact))], 'probe actual managed distributions')
    if json.loads(actual.stdout) != exact:
        raise ValueError('actual managed environment differs from qualified wheel closure')
    activation = home/'.venv'
    candidate = home/('.venv.activate-'+uuid.uuid4().hex)
    previous = home/('.venv.previous-'+uuid.uuid4().hex)
    if activation.is_symlink() or getattr(activation, 'is_junction', lambda: False)():
        if not activation.resolve().is_relative_to(base.resolve()):
            raise ValueError('user environment link conflicts with managed activation')
    elif activation.exists() and not activation.is_dir():
        raise ValueError('user .venv file conflicts with managed activation')
    moved = False
    try:
        if os.name == 'nt':
            checked([os.environ.get('COMSPEC', 'cmd.exe'), '/d', '/c', 'mklink', '/J', str(candidate), str(stage)],
                    'stage per-user environment junction')
        else:
            candidate.symlink_to(stage, target_is_directory=True)
        if not candidate.resolve().samefile(stage):
            raise ValueError('managed environment activation path differs')
        if activation.exists() or activation.is_symlink():
            activation.rename(previous)
            moved = True
        try:
            candidate.rename(activation)
        except BaseException:
            if moved:
                previous.rename(activation)
            raise
    finally:
        if candidate.is_symlink():
            candidate.unlink()
        elif getattr(candidate, 'is_junction', lambda: False)():
            candidate.rmdir()
    return activation/('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
