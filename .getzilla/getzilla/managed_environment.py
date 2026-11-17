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

PROJECTS = ('pip', 'pytest', 'pytest-xdist', 'pytest-cov', 'coverage', 'jsonschema', 'ruff', 'bandit', 'uv')


def execute(command, cwd=None, *, env=None):
    return subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True,
                          encoding='utf-8', errors='replace', check=False, timeout=900)  # nosec B603


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


def install_environment(home: Path, python: str, *, fetch, run=execute, projects=PROJECTS) -> Path:
    targets = {_name(name): pypi_version(name, fetch) for name in projects}
    base = home/'.getzilla/runtime/environments'
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
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
            raise ValueError(f'{phase}: latest exact targets incompatible or operation failed: {(result.stderr or result.stdout)[-500:]}')
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
    if activation.is_symlink() or getattr(activation, 'is_junction', lambda: False)():
        if not activation.resolve().is_relative_to(base.resolve()):
            raise ValueError('user environment link conflicts with managed activation')
        if os.name == 'nt':
            activation.rmdir()
        else:
            activation.unlink()
    elif activation.exists():
        if not activation.is_dir():
            raise ValueError('user .venv file conflicts with managed activation')
        activation.rename(home/('.venv.previous-'+uuid.uuid4().hex))
    if os.name == 'nt':
        checked([os.environ.get('COMSPEC', 'cmd.exe'), '/d', '/c', 'mklink', '/J', str(activation), str(stage)],
                'activate per-user environment junction')
    else:
        activation.symlink_to(stage, target_is_directory=True)
    if not activation.resolve().samefile(stage):
        raise ValueError('managed environment activation path differs')
    return activation/('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
