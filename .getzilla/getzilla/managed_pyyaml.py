"""Reviewed official PyYAML pure source build when the current runtime has no wheel.

This does not admit arbitrary sdists. Local output authority exists only in the
current invocation's private completion registry, after a real offline build/probe.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import tomllib
import weakref
import zipfile
from email.parser import BytesParser
from urllib.parse import urlsplit

from .latest_releases import Target, metadata, pypi_version
from .managed_runtime import entries


class _Completion:
    __slots__ = ('__weakref__',)


_issued = weakref.WeakKeyDictionary()

# This reviewed pure backend needs Python files and its private output only.
# It must not start a compiler/installer, contact a service or read user files.
_BACKEND = """import os,sys
source,output=sys.argv[1:]
roots=tuple(os.path.realpath(p) for p in (os.path.dirname(source),sys.prefix,sys.base_prefix))
def audit(event,args):
    if event.startswith(('socket.','ctypes.')) or event in ('subprocess.Popen','os.system','os.posix_spawn','os.exec','os.fork','os.forkpty'):
        raise PermissionError('PyYAML pure backend external effect refused')
    if event=='open' and not isinstance(args[0],int):
        path=os.path.realpath(os.fsdecode(args[0]))
        if not any(path==root or path.startswith(root+os.sep) for root in roots):
            raise PermissionError('PyYAML pure backend file outside private build/runtime refused')
sys.addaudithook(audit)
os.chdir(source)
sys.path.insert(0,os.path.join(source,'packaging'))
import _pyyaml_pep517 as backend
backend.build_wheel(output,config_settings={'--global-option':['--without-libyaml']})
"""


def _build_system(project):
    expected = {'requires': ['setuptools', "Cython; python_version < '3.13'",
                            "Cython>=3.0; python_version >= '3.13'"],
                'backend-path': ['packaging'], 'build-backend': '_pyyaml_pep517'}
    if project.get('build-system') != expected:
        raise ValueError('unsupported current PyYAML build system; no generic sdist fallback')


def _source(catalog, version, fetch):
    if catalog.get('info', {}).get('name', '').lower() != 'pyyaml' or catalog['info'].get('version') != version:
        raise ValueError('PyYAML official source identity differs')
    rows = [row for row in catalog.get('urls', []) if row.get('packagetype') == 'sdist' and row.get('yanked') is False]
    if len(rows) != 1:
        raise ValueError('current PyYAML source is missing/ambiguous')
    row = rows[0]
    filename, url, sha = row.get('filename', ''), row.get('url', ''), row.get('digests', {}).get('sha256', '')
    parsed = urlsplit(url)
    if (filename != 'pyyaml-'+version+'.tar.gz' or parsed.scheme != 'https'
            or parsed.netloc != 'files.pythonhosted.org' or parsed.query or parsed.fragment
            or parsed.path.rsplit('/', 1)[-1] != filename or not re.fullmatch('[a-f0-9]{64}', sha)):
        raise ValueError('unsupported current official PyYAML source')
    raw = fetch(url)
    if type(raw) is not bytes or len(raw) > 128*1024*1024:
        raise ValueError('PyYAML source exceeds byte bound')
    target = Target('pyyaml', version, url, sha256=sha, filename=filename)
    files, links = entries(target, raw)  # Expected publisher digest checked before parsing or execution.
    if links or not {'pyproject.toml', 'setup.py', 'packaging/_pyyaml_pep517.py', 'lib/yaml/__init__.py'} <= files.keys():
        raise ValueError('unsupported current PyYAML source layout')
    _build_system(tomllib.loads(files['pyproject.toml'][0].decode('utf-8')))
    return target, files


def _validate_wheel(raw, filename, version):
    if filename.lower() != 'pyyaml-'+version+'-py3-none-any.whl' or len(raw) > 128*1024*1024:
        raise ValueError('PyYAML build did not produce the exact universal pure wheel')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        items = archive.infolist()
        if not 0 < len(items) <= 16384:
            raise ValueError('PyYAML wheel member bound')
        names, total, dist = set(), 0, 'pyyaml-'+version+'.dist-info'
        for item in items:
            name = item.filename
            total += item.file_size
            if (name != item.orig_filename or item.flag_bits & 1 or name.startswith('/') or '\\' in name
                    or ':' in name or any(part in ('', '.', '..') for part in name.rstrip('/').split('/'))
                    or name.casefold() in names or item.file_size > 128*1024*1024 or total > 512*1024*1024
                    or stat.S_IFMT(item.external_attr >> 16) not in (0, stat.S_IFREG, stat.S_IFDIR)
                    or name.split('/')[0].lower() not in ('yaml', '_yaml', dist)
                    or name.lower().endswith(('.so', '.pyd', '.dll', '.a', '.o', '.obj', '.exe'))):
                raise ValueError('unsafe or native PyYAML wheel output')
            names.add(name.casefold())
        paths = {name.lower(): name for name in archive.namelist()}
        try:
            meta = BytesParser().parsebytes(archive.read(paths[dist+'/metadata']))
            wheel = BytesParser().parsebytes(archive.read(paths[dist+'/wheel']))
        except KeyError as exc:
            raise ValueError('PyYAML wheel identity metadata absent') from exc
        if (meta.get_all('Name') != ['PyYAML'] or meta.get_all('Version') != [version]
                or meta.get_all('Requires-Python') != ['>=3.8'] or meta.get_all('Requires-Dist')
                or wheel.get_all('Root-Is-Purelib') != ['true'] or wheel.get_all('Tag') != ['py3-none-any']
                or wheel.get_all('Wheel-Version') != ['1.0']):
            raise ValueError('PyYAML pure wheel metadata differs from the reviewed format')


def consume(capability, row, nonce):
    """A file URL/hash/JSON record cannot mint a completed source build."""
    if type(capability) is not _Completion or capability not in _issued:
        raise ValueError('PyYAML local wheel requires actual current build completion')
    owner, path, version, sha, identity = _issued[capability]
    if owner is not nonce or row.get('metadata', {}).get('name', '').lower() != 'pyyaml' or row['metadata'].get('version') != version:
        raise ValueError('PyYAML build completion owner/identity differs')
    if (row.get('download_info', {}).get('url') != path.as_uri()
            or row['download_info'].get('archive_info', {}).get('hashes', {}).get('sha256') != sha):
        raise ValueError('resolver local wheel differs from actual build completion')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (info.st_dev, info.st_ino, info.st_size) != identity or info.st_nlink != 1:
            raise ValueError('PyYAML built wheel identity changed')
        raw = stream.read(128*1024*1024+1)
    if hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError('PyYAML completed wheel bytes changed')
    _validate_wheel(raw, path.name, version)
    return 'pyyaml', version, path.name, sha, raw


def prepare(stage, executable, targets, *, fetch, checked, environment, nonce):
    """Return None for an official compatible wheel; otherwise build only PyYAML."""
    if 'bandit' not in targets:
        return None
    catalog = metadata(fetch, 'https://pypi.org/pypi/bandit/'+targets['bandit']+'/json')
    version = pypi_version('PyYAML', fetch)
    release = metadata(fetch, 'https://pypi.org/pypi/pyyaml/'+version+'/json')
    filenames = [row.get('filename') for row in release.get('urls', [])
                 if row.get('packagetype') == 'bdist_wheel' and row.get('yanked') is False]
    if (len(filenames) > 2048 or any(type(name) is not str or len(name) > 256 for name in filenames)
            or type(catalog.get('info', {}).get('requires_dist')) is not list):
        raise ValueError('PyYAML compatibility metadata unavailable or exceeds bound')
    compatibility = stage/'pyyaml-compatibility.json'
    compatibility.write_text(json.dumps(dict(filenames=filenames, version=version,
        requires_python=release.get('info', {}).get('requires_python'),
        requires_dist=catalog['info']['requires_dist'])))
    code = ("import json,sys;from pip._vendor.packaging.tags import sys_tags;"
            "from pip._vendor.packaging.utils import parse_wheel_filename,canonicalize_name;"
            "from pip._vendor.packaging.requirements import Requirement;"
            "from pip._vendor.packaging.specifiers import SpecifierSet;"
            "d=json.load(open(sys.argv[1]));tags=set(sys_tags());"
            "reqs=[Requirement(r) for r in d['requires_dist']];"
            "reqs=[r for r in reqs if canonicalize_name(r.name)=='pyyaml' and (r.marker is None or r.marker.evaluate())];"
            "assert len(reqs)==1 and reqs[0].url is None and d['version'] in reqs[0].specifier;"
            "assert '.'.join(map(str,sys.version_info[:3])) in SpecifierSet(d['requires_python']);"
            "print(json.dumps({'compatible':any(bool(parse_wheel_filename(n)[3]&tags) for n in d['filenames'])}))")
    result = checked([str(executable), '-I', '-c', code, str(compatibility)], 'check current PyYAML wheel compatibility')
    if result.stdout.strip() not in ('{"compatible": true}', '{"compatible": false}'):
        raise ValueError('invalid current PyYAML compatibility observation')
    if json.loads(result.stdout)['compatible']:
        return None
    target, files = _source(release, version, fetch)
    build = stage/'pyyaml-build'
    build.mkdir(mode=0o700)
    source = build/'source'
    source.mkdir(mode=0o700)
    for name, (body, mode) in files.items():
        path = source/name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(body)
        path.chmod(mode)
    builder = build/'venv'
    checked([str(executable), '-m', 'venv', str(builder)], 'create private PyYAML builder')
    python = builder/('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    prefix = [str(python), '-m', 'pip', '--isolated', '--disable-pip-version-check']
    report = build/'build-tools.json'
    checked([*prefix, 'install', '--dry-run', '--ignore-installed', '--only-binary=:all:', '--no-input',
             '--keyring-provider', 'disabled', '--retries', '0', '--timeout', '20',
             '--index-url', 'https://pypi.org/simple', '--report', str(report),
             'setuptools', 'Cython>=3.0', 'wheel'], 'resolve PyYAML binary build-tool closure')
    if report.stat().st_size > 2*1024*1024:
        raise ValueError('PyYAML build-tool report byte bound')
    rows = json.loads(report.read_text()).get('install')
    if type(rows) is not list or not 0 < len(rows) <= 512:
        raise ValueError('PyYAML build-tool graph bound')
    from .managed_environment import _wheel
    wheelhouse = build/'verified-build-tools'
    wheelhouse.mkdir(mode=0o700)
    lock, names, total, tools = [], set(), 0, []
    for row in rows:
        name, resolved, filename, sha, raw = _wheel(row, fetch)
        if name in names or (wheelhouse/filename).exists():
            raise ValueError('duplicate PyYAML build-tool identity')
        names.add(name)
        total += len(raw)
        if total > 512*1024*1024:
            raise ValueError('PyYAML build-tool batch byte bound')
        (wheelhouse/filename).write_bytes(raw)
        lock.append(f'{name}=={resolved} --hash=sha256:{sha}')
        tools.append(dict(name=name, version=resolved, sha256=sha))
    if not {'setuptools', 'cython', 'wheel'} <= names or not names <= {'setuptools', 'cython', 'wheel', 'packaging'}:
        raise ValueError('unsupported current PyYAML build-tool closure')
    requirements = build/'verified-build-tools.txt'
    requirements.write_text('\n'.join(lock)+'\n')
    checked([*prefix, 'install', '--no-index', '--find-links', str(wheelhouse), '--only-binary=:all:',
             '--require-hashes', '--no-input', '-r', str(requirements)], 'install verified PyYAML build tools offline')
    output = build/'wheels'
    output.mkdir(mode=0o700)
    # No pip resolution/build isolation during backend execution. These are the
    # publisher's explicit pure-build switches, not a forged wheel tag/metadata.
    previous = {key: environment.get(key) for key in ('PYYAML_FORCE_LIBYAML', 'PIP_NO_INDEX')}
    environment.update(PYYAML_FORCE_LIBYAML='0', PIP_NO_INDEX='1')
    try:
        checked([str(python), '-I', '-c', _BACKEND, str(source), str(output)], 'build verified PyYAML pure wheel offline')
    finally:
        for key, value in previous.items():
            if value is None:
                environment.pop(key, None)
            else:
                environment[key] = value
    wheels = list(output.iterdir())
    if len(wheels) != 1 or wheels[0].is_symlink() or not wheels[0].is_file() or wheels[0].stat().st_size > 128*1024*1024:
        raise ValueError('PyYAML build output is missing/ambiguous/unsafe')
    path = wheels[0]
    raw = path.read_bytes()
    _validate_wheel(raw, path.name, version)
    sha = hashlib.sha256(raw).hexdigest()
    checked([*prefix, 'install', '--no-index', '--no-deps', str(path)], 'install actual PyYAML build for runtime probe')
    probe = ("import json,yaml;assert yaml.__version__=="+repr(version)+";"
             "assert yaml.safe_load('owned: [true, 7]')=={'owned':[True,7]};"
             "assert not getattr(yaml,'__with_libyaml__',False);print(json.dumps({'pure':True,'safe_load':True}))")
    result = checked([str(python), '-I', '-c', probe], 'probe actual PyYAML pure wheel on managed runtime')
    if result.stdout.strip() != '{"pure": true, "safe_load": true}':
        raise ValueError('actual PyYAML pure runtime probe did not complete')
    info = path.stat()
    if path.read_bytes() != raw or info.st_nlink != 1:
        raise ValueError('PyYAML wheel changed during actual build probe')
    capability = _Completion()
    _issued[capability] = (nonce, path, version, sha, (info.st_dev, info.st_ino, info.st_size))
    # Observation only. This JSON is never read to authorize a local wheel.
    (build/'build-custody.json').write_text(json.dumps(dict(source=dict(url=target.url, version=version,
        sha256=target.sha256), build_tools=tools, wheel=dict(filename=path.name, sha256=sha),
        pure=True, actual_runtime_probe=True), sort_keys=True)+'\n')
    return capability


def location(capability, nonce):
    if type(capability) is not _Completion or capability not in _issued or _issued[capability][0] is not nonce:
        raise ValueError('PyYAML resolver location requires actual current build completion')
    return _issued[capability][1], _issued[capability][2]
