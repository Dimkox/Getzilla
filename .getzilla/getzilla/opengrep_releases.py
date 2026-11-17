"""OpenGrep release activation and independent upstream revalidation (#39)."""
from __future__ import annotations

import io
import json
import re
import stat
import zipfile
from pathlib import Path

from .latest_releases import github_asset, github_release, metadata, stable
from .managed_runtime import directory

MAX_ARTIFACT_BYTES = 512 * 1024 * 1024


def resolve(fetch, key):
    release = github_release('opengrep/opengrep', fetch)
    return _asset(release, key)


def _asset(release, key):
    system, arch = key
    arch = {'amd64': 'x86_64', 'x64': 'x86_64', 'arm64': 'aarch64'}.get(arch, arch)
    names = {('linux', 'x86_64'): 'opengrep_linux_x86', ('linux', 'aarch64'): 'opengrep_linux_aarch64',
             ('darwin', 'x86_64'): 'opengrep_osx_x86', ('darwin', 'aarch64'): 'opengrep_osx_arm64',
             ('windows', 'x86_64'): 'opengrep_windows_x86.zip'}
    if int(release['version'].split('.')[0]) < 2:
        raise ValueError('current stable OpenGrep uses an unsupported pre-2.x layout')
    if (system, arch) not in names:
        raise ValueError(f'current OpenGrep has no native {system}/{arch} adapter; no implicit emulation')
    return github_asset(release, names[system, arch], component='opengrep')


def members(target, data):
    target.verify(data)
    if not target.filename.endswith('.zip'):
        return {'opengrep': data}
    files, total = {}, 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        if not 1 <= len(archive.infolist()) <= 1024:
            raise ValueError('OpenGrep archive member bound')
        for item in archive.infolist():
            mode = item.external_attr >> 16
            name = item.filename
            if (item.orig_filename != name or not re.fullmatch(r'[A-Za-z0-9_.-]+', name)
                    or name in {'.', '..'} or name.lower() in {n.lower() for n in files}
                    or stat.S_IFMT(mode) not in (0, stat.S_IFREG) or item.flag_bits & 1
                    or item.file_size > MAX_ARTIFACT_BYTES):
                raise ValueError('unsafe OpenGrep archive entry')
            total += item.file_size
            if total > MAX_ARTIFACT_BYTES:
                raise ValueError('OpenGrep unpacked byte bound')
            files[name] = archive.read(item)
    if 'opengrep.exe' not in files or any(not (n == 'opengrep.exe' or n.lower().endswith('.dll')) for n in files):
        raise ValueError('unsupported OpenGrep Windows ZIP layout; exe and DLLs must stay together')
    return files


def verify_active(executable: Path, *, fetch, key):
    """No JSON receipt grants trust: fresh official digest and exact archive bytes do."""
    target = resolve(fetch, key)
    data = fetch(target.url)
    expected = members(target, data)
    binary = 'opengrep.exe' if target.filename.endswith('.zip') else 'opengrep'
    if executable.is_symlink() or not executable.is_file():
        raise ValueError('OpenGrep executable is missing or linked')
    for name, body in expected.items():
        path = executable if name == binary else executable.parent / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size != len(body) or path.read_bytes() != body:
            raise ValueError(f'OpenGrep {target.version}: active {name} differs from verified official artifact')
    return target


def install(fetch, root, key, *, run):
    from .updater import Result, _replace_bytes, _sha256_file, OPENGREP_ASSETS
    target = resolve(fetch, key)
    data = fetch(target.url)
    expected = members(target, data)
    folder = root / 'bin'
    directory(folder)
    hint = root/'opengrep-current-version.json'
    previous = {}
    if hint.exists():
        if hint.is_symlink() or hint.stat().st_size > 1024:
            raise ValueError('invalid OpenGrep version hint')
        saved = json.loads(hint.read_bytes())
        version = saved.get('version') if type(saved) is dict else None
        if not stable(version):
            raise ValueError('invalid OpenGrep previous version identity')
        if version != target.version:
            url = 'https://api.github.com/repos/opengrep/opengrep/releases/tags/v'+version
            release = metadata(fetch, url)
            if release.get('tag_name') != 'v'+version or release.get('draft') is not False or release.get('prerelease') is not False:
                raise ValueError('previous OpenGrep release is not official stable data')
            release.update(version=version, repository='opengrep/opengrep', metadata_url=url, metadata_sha256='')
            old = _asset(release, key)
            previous = members(old, fetch(old.url))
    # A writable version hint only selects an independent official lookup. It
    # never supplies expected hashes or authorizes arbitrary executable bytes.
    legacy = {digest for _name, digest in OPENGREP_ASSETS.values()}
    snapshots = {}
    for name in set(expected) | set(previous):
        path = folder/name
        if path.is_symlink() or path.exists() and not path.is_file():
            raise ValueError(f'user path conflict: {path}')
        body = path.read_bytes() if path.exists() else None
        snapshots[name] = body
        if body is not None and body != expected.get(name) and body != previous.get(name) and _sha256_file(path) not in legacy:
            raise ValueError(f'user/previous-version conflict: {path}; upstream bytes are unproved')
    for name, body in expected.items():
        path = folder / name
        if not path.exists() or path.read_bytes() != body:
            _replace_bytes(path, body, mode=0o755 if name.startswith('opengrep') else 0o644)
    executable = folder / ('opengrep.exe' if target.filename.endswith('.zip') else 'opengrep')
    checked = run([str(executable), '--version'], None)
    text = ((checked.stdout or '')+'\n'+(checked.stderr or '')).strip()
    if checked.returncode != 0 or not re.search(r'(?<![\w.])'+re.escape(target.version)+r'(?![\w.])', text):
        raise ValueError(f'OpenGrep target={target.version} path={executable}: actual version probe failed')
    for name, body in expected.items():
        if (folder / name).read_bytes() != body:
            raise ValueError('OpenGrep changed after activation')
    for name in set(previous)-set(expected):
        if snapshots[name] is None:
            continue
        path = folder/name
        if path.read_bytes() != snapshots[name]:
            raise ValueError('OpenGrep previous file changed before removal')
        path.unlink()
    _replace_bytes(hint, json.dumps({'version': target.version}).encode(), mode=0o600)
    return [Result('tool:opengrep', 'ok', f'target={target.version}; actual={target.version}; path={executable}; '
                   f'official SHA256 verified; {len(expected)} active files; fresh metadata {target.metadata_sha256}')]
