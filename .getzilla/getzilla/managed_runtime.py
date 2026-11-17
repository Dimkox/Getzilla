"""Stage verified public runtime archives; never replace a user's existing tree."""
from __future__ import annotations

import io
import os
import posixpath
import re
import shutil
import stat
import tarfile
import tempfile
import zipfile
from pathlib import Path

from .latest_releases import Target

MAX_FILES = 16384
MAX_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 128 * 1024 * 1024


def entries(target: Target, data: bytes):
    target.verify(data)
    files, links, total = {}, {}, 0

    def add(name, body, mode):
        nonlocal total
        if (not name or name.startswith('/') or '\\' in name or ':' in name
                or any(p in ('', '.', '..') for p in name.split('/'))
                or name.casefold() in {p.casefold() for p in [*files, *links]}):
            raise ValueError('unsafe/duplicate runtime archive path')
        total += len(body)
        if len(body) > MAX_FILE_BYTES or total > MAX_BYTES or len(files)+len(links) >= MAX_FILES:
            raise ValueError('runtime archive exceeds finite bounds')
        files[name] = (body, mode)

    if target.filename.endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if len(archive.infolist()) > MAX_FILES:
                raise ValueError('runtime member count exceeds bound')
            for item in archive.infolist():
                if item.orig_filename != item.filename or item.flag_bits & 1 or item.file_size > MAX_FILE_BYTES:
                    raise ValueError('unsafe runtime ZIP entry')
                if item.is_dir():
                    continue
                mode = item.external_attr >> 16
                if stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                    raise ValueError('linked or special runtime ZIP entry')
                add(item.filename, archive.read(item), 0o755 if mode & 0o111 or item.filename.endswith('.exe') else 0o644)
    elif target.filename.endswith(('.tar.gz', '.tgz', '.tar.xz')):
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as archive:
            for i, item in enumerate(archive):
                if i >= MAX_FILES or item.size > MAX_FILE_BYTES:
                    raise ValueError('runtime archive exceeds finite bounds')
                if item.isdir():
                    continue
                if item.issym():
                    name = item.name
                    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), item.linkname))
                    if (os.name == 'nt' or name in files or name in links or item.linkname.startswith('/')
                            or resolved.startswith('../') or '\\' in item.linkname):
                        raise ValueError('unsafe runtime symlink')
                    links[name] = item.linkname
                elif item.isfile():
                    stream = archive.extractfile(item)
                    if stream is None:
                        raise ValueError('truncated runtime archive')
                    with stream:
                        add(item.name, stream.read(MAX_FILE_BYTES+1), 0o755 if item.mode & 0o111 else 0o644)
                else:
                    raise ValueError('special runtime archive entry')
    else:
        raise ValueError('unsupported current runtime archive format')
    # Node's tarballs/ZIPs contain one version-named outer directory.
    roots = {p.split('/')[0] for p in [*files, *links]}
    if len(roots) == 1 and files and all('/' in p for p in [*files, *links]):
        files = {p.split('/', 1)[1]: body for p, body in files.items()}
        links = {p.split('/', 1)[1]: body for p, body in links.items()}
    for name, link in links.items():
        if any(p in ('', '.', '..') for p in name.split('/')):
            raise ValueError('unsafe runtime symlink name')
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), link))
        if resolved not in files:
            raise ValueError('runtime symlink target is not a closed regular member')
    if not files:
        raise ValueError('empty runtime archive')
    return files, links


def _validate(folder: Path, files, links):
    for name, (body, mode) in files.items():
        path = folder / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size != len(body) or path.read_bytes() != body:
            raise ValueError(f'user/runtime conflict: {path}')
        if os.name != 'nt' and stat.S_IMODE(path.stat().st_mode) != mode:
            raise ValueError(f'runtime mode conflict: {path}')
    for name, link in links.items():
        path = folder / name
        if not path.is_symlink() or os.readlink(path) != link:
            raise ValueError(f'runtime link conflict: {path}')
    found = {p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file() or p.is_symlink()}
    if found != set(files) | set(links):
        raise ValueError('unmanaged runtime files conflict')


def install(target: Target, data: bytes, root: Path, *, executable: str, run, version_args=('--version',)) -> Path:
    from .toolchain import parse_tool_version
    if not re.fullmatch('[a-z][a-z0-9-]*', target.component) or not re.fullmatch(r'[A-Za-z0-9_.-]+', target.version):
        raise ValueError('unsafe runtime target identity')
    files, links = entries(target, data)
    if executable not in files:
        raise ValueError(f'{target.component} {target.version}: executable absent from current archive')
    parent = root / 'runtimes' / target.component
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    for path in (root, root/'runtimes', parent):
        if path.is_symlink() or not path.is_dir():
            raise ValueError('linked managed runtime root')
    folder = parent / (target.version+'-'+(target.sha256 or '')[:16])
    if folder.is_symlink():
        raise ValueError('linked managed runtime conflict')
    if folder.exists():
        _validate(folder, files, links)
    else:
        stage = Path(tempfile.mkdtemp(prefix='.staging-', dir=parent))
        try:
            for name, (body, mode) in files.items():
                path = stage/name
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                path.write_bytes(body)
                path.chmod(mode)
            for name, link in links.items():
                path = stage/name
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                path.symlink_to(link)
            _validate(stage, files, links)
            if folder.exists():
                raise ValueError('managed runtime publication conflict')
            stage.rename(folder)
        finally:
            if stage.exists():
                shutil.rmtree(stage)
    path = folder/executable
    result = run([str(path), *version_args], None)
    actual = parse_tool_version('python3' if target.component == 'python' else target.component,
                                (result.stdout or '')+'\n'+(result.stderr or ''))
    if result.returncode or actual != target.version:
        raise ValueError(f'{target.component} target={target.version} path={path}: probe actual={actual} exit={result.returncode}')
    _validate(folder, files, links)
    return path
