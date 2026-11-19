"""Closed historical source-data catalogue; never code/execution authority.

This admits one immutable issue170 publication member. It does not unpack files,
import archived code, read a database, load vectors, or follow bundled refs.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
import re
import zlib

from .project_ingestion import _git

PUBLICATION = 'b106b5cc5acc0dbbe4d3112446512a077cea546f'
PUBLICATION_TREE = '98967459bf7e8ae91603ebf249e7314b0320fa59'
PREFIX = 'engineering/benchmarks/issue170'
SOURCE_PATH = PREFIX + '/upstream-source.tar.gz'
SOURCE_BLOB = 'a36b572827d9f5150c929a6bf8c6a9c33ba71bea'
SOURCE_SHA256 = '20fb49f2c527aa592bc142f09771fa2a2ddcf621ba3554414d2059cca48347ae'
SOURCE_SIZE = 60865
MANIFEST_BLOB = '84db3e108ad543d5487d0e20aa62460d5fc09423'
MANIFEST_SHA256 = '7eceb5f6d3a5119b87bcc5f1eb0807ceeb9b5e1dc3981c4367791dac8c2faefa'
CATALOGUE_VERSION = 1


def _octal(raw):
    value = raw.strip(b'\0 ')
    if not re.fullmatch(rb'[0-7]{1,12}', value):
        raise ValueError('HISTORICAL_TAR_NUMBER')
    return int(value, 8)


def _text(raw):
    value, separator, tail = raw.partition(b'\0')
    if separator and any(tail):
        raise ValueError('HISTORICAL_TAR_TEXT')
    return value.decode('ascii', 'strict')


def source_members(raw: bytes) -> list[dict]:
    """Validate the entire bounded gzip/tar representation without extraction.

    Only the historical PAX mtime record, directories and ordinary source files
    are supported. Links, devices, sparse files, name overrides, extra gzip
    streams, nonzero trailer bytes and incomplete directory closure are refused.
    """
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= SOURCE_SIZE:
        raise ValueError('HISTORICAL_GZIP_BOUNDS')
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        body = decoder.decompress(raw, 266241)
    except zlib.error as error:
        raise ValueError('HISTORICAL_GZIP_FORMAT') from error
    if (not decoder.eof or decoder.unused_data or decoder.unconsumed_tail
            or len(body) != 266240):
        raise ValueError('HISTORICAL_GZIP_CLOSURE')
    rows, seen, pending, offset, total = [], set(), False, 0, 0
    while offset + 512 <= len(body):
        header = body[offset:offset + 512]
        if header == bytes(512):
            break
        if len(rows) >= 72 or header[257:265] != b'ustar\x0000' or any(header[500:512]):
            raise ValueError('HISTORICAL_TAR_HEADER')
        if _octal(header[148:156]) != sum(header[:148] + b' ' * 8 + header[156:]):
            raise ValueError('HISTORICAL_TAR_CHECKSUM')
        name, prefix = _text(header[:100]), _text(header[345:500])
        name = prefix + '/' + name if prefix else name
        size, mode = _octal(header[124:136]), _octal(header[100:108])
        kind = header[156:157]
        start, end = offset + 512, offset + 512 + size
        padded = start + ((size + 511) // 512) * 512
        if size > 65536 or padded > len(body) or any(body[end:padded]) or _text(header[157:257]):
            raise ValueError('HISTORICAL_TAR_MEMBER_BOUNDS')
        content = body[start:end]
        offset = padded
        if kind == b'x':
            # The original writer emitted one per-member mtime record. No PAX
            # path/link/size override is interpreted, even if tarfile would.
            if pending or name != '././@PaxHeader' or size > 64:
                raise ValueError('HISTORICAL_PAX_SCHEMA')
            match = re.fullmatch(rb'([1-9][0-9]?) mtime=[0-9]{1,12}(?:\.[0-9]{1,12})?\n', content)
            if match is None or int(match[1]) != size:
                raise ValueError('HISTORICAL_PAX_SCHEMA')
            pending = True
            continue
        if not pending or kind not in (b'0', b'5'):
            raise ValueError('HISTORICAL_TAR_TYPE')
        pending = False
        if kind == b'5':
            name = name.removesuffix('/')
            if size != 0:
                raise ValueError('HISTORICAL_TAR_DIRECTORY')
        if (not re.fullmatch(r'[A-Za-z0-9_.@/+~-]{1,240}', name)
                or any(part in ('', '.', '..') for part in name.split('/'))
                or not (name == 'itsdangerous-2.2.0' or name.startswith('itsdangerous-2.2.0/'))
                or name.casefold() in seen or mode & ~0o777):
            raise ValueError('HISTORICAL_TAR_PATH')
        seen.add(name.casefold())
        total += size
        rows.append({'path': name, 'kind': 'directory' if kind == b'5' else 'source_file',
                     'bytes': size, 'mode': format(mode, '04o'),
                     'sha256': hashlib.sha256(content).hexdigest()})
    if (pending or len(body) - offset < 1024 or any(body[offset:]) or len(rows) != 72
            or total != 135624 or sum(row['kind'] == 'directory' for row in rows) != 12):
        raise ValueError('HISTORICAL_TAR_CLOSURE')
    directories = {row['path'] for row in rows if row['kind'] == 'directory'}
    if any(str(parent) not in directories for row in rows
           for parent in PurePosixPath(row['path']).parents if str(parent) != '.'):
        raise ValueError('HISTORICAL_TAR_PARENT_CLOSURE')
    return sorted(rows, key=lambda row: row['path'])


def _entry(root, ref, path):
    rows = _git(root, 'ls-tree', '-z', ref, '--', path).stdout.split(b'\0')
    if rows == [b'']:
        return None
    if len(rows) != 2 or rows[1] or rows[0].split(b'\t', 1)[1] != path.encode():
        raise ValueError('HISTORICAL_GIT_INVENTORY')
    return rows[0].split(b'\t', 1)[0].split()


def issue170_source(root, ref: str) -> dict | None:
    """Catalogue only exact committed original evidence with original ancestry.

    A whole-publication tree pin preserves provenance documents, original
    checksums and the four binary artifacts. No working file or caller-supplied
    manifest can substitute for the immutable Git blobs.
    """
    archive = _entry(root, ref, SOURCE_PATH)
    if archive is None:
        return None
    _git(root, 'merge-base', '--is-ancestor', PUBLICATION, ref)
    tree = _entry(root, ref, PREFIX)
    if (tree != [b'040000', b'tree', PUBLICATION_TREE.encode()]
            or _entry(root, PUBLICATION, PREFIX) != tree
            or archive != [b'100644', b'blob', SOURCE_BLOB.encode()]
            or _entry(root, ref, PREFIX + '/SHA256SUMS.json') != [b'100644', b'blob', MANIFEST_BLOB.encode()]):
        raise ValueError('HISTORICAL_PUBLICATION_IDENTITY')
    for oid, size in ((SOURCE_BLOB, SOURCE_SIZE), (MANIFEST_BLOB, 12201)):
        if _git(root, 'cat-file', '-s', oid).stdout.strip() != str(size).encode():
            raise ValueError('HISTORICAL_GIT_BOUNDS')
    raw = _git(root, 'cat-file', 'blob', SOURCE_BLOB).stdout
    manifest = _git(root, 'cat-file', 'blob', MANIFEST_BLOB).stdout
    if (len(raw) != SOURCE_SIZE or hashlib.sha256(raw).hexdigest() != SOURCE_SHA256
            or len(manifest) != 12201 or hashlib.sha256(manifest).hexdigest() != MANIFEST_SHA256
            or json.loads(manifest).get('upstream-source.tar.gz') != SOURCE_SHA256):
        raise ValueError('HISTORICAL_PUBLICATION_DIGEST')
    members = source_members(raw)
    return {'path': SOURCE_PATH, 'classification': 'historical_source_data',
            'publication_commit': PUBLICATION, 'publication_tree': PUBLICATION_TREE,
            'git_blob': SOURCE_BLOB, 'sha256': SOURCE_SHA256, 'bytes': SOURCE_SIZE, 'mode': '100644',
            'manifest_git_blob': MANIFEST_BLOB, 'manifest_sha256': MANIFEST_SHA256,
            'format': 'bounded-pax-mtime-gzip-tar', 'members': members,
            'execution_authority': False, 'archive_extracted': False}
