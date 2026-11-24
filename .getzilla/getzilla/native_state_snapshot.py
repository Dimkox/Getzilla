"""Bounded same-file snapshots for closed private native state paths.

Checksums bind bytes only. This is not an authority or an atomic leaf CAS.
No operation in this module replaces, truncates or unlinks a pathname.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import stat

from . import fsx

HEADER = b'\nGETZILLA_STATE_SNAPSHOT_V1\n'
MAX_FRAMES = 64
MAX_BYTES = 1_048_576


def metadata_limit(relative):
    text = os.fspath(relative)
    if text == '.getzilla/runtime/active-route.json':
        return MAX_BYTES
    if text == '.getzilla/runtime/active-change.json':
        return 4096
    if re.fullmatch(r'\.getzilla/runtime/routes/[0-9a-f]{12}\.json',text):
        return MAX_BYTES
    if re.fullmatch(r'\.getzilla/runtime/sessions/[A-Za-z0-9._-]{1,128}\.json',text):
        return 4096
    return None


def _fail():
    raise ValueError('native_state_snapshot_invalid')


def _pairs(items):
    value = {}
    for key,item in items:
        if key in value:
            _fail()
        value[key] = item
    return value


def _object(raw):
    try:
        def finite(value):
            number = float(value)
            if not math.isfinite(number):
                _fail()
            return number
        value = json.loads(raw.decode('utf-8'),object_pairs_hook=_pairs,
                           parse_constant=lambda _value: _fail(),parse_float=finite)
        if type(value) is not dict:
            _fail()
        return value
    except (ValueError,UnicodeError,RecursionError) as exc:
        raise ValueError('native_state_snapshot_invalid') from exc


def _bytes(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n'


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _scan(raw,limit):
    if type(raw) is not bytes or type(limit) is not int or not 0 < limit <= MAX_BYTES:
        _fail()
    if len(raw) > limit:
        raise ValueError('native_state_snapshot_limit')
    initial,marker,tail = raw.partition(HEADER)
    _object(initial)
    if not marker:
        return raw,0
    if not tail or not tail.endswith(b'\n'):
        _fail()
    lines = tail.splitlines(keepends=True)
    if len(lines) % 2 or len(lines)//2 > MAX_FRAMES:
        _fail()
    prefix,logical,sequence = initial+HEADER,initial,0
    for offset in range(0,len(lines),2):
        frame_raw,commit_raw = lines[offset:offset+2]
        frame,commit = _object(frame_raw),_object(commit_raw)
        sequence += 1
        if (set(frame) != {'snapshot_version','sequence','previous_sha256','payload_base64'}
                or type(frame['snapshot_version']) is not int or frame['snapshot_version'] != 1
                or type(frame['sequence']) is not int or frame['sequence'] != sequence
                or frame['previous_sha256'] != _digest(prefix)
                or type(frame['payload_base64']) is not str
                or set(commit) != {'snapshot_commit_version','sequence','frame_sha256'}
                or type(commit['snapshot_commit_version']) is not int or commit['snapshot_commit_version'] != 1
                or type(commit['sequence']) is not int or commit['sequence'] != sequence
                or commit['frame_sha256'] != _digest(frame_raw)):
            _fail()
        try:
            logical = base64.b64decode(frame['payload_base64'],validate=True)
        except (ValueError,UnicodeError) as exc:
            raise ValueError('native_state_snapshot_invalid') from exc
        _object(logical)
        prefix += frame_raw+commit_raw
    return logical,sequence


def decode(raw,*,limit=MAX_BYTES):
    return _scan(raw,limit)[0]


def extend(previous,logical,*,limit):
    _old,sequence = _scan(previous,limit)
    _object(logical)
    if sequence >= MAX_FRAMES:
        raise ValueError('native_state_snapshot_limit')
    prefix = previous if sequence else previous+HEADER
    frame = _bytes({'snapshot_version':1,'sequence':sequence+1,'previous_sha256':_digest(prefix),
                    'payload_base64':base64.b64encode(logical).decode('ascii')})
    commit = _bytes({'snapshot_commit_version':1,'sequence':sequence+1,'frame_sha256':_digest(frame)})
    complete = prefix+frame+commit
    if len(complete) > limit:
        raise ValueError('native_state_snapshot_limit')
    return complete


def _identity(info):
    return (info.st_dev,info.st_ino,info.st_uid,info.st_mode,info.st_nlink)


def _content_identity(info):
    return (*_identity(info),info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def write(directory,name,logical,*,limit,check,framed_only=False,charge=lambda **_kwargs:None):
    """Append to an admitted object; False means an ordinary unframed file.

    Callers retain their existing task/route locks and directory custody.
    A partial append stays unavailable, with all earlier bytes retained.
    """
    if type(logical) is not bytes or len(logical) > limit:
        raise ValueError('native_state_snapshot_limit')
    _object(logical)
    check()
    try:
        expected = fsx.lstat_at(directory,name)
    except FileNotFoundError:
        if framed_only:
            return False
        expected = None
    flags = os.O_RDWR | os.O_APPEND | fsx.O_NOFOLLOW | fsx.O_NONBLOCK | fsx.O_CLOEXEC
    if expected is None:
        flags |= os.O_CREAT | os.O_EXCL
    descriptor = fsx.open_at(directory,name,flags,0o600)
    locked = False
    try:
        before = os.fstat(descriptor)
        identity = _identity(before)
        private_required = not framed_only
        def custody():
            check()
            opened,named = os.fstat(descriptor),fsx.lstat_at(directory,name)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.geteuid()
                    or stat.S_IMODE(opened.st_mode) not in ({0o600} if private_required else {0o600,0o644})
                    or opened.st_nlink != 1
                    or _identity(opened) != identity or _identity(named) != identity
                    or opened.st_size > limit):
                raise ValueError('native_state_snapshot_changed')
        custody()
        if expected is not None and (identity != _identity(expected)
                or (before.st_size,before.st_mtime_ns,before.st_ctime_ns) !=
                   (expected.st_size,expected.st_mtime_ns,expected.st_ctime_ns)):
            raise ValueError('native_state_snapshot_changed')
        fsx.lock_file(descriptor,exclusive=True,blocking=False)
        locked = True
        def read_all():
            os.lseek(descriptor,0,os.SEEK_SET)
            expected_read = _content_identity(os.fstat(descriptor))
            def stable():
                custody()
                if _content_identity(os.fstat(descriptor)) != expected_read:
                    raise ValueError('native_state_snapshot_changed')
            chunks,total = [],0
            while True:
                stable()
                chunk = os.read(descriptor,min(65536,limit+1-total))
                charge(size=len(chunk))
                stable()
                if not chunk:
                    if total != expected_read[-3]:
                        raise ValueError('native_state_snapshot_changed')
                    return b''.join(chunks)
                total += len(chunk)
                if total > limit:
                    raise ValueError('native_state_snapshot_limit')
                chunks.append(chunk)
        previous = read_all()
        selected_content = _content_identity(os.fstat(descriptor))
        if framed_only and HEADER not in previous:
            # The ordinary compatibility probe returns no contents. A damaged
            # frame or malformed legacy document must not be overwritten.
            decode(previous,limit=limit)
            return False
        private_required = True
        custody()
        if expected is None:
            complete = logical
        else:
            current = decode(previous,limit=limit)
            # Reconcile the same exact logical bytes without spending bounded
            # history on unchanged session/package discovery projections.
            complete = previous if current == logical else extend(previous,logical,limit=limit)
        pending = complete[len(previous):]
        custody()
        if _content_identity(os.fstat(descriptor)) != selected_content:
            raise ValueError('native_state_snapshot_changed')
        # For an existing file, only the final closed commit line is delayed
        # until the prepared snapshot is durable. A new file is plain JSON.
        split = pending.rfind(b'\n',0,-1)+1 if expected is not None else len(pending)
        def write_all(raw):
            view = memoryview(raw)
            while view:
                custody()
                count = os.write(descriptor,view)
                if type(count) is not int or not 0 < count <= len(view):
                    raise OSError('native_state_snapshot_write')
                charge(size=count)
                view = view[count:]
        write_all(pending[:split])
        os.fsync(descriptor)
        custody()
        write_all(pending[split:])
        os.fsync(descriptor)
        fsx.fsync_dir(directory)
        custody()
        if read_all() != complete:
            raise ValueError('native_state_snapshot_changed')
        return True
    finally:
        try:
            if locked:
                fsx.unlock_file(descriptor)
        finally:
            os.close(descriptor)
