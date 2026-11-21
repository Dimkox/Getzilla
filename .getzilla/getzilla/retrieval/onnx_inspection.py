"""Inert, bounded ONNX v1.19.1 wire metadata observations, never model admission.

Schema: https://raw.githubusercontent.com/onnx/onnx/v1.19.1/onnx/onnx.proto
No ONNX/protobuf/native imports, deserialization hooks, network or execution.
Tensor bodies are opaque spans. External hashes require a separate current
streaming verification; stat custody here does not verify those bytes.
"""
from collections import Counter
from contextlib import ExitStack, contextmanager
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time

from .. import fsx

MAX_GRAPH_BYTES = 128 * 1024 * 1024
MAX_METADATA_BYTES = 8 * 1024 * 1024
MAX_FIELDS = 500000
MAX_NODES = MAX_TENSORS = MAX_EXTERNAL_REFERENCES = 100000
MAX_DEPTH = 16
MAX_STRING_BYTES = 4096
MAX_EXTERNAL_FILES = 2
MAX_EXTERNAL_BYTES = 3000000000
TIMEOUT_SECONDS = 30
_BLOCK = 65536
_MAX_INTEGER = (1 << 63) - 1
_SHA = re.compile(r'[0-9a-f]{64}\Z')
_PATH = re.compile(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\Z')


class OnnxInspectionError(ValueError):
    """Refusal; optional locations describe only a completed known wire walk."""

    def __init__(self, reason):
        super().__init__(reason)
        self.diagnostics = None


# Only these v1.19.1 field numbers and wire kinds are understood. A future or
# multi-device field refuses instead of silently hiding a new recursive edge.
_SCHEMAS = {
    'Model': {1: 'u', 2: 's', 3: 's', 4: 's', 5: 'u', 6: 's', 7: 'Graph',
              8: 'Opset', 14: 'Entry', 20: 'Training', 25: 'Function'},
    'Graph': {1: 'Node', 2: 's', 5: 'Tensor', 10: 's', 11: 'Value', 12: 'Value',
              13: 'Value', 14: 'Annotation', 15: 'Sparse', 16: 'Entry'},
    'Node': {1: 's', 2: 's', 3: 's', 4: 's', 5: 'Attribute', 6: 's', 7: 's', 8: 's', 9: 'Entry'},
    'Attribute': {1: 's', 2: 'f32', 3: 'u', 4: 'bytes', 5: 'Tensor', 6: 'Graph',
                  7: 'floats', 8: 'ints', 9: 'bytes', 10: 'Tensor', 11: 'Graph',
                  13: 's', 14: 'Type', 15: 'Type', 20: 'u', 21: 's', 22: 'Sparse', 23: 'Sparse'},
    'Tensor': {1: 'dims', 2: 'u', 3: 'Segment', 4: 'floats', 5: 'ints', 6: 'raw',
               7: 'ints', 8: 's', 9: 'raw', 10: 'doubles', 11: 'ints', 12: 's', 13: 'Entry', 14: 'u', 16: 'Entry'},
    'Sparse': {1: 'Tensor', 2: 'Tensor', 3: 'dims'},
    'Training': {1: 'Graph', 2: 'Graph', 3: 'Entry', 4: 'Entry'},
    'Function': {1: 's', 4: 's', 5: 's', 6: 's', 7: 'Node', 8: 's', 9: 'Opset',
                 10: 's', 11: 'Attribute', 12: 'Value', 13: 's', 14: 'Entry'},
    'Opset': {1: 's', 2: 'u'},
    'Entry': {1: 's', 2: 's'},
    'Value': {1: 's', 2: 'Type', 3: 's', 4: 'Entry'},
    'Type': {1: 'TensorType', 4: 'SequenceType', 5: 'MapType', 6: 's', 8: 'SequenceType', 9: 'TensorType'},
    'TensorType': {1: 'u', 2: 'Shape'},
    'SequenceType': {1: 'Type'},
    'MapType': {1: 'u', 2: 'Type'},
    'Shape': {1: 'Dimension'},
    'Dimension': {1: 'u', 2: 's', 3: 's'},
    'Segment': {1: 'u', 2: 'u'},
    'Annotation': {1: 's', 2: 'Entry'},
}
_REPEATED = {
    'Model': {8, 14, 20, 25}, 'Graph': {1, 5, 11, 12, 13, 14, 15, 16},
    'Node': {1, 2, 5, 9}, 'Attribute': {7, 8, 9, 10, 11, 15, 23},
    'Tensor': {1, 4, 5, 6, 7, 10, 11, 13, 16}, 'Sparse': {3},
    'Training': {3, 4}, 'Function': {4, 5, 6, 7, 9, 11, 12, 14},
    'Value': {4}, 'Shape': {1}, 'Annotation': {2},
}
_METADATA_FIELDS = {'Model': 14, 'Graph': 16, 'Node': 9, 'Tensor': 16, 'Function': 14, 'Value': 4}
_BITS = {1: 32, 2: 8, 3: 8, 4: 16, 5: 16, 6: 32, 7: 64, 9: 8, 10: 16,
         11: 64, 12: 32, 13: 64, 14: 64, 15: 128, 16: 16, 17: 8, 18: 8,
         19: 8, 20: 8, 21: 4, 22: 4, 23: 4, 24: 8}


def _fail(reason):
    raise OnnxInspectionError(reason)


def _relative(value):
    if (type(value) is not str or not value or len(value) > MAX_STRING_BYTES
            or not _PATH.fullmatch(value) or len(value.split('/')) > MAX_DEPTH
            or any(part in {'.', '..'} for part in value.split('/'))):
        _fail('unsafe artifact path')
    return value


def _pin(size, digest, limit):
    if type(size) is not int or not 0 < size <= limit or type(digest) is not str or not _SHA.fullmatch(digest):
        _fail('invalid artifact pin or size bound')


def _identity(info):
    return tuple(getattr(info, name) for name in
                 ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_uid', 'st_gid', 'st_nlink'))


def _owned(info, *, directory=False):
    if (not hasattr(os, 'geteuid') or info.st_uid != os.geteuid() or info.st_mode & 0o022
            or (not stat.S_ISDIR(info.st_mode) if directory else
                not stat.S_ISREG(info.st_mode) or info.st_nlink != 1)):
        _fail('foreign or mutable artifact custody')


@contextmanager
def _held(anchor, relative, expected_bytes):
    with ExitStack() as parents:
        directories = [(anchor.handle, anchor.check)]
        parts = PurePosixPath(relative).parts
        for index in range(1, len(parts)-1):
            path = '/'.join(parts[:index]) + '/__custody_check__'
            handle, _, current = parents.enter_context(anchor.parent(path))
            directories.append((handle, current))
        parent, name, check = parents.enter_context(anchor.parent(relative))
        directories.append((parent, check))
        def ancestry():
            for handle, current in directories:
                current()
                _owned(fsx.fstat_dir(handle), directory=True)
        ancestry()
        before = fsx.lstat_at(parent, name)
        _owned(before)
        if fsx.is_link(before) or before.st_size != expected_bytes:
            _fail('artifact size or link mismatch')
        descriptor = fsx.open_at(parent, name, os.O_RDONLY | fsx.O_NOFOLLOW | fsx.O_NONBLOCK | fsx.O_CLOEXEC)
        try:
            observed = _identity(before)
            def current():
                ancestry()
                if (_identity(os.fstat(descriptor)) != observed
                        or _identity(fsx.lstat_at(parent, name)) != observed):
                    _fail('artifact custody changed')
            current()
            yield descriptor, current
            current()
        finally:
            os.close(descriptor)


class _Wire:
    def __init__(self, descriptor, size, external, deadline):
        self.descriptor, self.size, self.external, self.deadline = descriptor, size, external, deadline
        self.counts = {'fields': 0, 'nodes': 0, 'tensors': 0, 'graphs': 0, 'metadata_bytes': 0,
                       'external_references': 0, 'maximum_depth': 0, 'parser_read_bytes': 0}
        self.cache_start, self.cache = -1, b''
        self.operators, self.opsets = Counter(), set()
        self.references, self.unsupported = [], set()

    def current(self):
        if time.monotonic() >= self.deadline:
            _fail('metadata deadline exceeded')

    def count(self, name, amount, limit):
        self.counts[name] += amount
        if self.counts[name] > limit:
            _fail(name + ' bound exceeded')

    def read(self, offset, length, *, charge=True):
        self.current()
        if offset < 0 or length < 0 or offset + length > self.size:
            _fail('truncated wire field')
        if charge:
            self.count('metadata_bytes', length, MAX_METADATA_BYTES)
        if not length:
            return b''
        start = offset // _BLOCK * _BLOCK
        if self.cache_start != start or offset + length > start + len(self.cache):
            os.lseek(self.descriptor, start, os.SEEK_SET)
            self.cache_start = start
            self.cache = os.read(self.descriptor, min(self.size - start, _BLOCK + MAX_STRING_BYTES))
            self.count('parser_read_bytes', len(self.cache), MAX_GRAPH_BYTES * 2)
        result = self.cache[offset-start:offset-start+length]
        if len(result) != length:
            _fail('truncated wire field')
        return result

    def varint(self, offset, end):
        value, shift, begin = 0, 0, offset
        while offset < end and offset - begin < 10:
            byte = self.read(offset, 1)[0]
            offset += 1
            if shift == 63 and byte > 1:
                _fail('varint overflow')
            value |= (byte & 127) << shift
            if byte < 128:
                if offset - begin > 1 and byte == 0:
                    _fail('noncanonical varint')
                return value, offset
            shift += 7
        _fail('truncated or oversized varint')

    def fields(self, start, end):
        position = start
        while position < end:
            self.current()
            self.count('fields', 1, MAX_FIELDS)
            tag, position = self.varint(position, end)
            number, wire = tag >> 3, tag & 7
            if not 0 < number < (1 << 29) or wire not in {0, 1, 2, 5}:
                _fail('unsupported wire tag')
            if wire == 0:
                value, position = self.varint(position, end)
                yield number, wire, value
            elif wire == 2:
                length, position = self.varint(position, end)
                if length > end - position:
                    _fail('truncated length-delimited field')
                yield number, wire, (position, position + length)
                position += length
            else:
                length = 8 if wire == 1 else 4
                if length > end-position:
                    _fail('truncated fixed-width field')
                yield number, wire, (position, position + length)
                position += length

    def value(self, kind, wire, value, depth):
        if kind == 'u':
            if wire != 0:
                _fail('wrong integer wire type')
            return value
        if kind in {'ints', 'dims'}:
            if wire == 0:
                values = [value]
            elif wire == 2:
                values, position = [], value[0]
                if kind == 'ints':
                    return value  # Tensor/attribute numeric payload is opaque, never executed.
                while position < value[1]:
                    item, position = self.varint(position, value[1])
                    values.append(item)
                    if len(values) > 64:
                        _fail('tensor rank bound exceeded')
            else:
                _fail('wrong packed integer wire type')
            return values if kind == 'dims' else value
        if kind in {'floats', 'doubles', 'f32'}:
            scalar_wire, width = (1, 8) if kind == 'doubles' else (5, 4)
            if wire != scalar_wire and not (wire == 2 and kind != 'f32' and (value[1]-value[0]) % width == 0):
                _fail('wrong floating-point wire type')
            return value
        if wire != 2:
            _fail('wrong message or string wire type')
        if kind in {'s', 'bytes', 'raw'}:
            start, end = value
            if kind == 'raw':
                return {'offset': start, 'length': end-start}
            if end-start > MAX_STRING_BYTES:
                _fail('string bound exceeded')
            raw = self.read(start, end-start)
            if kind == 'bytes':
                return raw
            try:
                text = raw.decode('utf-8')
            except UnicodeError as exc:
                raise OnnxInspectionError('invalid UTF-8 metadata') from exc
            if '\0' in text:
                _fail('NUL in metadata string')
            return text
        return self.message(kind, value[0], value[1], depth+1)

    def message(self, kind, start, end, depth):
        if depth > MAX_DEPTH:
            _fail('message depth bound exceeded')
        self.counts['maximum_depth'] = max(self.counts['maximum_depth'], depth)
        if kind == 'Node':
            self.count('nodes', 1, MAX_NODES)
        if kind == 'Tensor':
            self.count('tensors', 1, MAX_TENSORS)
        if kind == 'Graph':
            self.count('graphs', 1, MAX_FIELDS)
        values = {}
        repeated = _REPEATED.get(kind, set())
        for number, wire, raw in self.fields(start, end):
            field_kind = _SCHEMAS[kind].get(number)
            if field_kind is None:
                _fail('unsupported ' + kind + ' field ' + str(number))
            if number in values and number not in repeated:
                _fail('duplicate singular ' + kind + ' field')
            value = self.value(field_kind, wire, raw, depth)
            if number in repeated:
                values.setdefault(number, []).extend(value if field_kind == 'dims' else [value])
            else:
                values[number] = value
        metadata = _METADATA_FIELDS.get(kind)
        if metadata is not None:
            self.unique_entries(values.get(metadata, []))
        return self.finish(kind, values)

    @staticmethod
    def unique_entries(entries):
        result = {}
        for key, value in entries:
            if key in result:
                _fail('duplicate metadata key')
            result[key] = value
        return result

    def finish(self, kind, values):
        if kind == 'Entry':
            if set(values) != {1, 2} or not values[1]:
                _fail('incomplete metadata entry')
            return values[1], values[2]
        if kind == 'Opset':
            if not 0 < values.get(2, 0) <= _MAX_INTEGER:
                _fail('missing or invalid opset version')
            row = values.get(1, ''), values[2]
            self.opsets.add(row)
            if row[0] not in {'', 'ai.onnx'}:
                self.unsupported.add('custom_operator_domains')
            return row
        if kind == 'Node':
            if not values.get(4):
                _fail('missing operator type')
            domain = values.get(7, '')
            self.operators[domain, values[4]] += 1
            if domain not in {'', 'ai.onnx'}:
                self.unsupported.add('custom_operator_domains')
            if values.get(8):
                self.unsupported.add('operator_overloads')
            return None
        if kind == 'Tensor':
            return self.tensor(values)
        if kind == 'Graph':
            names = [value['name'] for value in values.get(5, []) + values.get(15, [])]
            if any(not name for name in names) or len(set(names)) != len(names):
                _fail('missing or duplicate initializer name')
            result = {}
            for number, key in ((11, 'inputs'), (12, 'outputs')):
                signatures = values.get(number, [])
                if (any(item['dtype'] is None for item in signatures)
                        or len({item['name'] for item in signatures}) != len(signatures)):
                    _fail('duplicate graph signature name')
                result[key] = signatures
            return result
        if kind == 'Sparse':
            self.unsupported.add('sparse_tensors')
            if 1 not in values or 2 not in values:
                _fail('incomplete sparse tensor')
            return {'name': values[1]['name']}
        if kind == 'Training':
            self.unsupported.add('training')
            self.unique_entries(values.get(3, []))
            self.unique_entries(values.get(4, []))
        if kind == 'Function':
            self.unsupported.add('local_functions')
        if kind == 'Segment':
            self.unsupported.add('tensor_segments')
        if kind == 'Type':
            content = set(values) - {6}
            if len(content) != 1:
                _fail('ambiguous or empty signature type')
            if content != {1}:
                self.unsupported.add('non_dense_signature_types')
                return {'dtype': None, 'shape': None}
            return values[1]
        if kind == 'TensorType':
            if not 1 <= values.get(1, 0) <= 24:
                _fail('invalid signature dtype')
            return {'dtype': values[1], 'shape': values.get(2)}
        if kind == 'Shape':
            return values.get(1, [])
        if kind == 'Dimension':
            if (1 in values) + (2 in values) > 1 or values.get(1, 0) > _MAX_INTEGER:
                _fail('ambiguous or negative signature dimension')
            return values.get(1, values.get(2))
        if kind == 'Value':
            if not values.get(1):
                _fail('incomplete graph signature')
            return {'name': values[1], **values.get(2, {'dtype': None, 'shape': None})}
        if kind == 'Model':
            if not 0 < values.get(1, 0) <= 12 or 7 not in values or not values.get(8):
                _fail('missing graph, IR or opset')
            imports = values[8]
            if len({item[0] for item in imports}) != len(imports):
                _fail('duplicate opset domain')
            return {'ir_version': values[1], **values[7]}
        return None

    def tensor(self, values):
        dtype, dimensions = values.get(2), values.get(1, [])
        if type(dtype) is not int or not 1 <= dtype <= 24 or len(dimensions) > 64 or any(dim > _MAX_INTEGER for dim in dimensions):
            _fail('invalid tensor dtype, rank or dimension')
        elements = 1
        for dim in dimensions:
            elements *= dim
            if elements > MAX_EXTERNAL_BYTES * 8:
                _fail('tensor element bound exceeded')
        tensor_bytes = (elements * _BITS[dtype]+7)//8 if dtype in _BITS else None
        if tensor_bytes is not None and tensor_bytes > MAX_EXTERNAL_BYTES:
            _fail('tensor byte bound exceeded')
        location = values.get(14, 0)
        if location not in {0, 1}:
            _fail('invalid tensor data location')
        entries = self.unique_entries(values.get(13, []))
        if location == 1:
            if set(values) & {4, 5, 6, 7, 9, 10, 11}:
                _fail('mixed inline and external tensor storage')
            if set(entries) - {'location', 'offset', 'length', 'checksum'} or 'location' not in entries:
                _fail('unsupported external tensor metadata')
            name = _relative(entries['location'])
            if name not in self.external:
                _fail('missing external tensor pin')
            size = self.external[name]['bytes']
            def integer(key, default):
                text = entries.get(key)
                if text is None:
                    return default
                if not re.fullmatch(r'0|[1-9][0-9]{0,18}', text):
                    _fail('invalid external ' + key)
                value = int(text)
                if value > _MAX_INTEGER:
                    _fail('external range overflow')
                return value
            offset = integer('offset', 0)
            length = integer('length', size-offset)
            if offset < 0 or length <= 0 or offset > size or length > size-offset or tensor_bytes != length:
                _fail('external tensor range or shape mismatch')
            checksum = entries.get('checksum')
            if checksum is not None:
                if not re.fullmatch(r'[0-9a-fA-F]{40}', checksum):
                    _fail('invalid external checksum')
                self.unsupported.add('external_sha1_unverified')
            self.count('external_references', 1, MAX_EXTERNAL_REFERENCES)
            self.references.append({'tensor': values.get(8, ''), 'location': name, 'offset': offset,
                                    'length': length, 'dtype': dtype, 'dimensions': dimensions})
        elif entries:
            _fail('external metadata without EXTERNAL location')
        if 9 in values and tensor_bytes is not None and values[9]['length'] != tensor_bytes:
            _fail('inline tensor shape mismatch')
        return {'name': values.get(8, ''), 'dtype': dtype, 'dimensions': dimensions}

    def parse(self):
        result = self.message('Model', 0, self.size, 0)
        self.current()
        observed = {item['location'] for item in self.references}
        declared = set(self.external)
        if observed != declared:
            # Every location was path/pin checked during the complete message
            # walk. Both sets remain bounded by MAX_EXTERNAL_FILES and each
            # string by MAX_STRING_BYTES. This is still the identical refusal,
            # never an ignore-extra option or runtime/admission authority.
            failure = OnnxInspectionError('external tensor closure mismatch')
            failure.diagnostics = {
                'status': 'metadata_unavailable', 'runtime_supported': False,
                'wire_walk_complete': True,
                'observed_locations': tuple(sorted(observed)),
                'declared_locations': tuple(sorted(declared)),
                'unused_locations': tuple(sorted(declared-observed)),
            }
            raise failure
        domains = {domain for domain, _ in self.opsets}
        if any(domain not in domains for domain, _ in self.operators):
            self.unsupported.add('operator_domain_without_opset')
        self.current()
        return {**result, 'operators': [{'domain': domain, 'op_type': op, 'count': count}
                                        for (domain, op), count in sorted(self.operators.items())],
                'opsets': [{'domain': domain, 'version': version} for domain, version in sorted(self.opsets)],
                'external_references': self.references, 'unsupported_features': sorted(self.unsupported),
                'counts': dict(self.counts), 'metadata_profile_supported': not self.unsupported,
                'runtime_supported': False, 'runtime_qualification': 'not_performed'}


def inspect_onnx(root: Path, graph: str, *, graph_bytes: int, graph_sha256: str,
                 external_files: dict[str, dict]) -> dict:
    """Observe one pinned graph and exact local external-file closure on POSIX.

    Caller supplies frozen expected pins, never authority. Graph SHA-256 is
    checked here. External files are held and stat-bound only, not hashed or
    loaded. Even an understood graph never authorizes native model execution.
    Bounds are fixed for public artifact metadata and change no source-cut or
    query budget. Deadline checks are cooperative, not an OS syscall timeout.
    Nothing invokes this module by default.
    """
    started = time.monotonic()
    deadline = started + TIMEOUT_SECONDS
    _pin(graph_bytes, graph_sha256, MAX_GRAPH_BYTES)
    graph = _relative(graph)
    if type(external_files) is not dict or len(external_files) > MAX_EXTERNAL_FILES:
        _fail('external file count bound exceeded')
    expected = {}
    for name, pin in external_files.items():
        name = _relative(name)
        if type(pin) is not dict or set(pin) != {'bytes', 'sha256'}:
            _fail('invalid external artifact pin')
        _pin(pin['bytes'], pin['sha256'], MAX_EXTERNAL_BYTES)
        expected[name] = dict(pin)
    if sum(pin['bytes'] for pin in expected.values()) > MAX_EXTERNAL_BYTES:
        _fail('external byte bound exceeded')
    try:
        root = Path(root)
        if root.is_symlink():
            _fail('unsafe artifact root')
        _owned(root.lstat(), directory=True)
        with ExitStack() as stack:
            anchor = stack.enter_context(fsx.ReadOnlyBoundRoot(root))
            descriptor, check = stack.enter_context(_held(anchor, graph, graph_bytes))
            checks = [check]
            graph_parent = PurePosixPath(graph).parent
            for name, pin in sorted(expected.items()):
                relative = (graph_parent / name).as_posix()
                if relative == graph:
                    _fail('external tensor aliases graph')
                _, current = stack.enter_context(_held(anchor, relative, pin['bytes']))
                checks.append(current)
            digest, read_bytes = hashlib.sha256(), 0
            while True:
                if time.monotonic() >= deadline:
                    _fail('metadata deadline exceeded')
                block = os.read(descriptor, min(_BLOCK, graph_bytes-read_bytes+1))
                if not block:
                    break
                read_bytes += len(block)
                if read_bytes > graph_bytes:
                    _fail('graph grew while hashing')
                digest.update(block)
            if read_bytes != graph_bytes or digest.hexdigest() != graph_sha256:
                _fail('graph hash or size mismatch')
            for current in checks:
                current()
            try:
                result = _Wire(descriptor, graph_bytes, expected, deadline).parse()
            except OnnxInspectionError as error:
                if error.diagnostics is not None:
                    # A completed wire walk does not establish current custody.
                    # Refusals also need these checks before exposing its facts;
                    # a changed file or expired deadline replaces the details.
                    for current in checks:
                        current()
                    if time.monotonic() >= deadline:
                        _fail('metadata deadline exceeded')
                raise
            for current in checks:
                current()
            if time.monotonic() >= deadline:
                _fail('metadata deadline exceeded')
            return {**result, 'schema_version': 1, 'schema': 'onnx-v1.19.1-wire-metadata',
                    'graph': graph, 'graph_bytes': graph_bytes, 'graph_sha256': graph_sha256,
                    'graph_sha256_verified': True, 'external_hashes_verified': False,
                    'external_files': expected, 'hash_read_bytes': read_bytes,
                    'elapsed_seconds': time.monotonic()-started}
    except (OSError, fsx.ComponentStateError) as exc:
        raise OnnxInspectionError('artifact custody unavailable or changed') from exc
