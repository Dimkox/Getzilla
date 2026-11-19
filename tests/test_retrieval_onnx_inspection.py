"""Tiny generated protobuf fixtures; no ONNX/native dependency or model weights."""
import hashlib
import importlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def varint(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    return bytes(result) + bytes([value])


def field(number, value):
    if type(value) is int:
        return varint(number << 3) + varint(value)
    if type(value) is str:
        value = value.encode()
    return varint(number << 3 | 2) + varint(len(value)) + value


def tensor(name='weight', *, external=None, dimensions=(2,), raw=b'12345678'):
    value = b''.join(field(1, dim) for dim in dimensions) + field(2, 1) + field(8, name)
    if external is None:
        return value + field(9, raw)
    return value + b''.join(field(13, field(1, key) + field(2, item)) for key, item in external) + field(14, 1)


def signature(name, dtype=7):
    shape = field(1, field(2, 'batch')) + field(1, field(2, 'sequence'))
    return field(1, name) + field(2, field(1, field(1, dtype) + field(2, shape)))


def node(*, domain='', attribute=b''):
    return field(1, 'input_ids') + field(2, 'output') + field(4, 'Identity') + field(7, domain) + attribute


def graph(*, initializer=None, nodes=None, extra=b''):
    return (field(2, 'test') + field(1, node() if nodes is None else nodes)
            + (field(5, tensor() if initializer is None else initializer))
            + field(11, signature('input_ids')) + field(12, signature('output', 1)) + extra)


def model(content=None, extra=b''):
    return field(1, 8) + field(8, field(1, '') + field(2, 17)) + field(7, graph() if content is None else content) + extra


@unittest.skipUnless(os.name == 'posix', 'public ONNX artifact custody profile requires POSIX ownership')
class OnnxInspectionTests(unittest.TestCase):
    def setUp(self):
        try:
            self.inspector = importlib.import_module('getzilla.retrieval.onnx_inspection')
        except ImportError:
            self.fail('the inert ONNX metadata inspector is absent')
        self.temporary = tempfile.TemporaryDirectory(prefix='owned-onnx-inspection-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        (self.root / 'onnx').mkdir(mode=0o700)
        self.path = self.root / 'onnx/model.onnx'

    def inspect(self, raw=None, external=None):
        raw = model() if raw is None else raw
        self.path.write_bytes(raw)
        self.path.chmod(0o600)
        return self.inspector.inspect_onnx(self.root, 'onnx/model.onnx', graph_bytes=len(raw),
            graph_sha256=hashlib.sha256(raw).hexdigest(), external_files=external or {})

    def external(self, name='model.onnx_data', raw=b'12345678'):
        path = self.root / 'onnx' / name
        path.write_bytes(raw)
        path.chmod(0o600)
        return {name: {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}}

    def test_inline_graph_reports_actual_signatures_operators_and_bounds(self):
        result = self.inspect()
        self.assertEqual(result['inputs'], [{'name': 'input_ids', 'dtype': 7, 'shape': ['batch', 'sequence']}])
        self.assertEqual(result['outputs'], [{'name': 'output', 'dtype': 1, 'shape': ['batch', 'sequence']}])
        self.assertEqual(result['operators'], [{'domain': '', 'op_type': 'Identity', 'count': 1}])
        self.assertEqual(result['opsets'], [{'domain': '', 'version': 17}])
        self.assertEqual(result['external_references'], [])
        self.assertTrue(result['graph_sha256_verified'])
        self.assertFalse(result['external_hashes_verified'])
        self.assertEqual(result['unsupported_features'], [])
        self.assertEqual(result['counts']['nodes'], 1)
        self.assertGreater(result['counts']['fields'], 10)
        self.assertLess(result['elapsed_seconds'], 30)
        self.assertNotIn('qualified', result)

    def test_external_exact_closure_records_span_without_reading_tensor(self):
        files = self.external()
        raw = model(graph(initializer=tensor(external=[('location', 'model.onnx_data'), ('offset', '0'), ('length', '8')])))
        real_read = os.read
        def bounded_read(fd, size):
            self.assertNotEqual(os.fstat(fd).st_size, 8, 'metadata inspection must not read external tensor bodies')
            return real_read(fd, size)
        with patch.object(os, 'read', side_effect=bounded_read):
            result = self.inspect(raw, files)
        self.assertEqual(result['external_references'][0]['location'], 'model.onnx_data')
        self.assertEqual(result['external_references'][0]['offset'], 0)
        self.assertEqual(result['external_references'][0]['length'], 8)
        self.assertFalse(result['external_hashes_verified'])

    def test_external_missing_extra_traversal_absolute_and_backslash_refuse(self):
        files = self.external()
        for location, supplied in [('absent', files), ('../escape', files), ('/etc/passwd', files),
                                   ('C:payload', files), ('dir\\payload', files), ('./model.onnx_data', files)]:
            with self.subTest(location=location), self.assertRaises(self.inspector.OnnxInspectionError):
                self.inspect(model(graph(initializer=tensor(external=[('location', location)]))), supplied)
        with self.assertRaises(self.inspector.OnnxInspectionError):
            self.inspect(external=files)

    def test_external_duplicate_keys_mixed_storage_and_bad_ranges_refuse(self):
        files = self.external()
        for suffix in [[('location', 'model.onnx_data')], [('offset', '-1')], [('offset', '01')],
                       [('offset', str(2**63))], [('offset', '1'), ('length', '8')],
                       [('length', '0')], [('checksum', 'not-sha1')], [('basepath', '/tmp')]]:
            with self.subTest(suffix=suffix), self.assertRaises(self.inspector.OnnxInspectionError):
                self.inspect(model(graph(initializer=tensor(external=[('location', 'model.onnx_data'), *suffix]))), files)
        bad = tensor(external=[('location', 'model.onnx_data')]) + field(9, b'12345678')
        with self.assertRaises(self.inspector.OnnxInspectionError):
            self.inspect(model(graph(initializer=bad)), files)

    def test_nested_graph_attribute_tensor_and_sparse_edges_are_inspected(self):
        files = self.external()
        external_tensor = tensor(external=[('location', 'model.onnx_data')])
        attrs = [field(5, external_tensor), field(10, external_tensor),
                 field(6, graph(initializer=external_tensor)), field(11, graph(initializer=external_tensor)),
                 field(22, field(1, external_tensor) + field(2, tensor(name='indices')) + field(3, 2)),
                 field(23, field(1, external_tensor) + field(2, tensor(name='indices')) + field(3, 2))]
        for content in attrs:
            attribute = field(1, 'value') + content
            with self.subTest(attribute=content[:1]):
                result = self.inspect(model(graph(nodes=node(attribute=field(5, attribute)))), files)
                self.assertEqual(len(result['external_references']), 1)
        sparse = field(1, external_tensor) + field(2, tensor(name='indices')) + field(3, 2)
        result = self.inspect(model(graph(initializer=tensor(name='dense'), extra=field(15, sparse))), files)
        self.assertIn('sparse_tensors', result['unsupported_features'])

    def test_training_and_function_edges_are_walked_before_unsupported_decision(self):
        files = self.external()
        ext = tensor(external=[('location', 'model.onnx_data')])
        training = field(1, graph(initializer=ext))
        function = field(1, 'local') + field(10, 'local.domain') + field(7, node()) + field(11, field(1, 'value') + field(5, ext))
        result = self.inspect(model(extra=field(20, training) + field(25, function)), files)
        self.assertEqual(len(result['external_references']), 2)
        self.assertIn('training', result['unsupported_features'])
        self.assertIn('local_functions', result['unsupported_features'])
        self.assertEqual(result['counts']['nodes'], 3)

    def test_custom_domains_are_observed_but_never_runtime_supported(self):
        result = self.inspect(model(graph(nodes=node(domain='com.evil'))))
        self.assertIn('custom_operator_domains', result['unsupported_features'])
        self.assertFalse(result['runtime_supported'])
        self.assertEqual(result['operators'][0]['domain'], 'com.evil')

    def test_duplicate_singular_fields_and_metadata_keys_refuse(self):
        for raw in [model(extra=field(7, graph())), model(extra=field(1, 8)),
                    model(extra=field(14, field(1, 'x') + field(2, 'a')) + field(14, field(1, 'x') + field(2, 'b'))),
                    model(graph(extra=field(11, signature('input_ids')))),
                    model(graph(initializer=tensor() + field(2, 1)))]:
            with self.subTest(raw=raw[:10]), self.assertRaises(self.inspector.OnnxInspectionError):
                self.inspect(raw)

    def test_malformed_wire_varint_length_wiretypes_and_unknown_edges_refuse(self):
        for raw in [b'\x80' * 11, b'\x08\x80\x00', b'\x3a\xff\xff\xff\xff\x7f',
                    b'\x0b', b'\x00', model(extra=field(26, b'')),
                    model(graph(nodes=node() + field(10, b''))), model(extra=field(100, b''))]:
            with self.subTest(raw=raw[:10]), self.assertRaises(self.inspector.OnnxInspectionError):
                self.inspect(raw)

    def test_recursive_graph_limit_refuses_before_python_stack_limit(self):
        nested = graph()
        for _ in range(10):
            nested = graph(nodes=node(attribute=field(5, field(1, 'body') + field(6, nested))))
        with self.assertRaisesRegex(self.inspector.OnnxInspectionError, 'depth'):
            self.inspect(model(nested))

    def test_wrong_digest_wrong_size_and_foreign_writable_custody_refuse(self):
        raw = model()
        self.path.write_bytes(raw)
        for expected_size, expected_sha in [(len(raw)+1, hashlib.sha256(raw).hexdigest()), (len(raw), '0'*64)]:
            with self.subTest(size=expected_size), self.assertRaises(self.inspector.OnnxInspectionError):
                self.inspector.inspect_onnx(self.root, 'onnx/model.onnx', graph_bytes=expected_size,
                    graph_sha256=expected_sha, external_files={})
        self.path.chmod(0o666)
        with self.assertRaises(self.inspector.OnnxInspectionError):
            self.inspector.inspect_onnx(self.root, 'onnx/model.onnx', graph_bytes=len(raw),
                graph_sha256=hashlib.sha256(raw).hexdigest(), external_files={})

    @unittest.skipUnless(os.name == 'posix', 'POSIX link and owner fixtures')
    def test_symlinks_hardlinks_and_foreign_owner_refuse(self):
        raw = model()
        target = self.root / 'target'
        target.write_bytes(raw)
        self.path.symlink_to(target)
        arguments = dict(graph_bytes=len(raw), graph_sha256=hashlib.sha256(raw).hexdigest(), external_files={})
        with self.assertRaises(self.inspector.OnnxInspectionError):
            self.inspector.inspect_onnx(self.root, 'onnx/model.onnx', **arguments)
        self.path.unlink()
        os.link(target, self.path)
        with self.assertRaises(self.inspector.OnnxInspectionError):
            self.inspector.inspect_onnx(self.root, 'onnx/model.onnx', **arguments)
        self.path.unlink()
        self.path.write_bytes(raw)
        with patch.object(os, 'geteuid', return_value=os.geteuid()+1), self.assertRaises(self.inspector.OnnxInspectionError):
            self.inspector.inspect_onnx(self.root, 'onnx/model.onnx', **arguments)

    def test_changed_held_graph_and_external_custody_refuse(self):
        original = self.inspector._Wire.parse
        files = self.external()
        raw = model(graph(initializer=tensor(external=[('location', 'model.onnx_data')])))
        for changed in [self.path, self.root / 'onnx/model.onnx_data']:
            def parse(wire):
                result = original(wire)
                changed.write_bytes(changed.read_bytes() + b'x')
                return result
            with self.subTest(changed=changed.name), patch.object(self.inspector._Wire, 'parse', parse), \
                 self.assertRaises(self.inspector.OnnxInspectionError):
                self.inspect(raw, files)
            if changed != self.path:
                changed.write_bytes(b'12345678')

    def test_resource_caps_are_closed_and_do_not_read_oversized_graph(self):
        raw = model()
        self.path.write_bytes(raw)
        with patch.object(os, 'read', side_effect=AssertionError('must refuse before graph read')):
            with self.assertRaises(self.inspector.OnnxInspectionError):
                self.inspector.inspect_onnx(self.root, 'onnx/model.onnx', graph_bytes=128*1024*1024+1,
                    graph_sha256=hashlib.sha256(raw).hexdigest(), external_files={})
        with self.assertRaises(self.inspector.OnnxInspectionError):
            self.inspect(model(graph(nodes=node(domain='a'*4097))))
        with patch.object(self.inspector.time, 'monotonic', side_effect=[0, 31, 31, 31, 31]):
            with self.assertRaisesRegex(self.inspector.OnnxInspectionError, 'deadline'):
                self.inspect()

    def test_changed_root_mode_and_writable_intermediate_directories_refuse(self):
        original = self.inspector._Wire.parse
        def parse(wire):
            result = original(wire)
            self.root.chmod(0o777)
            return result
        try:
            with patch.object(self.inspector._Wire, 'parse', parse), self.assertRaises(self.inspector.OnnxInspectionError):
                self.inspect()
        finally:
            self.root.chmod(0o700)
        nested = self.root / 'shared/deep'
        nested.mkdir(parents=True, mode=0o700)
        nested.parent.chmod(0o777)
        raw = model()
        (nested / 'model.onnx').write_bytes(raw)
        with self.assertRaises(self.inspector.OnnxInspectionError):
            self.inspector.inspect_onnx(self.root, 'shared/deep/model.onnx', graph_bytes=len(raw),
                graph_sha256=hashlib.sha256(raw).hexdigest(), external_files={})

    def test_wire_counter_caps_are_checked_during_actual_nested_walk(self):
        raw = model(graph(nodes=node(), extra=field(1, node())))
        for name, limit in [('MAX_FIELDS', 3), ('MAX_NODES', 1), ('MAX_TENSORS', 0), ('MAX_METADATA_BYTES', 3)]:
            with self.subTest(cap=name), patch.object(self.inspector, name, limit), \
                 self.assertRaisesRegex(self.inspector.OnnxInspectionError, 'bound'):
                self.inspect(raw)

    def test_external_ref_and_file_closure_caps_refuse(self):
        files = self.external()
        ext = tensor(external=[('location', 'model.onnx_data')])
        raw = model(graph(initializer=ext))
        with patch.object(self.inspector, 'MAX_EXTERNAL_REFERENCES', 0), self.assertRaisesRegex(self.inspector.OnnxInspectionError, 'bound'):
            self.inspect(raw, files)
        excessive = {name: {'bytes': 1, 'sha256': '0'*64} for name in ['one', 'two', 'three']}
        with self.assertRaisesRegex(self.inspector.OnnxInspectionError, 'count'):
            self.inspect(raw, excessive)
        oversized = {'one': {'bytes': 2000000000, 'sha256': '0'*64}, 'two': {'bytes': 2000000000, 'sha256': '0'*64}}
        with self.assertRaisesRegex(self.inspector.OnnxInspectionError, 'byte bound'):
            self.inspect(raw, oversized)

    def test_all_nested_external_edges_refuse_unbound_reference(self):
        ext = tensor(external=[('location', 'not-pinned')])
        carriers = [field(20, field(2, graph(initializer=ext))),
                    field(25, field(1, 'function') + field(7, node(attribute=field(5, field(1, 't') + field(10, ext))))),
                    field(25, field(1, 'function') + field(11, field(1, 'g') + field(11, graph(initializer=ext))))]
        for extra in carriers:
            with self.subTest(carrier=extra[:1]), self.assertRaisesRegex(self.inspector.OnnxInspectionError, 'missing external'):
                self.inspect(model(extra=extra))

    def test_same_bytes_named_replacement_refuses_stale_custody(self):
        original = self.inspector._Wire.parse
        def parse(wire):
            result = original(wire)
            replacement = self.path.with_suffix('.replacement')
            replacement.write_bytes(self.path.read_bytes())
            os.replace(replacement, self.path)
            return result
        with patch.object(self.inspector._Wire, 'parse', parse), self.assertRaisesRegex(self.inspector.OnnxInspectionError, 'custody changed'):
            self.inspect()

    def test_invalid_configuration_and_missing_signature_types_refuse(self):
        raw = model()
        self.path.write_bytes(raw)
        for name in ['../model.onnx', 'a/../model.onnx', '/model.onnx', '\ud800', '/'.join(['a']*17)]:
            with self.subTest(name=repr(name)), self.assertRaises(self.inspector.OnnxInspectionError):
                self.inspector.inspect_onnx(self.root, name, graph_bytes=len(raw),
                    graph_sha256=hashlib.sha256(raw).hexdigest(), external_files={})
        with self.assertRaises(self.inspector.OnnxInspectionError):
            self.inspect(model(graph(extra=field(12, field(1, 'untyped-output')))))
        result = self.inspect(model(graph(extra=field(13, field(1, 'untyped-intermediate')))))
        self.assertEqual(result['outputs'][0]['dtype'], 1)

    def test_small_deterministic_wire_mutations_never_escape_domain_errors(self):
        raw = model()
        for index in range(0, len(raw), 3):
            damaged = raw[:index] + bytes([raw[index] ^ 255]) + raw[index+1:]
            with self.subTest(index=index):
                try:
                    result = self.inspect(damaged)
                except self.inspector.OnnxInspectionError:
                    continue
                self.assertFalse(result['runtime_supported'])
                self.assertEqual(result['runtime_qualification'], 'not_performed')

    def test_surplus_external_file_still_refuses_with_complete_bounded_locations(self):
        files = self.external()
        files.update(self.external('unused.bin'))
        raw = model(graph(initializer=tensor(external=[('location', 'model.onnx_data')])))
        with self.assertRaisesRegex(self.inspector.OnnxInspectionError, '^external tensor closure mismatch$') as caught:
            self.inspect(raw, files)
        self.assertEqual(getattr(caught.exception, 'diagnostics', None), {
            'status': 'metadata_unavailable', 'runtime_supported': False, 'wire_walk_complete': True,
            'observed_locations': ('model.onnx_data',),
            'declared_locations': ('model.onnx_data', 'unused.bin'),
            'unused_locations': ('unused.bin',),
        })
        self.assertLessEqual(len(caught.exception.diagnostics['declared_locations']), 2)

    def test_early_malformed_and_resource_failures_expose_no_complete_walk_diagnostic(self):
        files = self.external()
        raw = model(graph(initializer=tensor(external=[('location', 'model.onnx_data')])))
        for malformed in [raw + b'\x80', raw + field(26, b''),
                          model(graph(initializer=tensor(external=[('location', 'not-declared')]))),
                          raw + field(7, graph())]:
            with self.subTest(malformed=malformed[-4:]), self.assertRaises(self.inspector.OnnxInspectionError) as caught:
                self.inspect(malformed, files)
            self.assertIsNone(getattr(caught.exception, 'diagnostics', None))
        with patch.object(self.inspector, 'MAX_FIELDS', 3), self.assertRaises(self.inspector.OnnxInspectionError) as caught:
            self.inspect(raw, files)
        self.assertIsNone(getattr(caught.exception, 'diagnostics', None))

    def test_expired_deadline_at_end_of_walk_does_not_expose_closure_diagnostic(self):
        original = self.inspector._Wire.message
        def message(wire, kind, start, end, depth):
            result = original(wire, kind, start, end, depth)
            if kind == 'Model':
                wire.deadline = 0
            return result
        files = self.external()
        with patch.object(self.inspector._Wire, 'message', message), \
             self.assertRaisesRegex(self.inspector.OnnxInspectionError, 'deadline') as caught:
            self.inspect(external=files)
        self.assertIsNone(getattr(caught.exception, 'diagnostics', None))
