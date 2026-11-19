"""Exact compile-and-inspect fixture admission must not enable production C."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tests.test_architecture_model import ARCH, ROOT, _rules, _system

SOURCE = 'tests/fixtures/reverse263/public-probe.c'
CONSUMER = 'tests/test_reverse_engineering.py'


class ExactSourceFixtureTests(unittest.TestCase):
    def setUp(self):
        runtime = ROOT / '.getzilla/runtime'
        runtime.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=runtime)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for path in ('architecture', 'schemas'):
            (self.root / path).mkdir()
        for name in ('architecture-system.schema.json', 'architecture-rules.schema.json'):
            (self.root / 'schemas' / name).write_bytes((ROOT / 'schemas' / name).read_bytes())
        self.system = _system()
        self.system['nodes'][0]['id'] = 'NODE-LOCAL-VERIFIER'
        self.system['nodes'][0]['repository_paths'] = ['tests']
        self.system['edges'][0]['from'] = 'NODE-LOCAL-VERIFIER'
        for relative in (SOURCE, CONSUMER):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / relative).read_bytes())
        self.row = dict(profile='c-public-elf-probe-v1', path=SOURCE,
                        sha256=hashlib.sha256((ROOT / SOURCE).read_bytes()).hexdigest(),
                        consumer_path=CONSUMER,
                        consumer_sha256=hashlib.sha256((ROOT / CONSUMER).read_bytes()).hexdigest(),
                        owner_node='NODE-LOCAL-VERIFIER', purpose='compile_inspect_only')
        self.system['source_fixtures'] = [self.row]
        self.write()

    def write(self):
        for relative, value in [('architecture/system.yaml', self.system), ('architecture/rules.yaml', _rules())]:
            (self.root / relative).write_text(json.dumps(ARCH._normalize(value), indent=2) + '\n')

    def findings(self):
        self.write()
        return ARCH.validate_repository_drift(self.root, ARCH.load_architecture(self.root))

    def refused(self):
        try:
            findings = self.findings()
        except ARCH.ArchitectureError:
            return
        self.assertTrue(findings, 'unsafe fixture became a fully admitted architecture')

    def test_exact_fixture_is_declared_without_general_c_support(self):
        try:
            findings = self.findings()
        except ARCH.ArchitectureError as error:
            self.fail(f'exact fixture profile unavailable: {error}')
        self.assertEqual(findings, ())
        self.assertNotIn('.c', ARCH._SUPPORTED_SOURCE_SUFFIXES)

    def test_undeclared_production_c_cpp_and_header_remain_unsupported(self):
        for suffix in ('.c', '.cpp', '.h'):
            with self.subTest(suffix=suffix):
                path = self.root / ('tests/production' + suffix)
                path.write_text('int x(void) { return 0; }\n')
                self.assertIn(('unsupported_source_artifact', path.relative_to(self.root).as_posix()),
                              [(f.code, f.path) for f in self.findings()])
                path.unlink()

    def test_missing_declaration_does_not_accept_the_known_body(self):
        self.system.pop('source_fixtures')
        self.assertIn(('unsupported_source_artifact', SOURCE), [(f.code, f.path) for f in self.findings()])

    def test_changed_source_even_with_self_issued_hash_refuses(self):
        (self.root / SOURCE).write_text('int main(void) { return 1; }\n')
        self.refused()
        self.row['sha256'] = hashlib.sha256((self.root / SOURCE).read_bytes()).hexdigest()
        self.refused()

    def test_changed_consumer_cannot_execute_or_dlopen_the_probe(self):
        for extra in ('\nsubprocess.run([str(cls.target)])\n', '\nctypes.CDLL(str(cls.target))\n'):
            with self.subTest(extra=extra):
                (self.root / CONSUMER).write_bytes((ROOT / CONSUMER).read_bytes() + extra.encode())
                self.refused()
                self.row['consumer_sha256'] = hashlib.sha256((self.root / CONSUMER).read_bytes()).hexdigest()
                self.refused()

    def test_missing_source_or_consumer_refuses(self):
        for relative in (SOURCE, CONSUMER):
            with self.subTest(relative=relative):
                path = self.root / relative
                saved = path.read_bytes()
                path.unlink()
                self.refused()
                path.write_bytes(saved)

    def test_symlink_and_hardlink_source_refuse(self):
        path = self.root / SOURCE
        saved = path.read_bytes()
        target = self.root / 'outside.txt'
        target.write_bytes(saved)
        path.unlink()
        path.symlink_to(target)
        self.refused()
        path.unlink()
        path.hardlink_to(target)
        self.refused()

    def test_unknown_profile_wildcard_owner_or_extra_fields_refuse(self):
        original = copy.deepcopy(self.row)
        for key, value in [('profile', 'arbitrary-c'), ('path', 'tests/fixtures/*.c'),
                           ('owner_node', 'NODE-B'), ('purpose', 'production'), ('extra', True)]:
            with self.subTest(key=key):
                self.system['source_fixtures'] = [{**original, key: value}]
                self.refused()

    def test_duplicate_fixture_refuses(self):
        self.system['source_fixtures'].append(copy.deepcopy(self.row))
        self.refused()

    def test_consumer_link_refuses(self):
        path = self.root / CONSUMER
        saved = path.read_bytes()
        other = self.root / 'copy.txt'
        other.write_bytes(saved)
        path.unlink()
        path.symlink_to(other)
        self.refused()

    def test_oversized_source_and_consumer_are_bounded_before_hash_admission(self):
        for relative, limit in ((SOURCE, 4096), (CONSUMER, 131072)):
            with self.subTest(relative=relative):
                path = self.root / relative
                saved = path.read_bytes()
                path.write_bytes(b'x' * (limit + 1))
                with self.assertRaises(ARCH.ArchitectureError) as caught:
                    ARCH._read_regular_bytes(self.root, relative, label='bounded fixture',
                                             limit=limit, single_link=True)
                self.assertEqual(caught.exception.code, 'limit')
                self.refused()
                path.write_bytes(saved)

    def test_production_service_cannot_adopt_the_verifier_identity(self):
        self.system['nodes'][0]['type'] = 'service'
        self.refused()
