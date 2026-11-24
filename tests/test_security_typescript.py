"""Pinned parser distribution refuses untrusted archives before extraction."""
import hashlib
import io
import tarfile
import unittest
from unittest import mock

from getzilla import security_acquisition as acquisition
from getzilla import security_opengrep as scanner


class TypeScriptDistributionTests(unittest.TestCase):
    def archive(self, *, duplicate=False, linked=False):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as bundle:
            for _ in range(2 if duplicate else 1):
                member = tarfile.TarInfo('package/lib/typescript.js')
                member.size = 6
                if linked:
                    member.type = tarfile.SYMTYPE
                    member.linkname = '/outside'
                bundle.addfile(member, None if linked else io.BytesIO(b'parser'))
        return stream.getvalue()

    def test_archive_pin_precedes_archive_parsing(self):
        with mock.patch.object(acquisition.tarfile, 'open', side_effect=AssertionError('untrusted archive opened')):
            with self.assertRaisesRegex(acquisition.SecurityDataError, 'archive differs'):
                acquisition.typescript_compiler(b'untrusted')

    def test_unique_regular_compiler_and_its_own_pin_are_required(self):
        for duplicate, linked in [(False, False), (True, False), (False, True)]:
            archive = self.archive(duplicate=duplicate, linked=linked)
            with self.subTest(duplicate=duplicate, linked=linked), \
                    mock.patch.object(acquisition, 'TYPESCRIPT_ARCHIVE_SHA256', hashlib.sha256(archive).hexdigest()), \
                    mock.patch.object(acquisition, 'TYPESCRIPT_COMPILER_SHA256', hashlib.sha256(b'parser').hexdigest()):
                if duplicate or linked:
                    with self.assertRaises(acquisition.SecurityDataError):
                        acquisition.typescript_compiler(archive)
                else:
                    self.assertEqual(acquisition.typescript_compiler(archive), b'parser')
                    with mock.patch.object(acquisition, 'TYPESCRIPT_COMPILER_SHA256', '0' * 64), \
                            self.assertRaisesRegex(acquisition.SecurityDataError, 'compiler differs'):
                        acquisition.typescript_compiler(archive)

    def test_typescript_has_its_own_grammar_and_rule_language(self):
        self.assertEqual(scanner._LANGUAGE['.ts'], 'typescript')
        self.assertEqual(scanner._FRONTENDS['typescript'][3], 'typescript5.9.3-module')
