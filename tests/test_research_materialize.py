"""Inert preparation rejects unsafe or unrecorded wheel members."""
import base64
import csv
import hashlib
import importlib.util
import io
from pathlib import Path
import unittest
import tempfile
import os
import zipfile
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('research_materialize', Path(__file__).parents[1] / 'scripts/getzilla_research_materialize.py')
materialize = importlib.util.module_from_spec(spec)
spec.loader.exec_module(materialize)


def wheel(rows, *, missing=False, wrong=False):
    stream = io.BytesIO()
    record = io.StringIO(newline='')
    writer = csv.writer(record)
    for name, body in rows:
        digest = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).decode().rstrip('=')
        if not missing:
            writer.writerow((name, 'sha256=' + ('A' * 43 if wrong else digest), len(body)))
    writer.writerow(('tiny-1.dist-info/RECORD', '', ''))
    with zipfile.ZipFile(stream, 'w') as archive:
        for name, body in rows:
            archive.writestr(name, body)
        archive.writestr('tiny-1.dist-info/RECORD', record.getvalue())
    return stream.getvalue()


class WheelTests(unittest.TestCase):
    def test_positive_full_record(self):
        value = wheel([('tiny.py', b'x=1\n'), ('tiny-1.dist-info/LICENSE', b'full grant')])
        rows = materialize.checked_wheel(value)
        self.assertEqual(set(rows), {'tiny.py', 'tiny-1.dist-info/LICENSE', 'tiny-1.dist-info/RECORD'})

    def test_exact_file_and_expanded_bounds(self):
        payload = wheel([('tiny.py', b'x')])
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            total = sum(row.file_size for row in archive.infolist())
        with patch.object(materialize, 'MAX_FILES', 2), patch.object(materialize, 'MAX_SOFTWARE', total):
            self.assertEqual(len(materialize.checked_wheel(payload)), 2)
        with patch.object(materialize, 'MAX_FILES', 1), self.assertRaises(ValueError):
            materialize.checked_wheel(payload)
        with patch.object(materialize, 'MAX_SOFTWARE', total - 1), self.assertRaises(ValueError):
            materialize.checked_wheel(payload)

    def test_bad_record(self):
        for kwargs in ({'missing': True}, {'wrong': True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                materialize.checked_wheel(wheel([('tiny.py', b'x')], **kwargs))

    def test_unsafe_paths_and_activation_files(self):
        for name in ('../escape.py', '/absolute.py', 'a\\b.py'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                materialize.checked_wheel(wheel([(name, b'x')]))

    def test_duplicate_collision(self):
        with self.assertRaises(ValueError):
            materialize.checked_wheel(wheel([('tiny.py', b'x'), ('tiny.py', b'x')]))

    def test_symlink_and_writable_special_modes(self):
        value = io.BytesIO(wheel([('tiny.py', b'x')]))
        with zipfile.ZipFile(value) as src:
            data = [(row, src.read(row)) for row in src.infolist()]
        for mode in (0o120777, 0o104755):
            out = io.BytesIO()
            with zipfile.ZipFile(out, 'w') as dest:
                for row, body in data:
                    row.external_attr = mode << 16
                    dest.writestr(row, body)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                materialize.checked_wheel(out.getvalue())


@unittest.skipUnless(os.name == 'posix', 'held source profile requires POSIX')
class TermBoundaryTests(unittest.TestCase):
    def test_actual_four_valid_terms_pass_five_valid_terms_refuse(self):
        from getzilla.retrieval.research_use_conditions import _HeldTerms
        from getzilla.security_artifacts import ArtifactError
        runtime = Path(__file__).parents[1] / '.getzilla/runtime'
        with tempfile.TemporaryDirectory(dir=runtime) as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            pins = {}
            for index in range(5):
                body = ('complete tiny grant ' + str(index)).encode()
                path = root / str(index)
                path.write_bytes(body)
                path.chmod(0o400)
                pins[path.name] = (hashlib.sha256(body).hexdigest(), len(body))
            with _HeldTerms(root, dict(list(pins.items())[:4])) as held:
                self.assertEqual(len(held.observe()), 4)
            with self.assertRaises(ArtifactError):
                with _HeldTerms(root, pins) as held:
                    held.observe()

    def test_actual_exact_total_byte_boundary(self):
        from getzilla.retrieval.research_use_conditions import _HeldTerms
        from getzilla.security_artifacts import ArtifactError
        runtime = Path(__file__).parents[1] / '.getzilla/runtime'
        with tempfile.TemporaryDirectory(dir=runtime) as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            pins = {}
            # Four individually valid complete bodies; only aggregate differs by one.
            for index in range(4):
                body = b'X' * 65536
                path = root / str(index)
                path.write_bytes(body)
                path.chmod(0o400)
                pins[path.name] = (hashlib.sha256(body).hexdigest(), len(body))
            with _HeldTerms(root, pins) as held:
                self.assertEqual(sum(len(value) for value in held.observe().values()), 262144)
            path = root / '3'
            path.chmod(0o600)
            body = b'X' * 65537
            path.write_bytes(body)
            path.chmod(0o400)
            pins['3'] = (hashlib.sha256(body).hexdigest(), len(body))
            with self.assertRaises(ArtifactError):
                with _HeldTerms(root, pins) as held:
                    held.observe()


class OutputTests(unittest.TestCase):
    def test_actual_copy_preserves_original_and_private_modes(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parents[1] / '.getzilla/runtime') as temporary:
            root = Path(temporary)
            source = root / 'held'
            source.write_bytes(b'full terms')
            source.chmod(0o400)
            before = materialize.identity(source.stat())
            output = materialize.PrivateOutput(root, 'fresh')
            try:
                materialize.copy_pinned(source, output, 'terms/LICENSE', (10, hashlib.sha256(b'full terms').hexdigest()), materialize.time.monotonic() + 2)
                self.assertEqual((root / 'fresh/terms/LICENSE').read_bytes(), b'full terms')
                self.assertEqual((root / 'fresh/terms/LICENSE').stat().st_mode & 0o777, 0o400)
                self.assertEqual(materialize.identity(source.stat()), before)
                with self.assertRaises(FileExistsError):
                    materialize.PrivateOutput(root, 'fresh')
            finally:
                output.close()

    def test_private_tiny_full_preparation_and_collision(self):
        # Private internal composition tests byte preparation, never production profile/ref.
        with tempfile.TemporaryDirectory(dir=Path(__file__).parents[1] / '.getzilla/runtime') as temporary:
            root = Path(temporary)
            payload = wheel([('tiny.py', b'x=1'), ('tiny-1.dist-info/entry_points.txt', b'inert metadata'), ('coloredlogs.pth', b'import NEVER_EXECUTE_THIS')])
            source = root / 'archive'
            source.write_bytes(payload)
            source.chmod(0o400)
            pin = (len(payload), hashlib.sha256(payload).hexdigest())
            catalog = {'wheels': [{'filename': 'one.whl'}]}
            output = materialize.PrivateOutput(root, 'fresh')
            try:
                report = materialize._populate(output, catalog, {'artifacts/one.whl': pin}, {'artifacts/one.whl': str(source)}, 'fresh', materialize.time.monotonic()+5)
                self.assertEqual(len(report['software_files']), 4)
                self.assertFalse(report['source_use_reference_created'])
                self.assertEqual((root / 'fresh/software/coloredlogs.pth').read_bytes(), b'import NEVER_EXECUTE_THIS')
                (root / 'fresh/software/extra').mkdir()
                with self.assertRaisesRegex(ValueError, 'unexpected software directory'):
                    materialize.check_software(output, report['software_files'], materialize.time.monotonic()+2)
            finally:
                output.close()
            output = materialize.PrivateOutput(root, 'collision')
            try:
                with self.assertRaisesRegex(ValueError, 'cross-wheel'):
                    materialize._populate(output, {'wheels': [{'filename': 'one.whl'}, {'filename': 'two.whl'}]}, {'artifacts/one.whl': pin, 'artifacts/two.whl': pin}, {'artifacts/one.whl': str(source), 'artifacts/two.whl': str(source)}, 'collision', materialize.time.monotonic()+5)
            finally:
                output.close()

    def test_symlink_checksum_and_deadline_refuse(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parents[1] / '.getzilla/runtime') as temporary:
            root = Path(temporary)
            source = root / 'held'
            source.write_bytes(b'X')
            source.chmod(0o400)
            (root / 'link').symlink_to(source)
            output = materialize.PrivateOutput(root, 'fresh')
            try:
                for index, (path, digest, deadline) in enumerate(((root / 'link', hashlib.sha256(b'X').hexdigest(), materialize.time.monotonic()+2), (source, '0'*64, materialize.time.monotonic()+2), (source, hashlib.sha256(b'X').hexdigest(), 0))):
                    with self.subTest(index=index), self.assertRaises((ValueError, OSError)):
                        materialize.copy_pinned(path, output, str(index), (1, digest), deadline)
            finally:
                output.close()


if __name__ == '__main__':
    unittest.main()
