import importlib
from pathlib import Path
import tempfile
import unittest


class StudyRunArtifactTests(unittest.TestCase):
    def owner(self):
        try:
            return importlib.import_module('getzilla.retrieval.study_run_artifacts')
        except ModuleNotFoundError:
            self.fail('immutable existing-owner run artifact adapter missing')

    def test_current_run_files_are_immutable_private_and_digest_bound(self):
        owner = self.owner()
        with tempfile.TemporaryDirectory() as temporary:
            with owner.RunArtifacts(Path(temporary), byte_limit=4096) as run:
                item = run.write('tiny.json', {'scope': 'inert'})
                self.assertEqual(item.bytes, len((Path(temporary) / item.path).read_bytes()))
                self.assertEqual((Path(temporary) / item.path).stat().st_mode & 0o777, 0o600)
                with self.assertRaises(ValueError):
                    run.write('tiny.json', {'scope': 'changed'})
                self.assertEqual(len(run.manifest()), 1)

    def test_quota_and_unsafe_filename_refuse_before_creating_a_file(self):
        owner = self.owner()
        with tempfile.TemporaryDirectory() as temporary:
            with owner.RunArtifacts(Path(temporary), byte_limit=8) as run:
                for name, value in (('../outside.json', {}), ('large.json', {'x': 'too large'})):
                    with self.subTest(name=name), self.assertRaises(ValueError):
                        run.write(name, value)
                self.assertEqual(run.manifest(), ())
