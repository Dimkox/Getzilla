"""Optional lifecycle and bounded hook notes never substitute for native access."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from tests import test_optional_modules as optional_fixtures


class ContextLifecycleTests(unittest.TestCase):
    def test_disabled_status_and_task_note_start_no_index_workers_or_models(self):
        from getzilla.retrieval.lifecycle import startup_note, append_note
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with mock.patch('getzilla.code_graph.store.GraphStore', side_effect=AssertionError('no index')):
                note = startup_note(root)
                self.assertIn('disabled', note)
            self.assertFalse((root / '.getzilla/index').exists())
            mandatory = 'Original scope\nPending amendment\nEvidence gaps: OPEN\n' * 200
            self.assertEqual(append_note(mandatory, 'x' * 16384), mandatory)
            self.assertEqual(append_note(mandatory, note), mandatory + '\n\n' + note)

    def test_existing_optional_lifecycle_enable_disable_keeps_graph_cache(self):
        from getzilla.retrieval.lifecycle import startup_note
        fixture = optional_fixtures.OptionalModuleTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        from getzilla.optional_modules import manage_modules
        manage_modules(fixture.root, 'install', {'context-retrieval': '0.1.0'}, source=ROOT)
        manage_modules(fixture.root, 'enable', {'context-retrieval': None}, source=ROOT)
        cache = fixture.root / '.getzilla/index/graph.sqlite'
        cache.parent.mkdir(parents=True)
        cache.write_bytes(b'existing cache sentinel')
        self.assertIn('authority_unavailable', startup_note(fixture.root))
        manage_modules(fixture.root, 'disable', {'context-retrieval': None}, source=ROOT)
        self.assertIn('disabled', startup_note(fixture.root))
        self.assertEqual(cache.read_bytes(), b'existing cache sentinel')
