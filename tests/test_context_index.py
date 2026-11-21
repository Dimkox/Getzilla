"""Current authorized-cut input reuses the existing graph store; no source IO here."""
from contextlib import closing
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.code_graph.models import GraphConfig, GraphError, make_graph_input
from getzilla.code_graph.store import GraphStore
from tests.test_retrieval_engine import document, snapshot
from getzilla.retrieval.extract import build_generation


class ContextIndexTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.cache = Path(temporary.name) / 'graph.sqlite'

    def graph_input(self, source, *, head=None):
        baseline = {'source_kind': 'folder', 'source_digest': source.source_digest}
        if head:
            baseline = {'source_kind': 'local_git', 'source_digest': source.source_digest,
                        'git': {'commit_oid': head, 'tree_oid': 'b' * 40}}
        return make_graph_input(baseline, {d.path: d.original for d in source.documents}, GraphConfig())

    def test_two_sessions_reuse_generation_without_parse_or_link_resolution(self):
        from getzilla.retrieval.graph_packet import current_graph
        source = snapshot(document())
        with closing(GraphStore(self.cache)) as store:
            first, counters = current_graph(self.graph_input(source), store)
        with closing(GraphStore(self.cache)) as store, mock.patch('getzilla.code_graph.incremental.update_index',
                                                        side_effect=AssertionError('unneeded update')):
            second, counters = current_graph(self.graph_input(source), store)
        self.assertEqual(first.generation_id, second.generation_id)
        self.assertEqual(counters, {'generation_reused': True, 'parsed_files': 0, 'link_resolution_runs': 0})

    def test_modify_rename_add_delete_dirty_and_branch_never_reuse_stale_references(self):
        from getzilla.retrieval.graph_packet import current_graph, prepare_graph_packet
        old = snapshot(document())
        with closing(GraphStore(self.cache)) as store:
            graph, _ = current_graph(self.graph_input(old), store)
            for changed in (snapshot(document(text='def modified():\n    return 2\n')),
                            snapshot(document(path='renamed.py')),
                            snapshot(document(), document(path='added.py', resource='r2')),
                            snapshot()):
                with self.assertRaisesRegex(ValueError, 'current_graph_unavailable'):
                    prepare_graph_packet(changed, build_generation(changed), graph, 'choose_key')
                updated, _ = current_graph(self.graph_input(changed), store)
                self.assertNotEqual(updated.input_identity, graph.input_identity)
            git_source = snapshot(document(), git=True)
            a, _ = current_graph(self.graph_input(git_source, head='2' * 40), store)
            b, counts = current_graph(self.graph_input(git_source, head='3' * 40), store)
            self.assertNotEqual(a.input_identity, b.input_identity)
            with self.assertRaisesRegex(ValueError, 'current_graph_unavailable'):
                prepare_graph_packet(git_source, build_generation(git_source), b, 'choose_key')

    def test_unknown_cache_is_preserved_and_fresh_store_rejects_stale_graph(self):
        from getzilla.retrieval.graph_packet import current_graph, prepare_graph_packet
        original = b'not sqlite'
        self.cache.write_bytes(original)
        with self.assertRaises(GraphError) as caught:
            GraphStore(self.cache)
        self.assertEqual(caught.exception.reason_code, 'CACHE_UNRECOGNIZED')
        self.assertEqual(self.cache.read_bytes(), original)
        self.cache.unlink()
        source = snapshot(document())
        with closing(GraphStore(self.cache)) as store:
            graph, _ = current_graph(self.graph_input(source), store)
        packet = prepare_graph_packet(source, build_generation(source), graph, 'choose_key')
        self.assertEqual(packet['graph']['generation_id'], graph.generation_id)
        self.assertIn('choose_key', packet['text'])
        changed = snapshot(document(text='def choose_key():\n    return 2\n'))
        with self.assertRaisesRegex(ValueError, 'current_graph_unavailable'):
            prepare_graph_packet(changed, build_generation(changed), graph, 'choose_key')

    def test_selected_class_and_file_spans_use_verified_original_bytes(self):
        from getzilla.retrieval.graph_packet import current_graph, prepare_graph_packet
        source=snapshot(document(text='import math\nclass Choice:\n    def answer(self):\n        return 42\n'))
        with closing(GraphStore(self.cache)) as store:
            graph,_=current_graph(self.graph_input(source),store)
        for query in ('Choice','a.py'):
            packet=prepare_graph_packet(source,build_generation(source),graph,query)
            self.assertIn('class Choice:',packet['text'])
            self.assertTrue(packet['citations'])
