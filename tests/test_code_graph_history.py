"""SHA-grounded history counts and explicit limits on real, disposable Git fixtures."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
import zlib
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.code_graph.cli import main  # noqa: E402
from getzilla.code_graph.history import (  # noqa: E402
    HistoryConfig, interpretation_packet, mine_history, select_interpretation, validate_model_selection,
)
from getzilla.code_graph.history_git import GitReader, HistoryReadError  # noqa: E402
from tests.branch_support import git  # noqa: E402

MODEL = {'system': {'architecture_id': 'fixture', 'nodes': [
    {'id': 'a', 'repository_paths': ['a']}, {'id': 'b', 'repository_paths': ['b']},
    {'id': 'c', 'repository_paths': ['c']},
]}, 'rules': {'architecture_id': 'fixture'}}
WINDOWS = ((1704067200, 1704240000), (1704240000, 1704412800))


class HistoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='history163-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        git(self.root, 'init', '-q', '-b', 'main')
        self.shas = []

    def commit(self, files, day=1):
        for name, content in files.items():
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if content is None:
                target.unlink()
            else:
                target.write_bytes(content)
        git(self.root, 'add', '-A')
        timestamp = f'2024-01-{day:02d}T12:00:00+00:00'
        git(self.root, '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid',
            'commit', '-q', '--date', timestamp, '-m', 'private narrative excluded',
            date=timestamp)
        sha = git(self.root, 'rev-parse', 'HEAD').strip()
        self.shas.append(sha)
        return sha

    def report(self, **kwargs):
        return mine_history(self.root, architecture=MODEL,
                            config=HistoryConfig(windows=WINDOWS, **kwargs))

    def test_known_counts_and_determinism(self):
        self.commit({'a/x': b'one\n', 'b/y': b'one\n'})
        self.commit({'a/x': b'two\n'}, day=2)
        self.commit({'a/x': b'three\n', 'b/y': b'two\n'}, day=3)
        self.commit({'a/x': b'four\n', 'b/y': b'three\n'}, day=4)
        first, second = self.report(), self.report()
        self.assertEqual(first['metrics'], second['metrics'])
        self.assertEqual(first['metrics_digest'], second['metrics_digest'])
        self.assertTrue(first['coverage']['complete'])
        a = first['metrics']['components']['a']
        self.assertEqual((a['touches'], a['insertions'], a['deletions']), (4, 4, 3))
        self.assertEqual(first['metrics']['pairs'], [{'a': 'a', 'b': 'b', 'commits': [self.shas[i] for i in (0, 2, 3)], 'touches': 3}])
        self.assertEqual(first['identity']['end'], self.shas[-1])
        self.assertNotIn('private narrative', json.dumps(first))
        self.assertEqual(first['observations']['llm_usage']['calls'], 0)

    def test_range_excludes_base_and_pins_end(self):
        first = self.commit({'a/x': b'one\n'})
        second = self.commit({'a/x': b'two\n'})
        self.commit({'a/x': b'three\n'})
        report = mine_history(self.root, architecture=MODEL, base=first, end=second)
        self.assertEqual(report['metrics']['commits_read'], 1)
        self.assertEqual(report['metrics']['components']['a']['commits'], [second])
        self.assertEqual(report['identity']['base'], first)

    def test_rename_is_explicit_delete_add_and_binary_churn_unknown(self):
        self.commit({'a/x': b'one\ntwo\n', 'b/image': b'\0first'})
        self.commit({'a/x': None, 'b/new': b'one\ntwo\n', 'b/image': b'\0second'})
        report = self.report()
        self.assertEqual(report['policies']['renames'], 'delete_add_no_detection')
        a, b = (report['metrics']['components'][name] for name in ('a', 'b'))
        self.assertEqual((a['insertions'], a['deletions']), (2, 2))
        self.assertEqual(b['binary_touches'], 2)
        self.assertFalse(b['line_churn_complete'])
        self.assertEqual(b['insertions'], 2)

    def test_bulk_filter_only_removes_pairs_and_exclusions_are_visible(self):
        self.commit({'a/x': b'a\n', 'b/y': b'b\n', 'c/z': b'c\n', 'vendor/z': b'ignored\n'})
        report = mine_history(self.root, architecture=MODEL,
                              config=HistoryConfig(bulk_components=2, exclude_prefixes=('vendor',)))
        self.assertEqual(report['metrics']['pairs'], [])
        self.assertEqual(report['metrics']['bulk_commits'], self.shas)
        self.assertEqual(report['metrics']['excluded_file_touches'], 1)
        self.assertEqual(report['metrics']['components']['a']['touches'], 1)
        self.assertTrue(report['coverage']['complete'])

    @unittest.skipIf(os.name == 'nt', 'Windows filenames cannot contain tab/newline')
    def test_nul_metadata_preserves_tabs_newlines_unicode(self):
        self.commit({'a/tab\tnew\nline-ю.py': b'first\n'})
        report = mine_history(self.root, architecture=MODEL)
        self.assertEqual(report['metrics']['components']['a']['touches'], 1)
        self.assertTrue(report['coverage']['complete'])

    def test_no_git_never_borrows_ancestor(self):
        self.commit({'a/x': b'x\n'})
        nested = self.root / 'nested'
        nested.mkdir()
        report = mine_history(nested, architecture=MODEL)
        self.assertFalse(report['coverage']['complete'])
        self.assertIn('NO_GIT_HISTORY', report['coverage']['reasons'])
        self.assertEqual(report['facts'], [])

    def test_unborn_empty_and_shallow_are_not_clean_risk(self):
        self.assertIn('UNBORN_HISTORY', self.report()['coverage']['reasons'])
        self.commit({'a/x': b'x\n'})
        (self.root / '.git' / 'shallow').write_text(self.shas[0] + '\n')
        report = self.report()
        self.assertIn('SHALLOW_HISTORY', report['coverage']['reasons'])
        self.assertFalse(report['coverage']['complete'])
        self.assertFalse(any(fact['kind'] == 'increase' for fact in report['facts']))

    def test_commit_and_byte_budgets_cannot_claim_full_history(self):
        self.commit({'a/x': b'x\n'})
        self.commit({'a/x': b'y\n'})
        limited = self.report(max_commits=1)
        self.assertEqual(limited['metrics']['commits_read'], 1)
        self.assertIn('COMMIT_BUDGET', limited['coverage']['reasons'])
        tiny = self.report(max_bytes=64)
        self.assertIn('BYTE_BUDGET', tiny['coverage']['reasons'])
        self.assertFalse(tiny['coverage']['complete'])

    def test_mapping_unknown_ties_and_empty_window_are_disclosed(self):
        self.commit({'other/x': b'x\n'})
        report = self.report()
        self.assertIn('UNMAPPED_PATHS', report['coverage']['reasons'])
        self.assertIn('EMPTY_WINDOW', report['coverage']['reasons'])
        tied = {'system': {'nodes': [{'id': 'one', 'repository_paths': ['other']},
                                    {'id': 'two', 'repository_paths': ['other']}]}, 'rules': {}}
        report = mine_history(self.root, architecture=tied)
        self.assertIn('AMBIGUOUS_MAPPING', report['coverage']['reasons'])

    def test_grounded_advisory_selection_rejects_invented_claims(self):
        self.commit({'a/x': b'x\n', 'b/y': b'y\n'})
        report = self.report()
        selected = select_interpretation(report, [report['facts'][0]['id']])
        self.assertEqual(selected['claims'], report['facts'][:1])
        self.assertEqual(selected['authority'], 'advisory_only')
        with self.assertRaises(ValueError):
            select_interpretation(report, ['b-causes-a'])
        self.assertFalse(any(item['kind'] == 'increase' for item in report['facts']))
        for fact in report['facts']:
            self.assertTrue(set(fact['commits']).issubset(self.shas))

    def test_growth_requires_two_equal_complete_nonempty_windows(self):
        self.commit({'a/x': b'x\n'}, day=1)
        self.commit({'a/x': b'y\n'}, day=3)
        self.commit({'a/x': b'z\n'}, day=4)
        report = self.report()
        growth = [fact for fact in report['facts'] if fact['kind'] == 'increase']
        self.assertEqual(len(growth), 1)
        self.assertEqual(growth[0]['values'], [1, 2])
        self.assertEqual(set(growth[0]['commits']), set(self.shas))
        unequal = mine_history(self.root, architecture=MODEL,
                               config=HistoryConfig(windows=((1704067200, 1704240000), (1704240000, 1704499200))))
        self.assertFalse(any(fact['kind'] == 'increase' for fact in unequal['facts']))
        self.assertIn('WINDOWS_NOT_COMPARABLE', unequal['coverage']['reasons'])

    def test_merges_excluded_but_side_branch_commit_included(self):
        self.commit({'a/x': b'x\n'})
        git(self.root, 'checkout', '-q', '-b', 'side')
        side = self.commit({'b/y': b'y\n'})
        git(self.root, 'checkout', '-q', 'main')
        self.commit({'a/x': b'z\n'})
        git(self.root, 'merge', '--no-ff', '-q', '-m', 'merge', 'side')
        merge = git(self.root, 'rev-parse', 'HEAD').strip()
        report = self.report()
        self.assertEqual(report['metrics']['merge_commits_excluded'], [merge])
        self.assertEqual(report['metrics']['components']['b']['commits'], [side])

    def test_read_only_even_with_external_diff_and_fsmonitor_config(self):
        self.commit({'a/x': b'x\n'})
        sentinel = self.root / 'executed'
        helper = self.root / 'hook.sh'
        helper.write_text('#!/bin/sh\ntouch ' + str(sentinel) + '\n')
        helper.chmod(0o755)
        git(self.root, 'config', 'diff.external', str(helper))
        git(self.root, 'config', 'core.fsmonitor', str(helper))
        before = git(self.root, '-c', 'core.fsmonitor=false', 'status', '--porcelain', '-z')
        self.report()
        self.assertFalse(sentinel.exists())
        self.assertEqual(git(self.root, '-c', 'core.fsmonitor=false', 'status', '--porcelain', '-z'), before)
        self.assertFalse((self.root / '.getzilla').exists())

    def test_bad_ref_and_invalid_config_refuse(self):
        self.commit({'a/x': b'x\n'})
        report = mine_history(self.root, architecture=MODEL, end='--all')
        self.assertIn('INVALID_REVISION', report['coverage']['reasons'])
        for kwargs in ({'max_commits': 0}, {'max_seconds': 0}, {'windows': ((2, 1),)},
                       {'exclude_prefixes': ('../escape',)}, {'bulk_components': True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                HistoryConfig(**kwargs)

    def test_cli_history_does_not_create_graph_cache(self):
        self.commit({'a/x': b'x\n'})
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = main(['history', '--root', str(self.root)])
        self.assertEqual(code, 0)
        report = json.loads(stream.getvalue())['history']
        self.assertIn('MAPPING_UNAVAILABLE', report['coverage']['reasons'])
        self.assertFalse((self.root / '.getzilla').exists())

    def test_recorded_model_response_requires_exact_packet_fact_and_citations(self):
        self.commit({'a/x': b'x\n', 'b/y': b'y\n'})
        report = self.report()
        packet = interpretation_packet(report)
        fact = report['facts'][0]
        response = {'packet_digest': packet['packet_digest'],
                    'claims': [{'id': fact['id'], 'commits': fact['commits']}]}
        output = validate_model_selection(report, response)
        self.assertEqual(output['claims'], [fact])
        self.assertEqual(output['authority'], 'advisory_only')
        for bad in ({**response, 'packet_digest': '0' * 64},
                    {**response, 'claims': [{'id': fact['id'], 'commits': ['0' * 40]}]},
                    {**response, 'claims': [{'id': fact['id'], 'commits': fact['commits'], 'text': 'causal'}]},
                    {**response, 'claims': response['claims'] * 2}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                validate_model_selection(report, bad)
        packet['facts'][0]['value'] = -1
        self.assertNotEqual(packet['facts'][0], report['facts'][0])
        other = copy.deepcopy(report)
        other['architecture_digest'] = '0' * 64
        with self.assertRaises(ValueError):
            validate_model_selection(other, response)

    def test_partial_clone_marker_and_unsupported_mapping_disable_growth(self):
        self.commit({'a/x': b'x\n'}, day=1)
        self.commit({'a/x': b'y\n'}, day=3)
        git(self.root, 'config', 'remote.origin.promisor', 'true')
        report = self.report()
        self.assertIn('PARTIAL_HISTORY', report['coverage']['reasons'])
        self.assertFalse(any(fact['kind'] == 'increase' for fact in report['facts']))
        invalid = {'system': {'nodes': [{'repository_paths': ['a']}]}, 'rules': {}}
        report = mine_history(self.root, architecture=invalid)
        self.assertIn('UNSUPPORTED_MAPPING', report['coverage']['reasons'])

    def test_nonmonotonic_committer_timestamps_do_not_prune_descendants(self):
        first = self.commit({'a/x': b'x\n'}, day=4)
        second = self.commit({'a/x': b'y\n'}, day=1)
        report = self.report()
        self.assertEqual(report['metrics']['components']['a']['commits'], [second, first])
        self.assertEqual(report['metrics']['components']['a']['windows'][1]['commits'], [first])

    def test_acquisition_deadline_returns_incomplete_before_unbounded_read(self):
        self.commit({'a/x': b'x\n'})
        report = mine_history(self.root, architecture=MODEL, config=HistoryConfig(max_seconds=0.000001))
        self.assertIn('TIME_BUDGET', report['coverage']['reasons'])
        self.assertFalse(report['coverage']['complete'])

    def test_time_expired_mid_commit_publishes_no_partial_churn(self):
        self.commit({'a/x': b'x\n', 'a/y': b'y\n'})
        from getzilla.code_graph import history
        original = history.bind_paths
        calls = []

        def expire(*args):
            result = original(*args)
            calls.append(1)
            return result

        # Keep real acquisition; change the analysis clock only after first path
        # has been fully bound. The second path must abort the whole commit.
        original_clock = history.time.monotonic
        def clock():
            return original_clock() + (1000 if calls else 0)

        with mock.patch.object(history, 'bind_paths', expire), mock.patch.object(history.time, 'monotonic', clock):
            report = self.report()
        self.assertIn('TIME_BUDGET', report['coverage']['reasons'])
        self.assertEqual(report['metrics']['components'], {})
        self.assertEqual(report['facts'], [])

    def test_owned_git_runner_caps_output_and_reaps_timeout(self):
        from getzilla import fsx
        from getzilla.code_graph import history_git
        original = fsx.owned_popen
        processes = []
        script = self.root / 'inert_probe.py'
        script.write_text('import sys,time\nsys.stdout.buffer.write(b"x"*1000000)\nsys.stdout.flush()\ntime.sleep(60)\n')

        def create(_command, **kwargs):
            child = original([sys.executable, str(script)], **kwargs)
            processes.append(child)
            return child

        with mock.patch.object(history_git.fsx, 'owned_popen', create):
            reader = GitReader(self.root, max_bytes=128, max_seconds=3)
            with self.assertRaisesRegex(HistoryReadError, 'BYTE_BUDGET'):
                reader.read('rev-parse', 'HEAD')
        self.assertIsNotNone(processes[-1].poll())
        self.assertLessEqual(reader.peak_buffer_bytes, 129)
        script.write_text('import sys,time\nsys.stderr.buffer.write(b"x"*1000000)\nsys.stderr.flush()\ntime.sleep(60)\n')
        with mock.patch.object(history_git.fsx, 'owned_popen', create):
            reader = GitReader(self.root, max_bytes=128, max_seconds=3)
            with self.assertRaisesRegex(HistoryReadError, 'BYTE_BUDGET'):
                reader.read('rev-parse', 'HEAD')
        self.assertIsNotNone(processes[-1].poll())
        self.assertLessEqual(reader.peak_buffer_bytes, 129)
        script.write_text('import time\ntime.sleep(60)\n')
        with mock.patch.object(history_git.fsx, 'owned_popen', create):
            reader = GitReader(self.root, max_bytes=128, max_seconds=0.05)
            with self.assertRaisesRegex(HistoryReadError, 'TIME_BUDGET'):
                reader.read('rev-parse', 'HEAD')
        self.assertIsNotNone(processes[-1].poll())

    def test_reader_drops_host_git_overrides_and_disables_project_execution(self):
        self.commit({'a/x': b'x\n'})
        from getzilla.code_graph import history_git
        from getzilla import fsx
        original = fsx.owned_popen
        seen = []

        def create(command, **kwargs):
            seen.append((command, kwargs['env']))
            return original(command, **kwargs)

        with mock.patch.dict(os.environ, {'GIT_DIR': '/not-authoritative', 'GIT_CONFIG_COUNT': '1'}), \
                mock.patch.object(history_git.fsx, 'owned_popen', create):
            report = self.report()
        self.assertNotIn('GIT_READ_FAILED', report['coverage']['reasons'])
        self.assertTrue(seen)
        for command, environment in seen:
            self.assertNotIn('GIT_DIR', environment)
            self.assertNotIn('GIT_CONFIG_COUNT', environment)
            self.assertEqual(environment['GIT_NO_LAZY_FETCH'], '1')
            self.assertEqual(environment['GIT_NO_REPLACE_OBJECTS'], '1')
            self.assertIn('protocol.allow=never', command)
            self.assertEqual(environment['GIT_OPTIONAL_LOCKS'], '0')

    @unittest.skipIf(os.name == 'nt', 'Windows directories cannot end in newline')
    def test_repository_root_newline_is_not_stripped(self):
        nested = self.root / 'repo\n'
        nested.mkdir()
        git(nested, 'init', '-q', '-b', 'main')
        (nested / 'a').mkdir()
        (nested / 'a/x').write_bytes(b'x\n')
        git(nested, 'add', '-A')
        git(nested, 'commit', '-q', '-m', 'root')
        report = mine_history(nested, architecture=MODEL)
        self.assertTrue(report['coverage']['complete'], report['coverage'])

    def test_declared_lf_line_algorithm_and_complexity_limits(self):
        from getzilla.code_graph.history import _line_churn
        for old, new, expected in ((b'', b'one\ntwo', (2, 0)), (b'a', b'a\n', (1, 1)),
                                   (b'a\rb\n', b'a\rc\n', (1, 1)), (b'a\n', b'', (0, 1))):
            with self.subTest(old=old, new=new):
                self.assertEqual(_line_churn(old, new, HistoryConfig()), expected)
        with self.assertRaisesRegex(HistoryReadError, 'LINE_DIFF_BUDGET'):
            _line_churn(b'a\nb\n', b'c\nd\n', HistoryConfig(max_line_comparisons=3))

    def test_fact_size_budgets_refuse_combinatorial_pairs_and_partial_commits(self):
        self.commit({'a/x': b'x\n', 'b/y': b'y\n', 'c/z': b'z\n'})
        report = self.report(max_pair_observations=2)
        self.assertIn('PAIR_BUDGET', report['coverage']['reasons'])
        self.assertEqual(report['metrics']['components'], {})
        self.assertEqual(report['metrics']['pairs'], [])
        report = self.report(max_file_touches=2)
        self.assertIn('FILE_TOUCH_BUDGET', report['coverage']['reasons'])
        self.assertEqual(report['metrics']['components'], {})

    def test_thread_start_failure_reaps_the_owned_process(self):
        from getzilla import fsx
        from getzilla.code_graph import history_git
        original = fsx.owned_popen
        processes = []
        def create(command, **kwargs):
            child = original(command, **kwargs)
            processes.append(child)
            return child
        with mock.patch.object(history_git.fsx, 'owned_popen', create), \
                mock.patch.object(history_git.threading.Thread, 'start', side_effect=RuntimeError('inert')):
            with self.assertRaisesRegex(HistoryReadError, 'LOCAL_RESOURCE_UNAVAILABLE'):
                GitReader(self.root, max_bytes=1000, max_seconds=2).read('status', '--short')
        self.assertIsNotNone(processes[0].poll())

    @unittest.skipIf(os.name == 'nt', 'Raw byte filenames are a POSIX fixture')
    def test_non_utf8_filename_is_not_split_or_executed(self):
        self.commit({'a/' + os.fsdecode(b'raw-\xff;touch sentinel'): b'x\n'})
        report = mine_history(self.root, architecture=MODEL)
        self.assertTrue(report['coverage']['complete'], report['coverage'])
        self.assertEqual(report['metrics']['components']['a']['touches'], 1)
        self.assertFalse((self.root / 'sentinel').exists())

    def test_missing_blob_returns_incomplete_without_repair_or_fetch(self):
        self.commit({'a/x': b'x\n'})
        oid = git(self.root, 'rev-parse', 'HEAD:a/x')
        object_path = self.root / '.git/objects' / oid[:2] / oid[2:]
        object_path.unlink()
        git(self.root, 'config', 'core.worktree', str(self.root))
        report = mine_history(self.root, architecture=MODEL)
        self.assertFalse(report['coverage']['complete'], report)
        self.assertIn('GIT_READ_FAILED', report['coverage']['reasons'])
        self.assertFalse(object_path.exists())
        self.assertEqual(report['facts'], [])

    def test_local_attributes_cannot_change_binary_or_line_count_policy(self):
        self.commit({'a/x': b'one\ntwo\n'})
        self.commit({'a/x': b'one\nthree\n'})
        baseline = self.report()
        (self.root / '.git/info/attributes').write_text('* -diff\n')
        git(self.root, 'config', 'diff.algorithm', 'histogram')
        git(self.root, 'config', 'diff.indentHeuristic', 'true')
        changed = self.report()
        self.assertEqual(baseline['metrics'], changed['metrics'])
        self.assertEqual(baseline['metrics_digest'], changed['metrics_digest'])
        self.assertTrue(changed['metrics']['components']['a']['line_churn_complete'])
        (self.root / '.git/info/attributes').write_text('* diff=evil\n')
        git(self.root, 'config', 'diff.evil.binary', 'true')
        git(self.root, 'config', 'diff.evil.xfuncname', '[')
        self.assertEqual(baseline['metrics_digest'], self.report()['metrics_digest'])

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'POSIX FIFO control')
    def test_worktree_attributes_fifo_is_not_read(self):
        self.commit({'a/x': b'x\n'})
        os.mkfifo(self.root / '.gitattributes')
        report = mine_history(self.root, architecture=MODEL, config=HistoryConfig(max_seconds=2))
        self.assertTrue(report['coverage']['complete'], report['coverage'])

    def substitute_object(self, oid, kind, content):
        path = self.root / '.git/objects' / oid[:2] / oid[2:]
        replacement = path.with_name(path.name + '.owned-fixture')
        replacement.write_bytes(zlib.compress(kind.encode() + b' ' + str(len(content)).encode() + b'\0' + content))
        replacement.replace(path)

    def test_wrong_hash_blob_cannot_change_sha_grounded_churn(self):
        self.commit({'a/x': b'one\n'})
        baseline = mine_history(self.root, architecture=MODEL)
        oid = git(self.root, 'rev-parse', 'HEAD:a/x')
        self.substitute_object(oid, 'blob', b'one\ntwo\nthree\n')
        report = mine_history(self.root, architecture=MODEL)
        self.assertEqual(baseline['identity'], report['identity'])
        self.assertFalse(report['coverage']['complete'])
        self.assertIn('OBJECT_ID_MISMATCH', report['coverage']['reasons'])
        self.assertEqual(report['metrics']['components'], {})

    def test_wrong_hash_commit_cannot_move_window_evidence(self):
        self.commit({'a/x': b'one\n'}, day=1)
        self.commit({'a/x': b'two\n'}, day=3)
        self.commit({'a/x': b'three\n'}, day=4)
        self.commit({'a/x': b'four\n'}, day=4)
        oid = self.shas[0]
        raw = git(self.root, 'cat-file', 'commit', oid).encode() + b'\n'
        # Preserve a well-formed commit under the old filename, moving only the
        # declared committer timestamp; Git will read it without hash admission.
        raw = b'\n'.join(line.replace(b'1704110400 +0000', b'1704283200 +0000')
                         if line.startswith(b'committer ') else line for line in raw.split(b'\n'))
        self.substitute_object(oid, 'commit', raw)
        report = self.report()
        self.assertFalse(report['coverage']['complete'])
        self.assertIn('OBJECT_ID_MISMATCH', report['coverage']['reasons'])
        self.assertFalse(any(fact['kind'] == 'increase' for fact in report['facts']))
        self.assertTrue(all(oid not in fact['commits'] for fact in report['facts']))

    def test_wrong_hash_tree_cannot_hide_paths(self):
        self.commit({'a/x': b'x\n'})
        tree = git(self.root, 'rev-parse', 'HEAD^{tree}')
        self.substitute_object(tree, 'tree', b'')
        report = mine_history(self.root, architecture=MODEL)
        self.assertFalse(report['coverage']['complete'])
        self.assertIn('OBJECT_ID_MISMATCH', report['coverage']['reasons'])
        self.assertEqual(report['metrics']['components'], {})

    def test_graft_metadata_does_not_rewrite_verified_ancestry(self):
        self.commit({'a/x': b'one\n'})
        self.commit({'a/x': b'two\n'})
        before = mine_history(self.root, architecture=MODEL)
        (self.root / '.git/info/grafts').write_text(self.shas[-1] + '\n')
        git(self.root, 'config', 'advice.graftFileDeprecated', 'false')
        after = mine_history(self.root, architecture=MODEL)
        self.assertTrue(after['coverage']['complete'], after['coverage'])
        self.assertEqual(after['metrics_digest'], before['metrics_digest'])
        self.assertEqual(after['metrics']['components']['a']['touches'], 2)

    def test_annotated_tag_object_is_verified_before_peeling(self):
        self.commit({'a/x': b'one\n'})
        git(self.root, 'tag', '-a', '-m', 'ordinary', 'fixture-tag')
        positive = mine_history(self.root, architecture=MODEL, end='fixture-tag')
        self.assertTrue(positive['coverage']['complete'])
        tag_oid = git(self.root, 'rev-parse', 'fixture-tag')
        raw = git(self.root, 'cat-file', 'tag', tag_oid).encode() + b'\n'
        self.substitute_object(tag_oid, 'tag', raw.replace(b'ordinary', b'changed'))
        report = mine_history(self.root, architecture=MODEL, end='fixture-tag')
        self.assertFalse(report['coverage']['complete'])
        self.assertIn('OBJECT_ID_MISMATCH', report['coverage']['reasons'])

    def test_sha256_object_format_and_tamper_controls(self):
        nested = self.root / 'sha256'
        nested.mkdir()
        git(nested, 'init', '-q', '-b', 'main', '--object-format=sha256')
        (nested / 'a').mkdir()
        (nested / 'a/x').write_bytes(b'one\n')
        git(nested, 'add', '-A')
        git(nested, 'commit', '-q', '-m', 'ordinary')
        positive = mine_history(nested, architecture=MODEL)
        self.assertTrue(positive['coverage']['complete'], positive['coverage'])
        self.assertEqual(len(positive['identity']['end']), 64)
        oid = git(nested, 'rev-parse', 'HEAD:a/x')
        path = nested / '.git/objects' / oid[:2] / oid[2:]
        replacement = path.with_name(path.name + '.owned-fixture')
        replacement.write_bytes(zlib.compress(b'blob 8\0one\ntwo\n'))
        replacement.replace(path)
        report = mine_history(nested, architecture=MODEL)
        self.assertIn('OBJECT_ID_MISMATCH', report['coverage']['reasons'])

    def test_range_membership_handles_branch_diverging_before_base(self):
        self.commit({'a/x': b'x\n'})
        git(self.root, 'checkout', '-q', '-b', 'side')
        side = self.commit({'b/y': b'y\n'})
        git(self.root, 'checkout', '-q', 'main')
        base = self.commit({'a/x': b'z\n'})
        git(self.root, 'merge', '--no-ff', '-q', '-m', 'merge', 'side')
        report = mine_history(self.root, architecture=MODEL, base=base)
        self.assertTrue(report['coverage']['complete'], report['coverage'])
        self.assertEqual(report['metrics']['components'], {'b': report['metrics']['components']['b']})
        self.assertEqual(report['metrics']['components']['b']['commits'], [side])

    def test_graft_warning_is_not_mistaken_for_object_payload(self):
        self.commit({'a/x': b'one\n'})
        self.commit({'a/x': b'two\n'})
        before = mine_history(self.root, architecture=MODEL)
        (self.root / '.git/info/grafts').write_text(self.shas[-1] + '\n')
        after = mine_history(self.root, architecture=MODEL)
        self.assertTrue(after['coverage']['complete'], after['coverage'])
        self.assertEqual(after['metrics_digest'], before['metrics_digest'])

    def test_raw_git_stdout_and_diagnostics_are_framed_separately(self):
        from getzilla import fsx
        from getzilla.code_graph import history_git
        original = fsx.owned_popen
        script = self.root / 'inert_probe.py'
        script.write_text('import sys\nsys.stderr.buffer.write(b"diagnostic")\nsys.stdout.buffer.write(b"raw-object-bytes")\n')
        def create(_command, **kwargs):
            return original([sys.executable, str(script)], **kwargs)
        with mock.patch.object(history_git.fsx, 'owned_popen', create):
            code, output = GitReader(self.root, max_bytes=1000, max_seconds=2).read('cat-file', 'blob', 'inert')
        self.assertEqual(code, 0)
        self.assertEqual(output, b'raw-object-bytes')

    def test_verified_commit_cannot_point_to_a_blob_as_tree(self):
        self.commit({'a/x': b'x\n'})
        raw = git(self.root, 'cat-file', 'commit', 'HEAD').encode() + b'\n'
        tree = git(self.root, 'rev-parse', 'HEAD^{tree}')
        blob = git(self.root, 'rev-parse', 'HEAD:a/x')
        malformed = raw.replace(('tree ' + tree).encode(), ('tree ' + blob).encode())
        payload = b'commit ' + str(len(malformed)).encode() + b'\0' + malformed
        oid = hashlib.sha1(payload, usedforsecurity=False).hexdigest()
        path = self.root / '.git/objects' / oid[:2] / oid[2:]
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(zlib.compress(payload))
        git(self.root, 'update-ref', 'refs/heads/main', oid)
        report = mine_history(self.root, architecture=MODEL)
        self.assertIn('OBJECT_TYPE_MISMATCH', report['coverage']['reasons'])
        self.assertEqual(report['facts'], [])

    def test_packed_objects_and_replace_refs_preserve_declared_history(self):
        self.commit({'a/x': b'one\n'})
        self.commit({'a/x': b'two\n'})
        before = mine_history(self.root, architecture=MODEL)
        git(self.root, 'repack', '-a', '-d')
        packed = mine_history(self.root, architecture=MODEL)
        self.assertEqual(before['metrics_digest'], packed['metrics_digest'])
        git(self.root, 'replace', self.shas[-1], self.shas[0])
        replaced = mine_history(self.root, architecture=MODEL)
        self.assertEqual(before['metrics_digest'], replaced['metrics_digest'])

    def test_integrity_failure_preserves_already_verified_prefix(self):
        self.commit({'a/x': b'one\n'}, day=1)
        self.commit({'a/x': b'two\n'}, day=2)
        self.commit({'a/x': b'three\n'}, day=3)
        oid = git(self.root, 'rev-parse', 'HEAD:a/x')
        self.substitute_object(oid, 'blob', b'three\nfour\n')
        report = mine_history(self.root, architecture=MODEL)
        self.assertIn('OBJECT_ID_MISMATCH', report['coverage']['reasons'])
        self.assertEqual(report['metrics']['components']['a']['touches'], 2)
        self.assertEqual(report['metrics']['components']['a']['commits'], self.shas[:2])
        self.assertFalse(any(fact['kind'] == 'increase' for fact in report['facts']))

    def test_merge_base_frontier_excludes_old_crossover_commits(self):
        self.commit({'a/x': b'root\n'})
        git(self.root, 'checkout', '-q', '-b', 'old-chain')
        middle = self.commit({'a/x': b'old\n'})
        self.commit({'b/y': b'base-branch\n'})
        git(self.root, 'checkout', '-q', 'main')
        git(self.root, 'merge', '--no-ff', '-q', '-m', 'base merge', 'old-chain')
        base = git(self.root, 'rev-parse', 'HEAD')
        git(self.root, 'checkout', '-q', '-b', 'side', middle)
        new = self.commit({'c/z': b'new\n'})
        git(self.root, 'checkout', '-q', 'main')
        git(self.root, 'merge', '--no-ff', '-q', '-m', 'end merge', 'side')
        report = mine_history(self.root, architecture=MODEL, base=base)
        self.assertTrue(report['coverage']['complete'], report['coverage'])
        self.assertEqual(set(report['metrics']['components']), {'c'})
        self.assertEqual(report['metrics']['components']['c']['commits'], [new])

    def test_tree_file_directory_and_mode_transitions(self):
        self.commit({'a/x': b'one\n'})
        self.commit({'a/x': None, 'a/x/y': b'two\n'})
        (self.root / 'a/x/y').unlink()
        (self.root / 'a/x').rmdir()
        self.commit({'a/x': b'three\n'})
        report = mine_history(self.root, architecture=MODEL)
        value = report['metrics']['components']['a']
        self.assertTrue(report['coverage']['complete'], report['coverage'])
        self.assertEqual((value['touches'], value['file_touches'], value['insertions'], value['deletions']), (3, 5, 3, 2))
        git(self.root, 'update-index', '--chmod=+x', 'a/x')
        git(self.root, 'commit', '-q', '-m', 'mode only')
        changed = mine_history(self.root, architecture=MODEL)['metrics']['components']['a']
        self.assertEqual((changed['touches'], changed['file_touches'], changed['insertions'], changed['deletions']), (4, 6, 3, 2))

    def test_revision_ancestry_expressions_do_not_use_unverified_git_graph(self):
        self.commit({'a/x': b'one\n'})
        self.commit({'a/x': b'two\n'})
        report = mine_history(self.root, architecture=MODEL, end='HEAD~1')
        self.assertIn('INVALID_REVISION', report['coverage']['reasons'])
        self.assertEqual(report['facts'], [])

    def test_reader_interrupt_after_both_streams_start_reaps_and_joins(self):
        from getzilla import fsx
        from getzilla.code_graph import history_git
        original_create = fsx.owned_popen
        original_start = history_git.threading.Thread.start
        children, started = [], []
        script = self.root / 'inert_probe.py'
        script.write_text('import time\ntime.sleep(60)\n')
        def create(_command, **kwargs):
            child = original_create([sys.executable, str(script)], **kwargs)
            children.append(child)
            return child
        def start(thread):
            original_start(thread)
            started.append(thread)
            if len(started) == 2:
                raise KeyboardInterrupt('owned fixture interruption')
        with mock.patch.object(history_git.fsx, 'owned_popen', create), \
                mock.patch.object(history_git.threading.Thread, 'start', start):
            with self.assertRaises(KeyboardInterrupt):
                GitReader(self.root, max_bytes=1000, max_seconds=2).read('cat-file', 'blob', 'inert')
        self.assertIsNotNone(children[0].poll())
        self.assertTrue(started)
        self.assertTrue(all(not thread.is_alive() for thread in started))


if __name__ == '__main__':
    unittest.main()
