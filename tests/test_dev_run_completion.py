"""Declared DEV checks remain work after ordinary source receipts pass."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest

from tests._support import observed_context, prepare_review_source, project_copy
import tests.test_stop_continuation as fixtures
from getzilla import state
from getzilla.change import transition
from getzilla.receipts import validate_evidence, write_receipt
from getzilla.util import now_utc


class DevRunCompletionTests(unittest.TestCase):
    package = fixtures.StopContinuationTests.package
    root_stop = fixtures.StopContinuationTests.root_stop
    REMAINING = ('DEV_ADDITIONAL_RESULTS', 'DEV_OTHER_MODELS', 'DEV_INTERVALS')

    def prepare(self, root):
        path = self.package(root, '- [x] Deliver all source changes.\n', ('verification',))
        destination = root / '.getzilla/runtime/dev-fixture/state.json'
        destination.parent.mkdir()
        destination.write_text(json.dumps({'target': 'isolated-pulse-dev', 'revision': 'fixture-r1',
                                           'features': ['DEV_EXPERT']}))
        checker = root / 'dev_checker.py'
        checker.write_text(
            'import json, pathlib, sys\n'
            'target = json.loads(pathlib.Path(sys.argv[1]).read_text())\n'
            'observed = sys.argv[2] in target["features"]\n'
            'print(json.dumps({"target": target["target"], "revision": target["revision"], '
            '"feature": sys.argv[2], "observed": observed}, sort_keys=True))\n'
            'sys.exit(0 if observed else 1)\n')
        source = prepare_review_source(root)
        document = json.loads((path / 'state.json').read_text())
        document['evidence_accounting']['obligations'] = [
            {'id': kind, 'kind': 'receipt', 'receipt_kind': kind, 'status': 'not_run',
             'reason': 'Current receipts are maintained by the existing receipt APIs.'}
            for kind in state.get_active_route(root)['required_evidence']]
        (path / 'state.json').write_text(json.dumps(document))
        rows = [self.probe(root, path, 'DEV_EXPERT')]
        rows.extend({'id': item, 'kind': 'run', 'status': 'not_run',
                     'reason': 'Merged source; DEV readback is still missing.'} for item in self.REMAINING)
        self.rows(path, rows)
        self.receipts(root, source)
        return path, source, destination

    def rows(self, path, rows):
        document = json.loads((path / 'state.json').read_text())
        receipts = [row for row in document['evidence_accounting']['obligations'] if row['kind'] == 'receipt']
        document['evidence_accounting']['obligations'] = receipts + rows
        (path / 'state.json').write_text(json.dumps(document))

    def probe(self, root, path, feature):
        command = [sys.executable, 'dev_checker.py', '.getzilla/runtime/dev-fixture/state.json', feature]
        result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=5)
        report = f'evidence/{feature}.json'
        (path / report).write_text(result.stdout)
        self.assertEqual(json.loads(result.stdout)['target'], 'isolated-pulse-dev')
        return {'id': feature, 'kind': 'run', 'status': 'recorded',
                'outcome': 'pass' if result.returncode == 0 else 'fail',
                'recorded_at': now_utc(), 'reference': report, 'command': command}

    def receipts(self, root, source):
        for kind in state.get_active_route(root)['required_evidence']:
            write_receipt(root, kind, 'pass', expected_context=observed_context(root),
                          **({} if kind == 'verification' else source))
        self.assertEqual(validate_evidence(root, state.get_active_route(root)), [])

    def ready(self, root):
        change = state.get_active_change(root)['change_id']
        for target in ('scoped', 'approved', 'implementing', 'verifying', 'reviewing', 'ready'):
            transition(root, change, target, 'Isolated fixture source receipts are current.')
        return change

    def test_current_source_receipts_do_not_hide_pending_or_failed_dev_runs(self):
        with project_copy(git=True) as root:
            path, source, _ = self.prepare(root)
            before = (path / 'state.json').read_bytes()
            route = state.get_active_route(root)
            pending = self.root_stop(root)
            self.assertEqual(pending.get('decision'), 'block', pending)
            for feature in self.REMAINING:
                self.assertIn(feature, pending['reason'])
            self.assertNotIn('DEV_EXPERT:', pending['reason'])
            self.assertEqual((path / 'state.json').read_bytes(), before)
            self.assertEqual(state.get_active_route(root), route)
            self.rows(path, [self.probe(root, path, feature) for feature in ('DEV_EXPERT', *self.REMAINING)])
            self.receipts(root, source)
            failed = self.root_stop(root)
            self.assertEqual(failed.get('decision'), 'block', failed)
            self.assertIn('recorded (fail)', failed['reason'])

    def test_terminal_package_closure_requires_observed_dev_checks(self):
        with project_copy(git=True) as root:
            path, source, destination = self.prepare(root)
            change = self.ready(root)
            before = (path / 'state.json').read_bytes()
            route = state.get_active_route(root)
            with self.assertRaisesRegex(ValueError, 'DEV_ADDITIONAL_RESULTS'):
                transition(root, change, 'released', 'Attempt premature fixture closure.')
            self.assertEqual((path / 'state.json').read_bytes(), before)
            self.assertEqual(state.get_active_route(root), route)
            destination.write_text(json.dumps({'target': 'isolated-pulse-dev', 'revision': 'fixture-r2',
                                               'features': ['DEV_EXPERT', *self.REMAINING]}))
            self.rows(path, [self.probe(root, path, feature) for feature in ('DEV_EXPERT', *self.REMAINING)])
            self.receipts(root, source)
            observed = self.root_stop(root)
            self.assertNotEqual(observed.get('decision'), 'block', observed)
            released = transition(root, change, 'released', 'All fixture DEV checks observed on revision r2.')
            self.assertEqual(released['status'], 'released')

    def test_missing_passing_dev_report_still_blocks_terminal_closure(self):
        with project_copy(git=True) as root:
            path, source, destination = self.prepare(root)
            destination.write_text(json.dumps({'target': 'isolated-pulse-dev', 'revision': 'fixture-r2',
                                               'features': ['DEV_EXPERT', *self.REMAINING]}))
            self.rows(path, [self.probe(root, path, feature) for feature in ('DEV_EXPERT', *self.REMAINING)])
            self.receipts(root, source)
            change = self.ready(root)
            (path / 'evidence/DEV_INTERVALS.json').unlink()
            before = (path / 'state.json').read_bytes()
            with self.assertRaisesRegex(ValueError, 'evidence|file_missing'):
                transition(root, change, 'released', 'Missing fixture readback report.')
            self.assertEqual((path / 'state.json').read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
