"""Source-plan accounting and sole-writer admission on isolated public fixtures."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tests.branch_support import git

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import change, state
from getzilla.continuity import MAX_ITEM_BYTES, submit
from getzilla.package_status import inspect_package
from getzilla.review_plan import reconcile_route

OWNER = 'public-reconciliation-fixture'
REQUIRED = {'verification', 'code_review', 'data_review', 'release_review', 'security_review'}


class ReconciliationStateTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='getzilla-reconciliation-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.environment = mock.patch.dict(os.environ, {'GETZILLA_SESSION_ID': OWNER})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.addCleanup(state.bind_session, None)
        state.bind_session(OWNER)
        for name in ('routing.json', 'diff-risk-rules.json'):
            path = self.root / '.getzilla/config' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / '.getzilla/config' / name, path)
        shutil.copytree(ROOT / '.getzilla/templates/change', self.root / '.getzilla/templates/change')
        (self.root / '.gitignore').write_text('.getzilla/runtime/\n')
        (self.root / 'app.py').write_text('value = 1\n')
        git(self.root, 'init', '-q', '-b', 'work')
        git(self.root, 'config', 'gc.auto', '0')
        git(self.root, 'config', 'maintenance.auto', 'false')
        self.commit()
        git(self.root, 'update-ref', 'refs/remotes/origin/main', git(self.root, 'rev-parse', 'HEAD'))

    def commit(self):
        git(self.root, 'add', '.')
        git(self.root, 'commit', '-qm', 'public fixture')

    def route(self, *, package=True, prompt='Implement a large ordinary feature.'):
        submit(self.root, prompt, OWNER)
        if package:
            change.start_change(self.root)
            self.package = self.root / state.get_active_change(self.root)['path']
            self.path = self.package / 'state.json'
        return state.get_active_route(self.root)

    def risk_diff(self):
        for name, text in (('auth/login.py', 'def check():\n    return True\n'),
                           ('migrations/001.sql', 'CREATE TABLE public_fixture (id INT);\n'),
                           ('.github/workflows/public.yml', 'name: public-fixture\n')):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        self.commit()

    def read(self):
        return json.loads(self.path.read_text())

    def write(self, document):
        self.path.write_text(json.dumps(document, indent=2) + '\n')

    def kinds(self):
        return {row['receipt_kind'] for row in self.read()['evidence_accounting']['obligations'] if row['kind'] == 'receipt'}

    def test_new_selected_rows_preserve_records_history_and_exact_plan(self):
        original = self.route()
        document = self.read()
        report = self.package / 'evidence/public-failure.md'
        report.write_text('FAIL: actual public diagnostic fixture, not a qualifying source review.\n')
        row = document['evidence_accounting']['obligations'][1]
        row.update(status='recorded', outcome='fail', recorded_at='2026-01-01T00:00:00+00:00',
                   reference='evidence/public-failure.md', retained_extension={'value': 7})
        row.pop('reason')
        document['evidence_accounting']['obligations'].append(
            {'id': 'public-run', 'kind': 'run', 'status': 'recorded', 'outcome': 'fail',
             'recorded_at': '2026-01-01T00:00:00+00:00', 'reference': 'evidence/public-failure.md',
             'command': ['public-fixture'], 'retained': True})
        document['retained_extension'] = {'unchanged': True}
        self.write(document)
        self.risk_diff()
        current = reconcile_route(self.root)
        self.assertEqual(current['risk_assessment']['status'], 'complete')
        self.assertEqual(set(current['required_evidence']), REQUIRED)
        self.assertEqual(self.kinds(), REQUIRED)
        after = self.read()
        self.assertEqual(after['evidence_accounting']['obligations'][:3], document['evidence_accounting']['obligations'])
        self.assertEqual(after['history'], document['history'])
        self.assertEqual(after['retained_extension'], document['retained_extension'])
        self.assertEqual(report.read_text(), 'FAIL: actual public diagnostic fixture, not a qualifying source review.\n')
        for row in after['evidence_accounting']['obligations'][3:]:
            self.assertEqual(row['status'], 'not_run')
            self.assertTrue(row['reason'])
            self.assertNotIn('outcome', row)
        for key in ('route_id', 'task', 'logical_task_id', 'session_id', 'origin_session_id', 'authority_epoch', 'context'):
            self.assertEqual(current[key], original[key])
        self.assertEqual(current['required_evidence'], current['review_plan']['required_evidence'])

    def test_replay_and_reduced_plan_never_duplicate_or_erase_accounting(self):
        self.route()
        self.risk_diff()
        reconcile_route(self.root)
        self.assertEqual(self.kinds(), REQUIRED)
        stable = self.path.read_bytes()
        reconcile_route(self.root)
        self.assertEqual(self.path.read_bytes(), stable)
        git(self.root, 'rm', '-r', 'auth', 'migrations', '.github')
        self.commit()
        reduced = reconcile_route(self.root)
        self.assertEqual(set(reduced['required_evidence']), {'verification', 'code_review'})
        self.assertEqual(self.path.read_bytes(), stable)

    def test_exact_utf8_output_boundary_preserves_state_and_route_on_refusal(self):
        from getzilla.package_status import MAX_FILE_BYTES, read_package_file
        self.assertEqual(MAX_FILE_BYTES, 262144)
        self.route()
        original = self.read()
        self.risk_diff()
        reconcile_route(self.root)
        # Calibrate only the real serialized row-growth overhead on this fixture.
        # The independent oracle is the ordinary reader's fixed byte limit.
        expanded = self.read()
        expanded['retained-public-padding'] = ''
        def encoded(document):
            return (json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2,
                               allow_nan=False) + '\n').encode('utf-8')
        overhead = len(encoded(expanded))
        for character in ('p', '界'):
            for target in (262143, 262144, 262145):
                with self.subTest(character=character, output_bytes=target):
                    remaining = target - overhead
                    width = len(character.encode('utf-8'))
                    padding = character * (remaining // width) + 'p' * (remaining % width)
                    projected = {**expanded, 'retained-public-padding': padding}
                    self.assertEqual(len(encoded(projected)), target)
                    document = {**original, 'retained-public-padding': padding}
                    state.durable_json(self.root, self.path, document)
                    relative = self.path.relative_to(self.root).as_posix()
                    before = read_package_file(self.root, relative)
                    self.assertLess(len(before), MAX_FILE_BYTES)
                    authority = state.get_active_route(self.root)
                    with mock.patch.object(change, 'durable_json', wraps=change.durable_json) as publication:
                        if target > MAX_FILE_BYTES:
                            with self.assertRaises(ValueError):
                                reconcile_route(self.root)
                            self.assertEqual(publication.call_count, 0)
                            self.assertEqual(self.path.read_bytes(), before)
                            self.assertEqual(state.get_active_route(self.root), authority)
                        else:
                            try:
                                current = reconcile_route(self.root)
                            except ValueError as error:
                                self.fail(f'ordinary-reader-admitted output refused: {error}')
                            self.assertEqual(publication.call_count, 1)
                            self.assertEqual(len(read_package_file(self.root, relative)), target)
                            self.assertEqual(self.kinds(), REQUIRED)
                            self.assertEqual(self.read()['retained-public-padding'], padding)
                            self.assertEqual(self.read()['evidence_accounting']['obligations'][:2],
                                             original['evidence_accounting']['obligations'])
                            observed = inspect_package(self.root, current, state.get_active_change(self.root))
                            self.assertFalse(any(row['code'] == 'file_too_large' for row in observed['findings']))
    def test_no_package_and_legacy_warning_do_not_create_typed_acceptance(self):
        self.route(package=False)
        self.risk_diff()
        self.assertEqual(set(reconcile_route(self.root)['required_evidence']), REQUIRED)
        self.assertIsNone(state.get_active_change(self.root))
        change.start_change(self.root)
        self.package = self.root / state.get_active_change(self.root)['path']
        self.path = self.package / 'state.json'
        legacy = self.read()
        legacy.pop('evidence_accounting')
        self.write(legacy)
        current = reconcile_route(self.root)
        self.assertNotIn('evidence_accounting', self.read())
        findings = inspect_package(self.root, current, state.get_active_change(self.root))['findings']
        self.assertTrue(any(row['code'] == 'legacy_evidence_accounting' for row in findings))

    def test_malformed_duplicate_unknown_and_full_accounting_refuse(self):
        self.route()
        self.risk_diff()
        original = self.read()
        variants = []
        for field, value in (('schema_version', 99), ('obligations', {})):
            doc = copy.deepcopy(original)
            doc['evidence_accounting'][field] = value
            variants.append(doc)
        for mutation in ('duplicate-id', 'duplicate-kind', 'unknown-kind', 'invalid-status', 'full'):
            doc = copy.deepcopy(original)
            rows = doc['evidence_accounting']['obligations']
            if mutation == 'duplicate-id':
                rows.append({**rows[0], 'receipt_kind': 'data_review'})
            elif mutation == 'duplicate-kind':
                rows.append({**rows[0], 'id': 'another-id'})
            elif mutation == 'unknown-kind':
                rows.append({**rows[0], 'id': 'unknown', 'receipt_kind': 'invented'})
            elif mutation == 'invalid-status':
                rows[0]['status'] = 'accepted'
            else:
                rows.extend({'id': f'run-{n}', 'kind': 'run', 'status': 'not_run', 'reason': 'not run'} for n in range(62))
            variants.append(doc)
        for doc in variants:
            with self.subTest(accounting=doc['evidence_accounting']):
                self.write(doc)
                before, authority = self.path.read_bytes(), state.get_active_route(self.root)
                with self.assertRaises((ValueError, RuntimeError)):
                    reconcile_route(self.root)
                self.assertEqual(self.path.read_bytes(), before)
                self.assertEqual(state.get_active_route(self.root), authority)

    def test_symlink_and_mismatched_package_refuse_without_foreign_writes(self):
        self.route()
        self.risk_diff()
        original = self.read()
        foreign = self.root / '.getzilla/runtime/foreign-state.json'
        foreign.write_bytes(self.path.read_bytes())
        self.path.unlink()
        self.path.symlink_to(foreign)
        before, authority = foreign.read_bytes(), state.get_active_route(self.root)
        with self.assertRaises((ValueError, RuntimeError, OSError)):
            reconcile_route(self.root)
        self.assertEqual(foreign.read_bytes(), before)
        self.assertEqual(state.get_active_route(self.root), authority)
        self.path.unlink()
        original['route_id'] = 'different-public-route'
        self.write(original)
        with self.assertRaises((ValueError, RuntimeError)):
            reconcile_route(self.root)
        self.assertEqual(state.get_active_route(self.root), authority)

    def test_publication_cuts_are_not_success_and_retry_is_idempotent(self):
        self.route()
        self.risk_diff()
        original, authority = self.path.read_bytes(), state.get_active_route(self.root)
        native = change.durable_json
        for after in (False, True):
            self.path.write_bytes(original)
            def interrupted(root, path, document):
                if after:
                    native(root, path, document)
                raise OSError('controlled public publication cut')
            with self.subTest(after=after), mock.patch.object(change, 'durable_json', interrupted):
                with self.assertRaises(OSError):
                    reconcile_route(self.root)
            self.assertEqual(state.get_active_route(self.root), authority)
            self.assertEqual(self.path.read_bytes() == original, not after)
        reconcile_route(self.root)
        stable = self.path.read_bytes()
        reconcile_route(self.root)
        self.assertEqual(self.kinds(), REQUIRED)
        self.assertEqual(self.path.read_bytes(), stable)

    def test_source_drift_after_package_write_refuses_route_and_can_retry(self):
        self.route()
        self.risk_diff()
        authority = state.get_active_route(self.root)
        native = change.durable_json
        def drift(root, path, document):
            native(root, path, document)
            (self.root / 'app.py').write_text('value = 99\n')
        with mock.patch.object(change, 'durable_json', drift), self.assertRaises(ValueError):
            reconcile_route(self.root)
        self.assertEqual(state.get_active_route(self.root), authority)
        self.assertEqual(self.kinds(), REQUIRED)  # extra not_run rows grant nothing
        (self.root / 'app.py').write_text('value = 1\n')
        current = reconcile_route(self.root)
        self.assertEqual(set(current['required_evidence']), REQUIRED)

    def test_package_drift_after_write_is_not_overwritten_or_published(self):
        self.route()
        self.risk_diff()
        authority = state.get_active_route(self.root)
        native = change.durable_json
        def drift(root, path, document):
            native(root, path, document)
            altered = json.loads(path.read_text())
            altered['foreign-retained'] = True
            path.write_text(json.dumps(altered))
        with mock.patch.object(change, 'durable_json', drift), self.assertRaises(ValueError):
            reconcile_route(self.root)
        self.assertTrue(self.read()['foreign-retained'])
        self.assertEqual(state.get_active_route(self.root), authority)

    def test_reconciliation_requires_the_current_owner_before_any_write(self):
        self.route()
        self.risk_diff()
        before = self.path.read_bytes()
        state.bind_session('other-public-fixture')
        with self.assertRaises((ValueError, RuntimeError)):
            reconcile_route(self.root)
        self.assertEqual(self.path.read_bytes(), before)

    def test_owner_and_route_drift_after_package_write_refuse(self):
        self.route()
        self.risk_diff()
        original, authority = self.path.read_bytes(), state.get_active_route(self.root)
        native = change.durable_json
        for owner_change in (True, False):
            self.path.write_bytes(original)
            def drift(root, path, document):
                native(root, path, document)
                if owner_change:
                    state.bind_session('other-public-fixture')
                else:
                    state.update_route(root, status='scoped')
            try:
                with self.subTest(owner_change=owner_change), mock.patch.object(change, 'durable_json', drift):
                    with self.assertRaises(ValueError):
                        reconcile_route(self.root)
            finally:
                state.bind_session(OWNER)
            current = state.get_active_route(self.root)
            if owner_change:
                self.assertEqual(current, authority)
            else:
                self.assertEqual(current['status'], 'scoped')
                self.assertEqual(current['required_evidence'], authority['required_evidence'])

    def test_source_drift_during_route_publication_is_not_success(self):
        self.route()
        self.risk_diff()
        native = state.durable_json
        def drift(root, path, document):
            native(root, path, document)
            if path.parent.name == 'routes':
                (self.root / 'app.py').write_text('value = 99\n')
        with mock.patch.object(state, 'durable_json', drift), self.assertRaises(ValueError):
            reconcile_route(self.root)
        # A published stale plan is not fresh authority; exact source validation
        # must reject it, rather than returning reconciliation success.
        from getzilla.review_plan import validate_review_plan
        self.assertTrue(validate_review_plan(self.root, state.get_active_route(self.root)))

    def test_closed_package_is_not_rewritten(self):
        current = self.route()
        self.risk_diff()
        change.transition(self.root, current['change_id'], 'cancelled', 'public fixture cancelled')
        before, authority = self.path.read_bytes(), state.get_active_route(self.root)
        with self.assertRaises(ValueError):
            reconcile_route(self.root)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(state.get_active_route(self.root), authority)

    def test_receipt_id_collision_preserves_existing_run_identity(self):
        self.route()
        doc = self.read()
        row = {'id': 'data_review', 'kind': 'run', 'status': 'not_run', 'reason': 'retained public run'}
        doc['evidence_accounting']['obligations'].append(row)
        self.write(doc)
        self.risk_diff()
        reconcile_route(self.root)
        rows = self.read()['evidence_accounting']['obligations']
        self.assertIn(row, rows)
        selected = next(item for item in rows if item.get('receipt_kind') == 'data_review')
        self.assertNotEqual(selected['id'], row['id'])
        self.assertEqual(len({item['id'] for item in rows}), len(rows))

    def test_release_amendment_selects_only_derived_writer_and_preserves_identity(self):
        original = self.route(package=False, prompt='Publish a release to production.')
        self.assertIsNone(original['write_agent'])
        text = 'Implement a Python repair for the release preparation fixture. Add tests.'
        current = submit(self.root, text, OWNER, event_id='implementation')
        self.assertEqual(current['write_agent'], 'general_implementer')
        self.assertIn(current['write_agent'], current['allowed_agents'])
        self.assertEqual(current['risk_assessment']['status'], 'provisional')
        for key in ('route_id', 'task', 'logical_task_id', 'session_id', 'origin_session_id', 'authority_epoch'):
            self.assertEqual(current[key], original[key])
        self.assertLessEqual(set(original['required_evidence']), set(current['required_evidence']))
        self.assertEqual(current['context']['revision'], original['context']['revision'] + 1)
        self.assertEqual(submit(self.root, text, OWNER, event_id='implementation'), current)
        self.assertEqual(current['context']['pending'][0]['text'], text)

    def test_passive_review_rejected_and_existing_writer_are_not_reselected(self):
        original = self.route(package=False, prompt='Publish a release to production.')
        self.assertIsNone(submit(self.root, 'continue', OWNER)['write_agent'])
        self.assertEqual(state.get_active_route(self.root), original)
        reviewed = submit(self.root, 'Review the Python source and its tests.', OWNER)
        self.assertIsNone(reviewed['write_agent'])
        with self.assertRaises(ValueError):
            submit(self.root, 'Implement ' + 'x' * MAX_ITEM_BYTES, OWNER)
        self.assertIsNone(state.get_active_route(self.root)['write_agent'])

    def test_existing_writer_survives_different_domain_and_release_amendments(self):
        original = self.route(package=False)
        self.assertEqual(original['write_agent'], 'general_implementer')
        for text in ('Implement a frontend TypeScript UI component.', 'Publish a release to production.'):
            self.assertEqual(submit(self.root, text, OWNER)['write_agent'], original['write_agent'])

    def test_truthful_fail_cli_remains_recordable_with_missing_accounting(self):
        self.route()
        self.risk_diff()
        current = reconcile_route(self.root)
        self.assertEqual(self.kinds(), REQUIRED)
        doc = self.read()
        doc['evidence_accounting']['obligations'] = [row for row in doc['evidence_accounting']['obligations']
                                                    if row['receipt_kind'] != 'data_review']
        self.write(doc)
        change.transition(self.root, current['change_id'], 'scoped', 'public fixture scope, not human approval')
        inspected = inspect_package(self.root, state.get_active_route(self.root), state.get_active_change(self.root))
        self.assertTrue(any(row['code'] == 'obligation_missing' and row['severity'] == 'error' for row in inspected['findings']))
        report = self.root / '.getzilla/runtime/public-diagnostic.md'
        report.write_text('FAIL: public diagnostic fixture; not an independent passing review.\n')
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/getzilla_review.py'), 'data_review',
                                 '--status', 'fail', '--report', str(report.relative_to(self.root))],
                                cwd=self.root, env={**os.environ, 'GETZILLA_SESSION_ID': OWNER},
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        from getzilla.receipts import get_receipt, validate_evidence
        self.assertEqual(get_receipt(self.root, current['route_id'], 'data_review')['status'], 'fail')
        self.assertTrue(validate_evidence(self.root, state.get_active_route(self.root)))


if __name__ == '__main__':
    unittest.main()
