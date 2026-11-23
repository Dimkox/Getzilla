"""Real current-owner publication controls, with separate tiny source fixtures."""
from contextlib import chdir
from pathlib import Path
import sys
import os
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))


class PublicReviewWitnessTests(unittest.TestCase):
    def test_source_binding_matches_full_observation_after_worktree_and_index_changes(self):
        from getzilla.retrieval import public_review_witness as witness
        from tests._support import project_copy
        import subprocess

        with project_copy(git=True) as root:
            path = root / "witness-binding-test.txt"
            for stage in ("initial", "untracked", "staged", "modified"):
                with self.subTest(stage=stage):
                    if stage == "untracked":
                        path.write_text("first")
                    elif stage == "staged":
                        subprocess.run(["git", "add", "--", path.name], cwd=root, check=True)
                    elif stage == "modified":
                        path.write_text("second")
                    self.assertEqual(witness._source_binding(root),
                                     (witness._exact_head(root), witness.tree_fingerprint(root)))

    def test_observation_kind_is_not_merge_evidence_and_cannot_be_pass(self):
        from getzilla.receipts import write_receipt, get_receipt, RECEIPT_KINDS
        from getzilla import state
        from tests._support import project_copy
        from tests.execution_contract_support import owned_route
        kind = 'retrieval-public-witness-a'
        self.assertNotIn(kind, RECEIPT_KINDS)
        with project_copy() as root, chdir(root):
            self.addCleanup(state.bind_session, None)
            route = owned_route(root)
            (root / '.getzilla/runtime').chmod(0o700)
            with self.assertRaises(ValueError):
                write_receipt(root, kind, 'pass', details={'not_authority': True})
            write_receipt(root, kind, 'observed', details={'assurance': 'operator-witnessed-public-only'})
            value = get_receipt(root, route['route_id'], kind)
            self.assertEqual(value['status'], 'observed')
            self.assertEqual(value['details']['assurance'], 'operator-witnessed-public-only')
            from getzilla.metrics_journal import load
            self.assertFalse(any(event.get('event') == 'receipt' and event.get('kind') == kind
                                 for event in load(root)), 'data witness must not count as a failed ordinary review')
            import json
            from getzilla.receipts import validate_evidence
            self.assertTrue(validate_evidence(root, {**route, 'required_evidence': [kind]}))
            path = root / '.getzilla/runtime/receipts' / route['route_id'] / (kind + '.json')
            forged = json.loads(path.read_text())
            forged['status'] = 'pass'
            path.write_text(json.dumps(forged))
            with self.assertRaisesRegex(RuntimeError, 'must remain observed'):
                get_receipt(root, route['route_id'], kind)
            forged['status'], forged['kind'] = 'observed', 'verification'
            path.write_text(json.dumps(forged))
            with self.assertRaisesRegex(RuntimeError, 'binding mismatch'):
                get_receipt(root, route['route_id'], kind)

    def _owned_roundtrip(self, mutation, *, prepare=None, consume=None, after_route=None):
        if os.name != 'posix' or not hasattr(os, 'register_at_fork'):
            self.skipTest('POSIX native-root witness profile; unsupported platforms fail closed')
        from getzilla import state
        from getzilla.retrieval import public_review_witness as witness
        from getzilla.optional_modules import manage_modules
        from tests.test_optional_modules import OptionalModuleTests
        from tests.execution_contract_support import owned_route
        from tests.test_public_review_inputs import scenario, PROFILE, NAMES
        from unittest.mock import patch
        import json
        import hashlib
        import tempfile
        temporary = tempfile.TemporaryDirectory(prefix='public-review-owned-', dir=Path.home())
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        root.chmod(0o700)
        OptionalModuleTests().install_core(root)
        with chdir(root), patch.dict('os.environ', {'GETZILLA_SESSION_ID': 'owner'}):
            self.addCleanup(state.bind_session, None)
            (root / '.getzilla/runtime').mkdir(mode=0o700, exist_ok=True)
            (root / '.getzilla/runtime').chmod(0o700)
            manage_modules(root, 'install', {'retrieval-research': '0.1.0'}, source=ROOT)
            manage_modules(root, 'enable', {'context-retrieval': None, 'retrieval-research': None}, source=ROOT)
            policy = root / '.getzilla/config/policy.json'
            policy.parent.mkdir(exist_ok=True)
            policy.write_text('{"schema_version":2,"secret_read_paths":[]}')
            policy.chmod(0o644)
            prefix = '.getzilla/runtime/public-witness-fixture'
            final, old_hashes, first, second, query = scenario()
            from copy import deepcopy
            old = deepcopy(final)
            for table in old[3]['tables']:
                for row in table['rows']:
                    row['judgments'] = [0] * len(row['judgments'])
            def save(name, value, source=False):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                if not source:
                    parent = path.parent
                    while parent != root / '.getzilla':
                        parent.chmod(0o700)
                        parent = parent.parent
                raw = value if type(value) is bytes else json.dumps(value, sort_keys=True).encode()
                path.write_bytes(raw)
                path.chmod(0o644 if source else 0o600)
                return {'path': name, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
            for label, data in (('final', final), ('old', old)):
                for name, body in zip(NAMES, data[:4]):
                    save(prefix + '/' + label + '/' + name, body)
            catalogs = []
            for corpus in ('small', 'large'):
                rows = []
                for (selected, name), raw in final[4].items():
                    if selected == corpus:
                        save(prefix + '/sources/' + corpus + '/' + name, raw)
                        rows.append({'path': name, 'candidate': True, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
                catalog = save('engineering/benchmarks/issue162/data/' + corpus + '-manifest.json',
                               {'corpus': corpus, 'commit': '1' * 40, 'files': rows}, source=True)
                catalogs.append((corpus, '1' * 40, catalog['sha256']))
            groups = []
            for role, reports in (('initial', first), ('second', second), ('query', [query])):
                for ordinal, report in enumerate(reports):
                    location = prefix + '/' + role + '-' + str(ordinal)
                    annotation = save(location + '.json', report)
                    groups.append({'role': role, 'original': annotation, 'annotations': [annotation],
                        'reports': [save(location + '.md', b'Separate owned source fixture report.')],
                        'delivery': save(location + '.delivery', b'Separate owned test delivery; no production native identity.'),
                        'delivery_identity': {key: report['reviewer'][key] for key in
                            ('agent_task', 'native_session_id', 'native_generation')}, 'supplement': None})
            config = save(prefix + '/config.json', {})
            registration = {'schema_version': 1, 'kind': 'operator-public-reviews/v1',
                'dataset': prefix + '/final', 'predecessor': prefix + '/old', 'public_sources': prefix + '/sources',
                'config': config, 'author': {'agent_task': 'author', 'native_session_id': 'author'},
                'groups': groups, 'dispositions': save(prefix + '/dispositions.json', {'dispositions': []}),
                'no_answer_resolutions': save(prefix + '/resolutions.json', {'resolutions': []})}
            path = save(prefix + '/registration.json', registration)['path']
            tiny = witness._Composition('test-only-public-source/v1', PROFILE, tuple(catalogs),
                                        config['sha256'], tuple(old_hashes[name] for name in NAMES))
            auxiliary = None if prepare is None else prepare(root, save)
            # A real committed application source is required, separate from Gitless corpus bytes.
            import subprocess
            (root / '.gitignore').write_text('.getzilla/runtime/\n')
            for command in (['git', 'init', '-q'], ['git', 'add', '.'],
                            ['git', '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid',
                             'commit', '-qm', 'owned fixture source']):
                subprocess.run(command, cwd=root, check=True, capture_output=True)
            owned_route(root)
            if after_route is not None:
                after_route(root)
            with self.assertRaises(TypeError):
                witness.OperatorWitnessedPublicReviewedInputs()
            reference = witness._witness(root, path, tiny)
            self.assertEqual(witness._consume(reference, tiny)['facts']['cells'], 40)
            dataset = witness._reviewed_dataset(reference, tiny)
            self.assertEqual(tuple(dataset['inputs']), tuple(final[:4]))
            self.assertFalse(dataset['facts']['ranking_permitted'])
            self.assertEqual(witness._witness(root, path, tiny)._receipt_digest, reference._receipt_digest)
            with self.assertRaisesRegex(ValueError, 'public_witness_unavailable'):
                witness.consume_public_reviews(reference)
            with self.assertRaises(ValueError):
                witness.witness_public_reviews(root, path)
            with self.assertRaises(ValueError):
                witness.consume_public_reviews({'profile': 'public-research162/v1'})
            with self.assertRaises(ValueError):
                witness.consume_public_reviews(object.__new__(witness.OperatorWitnessedPublicReviewedInputs))
            import pickle
            with self.assertRaises(TypeError):
                pickle.dumps(reference)
            from dataclasses import replace
            with self.assertRaisesRegex(ValueError, 'public_witness_unavailable'):
                witness._witness(root, path, replace(tiny, profile=witness._PRODUCTION.profile))
            if consume is not None:
                consume(root, reference, tiny, save, auxiliary)
            if mutation == 'assurance':
                registration['groups'][0]['delivery_assurance'] = 'authenticated-native-bridge'
                wrong = save(prefix + '/wrong-assurance.json', registration)['path']
                with self.assertRaisesRegex(ValueError, 'public_witness_delivery_assurance_invalid'):
                    witness._witness(root, wrong, tiny)
                self.assertEqual(witness._consume(reference, tiny)['facts']['cells'], 40)
            elif mutation == 'source_cut':
                from getzilla.retrieval.public_review_witness import _reviewed_source_cut
                def fresh_cut():
                    return _reviewed_source_cut(reference, batch=0, composition=tiny)

                with fresh_cut() as (broker, handle, cut):
                    self.assertEqual(len(cut.documents), 4)
                    observation = witness._check_reviewed_source_batch(reference, broker, handle, tiny)
                    self.assertEqual(observation['documents'], 4)
                with fresh_cut() as (broker, handle, _):
                    self.assertEqual(witness._check_reviewed_source_dataset(reference, ((broker, handle),), tiny)['documents'], 4)
                with fresh_cut() as (broker, handle, _), self.assertRaises(ValueError):
                    witness._check_reviewed_source_dataset(reference, ((broker, handle), (broker, handle)), tiny)
                with fresh_cut() as (broker, handle, _), self.assertRaises(ValueError):
                    witness.check_reviewed_public_source_batch(reference, broker, handle)
                with fresh_cut() as (broker, handle, _):
                    broker.check_current(handle)
                    (root / groups[0]['reports'][0]['path']).write_bytes(b'Changed actual review custody.')
                    with self.assertRaises(ValueError):
                        broker.check_current(handle)
            elif mutation == 'producer_unknown':
                request = {'schema_version': 1, 'kind': 'operator-public-producer-reference/v1',
                    'original': groups[0]['original'], 'producer_identity': groups[0]['delivery_identity'],
                    'supplement': groups[0]['reports'][0]}
                request_path = save(prefix + '/unknown-producer.json', request)['path']
                with self.assertRaises(ValueError):
                    witness.observe_public_producer(root, request_path)
                from getzilla.receipts import get_receipt
                self.assertIsNone(get_receipt(root, state.require_route_owner(root)['route_id'], witness.PRODUCER_KIND))
            elif mutation == 'report':
                (root / groups[0]['reports'][0]['path']).write_bytes(b'mutated report')
                with self.assertRaisesRegex(ValueError, 'public_witness_changed'):
                    witness._consume(reference, tiny)
            elif mutation == 'owner':
                state.bind_session('other-owner')
                with self.assertRaises(ValueError):
                    witness._consume(reference, tiny)
            elif mutation == 'context':
                from getzilla.continuity import submit
                before = state.require_route_owner(root)
                after = submit(root, 'Fix the README typo and punctuation.', 'owner')
                self.assertEqual(after['logical_task_id'], before['logical_task_id'])
                self.assertNotEqual(after['context']['revision'], before['context']['revision'])
                with self.assertRaises(ValueError):
                    witness._consume(reference, tiny)
            elif mutation == 'conflict':
                other = save(prefix + '/other-registration.json', registration)['path']
                with self.assertRaisesRegex(ValueError, 'public_witness_conflict'):
                    witness._witness(root, other, tiny)
                self.assertEqual(witness._consume(reference, tiny)['facts']['cells'], 40)

    def test_owned_witness_roundtrip_is_tiny_only_and_fences_mutation(self):
        self._owned_roundtrip('report')

    def test_different_actual_owner_cannot_consume_witness(self):
        self._owned_roundtrip('owner')

    def test_normal_task_amendment_invalidates_prior_witness(self):
        self._owned_roundtrip('context')

    def test_conflicting_registration_cannot_overwrite_owned_witness(self):
        self._owned_roundtrip('conflict')

    def test_fresh_owner_witness_after_normal_ack_does_not_revive_old_ref(self):
        from getzilla import state
        from getzilla.change import start_change
        from getzilla.spec import load_spec, dump_canonical_spec
        from getzilla.continuity import ack_scope, submit, scope_gaps
        from getzilla.retrieval import public_review_witness as witness
        from tests.test_task_continuity import ContinuityTests
        import shutil
        package_path = None
        def private_package():
            for item in package_path.rglob("*"):
                item.chmod(0o700 if item.is_dir() else 0o600)
            package_path.chmod(0o700)
            package_path.parent.chmod(0o700)
        def typed(root):
            nonlocal package_path
            (root / 'tests').mkdir(exist_ok=True)
            shutil.copyfile(__file__, root / 'tests/test_public_review_witness.py')
            shutil.copytree(ROOT / '.getzilla/templates/change', root / '.getzilla/templates/change')
            shutil.copytree(ROOT / 'schemas', root / 'schemas')
            start_change(root)
            package_path = root / state.get_active_change(root)['path']
            spec = load_spec(package_path / 'change-spec.yaml')
            spec['objective'].update(success_metric='Current source/data controls', target='Retain all exact public review facts')
            spec['acceptance_criteria'] = [{'id': 'AC-001', 'statement': state.require_route_owner(root)['task'],
                'evidence': [{'test': 'tests/test_public_review_witness.py'}]}]
            spec['forbidden_outcomes'] = [{'id': 'FORBID-001', 'statement': 'No stale source or native authority.',
                'evidence': [{'test': 'tests/test_public_review_witness.py'}]}]
            spec['approvals']['required_scopes'] = ['scope_and_design_approval']
            (package_path / 'change-spec.yaml').write_text(dump_canonical_spec(spec))
            (package_path / 'requirements.md').write_text(state.require_route_owner(root)['task'] + '\n')
            ack_scope(root, ContinuityTests().ack_request(root))
            private_package()
            self.assertFalse(scope_gaps(root))
        def refresh(root, old, composition, save, unused):
            message = 'Retain the current public review observations after the README punctuation amendment.'
            amended = submit(root, message, 'owner')
            pending = [row['id'] for row in amended['context']['pending']]
            path = '.getzilla/runtime/public-witness-fixture/registration.json'
            with self.assertRaises(ValueError):
                witness._consume(old, composition)
            with self.assertRaisesRegex(ValueError, 'public_witness_scope_unacknowledged'):
                witness._witness(root, path, composition)
            spec = load_spec(package_path / 'change-spec.yaml')
            spec['acceptance_criteria'].append({'id': 'AC-002', 'statement': message,
                'evidence': [{'test': 'tests/test_public_review_witness.py'}]})
            (package_path / 'change-spec.yaml').write_text(dump_canonical_spec(spec))
            with (package_path / 'requirements.md').open('a') as stream:
                stream.write(message + '\n')
            request = ContinuityTests().ack_request(root, pending)
            request['items'].update({identifier: ['AC-002'] for identifier in pending})
            ack_scope(root, request)
            private_package()
            self.assertFalse(scope_gaps(root))
            current = witness._witness(root, path, composition)
            self.assertNotEqual(current._receipt_digest, old._receipt_digest)
            self.assertEqual(witness._consume(current, composition)['facts']['cells'], 40)
            self.assertEqual(witness._witness(root, path, composition)._receipt_digest, current._receipt_digest)
            with self.assertRaises(ValueError):
                witness._consume(old, composition)
        self._owned_roundtrip('refresh', after_route=typed, consume=refresh)

    def test_observation_notes_cannot_claim_authenticated_native_delivery(self):
        self._owned_roundtrip('assurance')

    def test_owned_review_source_cut_checks_report_custody_before_use(self):
        self._owned_roundtrip('source_cut')

    def test_actual_owner_cannot_observe_arbitrary_producer_as_fixed_original(self):
        self._owned_roundtrip('producer_unknown')

    @unittest.skipIf(os.name == 'posix' and hasattr(os, 'register_at_fork'), 'actual unsupported-platform control')
    def test_unsupported_platform_does_not_issue_witness(self):
        from getzilla.retrieval.public_review_witness import witness_public_reviews
        with self.assertRaisesRegex(ValueError, 'native_trace_root_unavailable'):
            witness_public_reviews(ROOT, '.getzilla/runtime/missing-witness.json')


if __name__ == '__main__':
    unittest.main()
