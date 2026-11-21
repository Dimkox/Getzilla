"""Real owned tiny data intent; fixtures cannot authorize production/native work."""
from dataclasses import replace
import hashlib
from pathlib import Path
import pickle
import shutil
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla.retrieval import public_study_operation as owner
from getzilla.retrieval import research_use_conditions as conditions_owner
from getzilla.retrieval.study_resources import RESOURCE_PROFILE_SHA256


class PublicStudyOperationTests(unittest.TestCase):
    def test_forged_objects_and_data_projection_are_not_operations(self):
        for value in ({'allow_execution': True}, object(), object.__new__(owner.PublicStudyOperationRef)):
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError):
                owner.check_public_study_operation(value)
        with self.assertRaises(TypeError):
            owner.PublicStudyOperationRef()
        self.assertFalse(owner.operation_status()['execution_enabled'])

    def roundtrip(self, mutation):
        from tests.test_public_review_witness import PublicReviewWitnessTests
        from tests.research_use_support import populate_research_use
        helper = PublicReviewWitnessTests()
        self.addCleanup(helper.doCleanups)
        def prepare(root, save):
            path, composition = populate_research_use(root, software=True)
            save('owned-inert-worker.py', b'# Trusted inert fixture; never executed.\n', source=True)
            return path, composition
        def consume(root, phase_a, review_composition, save, auxiliary):
            condition_path, condition_composition = auxiliary
            condition_ref = conditions_owner._require_public_research_use(root, condition_path, condition_composition)
            self.addCleanup(conditions_owner.close_public_research_use, condition_ref)
            facts = conditions_owner._check_public_research_use(condition_ref, condition_composition)
            (root / '.getzilla/runtime/study-export-preparations').mkdir(mode=0o700)
            prefix = '.getzilla/runtime/study-export-preparations/operation-fixture-exports'
            outer = root / prefix
            outer.mkdir(mode=0o700)
            def export(name, files, source=None):
                target = outer / name
                target.mkdir(mode=0o700)
                for path, size, digest in files:
                    body = (source / path).read_bytes() if source is not None else b'x'
                    self.assertEqual((len(body), hashlib.sha256(body).hexdigest()), (size, digest))
                    output = target / path
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_bytes(body)
                    output.chmod(0o444)
                for directory in sorted((p for p in target.rglob('*') if p.is_dir()), reverse=True):
                    directory.chmod(0o555)
                target.chmod(0o555)
                return target.relative_to(root).as_posix()
            entry = 'getzilla/retrieval/study_worker_entry.py'
            worker_body = (root / 'owned-inert-worker.py').read_bytes()
            worker_files = ((entry, len(worker_body), hashlib.sha256(worker_body).hexdigest()),)
            worker_source = outer / 'source-only'
            (worker_source / entry).parent.mkdir(parents=True)
            (worker_source / entry).write_bytes(worker_body)
            worker = export('worker', worker_files, worker_source)
            shutil.rmtree(worker_source)
            model = export('model', facts['artifact_files'])
            software = export('software', facts['software_files'], facts['software_root'])
            # The owned test port inspects this root-owned executable without running Docker.
            executable = str(Path('/usr/bin/true').resolve())
            composition = owner._Composition('test-only-operation/v1', review_composition,
                condition_composition, (('owned-inert-worker.py', entry),), executable)
            image = facts['image']['config']['digest']
            runtime = {'inference_image_id': image, 'inspection_image_id': image,
                'docker_executable': executable, 'docker_sha256': hashlib.sha256(Path(executable).read_bytes()).hexdigest(),
                'daemon_id': 'inert-unobserved-daemon-fixture', 'model_root': model,
                'software_root': software, 'worker_root': worker, 'artifact_files': facts['artifact_files'],
                'software_files': facts['software_files'], 'worker_files': worker_files, 'cpu_ids': [0, 1],
                'hard_timeout_seconds': 10, 'resource_profile_sha256': RESOURCE_PROFILE_SHA256,
                'base_image_digest': image.removeprefix('sha256:'), 'recipe_digest': 'a' * 64}
            request = {'schema_version': 1, 'kind': 'public-study-operation/v1', 'operation': owner.INSPECT,
                'phase_a_sha256': phase_a._receipt_digest, 'phase_b_sha256': None,
                'conditions_sha256': facts['conditions_sha256'],
                'artifact_manifest_sha256': facts['artifact_manifest_sha256'], 'graph_observations': None, 'runtime': runtime}
            if mutation in {'arbitrary_export', 'mixed_child_export'}:
                request['runtime']['model_root'] = (
                    '.getzilla/runtime/scratch/unregistered-model' if mutation == 'arbitrary_export'
                    else '.getzilla/runtime/study-export-preparations/foreign-child/model')
                rejected = save('.getzilla/runtime/operation-invalid-export.json', request)['path']
                with patch.object(owner, 'snapshot_study_export', side_effect=AssertionError('export access forbidden')), \
                        patch.object(owner, '_docker', side_effect=AssertionError('runtime access forbidden')):
                    with self.assertRaisesRegex(ValueError, 'public_study_export_unavailable'):
                        owner._register_public_study_operation(root, owner.INSPECT, rejected, phase_a,
                            condition_ref, None, composition)
                return
            registration = save('.getzilla/runtime/operation-fixture-registration.json', request)['path']
            ref = owner._register_public_study_operation(root, owner.INSPECT, registration, phase_a,
                condition_ref, None, composition)
            self.addCleanup(lambda: [snapshot.close() for snapshot in ref._exports])
            projection = owner._check_public_study_operation(ref, composition)
            self.assertEqual(projection.model_root, root / model)
            self.assertEqual(projection.resource_profile_sha256, RESOURCE_PROFILE_SHA256)
            self.assertEqual(projection.execution_intent, 'study162-inspect-' + projection.operation_digest)
            again = owner._register_public_study_operation(root, owner.INSPECT, registration, phase_a,
                condition_ref, None, composition)
            self.addCleanup(lambda: [snapshot.close() for snapshot in again._exports])
            self.assertEqual(again._receipt_sha256, ref._receipt_sha256)
            with self.assertRaises(ValueError):
                owner.check_public_study_operation(ref)
            with self.assertRaises(ValueError):
                owner._register_public_study_operation(root, owner.INSPECT, registration, phase_a,
                    condition_ref, None, replace(composition, profile=owner._PRODUCTION.profile))
            with self.assertRaises(TypeError):
                pickle.dumps(ref)
            if mutation == 'revoke':
                owner._revoke_public_study_operation(root, ref, composition)
                with self.assertRaises(ValueError):
                    owner._register_public_study_operation(root, owner.INSPECT, registration, phase_a,
                        condition_ref, None, composition)
            elif mutation == 'no_b':
                request['operation'], request['phase_b_sha256'] = owner.RANK, None
                missing_b = save('.getzilla/runtime/operation-missing-b.json', request)['path']
                with self.assertRaisesRegex(ValueError, 'public_study_inspection_required'):
                    owner._register_public_study_operation(root, owner.RANK, missing_b, phase_a,
                        condition_ref, None, composition)
                return
            elif mutation == 'claim':
                from getzilla import execution, state
                from tests.execution_contract_support import CountingBackend
                label = '162holdout ' + 'a' * 64
                caller = execution.trusted_caller(root)
                request = execution.SubmitRequest('actual-inert-contract-claim', {}, 10, label, operation_id='b' * 64)
                backend = CountingBackend(complete=False)
                execution.submit(root, caller, request, backend=backend)
                owner._holdout_claim(root, state.require_route_owner(root), label, 'b' * 64)
                from tests.execution_contract_support import owned_route
                owned_route(root, session='new-real-owner', task='Run this fixed public study in a new task.')
                with self.assertRaisesRegex(ValueError, 'public_study_holdout_already_claimed'):
                    owner._holdout_claim(root, state.require_route_owner(root), label, 'c' * 64)
                return
            elif mutation == 'view':
                changed = root / model / facts['artifact_files'][0][0]
                changed.chmod(0o644)
            elif mutation == 'conditions':
                conditions_owner.close_public_research_use(condition_ref)
            elif mutation == 'owner':
                from getzilla import state
                state.bind_session('other-owner')
            elif mutation == 'context':
                from getzilla.continuity import submit
                submit(root, 'Fix a newly requested README punctuation issue.', 'owner')
            else:
                raise AssertionError(mutation)
            with self.assertRaises(ValueError):
                owner._check_public_study_operation(ref, composition)
        helper._owned_roundtrip('operation', prepare=prepare, consume=consume)

    def test_true_owned_opaque_intent_roundtrip_and_view_change_refuses(self):
        self.roundtrip('view')

    def test_closed_source_conditions_cannot_be_reused(self):
        self.roundtrip('conditions')

    def test_actual_owner_change_refuses_intent(self):
        self.roundtrip('owner')

    def test_normal_task_amendment_refuses_old_intent(self):
        self.roundtrip('context')

    def test_owner_revocation_cannot_be_rearmed_from_same_registration(self):
        self.roundtrip('revoke')

    def test_rank_cannot_begin_from_a_without_genuine_b(self):
        self.roundtrip('no_b')

    def test_existing_registry_reserves_even_an_unfinished_contract_claim(self):
        self.roundtrip('claim')

    def test_arbitrary_export_root_refuses_before_export_or_runtime_access(self):
        self.roundtrip('arbitrary_export')

    def test_mixed_child_export_refuses_before_export_or_runtime_access(self):
        self.roundtrip('mixed_child_export')
