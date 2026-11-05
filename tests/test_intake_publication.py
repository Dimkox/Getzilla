"""Native publication uses real package CAS, canonical routes and actual scope ACK."""
import copy
import hashlib
import json
import shutil
import sys
import unittest
from unittest.mock import patch
from pathlib import Path

from tests._support import project_copy
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla import state, continuity
from getzilla.change import start_change
from getzilla.intake_publication import (prepare_intake, recover_intake, read_intake_cut,
                                       native_policy, native_identity, cut_digest, require_intake_ready)
from getzilla.requirements_intake import IntakeError
from getzilla.spec import dump_canonical_spec
from tests.test_requirements_intake import snapshot


class PublicationTests(unittest.TestCase):
    def fixture(self, root):
        # Actual hook subprocesses load the installed root's schema files, not
        # the test runner's imported package schema directory.
        source=Path(__file__).resolve().parents[1]/'schemas'
        (root/'schemas').mkdir(exist_ok=True)
        for name in ('change-spec.schema.json','requirement-intake-v1.schema.json','intake-readiness-v1.schema.json'):
            shutil.copyfile(source/name,root/'schemas'/name)
        continuity.submit(root, 'Implement a bounded record-retention feature and preserve source requirements.', 'fixture-owner', event_id='initial')
        start_change(root)
        route = state.require_route_owner(root)
        package = root / state.get_active_change(root)['path']
        data = snapshot()
        data['identity'] = native_identity(root, route)
        data['policy'] = native_policy(root)
        data['spec']['change_id'] = route['change_id']
        (root/'tests').mkdir(exist_ok=True)
        (root/'tests/test_requirements_intake.py').write_text('# inert native evidence target\n')
        (package/'change-spec.yaml').write_text(dump_canonical_spec(data['spec']))
        requirements = 'Retain records for seven days.\n'
        (package/'requirements.md').write_text(requirements)
        relative = (package/'requirements.md').relative_to(root).as_posix()
        data['sources'][0].update(uri='native:'+relative, sha256=hashlib.sha256(requirements.encode()).hexdigest(),
                                  locator={'kind':'lines','path':relative,'start':1,'end':1})
        return package, {'snapshot':data, 'requirements':requirements, 'event': {'id':'event-one','kind':'record'}}

    def publish(self, root, intent):
        return prepare_intake(root, intent, expected_cut_digest=None, expected_state_digest='0'*64)

    def test_real_native_ack_and_committed_cut_recompute_ready(self):
        with project_copy() as root:
            package, intent = self.fixture(root)
            result = self.publish(root, intent)
            route = state.require_route_owner(root)
            self.assertEqual(route['context']['version'], 2)
            self.assertEqual(route['context']['revision'], 1)
            self.assertEqual(route['context']['intake']['committed'], result['cut'])
            self.assertIsNone(route['context']['intake']['pending'])
            self.assertEqual(json.loads((package/'state.json').read_text())['scope_ack'], route['context']['last_ack'])
            self.assertEqual(require_intake_ready(root)['assessment']['status'], 'ready')
            self.assertEqual(result, self.publish(root, intent))

    def test_crashes_after_each_durable_boundary_recover_exactly_once(self):
        for point in ('staged', 'pending', 'spec', 'requirements', 'ack', 'target_state', 'state', 'commit'):
            with self.subTest(point=point), project_copy() as root:
                _, intent = self.fixture(root)
                from getzilla import intake_publication as publisher
                def interrupt(boundary):
                    if boundary == point:
                        raise RuntimeError('inert interruption')
                with patch.object(publisher, '_boundary', interrupt), self.assertRaises(RuntimeError):
                    self.publish(root, intent)
                if point not in {'staged','commit'}:
                    with self.assertRaises(IntakeError):
                        require_intake_ready(root)
                recovered = self.publish(root, intent) if point == 'staged' else recover_intake(root, publisher.publication_id(root, intent, None, '0'*64))
                self.assertEqual(recovered['cut'], require_intake_ready(root)['cut'])
                self.assertEqual(state.require_route_owner(root)['context']['revision'], 1)

    def test_third_value_human_edits_preserved_and_pending(self):
        for target in ('change-spec.yaml','requirements.md','workflow/projections/intake.json'):
            with self.subTest(target=target), project_copy() as root:
                package, intent = self.fixture(root)
                from getzilla import intake_publication as publisher
                with patch.object(publisher, '_boundary', side_effect=lambda point: (_ for _ in ()).throw(RuntimeError()) if point=='pending' else None):
                    with self.assertRaises(RuntimeError):
                        self.publish(root,intent)
                path = package/target
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(b'human private sentinel\n')
                inode = path.stat().st_ino
                transaction = state.require_route_owner(root)['context']['intake']['pending']['publication_id']
                with self.assertRaises(IntakeError):
                    recover_intake(root,transaction)
                self.assertEqual(path.read_bytes(), b'human private sentinel\n')
                self.assertEqual(path.stat().st_ino,inode)
                self.assertIsNotNone(state.require_route_owner(root)['context']['intake']['pending'])

    def test_mutable_event_updates_mk_without_rewriting_dsrc(self):
        with project_copy() as root:
            package,intent=self.fixture(root)
            first=self.publish(root,intent)
            route=state.require_route_owner(root)
            identities={name:(package/name).stat().st_ino for name in ('change-spec.yaml','requirements.md')}
            intent['event']={'id':'event-two','kind':'question_round'}
            second=prepare_intake(root,intent,cut_digest(first['cut']),first['cut']['M'])
            for key in ('D','S','R','A','C'):
                self.assertEqual(first['cut'][key],second['cut'][key])
            self.assertNotEqual(first['cut']['M'],second['cut']['M'])
            self.assertEqual(state.require_route_owner(root)['context']['revision'],route['context']['revision'])
            self.assertEqual(identities,{name:(package/name).stat().st_ino for name in identities})

    def test_bookkeeping_preserves_equivalent_human_spec_formatting(self):
        with project_copy() as root:
            package,intent=self.fixture(root)
            first=self.publish(root,intent)
            path=package/'change-spec.yaml'
            path.write_bytes(path.read_bytes()+b'\n')
            before=path.read_bytes()
            inode=path.stat().st_ino
            intent['event']={'id':'bookkeeping-two','kind':'record'}
            prepare_intake(root,intent,cut_digest(first['cut']),first['cut']['M'])
            self.assertEqual(path.read_bytes(),before)
            self.assertEqual(path.stat().st_ino,inode)

    def test_event_collision_old_epoch_and_forged_approval_are_refused(self):
        with project_copy() as root:
            _,intent=self.fixture(root)
            first=self.publish(root,intent)
            for mutate in (lambda d:d['event'].update(kind='question_round'),
                           lambda d:d['snapshot']['identity'].update(authority_epoch=9),
                           lambda d:d['event'].update(approved=True,principal='owner')):
                changed=copy.deepcopy(intent)
                mutate(changed)
                with self.assertRaises(IntakeError):
                    prepare_intake(root,changed,cut_digest(first['cut']),first['cut']['M'])

    def test_enabled_mode_cannot_be_disabled_and_missing_input_refuses(self):
        with project_copy() as root:
            package,intent=self.fixture(root)
            first=self.publish(root,intent)
            route=state.require_route_owner(root)
            changed=copy.deepcopy(route)
            changed['context'].pop('intake')
            changed['context']['version']=1
            changed['state_revision']+=1
            with self.assertRaises(ValueError):
                state._commit_route(root,changed,expected=route)
            path=package/f"workflow/projections/intake/versions/{first['cut']['D']}.json"
            path.unlink()
            with self.assertRaises(IntakeError):
                require_intake_ready(root)

    def test_current_source_and_policy_changes_refuse_stored_ready(self):
        with project_copy() as root:
            package,intent=self.fixture(root)
            self.publish(root,intent)
            (package/'requirements.md').write_text('Human changed requirements.\n')
            with self.assertRaises(IntakeError):
                require_intake_ready(root)

    def test_pending_bookkeeping_never_reuses_previous_ready(self):
        with project_copy() as root:
            _,intent=self.fixture(root)
            first=self.publish(root,intent)
            intent['event']={'id':'bookkeeping-two','kind':'record'}
            from getzilla import intake_publication as publisher
            with patch.object(publisher,'_boundary',side_effect=lambda p: (_ for _ in ()).throw(RuntimeError()) if p=='pending' else None):
                with self.assertRaises(RuntimeError):
                    prepare_intake(root,intent,cut_digest(first['cut']),first['cut']['M'])
            with self.assertRaises(IntakeError):
                require_intake_ready(root)

    def test_projection_bytes_and_original_epoch_are_rederived(self):
        with project_copy() as root:
            package,intent=self.fixture(root)
            invalid=copy.deepcopy(intent)
            invalid['snapshot']['identity']['authority_epoch']=1
            with self.assertRaises(IntakeError):
                self.publish(root,invalid)
            self.publish(root,intent)
            path=package/'workflow/projections/intake.json'
            forged=json.loads(path.read_text())
            forged['assessment']['status']='ready'
            forged['assessment']['authority']=True
            path.write_text(json.dumps(forged))
            with self.assertRaises(IntakeError):
                require_intake_ready(root)

    def test_undeclared_task_is_explicit_not_run_without_writes(self):
        with project_copy() as root:
            self.fixture(root)
            route=state.require_route_owner(root)
            self.assertEqual(require_intake_ready(root)['status'],'not_run')
            self.assertEqual(state.require_route_owner(root),route)

    def test_real_package_first_ack_crash_replays_same_request(self):
        with project_copy() as root:
            package,intent=self.fixture(root)
            commit=state._commit_route
            def fail_ack(root,route,**kwargs):
                if route['context']['last_ack'] is not None:
                    raise OSError('inert crash before route ACK')
                return commit(root,route,**kwargs)
            with patch.object(state,'_commit_route',fail_ack), self.assertRaises(IntakeError):
                self.publish(root,intent)
            route=state.require_route_owner(root)
            self.assertEqual(route['context']['revision'],0)
            mirror=json.loads((package/'state.json').read_text())['scope_ack']
            self.assertEqual(mirror['revision'],1)
            result=recover_intake(root,route['context']['intake']['pending']['publication_id'])
            self.assertEqual(state.require_route_owner(root)['context']['last_ack'],mirror)
            self.assertEqual(result['cut'],require_intake_ready(root)['cut'])

    def test_busy_writer_latches_pending_before_any_document_edit(self):
        with project_copy() as root:
            package,intent=self.fixture(root)
            from getzilla.agent_lifecycle import start_agent
            route=state.require_route_owner(root)
            start_agent(root,'fixture-writer',route['write_agent'])
            before=(package/'change-spec.yaml').read_bytes()
            with self.assertRaisesRegex(IntakeError,'writer_quiescence_required'):
                self.publish(root,intent)
            self.assertEqual((package/'change-spec.yaml').read_bytes(),before)
            self.assertIsNotNone(state.require_route_owner(root)['context']['intake']['pending'])

    def test_budget_reserves_recovery_space_before_required_latch(self):
        with project_copy() as root:
            _,intent=self.fixture(root)
            from getzilla import intake_publication as publisher
            before=state.require_route_owner(root)
            with patch.object(publisher,'MAX_RETAINED_BYTES',30000), self.assertRaisesRegex(IntakeError,'budget_exhausted'):
                self.publish(root,intent)
            self.assertEqual(state.require_route_owner(root),before)

    def test_existing_native_cas_recovery_bytes_count_toward_retained_bound(self):
        with project_copy() as root:
            _,intent=self.fixture(root)
            route=state.require_route_owner(root)
            recovery=root/'.getzilla/runtime/workflow-cas'/route['change_id']
            recovery.mkdir(parents=True,exist_ok=True)
            (recovery/'retained-recovery').write_bytes(b'x'*1_000_000)
            with self.assertRaisesRegex(IntakeError,'budget_exhausted'):
                self.publish(root,intent)
            self.assertEqual(state.require_route_owner(root),route)

    def test_revision_and_event_ceiling_never_evict_unresolved_identity(self):
        from getzilla.requirements_intake import reduce_intake,NativeIntakeContext
        trusted=NativeIntakeContext({'logical_task_id':'fixture','authority_epoch':0},'a'*64,'b'*64,'2026-11-05T00:00:00Z')
        previous={'identity':trusted.identity,'events':[{'id':f'old-{i}','request_digest':'a'*64,'event_digest':'c'*64} for i in range(4096)],'rounds':3,'withdrawn':False}
        before=copy.deepcopy(previous)
        with self.assertRaisesRegex(IntakeError,'budget_exhausted'):
            reduce_intake(previous,{'id':'new','kind':'record'},trusted)
        self.assertEqual(previous,before)
        with project_copy() as root:
            package,intent=self.fixture(root)
            versions=package/'workflow/projections/intake/versions'
            versions.mkdir(parents=True)
            for number in range(64):
                (versions/f'{number:064x}.json').write_text('{}\n')
            before=state.require_route_owner(root)
            with self.assertRaisesRegex(IntakeError,'budget_exhausted'):
                self.publish(root,intent)
            self.assertEqual(state.require_route_owner(root),before)

    def test_public_cas_cannot_escape_to_native_documents(self):
        with project_copy() as root:
            package,_=self.fixture(root)
            from getzilla.workflow_artifacts import cas_write,WorkflowArtifactError
            before=(package/'change-spec.yaml').read_bytes()
            for target in ('../change-spec.yaml','change-spec.yaml'):
                with self.assertRaises(WorkflowArtifactError):
                    cas_write(root,state.require_route_owner(root)['change_id'],target,b'overwrite','0'*64)
            self.assertEqual((package/'change-spec.yaml').read_bytes(),before)

    def test_reducer_replay_collision_and_untrusted_context(self):
        from getzilla.requirements_intake import reduce_intake, NativeIntakeContext
        trusted=NativeIntakeContext(identity={'logical_task_id':'fixture','authority_epoch':0},
                                   request_digest='a'*64,publication_id='b'*64,at='2026-11-05T00:00:00Z')
        event={'id':'question-one','kind':'question_round'}
        first=reduce_intake(None,event,trusted)
        self.assertEqual(first['rounds'],1)
        self.assertEqual(reduce_intake(first,event,trusted),first)
        with self.assertRaises(IntakeError):
            reduce_intake(first,{**event,'kind':'record'},trusted)
        with self.assertRaises(IntakeError):
            reduce_intake(None,event,{'principal':'owner','approved':True})

    def test_actual_cli_inspect_is_read_only_and_apply_requires_exact_cas(self):
        from tests.test_workflow_artifacts_cli import _run_cli_process
        with project_copy() as root:
            package,intent=self.fixture(root)
            request=package/'request.json'
            request.write_text(json.dumps(intent))
            relative=request.relative_to(root).as_posix()
            before=state.require_route_owner(root)
            code,output=_run_cli_process(str(root),['intake','inspect'])
            self.assertEqual(code,0,output)
            self.assertEqual(json.loads(output)['status'],'not_run')
            self.assertEqual(state.require_route_owner(root),before)
            code,output=_run_cli_process(str(root),['intake','apply','--request',relative,'--expected-cut','none','--expected-state','0'*64])
            self.assertEqual(code,0,output)
            self.assertEqual(json.loads(output)['cut'],read_intake_cut(root)['cut'])
