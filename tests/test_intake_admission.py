"""Exercise actual consumers before their first product write."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests._support import project_copy,run_hook
from tests import test_intake_publication as publication_tests
from getzilla import state
from getzilla.change import transition
from getzilla.agent_lifecycle import start_agent
from getzilla.policy import evaluate_pre_tool
from getzilla.intake_publication import prepare_intake,cut_digest


class AdmissionTests(unittest.TestCase):
    fixture=publication_tests.PublicationTests.fixture
    publish=publication_tests.PublicationTests.publish

    def pending(self,root,intent):
        from getzilla import intake_publication as publisher
        with patch.object(publisher,'_boundary',side_effect=lambda p: (_ for _ in ()).throw(RuntimeError()) if p=='pending' else None):
            with self.assertRaises(RuntimeError):
                self.publish(root,intent)

    def test_implementing_refuses_before_checkpoint_or_state_write(self):
        with project_copy() as root:
            package,intent=self.fixture(root)
            change=state.require_route_owner(root)['change_id']
            transition(root,change,'scoped','fixture scope')
            transition(root,change,'approved','ordinary existing delegation')
            self.pending(root,intent)
            before=(package/'state.json').read_bytes()
            with self.assertRaises(ValueError):
                transition(root,change,'implementing','must not start')
            self.assertEqual((package/'state.json').read_bytes(),before)

    def test_writer_start_refuses_pending_before_registration(self):
        with project_copy() as root:
            _,intent=self.fixture(root)
            self.pending(root,intent)
            route=state.require_route_owner(root)
            with self.assertRaises(ValueError):
                start_agent(root,'fixture-writer',route['write_agent'])
            self.assertFalse(state.get_agent_state(root).get('active'))

    def test_complete_cut_admits_actual_transition_and_hook(self):
        with project_copy() as root:
            _,intent=self.fixture(root)
            self.publish(root,intent)
            change=state.require_route_owner(root)['change_id']
            transition(root,change,'scoped','fixture scope')
            transition(root,change,'approved','ordinary existing delegation')
            result=transition(root,change,'implementing','current intake admitted')
            self.assertEqual(result['status'],'implementing')
            (root/'src').mkdir(exist_ok=True)
            code,result,error=run_hook(root,'pre_tool_use.py',{'cwd':str(root),'session_id':'fixture-owner','tool_name':'Write','tool_input':{'file_path':'src/retention.py','content':'inert'}})
            self.assertEqual(code,0,error)
            self.assertEqual(result.get('hookSpecificOutput',{}).get('permissionDecision'),'allow',result)

    def test_actual_mutation_consumers_refuse_pending_and_keep_reads(self):
        events=[{'tool_name':tool,'tool_input':{'file_path':'src/retention.py','new_string':'inert'}} for tool in ('Edit','Write')]
        events += [{'tool_name':'apply_patch','tool_input':{'patch':'*** Begin Patch\n*** Add File: src/retention.py\n+x\n*** End Patch'}},
                   {'tool_name':'Bash','tool_input':{'command':'touch src/retention.py'}},
                   {'tool_name':'Bash','tool_input':{'command':'git diff --output=src/inert.txt'}},
                   {'tool_name':'Bash','tool_input':{'command':'python3 scripts/inert.py'}}]
        with project_copy() as root:
            _,intent=self.fixture(root)
            self.pending(root,intent)
            for event in events:
                with self.subTest(event=event['tool_name']):
                    self.assertFalse(evaluate_pre_tool(root,event)[0])
            self.assertTrue(evaluate_pre_tool(root,{'tool_name':'Read','tool_input':{'file_path':'src/retention.py'}})[0])
            self.assertTrue(evaluate_pre_tool(root,{'tool_name':'Write','tool_input':{'file_path':'.getzilla/runtime/scratch/inert.txt','content':'inert'}})[0])
            self.assertTrue(evaluate_pre_tool(root,{'tool_name':'Bash','tool_input':{'command':'python3 scripts/getzilla_artifacts.py intake recover --publication-id '+'a'*64}})[0])

    def test_genuine_cut_allows_ordinary_write_then_withdrawal_denies_writer_reuse(self):
        with project_copy() as root:
            _,intent=self.fixture(root)
            first=self.publish(root,intent)
            route=state.require_route_owner(root)
            worker=start_agent(root,'fixture-writer',route['write_agent'])
            self.assertTrue(evaluate_pre_tool(root,{'tool_name':'Write','tool_input':{'file_path':'src/retention.py'}})[0])
            intent['event']={'id':'withdraw-one','kind':'withdraw'}
            prepare_intake(root,intent,cut_digest(first['cut']),first['cut']['M'])
            with self.assertRaises(ValueError):
                start_agent(root,'fixture-writer',route['write_agent'],generation=worker['generation'])
            self.assertFalse(evaluate_pre_tool(root,{'tool_name':'Write','tool_input':{'file_path':'src/retention.py'}})[0])

    def test_actual_hook_helper_loss_denies_ordinary_edit_and_unknown_shell(self):
        for failure in ('intake_publication.py','policy.py'):
            with self.subTest(failure=failure),project_copy() as root:
                _,intent=self.fixture(root)
                self.publish(root,intent)
                (root/'.getzilla/getzilla'/failure).unlink()
                for tool,inputs in [('Write',{'file_path':'src/retention.py','content':'inert'}),
                                    ('Bash',{'command':'python3 scripts/inert.py'})]:
                    code,result,error=run_hook(root,'pre_tool_use.py',{'cwd':str(root),'session_id':'fixture-owner','tool_name':tool,'tool_input':inputs})
                    self.assertEqual(code,0,error)
                    self.assertEqual(result.get('hookSpecificOutput',{}).get('permissionDecision'),'deny',result)

    def test_actual_hook_lib_loss_denies_required_product_edit(self):
        with project_copy() as root:
            _,intent=self.fixture(root)
            self.publish(root,intent)
            (root/'.grok/hooks/_lib.py').unlink()
            code,result,error=run_hook(root,'pre_tool_use.py',{'cwd':str(root),'session_id':'fixture-owner','tool_name':'Write','tool_input':{'file_path':'src/retention.py','content':'inert'}})
            self.assertEqual(code,0,error)
            self.assertEqual(result.get('hookSpecificOutput',{}).get('permissionDecision'),'deny',result)

    def test_later_verifier_records_cut_as_data_and_rechecks_withdrawal(self):
        from getzilla.verification import _change_specs
        with project_copy() as root:
            _,intent=self.fixture(root)
            first=self.publish(root,intent)
            route=state.require_route_owner(root)
            check,metadata=_change_specs(root,[],route,'fast')
            self.assertEqual(metadata['intake']['cut'],first['cut'])
            intent['event']={'id':'withdraw-one','kind':'withdraw'}
            prepare_intake(root,intent,cut_digest(first['cut']),first['cut']['M'])
            check,_=_change_specs(root,[],state.require_route_owner(root),'fast')
            self.assertEqual(check.status,'fail')

    def test_actual_installer_ships_intake_schema_contracts(self):
        from tests import test_installer as installer_tests
        source=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            target=Path(temporary)/'installed'
            installer_tests.MODULE._materialize_new(source,target,include_dependencies=False,include_optional=False,
                                                   selection=installer_tests.MODULE.PayloadSelection(()))
            for name in ('requirement-intake-v1.schema.json','intake-readiness-v1.schema.json'):
                self.assertEqual((target/'schemas'/name).read_bytes(),(source/'schemas'/name).read_bytes())

    def test_trace_binds_source_and_native_spec_without_accepting_imported_pr_state(self):
        from getzilla.intake_publication import trace_requirement
        with project_copy() as root:
            _,intent=self.fixture(root)
            first=self.publish(root,intent)
            delivery={'number':7,'state':'merged','head_sha':'a'*40,'observed_head_sha':'a'*40}
            trace=trace_requirement(root,'AC-001',delivery)
            self.assertEqual(trace['draft_digest'],first['cut']['D'])
            self.assertEqual(trace['spec_digest'],first['cut']['S'])
            self.assertEqual(trace['source_refs'][0]['id'],'source-one')
            self.assertEqual(trace['delivery_status'],'observed_unqualified')
            self.assertFalse(trace['accepted'])
            delivery['observed_head_sha']='b'*40
            self.assertEqual(trace_requirement(root,'AC-001',delivery)['delivery_status'],'stale')
