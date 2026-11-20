"""Legacy verdicts cannot create a parallel execution ledger or dispatch twice."""
import json
import unittest
from tests._support import PROJECT, project_copy, run_hook, activate_owned_route
import sys
sys.path.insert(0, str(PROJECT / '.getzilla'))
from getzilla import execution_admission as admission
from getzilla.router import build_route
from getzilla.state import add_approval

class TaskExecutionAdmissionTests(unittest.TestCase):
    def fixture(self, root):
        activate_owned_route(root, build_route(root, 'Fix ordinary source', 'legacy-observation').to_dict())

    def test_ordinary_source_write_needs_exact_task_scope(self):
        with project_copy(git=True) as root:
            self.fixture(root)
            allowed, reason = admission.evaluate_task_execution(root, 'Write', {'file_path': 'source.py', 'content': 'x'})
            self.assertFalse(allowed)
            self.assertIn('execution.submit', reason)
            self.assertFalse((root/'source.py').exists())

    def test_exact_authorized_action_works_and_changed_args_deny(self):
        with project_copy(git=True) as root:
            self.fixture(root)
            for content in ('first', 'changed'):
                inputs = {'file_path': 'source.py', 'content': content}
                with self.assertRaises(ValueError):
                    add_approval(root, 'task-execution', 'retired ledger', actions=['task-tool-execute'],
                                 resources=[admission.task_execution_resource('Write', inputs)])
                self.assertFalse(admission.evaluate_task_execution(root, 'Write', inputs)[0])

    def test_elapsed_window_expiry_denies_even_with_matching_args(self):
        with project_copy(git=True) as root:
            self.fixture(root)
            runtime = root/'.getzilla/runtime'
            (runtime/'approvals.json').write_text(json.dumps([{'scope':'task-execution','expires_at':'2099-01-01T00:00:00Z'}]))
            self.assertFalse(admission.evaluate_task_execution(root, 'Bash', {'command':'touch result', 'timeout_ms':1})[0])
            self.assertFalse((root/'result').exists())

    def test_shell_must_fit_remaining_time_and_cannot_extend_with_grant(self):
        with project_copy(git=True) as root:
            self.fixture(root)
            for timeout in (1, 600000, 86400000):
                self.assertFalse(admission.evaluate_task_execution(root, 'Bash',
                    {'command':'/usr/bin/timeout --signal=KILL 5s touch result','timeout_ms':timeout})[0])

    def test_safe_observation_and_readonly_bootstrap_stay_usable(self):
        with project_copy(git=True) as root:
            self.fixture(root)
            for tool, inputs in (('Read',{'path':'README.md'}),('Bash',{'command':'git status --short'}),
                                 ('Bash',{'command':'python3 scripts/getzilla_status.py'})):
                self.assertTrue(admission.evaluate_task_execution(root, tool, inputs)[0])
            self.assertFalse(admission.evaluate_task_execution(root,'Read',{'path':'../outside.txt'})[0])
            self.assertFalse(admission.evaluate_task_execution(root,'Read',{'path':'.env'})[0])

    def test_read_tool_preprocessor_is_not_safe_observation(self):
        with project_copy(git=True) as root:
            for command in ('rg --pre helper pattern .', 'git status; touch result'):
                self.assertFalse(admission.evaluate_task_execution(root,'Bash',{'command':command})[0])
            self.assertFalse(admission.evaluate_task_execution(root,'Glob',{'pattern':'../outside/*'})[0])

    def test_fresh_native_read_works_without_route_grant_or_old_receipt(self):
        with project_copy(git=True) as root:
            for tool, inputs in (('functions.read_file',{'path':'README.md'}),
                                 ('functions.write_file',{'path':'source.py','content':'ordinary source'})):
                code, result, _ = run_hook(root,'pre_tool_use.py',{'cwd':str(root),'tool_name':tool,'tool_input':inputs})
                self.assertEqual(code,0)
                self.assertEqual(result['decision'],'allow')
            self.assertFalse((root/'source.py').exists(), 'a hook verdict is not an executed effect')

    def test_runtime_claims_and_source_change_cannot_mint_or_reuse_authority(self):
        with project_copy(git=True) as root:
            for phase in ('original','changed'):
                (root/'source.py').write_text(phase)
                self.assertFalse(admission.evaluate_task_execution(root,'Write',{'file_path':'source.py','content':'effect'})[0])
                self.assertEqual((root/'source.py').read_text(),phase)

    def test_exact_task_action_is_one_shot(self):
        with project_copy(git=True) as root:
            self.fixture(root)
            inputs={'file_path':'source.py','content':'effect'}
            self.assertEqual(admission.task_execution_resource('Write',inputs),admission.task_execution_resource('Write',dict(inputs)))
            self.assertNotEqual(admission.task_execution_resource('Write',inputs),
                                admission.task_execution_resource('Write',{**inputs,'content':'changed'}))
            for _ in range(2):
                self.assertFalse(admission.evaluate_task_execution(root,'Write',inputs)[0])
            self.assertFalse((root/'.getzilla/runtime/approvals.json').exists())
