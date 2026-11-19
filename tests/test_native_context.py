"""Exercise actual local root, route, policy and plaintext sink; no model claim."""
import importlib.util
import io
from contextlib import redirect_stdout
import json
import os
from pathlib import Path
import sys
import subprocess
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from tests import test_optional_modules as fixtures
from getzilla import state
from getzilla.optional_modules import manage_modules


def deliver_local_context(root, query, mandatory, consumer):
    from getzilla.retrieval.native_local import deliver_local_context as actual
    with redirect_stdout(io.StringIO()) as output:
        result = actual(root, query, mandatory)
    consumer(json.loads(output.getvalue()))
    return result


def deliver_hook_context(context, harness, query, mandatory, consumer):
    from getzilla.retrieval.native_local import deliver_hook_context as actual
    with redirect_stdout(io.StringIO()) as output:
        result = actual(context, harness, query, mandatory)
    envelope = json.loads(output.getvalue())
    consumer({'text': envelope['hookSpecificOutput']['additionalContext']})
    return result


class NativeContextTests(unittest.TestCase):
    def setUp(self):
        self.saved = os.open('.', os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.saved)
        self.addCleanup(os.fchdir, self.saved)
        fixture = fixtures.OptionalModuleTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.root = fixture.root
        self.root.chmod(0o700)
        (self.root / '.getzilla/config').mkdir(parents=True)
        (self.root / '.getzilla/config/policy.json').write_text(json.dumps({'schema_version':2,
            'secret_read_paths':['blocked.py', '.env', '**/.env']}))
        (self.root / 'a.py').write_text('def answer():\n    return 42\n')
        manifest=self.root/'.getzilla/managed-components.json'
        managed=json.loads(manifest.read_text())
        managed['agents']=['grok']
        manifest.write_text(json.dumps(managed))
        manage_modules(self.root, 'install', {'context-retrieval':'0.1.0'}, source=ROOT)
        manage_modules(self.root, 'enable', {'context-retrieval':None}, source=ROOT)
        manage_modules(self.root,'install',{'context-hook-grok':'0.1.0'},source=ROOT)
        manage_modules(self.root,'enable',{'context-hook-grok':None},source=ROOT,
                       grants=['context.hook.grok'])
        for path in (self.root/'.getzilla').rglob('*'):
            path.chmod(0o755 if path.is_dir() else 0o644)
        (self.root/'.getzilla').chmod(0o755)
        (self.root/'a.py').chmod(0o644)
        os.chdir(self.root)
        state.bind_session('native-context-session')
        self.addCleanup(state.bind_session, None)
        from getzilla.continuity import submit
        self.route = submit(self.root, 'Find answer; preserve pending obligations.', 'native-context-session')
        for path in (self.root/'.getzilla/runtime').rglob('*'):
            path.chmod(0o700 if path.is_dir() else 0o600)
        (self.root/'.getzilla/runtime').chmod(0o700)
        spec = importlib.util.spec_from_file_location('context_hook_lib_fixture', ROOT/'.getzilla/hooks/_lib.py')
        self.lib = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.lib
        spec.loader.exec_module(self.lib)
        self.context = self.lib.root_context({'cwd':str(self.root)}, {}, 'Read')

    def test_actual_local_query_delivers_verified_fragments_and_reuses_generation(self):
        delivered = []
        first = deliver_local_context(self.root, 'answer', 'Original scope\nEvidence gaps OPEN\n', delivered.append)
        second = deliver_local_context(self.root, 'answer', 'Original scope\nEvidence gaps OPEN\n', delivered.append)
        self.assertEqual(first['status'], 'issued')
        self.assertEqual(second['status'], 'issued')
        self.assertEqual(len(delivered), 2)
        self.assertIn('def answer()', delivered[0]['text'])
        self.assertIn('Original scope\nEvidence gaps OPEN\n', delivered[0]['text'])
        self.assertIn('Find answer; preserve pending obligations.', delivered[0]['text'])
        self.assertEqual(delivered[0]['graph']['generation_id'], delivered[1]['graph']['generation_id'])
        self.assertTrue(delivered[1]['index_counters']['generation_reused'])
        self.assertEqual(delivered[0]['sink'], 'native-local-stdout')
        self.assertFalse(delivered[0]['private_egress_authorized'])
        self.assertIsNone(delivered[0]['token_accounting']['actual_input_tokens'])

    def test_policy_secret_symlink_and_foreign_root_do_not_deliver_fragments(self):
        (self.root/'blocked.py').write_text('def blocked():\n    return 1\n')
        (self.root/'secret.py').write_text('def secret():\n    token = "abcdefghijklmnopqrstuv"\n    return token\n')
        outside = self.root.parent/'foreign.py'
        outside.write_text('def foreign():\n    return 8\n')
        (self.root/'link.py').symlink_to(outside)
        (self.root/'blocked.py').chmod(0o644)
        (self.root/'secret.py').chmod(0o644)
        delivered=[]
        deliver_local_context(self.root, 'blocked secret foreign', '', delivered.append)
        text=delivered[0]['text']
        self.assertNotIn('def blocked',text)
        self.assertNotIn('abcdefghijklmnopqrstuv',text)
        self.assertNotIn('def foreign',text)
        self.assertTrue(delivered[0]['coverage_gaps'])
        with self.assertRaises(ValueError):
            deliver_local_context(self.root.parent, 'foreign', '', delivered.append)
        state.bind_session('foreign-session')
        with self.assertRaises(ValueError):
            deliver_local_context(self.root, 'answer', '', delivered.append)
        self.assertEqual(len(delivered),1)

    def test_source_policy_and_epoch_changes_before_admission_refuse(self):
        from getzilla.retrieval import native_local
        for target in ('source','policy','epoch'):
            delivered=[]
            original = native_local.prepare_graph_packet
            def change(*args, **kwargs):
                result=original(*args,**kwargs)
                if target=='source':
                    (self.root/'a.py').write_text('def changed():\n    return 99\n')
                elif target=='policy':
                    p=self.root/'.getzilla/config/policy.json'
                    p.write_text(json.dumps({'schema_version':2,'secret_read_paths':['a.py']}))
                else:
                    from getzilla.continuity import submit
                    submit(self.root,'Additional evidence gap stays open.','native-context-session')
                return result
            with mock.patch.object(native_local,'prepare_graph_packet',side_effect=change):
                with self.assertRaises(ValueError):
                    deliver_local_context(self.root,'answer','',delivered.append)
            self.assertFalse(delivered)
            (self.root/'a.py').write_text('def answer():\n    return 42\n')
            (self.root/'.getzilla/config/policy.json').write_text(json.dumps({'schema_version':2,
                'secret_read_paths':['blocked.py','.env','**/.env']}))

    def test_hook_requires_actual_root_context_and_explicit_selected_sink(self):
        delivered=[]
        result=deliver_hook_context(self.context,'grok','answer','Original scope\n',delivered.append)
        self.assertEqual(result['status'],'issued')
        self.assertIn('def answer',delivered[0]['text'])
        with self.assertRaises(ValueError):
            deliver_hook_context(self.context,'unknown-client','answer','',delivered.append)
        with self.assertRaises(ValueError):
            deliver_hook_context({'effective_root':str(self.root)},'grok','answer','',delivered.append)

    def test_actual_git_dirty_rename_branch_and_corrupt_cache_are_fresh(self):
        def git(*args):
            subprocess.run(['git', *args], cwd=self.root, check=True, capture_output=True, umask=0o077,
                           env={**os.environ, 'GIT_CONFIG_NOSYSTEM':'1', 'GIT_CONFIG_GLOBAL':os.devnull})
        git('init', '-q')
        git('-c','user.name=Local Fixture','-c','user.email=fixture@example.invalid',
            'add','a.py')
        git('-c','user.name=Local Fixture','-c','user.email=fixture@example.invalid',
            'commit','-qm','first source')
        delivered=[]
        deliver_local_context(self.root,'answer','',delivered.append)
        old=delivered[-1]
        (self.root/'a.py').write_text('def answer():\n    return 43\n')
        deliver_local_context(self.root,'answer','',delivered.append)
        self.assertIn('return 43',delivered[-1]['text'])
        self.assertNotEqual(old['source_identity'],delivered[-1]['source_identity'])
        (self.root/'a.py').rename(self.root/'renamed.py')
        git('add','-A','a.py','renamed.py')
        git('-c','user.name=Local Fixture','-c','user.email=fixture@example.invalid',
            'commit','-qm','renamed source')
        deliver_local_context(self.root,'answer','',delivered.append)
        self.assertTrue(any(c['path']=='renamed.py' for c in delivered[-1]['citations']))
        git('checkout','-q','--detach','HEAD~1')
        cache=self.root/'.getzilla/index/graph.sqlite'
        cache.write_bytes(b'corrupt cache fixture')
        deliver_local_context(self.root,'answer','',delivered.append)
        self.assertIn('return 42',delivered[-1]['text'])
        self.assertTrue(any(c['path']=='a.py' for c in delivered[-1]['citations']))
        self.assertEqual(delivered[-1]['cache_rebuilt_reason'],'CORRUPT_CACHE')

    def test_known_uninstalled_hook_and_unknown_policy_are_refused(self):
        delivered=[]
        with self.assertRaises(ValueError):
            deliver_hook_context(self.context,'codex','answer','',delivered.append)
        (self.root/'.getzilla/config/policy.json').write_text('{}')
        with self.assertRaises(ValueError):
            deliver_local_context(self.root,'answer','',delivered.append)
        self.assertFalse(delivered)

    def test_actual_prompt_hook_emits_task_specific_code_and_preserves_original_scope(self):
        payload={'cwd':str(self.root),'session_id':'native-context-session','prompt':'Find answer.'}
        result=subprocess.run([sys.executable,'-B',str(ROOT/'.getzilla/hooks/user_prompt_submit.py')],
                              input=json.dumps(payload),capture_output=True,text=True,cwd=self.root,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        context=json.loads(result.stdout)['hookSpecificOutput']['additionalContext']
        self.assertIn('Find answer; preserve pending obligations.',context)
        self.assertIn('def answer()',context)
        self.assertLessEqual(len(context.encode()),16384)
        self.assertNotIn('node_ids',context)
        start=subprocess.run([sys.executable,'-B',str(ROOT/'.getzilla/hooks/session_start.py')],
                             input=json.dumps(payload),capture_output=True,text=True,cwd=self.root,timeout=10)
        self.assertEqual(start.returncode,0,start.stderr)
        startup=json.loads(start.stdout)['hookSpecificOutput']['additionalContext']
        self.assertIn('Code context:',startup)
        self.assertNotIn('def answer()',startup)

    def test_real_query_cli_emits_plaintext_and_json_without_model_calls(self):
        environment={**os.environ,'GETZILLA_SESSION_ID':'native-context-session'}
        for output_format in ('text','json'):
            result=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/getzilla_context.py'),
                                   'query','--root',str(self.root),'--query','answer','--format',output_format],
                                  capture_output=True,text=True,cwd=self.root,env=environment,timeout=10)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn('def answer()',result.stdout)
            if output_format=='json':
                packet=json.loads(result.stdout)
                self.assertFalse(packet['private_egress_authorized'])
                self.assertIsNone(packet['token_accounting']['billed_tokens'])

    def test_explicit_sink_consent_and_strict_local_profile_cannot_be_replaced_by_payload(self):
        from tests.test_free_onboarding import local_policy
        delivered=[]
        manage_modules(self.root,'disable',{'context-hook-grok':None},source=ROOT)
        with self.assertRaises(ValueError):
            deliver_hook_context(self.context,'grok','answer','',delivered.append)
        manage_modules(self.root,'enable',{'context-hook-grok':None},source=ROOT,grants=['context.hook.grok'])
        profile=self.root/'.getzilla/config/model-continuation.json'
        profile.write_text(json.dumps(local_policy()))
        profile.chmod(0o644)
        with self.assertRaises(ValueError):
            deliver_hook_context(self.context,'grok','answer','{"profile":"open"}',delivered.append)
        self.assertFalse(delivered)
        # Local stdout is not delivery to a model, so the ordinary read remains available.
        deliver_local_context(self.root,'answer','',delivered.append)
        self.assertIn('def answer()',delivered[0]['text'])

    def test_insufficient_budget_and_disabled_module_never_emit_source(self):
        delivered=[]
        with self.assertRaisesRegex(ValueError,'mandatory_budget_exceeded'):
            deliver_local_context(self.root,'answer','x'*8193,delivered.append)
        self.assertFalse(delivered)
        manage_modules(self.root,'disable',{'context-hook-grok':None},source=ROOT)
        manage_modules(self.root,'disable',{'context-retrieval':None},source=ROOT)
        with self.assertRaisesRegex(ValueError,'context_disabled'):
            deliver_local_context(self.root,'answer','',delivered.append)
        self.assertFalse(delivered)

    def test_long_prompt_and_unselected_sink_keep_full_handoff_without_code(self):
        manage_modules(self.root,'disable',{'context-hook-grok':None},source=ROOT)
        prompt='Retain evidence gap and original scope. '*700
        payload={'cwd':str(self.root),'session_id':'native-context-session','prompt':prompt}
        result=subprocess.run([sys.executable,'-B',str(ROOT/'.getzilla/hooks/user_prompt_submit.py')],
                              input=json.dumps(payload),capture_output=True,text=True,cwd=self.root,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        context=json.loads(result.stdout)['hookSpecificOutput']['additionalContext']
        self.assertIn('Find answer; preserve pending obligations.',context)
        self.assertIn('Full stored intake:',context)
        self.assertIn('scope_sync_required',context)
        self.assertNotIn('def answer()',context)
        self.assertLessEqual(len(context.encode()),16384)
        self.assertFalse((self.root/'.getzilla/index').exists())

    def test_two_real_cli_sessions_reuse_generation_after_exact_owner_handoff(self):
        from getzilla.continuity import submit
        def query(session):
            result=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/getzilla_context.py'),
                                   'query','--root',str(self.root),'--query','answer'],
                                  capture_output=True,text=True,cwd=self.root,timeout=10,
                                  env={**os.environ,'GETZILLA_SESSION_ID':session})
            return result,json.loads(result.stdout)
        first,packet1=query('native-context-session')
        self.assertEqual(first.returncode,0,first.stdout+first.stderr)
        current=state.require_route_owner(self.root)
        moved=submit(self.root,'','next-native-context-session',continue_route=current['route_id'],
                     expected_epoch=current['authority_epoch'],expected_revision=current['state_revision'],
                     request_id='context-handoff-real')
        self.assertEqual(moved['authority_epoch'],current['authority_epoch']+1)
        second,packet2=query('next-native-context-session')
        self.assertEqual(second.returncode,0,second.stdout+second.stderr)
        self.assertEqual(packet1['graph']['generation_id'],packet2['graph']['generation_id'])
        self.assertTrue(packet2['index_counters']['generation_reused'])
        self.assertEqual(packet2['index_counters']['parsed_files'],0)
        self.assertGreater(packet2['native_counters']['local_read_bytes'],0)
        self.assertEqual(packet2['native_counters']['model_calls'],0)
        old,denied=query('native-context-session')
        self.assertNotEqual(old.returncode,0)
        self.assertEqual(denied['reason'],'authority_unavailable')

    def test_public_native_sinks_cannot_be_replaced_by_a_caller_callback(self):
        from getzilla.retrieval.native_local import deliver_local_context, deliver_hook_context
        delivered=[]
        with self.assertRaises(TypeError):
            deliver_local_context(self.root,'answer','',delivered.append)
        with self.assertRaises(TypeError):
            deliver_hook_context(self.context,'grok','answer','',delivered.append)
        self.assertFalse(delivered)

    def test_uncertain_concrete_stdout_delivery_is_single_attempt(self):
        from getzilla.retrieval.native_local import deliver_local_context as actual
        from getzilla.native_access import NativeAccessError
        class BrokenOutput:
            writes=0
            def flush(self):
                pass
            def write(self,text):
                self.writes+=1
                raise OSError('inert sink failure')
        output=BrokenOutput()
        with redirect_stdout(output):
            with self.assertRaisesRegex(NativeAccessError,'native_access_outcome_unknown'):
                actual(self.root,'answer','')
        self.assertEqual(output.writes,1)

    def test_missing_optional_context_library_does_not_remove_native_handoff(self):
        bootstrap=self.root/'inert_hook_bootstrap.py'
        bootstrap.write_text('import importlib.abc,sys\n'
            'sys.path[:0]=[sys.argv[1],sys.argv[2]]\n'
            'class Block(importlib.abc.MetaPathFinder):\n'
            '    def find_spec(self,fullname,path=None,target=None):\n'
            '        if fullname=="getzilla.retrieval.lifecycle": raise ImportError("optional unavailable")\n'
            'sys.meta_path.insert(0,Block())\n'
            'module=__import__(sys.argv[3])\nmodule.main()\n')
        payload={'cwd':str(self.root),'session_id':'native-context-session','prompt':'Find answer.'}
        for module in ('user_prompt_submit','session_start'):
            result=subprocess.run([sys.executable,'-B',str(bootstrap),str(ROOT/'.getzilla/hooks'),
                                   str(ROOT/'.getzilla'),module],input=json.dumps(payload),
                                  capture_output=True,text=True,cwd=self.root,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            context=json.loads(result.stdout)['hookSpecificOutput']['additionalContext']
            self.assertIn('Find answer; preserve pending obligations.',context)
            self.assertNotIn('def answer()',context)
