"""Owned fake MCP children only. No Jira, OAuth, remote mutation or MCP service."""
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
PACKAGE = ROOT / '.getzilla/optional-modules/mcp-jira/0.1.0'
spec = importlib.util.spec_from_file_location('getzilla_test_mcp', PACKAGE / '__init__.py', submodule_search_locations=[str(PACKAGE)])
pkg = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = pkg
spec.loader.exec_module(pkg)
from getzilla_test_mcp.transport import CAP, Frames, Session, TransportError, native_bypass
from getzilla_test_mcp.admission import gate, scope_key
from getzilla_test_mcp.runtime import Runtime

PROGRAM = '''import sys,json,time,signal
signal.signal(signal.SIGTERM,signal.SIG_IGN)
for l in sys.stdin:
 m=json.loads(l); k=m.get('method'); i=m.get('id')
 if k=='initialize':
  print(json.dumps({'jsonrpc':'2.0','id':i,'result':{'protocolVersion':'2025-11-25','capabilities':{},'serverInfo':{'name':'fixture','version':'1.0.0'}}}),flush=True)
 if k=='tools/list': print(json.dumps({'jsonrpc':'2.0','id':i,'result':{'tools':[{'name':'fixture_read','inputSchema':{'type':'object'},'annotations':{'readOnlyHint':True}}]}}),flush=True)
 if k=='tools/call':
  a=m['params']['arguments']; mode=a.get('mode','ok')
  if mode in ('hang','ignore_cancel'): time.sleep(100)
  if mode=='slow': time.sleep(.15)
  if mode=='late':
   print(json.dumps({'jsonrpc':'2.0','id':'old','result':{}}),flush=True); time.sleep(100)
  if mode=='huge': print('x'*1048577,flush=True); continue
  if mode=='malformed': print('{bad}',flush=True); continue
  if mode=='disconnect': sys.exit(0)
  if mode=='task':
   print(json.dumps({'jsonrpc':'2.0','id':i,'result':{'task':{'taskId':'remote-job-1'}}}),flush=True); continue
  print(json.dumps({'jsonrpc':'2.0','id':i,'result':{'isError':mode=='domain','content':[{'type':'text','text':'ok'}]}}),flush=True)
'''
ARGUMENT = 'exec(' + repr(PROGRAM) + ')'


class WireTests(unittest.TestCase):
    def child(self):
        process = subprocess.Popen([sys.executable, '-c', ARGUMENT], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        def cleanup():
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
        self.addCleanup(cleanup)
        return process

    def call(self, mode, *, duration=.3, watch=lambda: 'running'):
        session = Session(self.child(), deadline=time.monotonic()+duration, watch=watch, request_id='request')
        try:
            return session.call('fixture_read', {'mode': mode})
        finally:
            session.close()

    def test_T20_ignored_cancel_keeps_remote_unconfirmed(self):
        cancelled = threading.Event()
        timer = threading.Timer(.1, cancelled.set)
        timer.start()
        self.addCleanup(timer.cancel)
        result = self.call('ignore_cancel', duration=1, watch=lambda: 'cancelled' if cancelled.is_set() else 'running')
        self.assertEqual(result.status, 'cancelled')
        self.assertTrue(result.sent)
        self.assertFalse(result.remote_confirmed)

    def test_T21_hung_A_does_not_block_B_or_local_work(self):
        values = []
        thread = threading.Thread(target=lambda: values.append(self.call('hang', duration=.3)))
        thread.start()
        self.assertEqual(self.call('ok').status, 'success')
        self.assertEqual(sum(range(10)), 45)
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(values[0].status, 'deadline')

    def test_slow_late_disconnect_malformed_and_domain(self):
        for mode, expected in [('slow','success'), ('late','deadline'), ('disconnect','infra'),
                               ('malformed','infra'), ('domain','domain')]:
            with self.subTest(mode=mode):
                self.assertEqual(self.call(mode, duration=.4).status, expected)

    def test_T25_preparse_cap_and_huge_actual_child(self):
        frames = Frames()
        with patch('json.loads', side_effect=AssertionError('parser must not run')):
            with self.assertRaisesRegex(TransportError,'oversize'):
                frames.feed(b'x'*(CAP+1))
        self.assertEqual(len(frames.pending),0)
        reply = self.call('huge', duration=1)
        self.assertEqual((reply.status,reply.reason),('infra','oversize'))
        self.assertTrue(reply.sent)

    def test_parse_boundary_cannot_accept_a_result_after_deadline(self):
        session=Session(self.child(),deadline=time.monotonic()+1,watch=lambda:'running',request_id='parse-boundary')
        original=session.frames.feed
        def late_parse(chunk):
            result=original(chunk)
            if result:
                session.deadline=time.monotonic()-1
            return result
        session.frames.feed=late_parse
        try:
            self.assertEqual(session.call('fixture_read',{}).status,'deadline')
        finally:
            session.close()

    def test_remote_task_identity_is_separate_and_never_invented_done(self):
        result=self.call('task')
        self.assertEqual(result.remote_task_id,'remote-job-1')
        self.assertEqual(result.status,'unsupported')
        self.assertFalse(result.remote_confirmed)

    def test_T35_native_bypass_has_no_managed_claim(self):
        self.assertEqual(native_bypass()['management'],'unmanaged')
        self.assertFalse(native_bypass()['limits_enforced'])


class GateTests(unittest.TestCase):
    def setUp(self):
        self.now=datetime.now(timezone.utc)
        self.label=scope_key(endpoint='stdio://binary',project='project',credential_scope='principal',configuration={'pin':'v1'})

    def record(self, *, label=None, reason=None, age=0, active=False, cleanup='confirmed'):
        return dict(input={'display':{'label':label or self.label}}, execution_status='running' if active else 'failed',
                    cleanup_status=cleanup,terminal_reason=reason,
                    retention_until=None if active else (self.now-timedelta(seconds=age)+timedelta(days=1)).isoformat())

    def test_T22_scope2_global8_and_unconfirmed_consumes_capacity(self):
        registry={'records':{'a':self.record(active=True),'b':self.record(cleanup='unconfirmed')}}
        self.assertEqual(gate(registry,self.label,now=self.now),'resource_busy')
        registry={'records':{str(i):self.record(label='mcp-'+str(i),active=True) for i in range(8)}}
        self.assertEqual(gate(registry,self.label,now=self.now),'resource_busy')

    def test_T23_breaker3_cooldown60_one_safe_probe(self):
        records={str(i):self.record(reason='mcp_infra_disconnect',age=i) for i in range(3)}
        self.assertEqual(gate({'records':records},self.label,now=self.now),'breaker_open')
        after=self.now+timedelta(seconds=61)
        self.assertIsNone(gate({'records':records},self.label,now=after))
        self.assertEqual(gate({'records':records},self.label,now=after,read_only=False),'breaker_safe_probe_required')
        records['probe']=self.record(active=True)
        self.assertEqual(gate({'records':records},self.label,now=after),'breaker_probe_busy')

    def test_unresolved_remote_budget_stays_bounded_after_local_cleanup(self):
        records={str(i):dict(self.record(reason='mcp_unsupported'),remote_task_id='remote-'+str(i),operation_outcome='unknown') for i in range(32)}
        self.assertEqual(gate({'records':records},self.label,now=self.now),'unresolved_budget_busy')

    def test_failed_half_open_probe_reopens_and_no_response_does_not_heal(self):
        records={str(i):self.record(reason='mcp_infra_disconnect',age=i) for i in range(3)}
        later=self.now+timedelta(seconds=600)
        self.assertEqual(gate({'records':records},self.label,now=later,read_only=False),'breaker_safe_probe_required')
        records['failed-probe']=self.record(reason='mcp_infra_disconnect',age=-600)
        self.assertEqual(gate({'records':records},self.label,now=later),'breaker_open')

    def test_T24_domain_policy_cancel_wait_expiry_do_not_charge_health(self):
        for reason in ('mcp_domain','mcp_policy','mcp_cancelled','mcp_wait_expiry'):
            registry={'records':{str(i):self.record(reason=reason,age=i) for i in range(3)}}
            self.assertIsNone(gate(registry,self.label,now=self.now))


class NativeTests(unittest.TestCase):
    """Actual namespace process and existing module/execution lifecycle."""
    def setUp(self):
        from tests.test_optional_modules import OptionalModuleTests
        from tests.execution_contract_support import owned_route
        from getzilla import state
        from getzilla.optional_modules import manage_modules
        from getzilla.module_runtime import ActivationRequestV1, plan_activation, commit_activation
        from getzilla.component_state import read_state
        from getzilla_test_mcp.admission import HostBudget
        import hashlib
        import shutil
        self.fixture=OptionalModuleTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root
        self.root.chmod(0o700)
        self.enterContext(patch.dict(os.environ,{'GETZILLA_SESSION_ID':'owner'}))
        self.addCleanup(state.bind_session,None)
        self.route=owned_route(self.root)
        manage_modules(self.root,'install',{'mcp-jira':'0.1.0'},source=ROOT)
        python=Path(sys.executable).resolve()
        self.binary=self.fixture.workspace/'bin/python3'
        self.binary.parent.mkdir(mode=0o700,parents=True)
        shutil.copyfile(python,self.binary)
        self.binary.chmod(0o755)
        self.server_script=self.root/'fake_server.py'
        self.server_script.write_text(PROGRAM)
        self.server_script.chmod(0o644)
        (self.root/'.getzilla/config').mkdir(exist_ok=True)
        (self.root/'.getzilla/config/policy.json').write_text('{"schema_version":2}')
        (self.root/'.getzilla/config/toolchain.json').write_text(json.dumps({'schema_version':1,'tools':[{
            'id':'fake-mcp','commands':['python3'],'managed':{'executable':str(self.binary),
            'sha256':hashlib.sha256(self.binary.read_bytes()).hexdigest(),'argv':[str(self.server_script)]}}]}))
        (self.root/'.getzilla/config/toolchain.json').chmod(0o644)
        # Public fixture sources meet the canonical source-reader custody rules.
        for path in self.root.rglob('*'):
            if path.is_dir() and '.getzilla/runtime' not in str(path):
                path.chmod(0o755)
            if path.is_file() and '.getzilla/runtime/' not in str(path):
                path.chmod(0o644)
        self.profile={'transport':'stdio','protocol':'2025-11-25','credential_scope':'local-uid:'+str(os.getuid()),
                      'tool_id':'fake-mcp','server_version':'1.0.0','endpoint':'stdio://fixture','tools':{'fixture_read':'read'}}
        class Authority:
            calls=0
            def authorize_activation(host,request): return object()
            def validate_activation(host,request,handle): host.calls+=1
        self.authority=Authority()
        self.runtime=Runtime(self.root,authority=self.authority,profile=self.profile,
                             host_budget=HostBudget(self.root,[self.root]))
        metadata=read_state(self.root).manifest['components']['module:mcp-jira']['module']
        self.request=ActivationRequestV1(str(self.root),'mcp-jira','0.1.0',metadata['manifest_sha256'],
            self.route['logical_task_id'],'fixture-run','owner',self.route['authority_epoch'],'a'*64,
            'managed-stdio-v1',hashlib.sha256(json.dumps(self.profile,sort_keys=True,separators=(',',':')).encode()).hexdigest(),('jira.read',))
        self.plan=plan_activation(self.root,'mcp-jira',self.request,native=self.runtime,runtime=self.runtime,authority=self.authority)
        self.activate=lambda: commit_activation(self.root,self.plan,native=self.runtime,runtime=self.runtime,authority=self.authority)

    def test_invalid_policy_denies_before_execution_allocation(self):
        from getzilla import execution, execution_store
        self.activate()
        (self.root/'.getzilla/config/policy.json').write_text('{}')
        with self.assertRaisesRegex(execution.ExecutionError, 'mcp_identity_unverified'):
            self.runtime.call(tool='fixture_read',arguments={},intent_key='invalid-policy')
        self.assertEqual(execution_store.load_registry(self.root)['records'], {})

    def test_T26_disabled_zero_provider_work_and_no_configuration_mutation(self):
        before={str(path):path.read_bytes() for path in self.root.rglob('*') if path.is_file()}
        from getzilla import managed_execution
        policy=self.enterContext(patch('getzilla.managed_execution._policy', wraps=managed_execution._policy))
        calls=self.authority.calls
        result=self.runtime.call(tool='fixture_read',arguments={},intent_key='disabled')
        self.assertEqual(result['status'],'disabled')
        self.assertEqual(self.authority.calls,calls)
        policy.assert_not_called()
        self.assertEqual(before,{str(path):path.read_bytes() for path in self.root.rglob('*') if path.is_file()})
        self.fixture.assert_user_settings()

    def test_read_only_activation_cannot_create_an_effect_intent(self):
        from getzilla import execution
        from getzilla_test_mcp.effects import Effects
        self.activate()
        effects=Effects(self.root,caller=execution.trusted_caller(self.root),access=object(),provider=object(),runtime=self.runtime)
        with self.assertRaisesRegex(ValueError,'module_write_not_granted'):
            effects.intent('a'*32,'write',target={},operation='comment',arguments={},baseline='revision')

    def test_native_tool_identity_requires_actual_port_and_enabled_owned_bytes(self):
        from getzilla.supply_chain import check_tool_trust
        event={'tool_name':'mcp__managed_stdio__fixture_read','managed':True,'qualified':True}
        self.assertFalse(check_tool_trust(self.root,event)[0])
        self.assertFalse(check_tool_trust(self.root,event,managed_adapter=self.runtime)[0])
        self.activate()
        self.assertTrue(check_tool_trust(self.root,event,managed_adapter=self.runtime)[0])
        self.assertFalse(check_tool_trust(self.root,{'tool_name':'mcp__other__mutate'},managed_adapter=self.runtime)[0])
        self.runtime.profile['server_version']='changed'
        self.assertFalse(check_tool_trust(self.root,event,managed_adapter=self.runtime)[0])

    def test_host_global_budget_reads_actual_other_project_registry(self):
        from getzilla import execution
        from getzilla_test_mcp.admission import HostBudget
        from tests.execution_contract_support import CountingBackend,owned_route
        other=self.fixture.workspace/'other-project'
        other.mkdir(mode=0o700)
        owned_route(other)
        caller=execution.trusted_caller(other)
        for index in range(8):
            execution.submit(other,caller,execution.SubmitRequest('held-'+str(index),{},30,label='mcp-other-'+str(index)),backend=CountingBackend(complete=False))
        self.runtime.host_budget=HostBudget(self.root,[self.root,other])
        self.activate()
        with self.assertRaisesRegex(execution.ExecutionError,'resource_busy'):
            self.runtime.call(tool='fixture_read',arguments={},intent_key='host-capacity')

    @unittest.skipUnless(sys.platform=='linux' and Path('/usr/bin/bwrap').exists(),'Linux namespace profile required')
    def test_disable_after_result_before_release_suppresses_cached_reply(self):
        from getzilla import execution
        from getzilla.module_runtime import quiesce_module
        self.activate()
        original=execution.submit
        def finish_then_disable(*args,**kwargs):
            value=original(*args,**kwargs)
            quiesce_module(self.root,'mcp-jira',runtime=self.runtime,deadline=time.monotonic()+2)
            return value
        with patch.object(execution,'submit',side_effect=finish_then_disable):
            result=self.runtime.call(tool='fixture_read',arguments={},intent_key='release-fence',hard_timeout_seconds=3)
        self.assertIsNone(result['reply'])
        self.assertEqual(result['result_status'],'denied')

    @unittest.skipUnless(sys.platform=='linux' and Path('/usr/bin/bwrap').exists(),'Linux namespace profile required')
    def test_T21_two_hung_A_attempts_leave_B_and_canonical_local_checks_running(self):
        from dataclasses import replace
        import hashlib
        import shutil
        from getzilla import execution_store,supervised_execution
        from getzilla.module_runtime import plan_activation
        script=self.root/'fake_server_b.py'
        script.write_text(PROGRAM)
        script.chmod(0o644)
        config_path=self.root/'.getzilla/config/toolchain.json'
        config=json.loads(config_path.read_text())
        config['tools'].append(dict(id='fake-mcp-b',commands=['python3'],managed=dict(executable=str(self.binary),sha256=hashlib.sha256(self.binary.read_bytes()).hexdigest(),argv=[str(script)])))
        local=self.fixture.workspace/'bin/true'
        shutil.copyfile('/usr/bin/true',local)
        local.chmod(0o755)
        config['tools'].append(dict(id='local-true',commands=['true'],managed=dict(executable=str(local),sha256=hashlib.sha256(local.read_bytes()).hexdigest(),argv=[])))
        config_path.write_text(json.dumps(config))
        profile=dict(self.profile)
        self.runtime.profile={'servers':{'a':profile,'b':dict(profile,tool_id='fake-mcp-b')}}
        self.request=replace(self.request,scope_digest=hashlib.sha256(json.dumps(self.runtime.profile,sort_keys=True,separators=(',',':')).encode()).hexdigest())
        self.plan=plan_activation(self.root,'mcp-jira',self.request,native=self.runtime,runtime=self.runtime,authority=self.authority)
        self.activate()
        values=[]
        def hang(index):values.append(self.runtime.call(server_id='a',tool='fixture_read',arguments={'mode':'hang'},intent_key='branch-a-'+str(index),hard_timeout_seconds=5))
        threads=[threading.Thread(target=hang,args=(index,)) for index in range(2)]
        for thread in threads:
            thread.start()
            self.addCleanup(lambda thread=thread:thread.join(5))
        end=time.monotonic()+2
        while len(execution_store.load_registry(self.root)['records'])<2 and time.monotonic()<end:
            time.sleep(.01)
        healthy=self.runtime.call(server_id='b',tool='fixture_read',arguments={},intent_key='branch-b',hard_timeout_seconds=3)
        self.assertEqual(healthy['reply'].status,'success')
        local_job=supervised_execution.start(self.root,tool_id='local-true',intent_key='local-check',hard_timeout_seconds=3)
        local_result=supervised_execution.observe(self.root,local_job['execution_id'],wait_seconds=3)
        self.assertEqual(local_result['execution']['execution_status'],'succeeded',local_result)
        for thread in threads:
            thread.join(5)
            self.assertFalse(thread.is_alive())
        self.assertTrue(all(value['execution']['cleanup_status']=='confirmed' for value in values))

    @unittest.skipUnless(sys.platform=='linux' and Path('/usr/bin/bwrap').exists(),'Linux namespace profile required')
    def test_T22_actual_scope_saturation_has_two_owned_attempts_and_no_wait_queue(self):
        from getzilla import execution,execution_store
        self.activate()
        values=[]
        def call(index):
            values.append(self.runtime.call(tool='fixture_read',arguments={'mode':'hang'},intent_key='saturated-'+str(index),hard_timeout_seconds=2))
        threads=[threading.Thread(target=call,args=(index,)) for index in range(2)]
        for thread in threads:
            thread.start()
            self.addCleanup(lambda thread=thread:thread.join(5))
        end=time.monotonic()+1.5
        while time.monotonic()<end:
            if len(execution_store.load_registry(self.root)['records'])==2:
                break
            time.sleep(.01)
        with self.assertRaisesRegex(execution.ExecutionError,'resource_busy'):
            self.runtime.call(tool='fixture_read',arguments={},intent_key='third',hard_timeout_seconds=2)
        for thread in threads:
            thread.join(5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(execution_store.load_registry(self.root)['records']),2)
        self.assertEqual(len(values),2)
        self.assertTrue(all(value['execution']['cleanup_status']=='confirmed' for value in values))

    @unittest.skipUnless(sys.platform=='linux' and Path('/usr/bin/bwrap').exists(),'Linux namespace profile required')
    def test_actual_managed_call_uses_canonical_registry_and_replay(self):
        from getzilla import execution_store
        self.activate()
        result=self.runtime.call(tool='fixture_read',arguments={},intent_key='first',hard_timeout_seconds=2)
        self.assertEqual(result['execution']['execution_status'],'succeeded',result)
        self.assertEqual(result['reply'].status,'success')
        repeated=self.runtime.call(tool='fixture_read',arguments={},intent_key='first',hard_timeout_seconds=2)
        self.assertEqual(repeated['execution']['execution_id'],result['execution']['execution_id'])
        self.assertEqual(len(execution_store.load_registry(self.root)['records']),1)
        self.assertEqual(result['execution']['cleanup_status'],'confirmed')

    @unittest.skipUnless(sys.platform=='linux' and Path('/usr/bin/bwrap').exists(),'Linux namespace profile required')
    def test_T27_disable_stops_owned_child_preserves_uncertainty_and_user_settings(self):
        from getzilla.module_runtime import quiesce_module
        self.activate()
        values=[]
        thread=threading.Thread(target=lambda:values.append(self.runtime.call(tool='fixture_read',arguments={'mode':'ignore_cancel'},intent_key='disable',hard_timeout_seconds=3)))
        thread.start()
        from getzilla import execution_store
        end=time.monotonic()+2
        while time.monotonic()<end:
            records=execution_store.load_registry(self.root)['records'].values()
            if any((record.get('launch') or {}).get('phase')=='released' for record in records):
                break
            time.sleep(.01)
        else:
            self.fail('fake MCP launch did not reach its owned gate')
        outcome=quiesce_module(self.root,'mcp-jira',runtime=self.runtime,deadline=time.monotonic()+2)
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(outcome.workers,0)
        self.assertFalse(values[0]['remote_termination_confirmed'])
        self.assertEqual(values[0]['execution']['cleanup_status'],'confirmed')
        self.fixture.assert_user_settings()


class EffectsTests(unittest.TestCase):
    def setUp(self):
        NativeTests.setUp(self)
        from dataclasses import replace
        from getzilla.module_runtime import plan_activation
        self.request=replace(self.request,operations=('jira.read','jira.write'))
        self.plan=plan_activation(self.root,'mcp-jira',self.request,native=self.runtime,runtime=self.runtime,authority=self.authority)
        self.activate()
        from getzilla import execution
        from tests.execution_contract_support import CountingBackend
        from getzilla_test_mcp.effects import Effects
        self.caller=execution.trusted_caller(self.root)
        self.operation='fixture-comment-1'
        self.execution=execution.submit(self.root,self.caller,execution.SubmitRequest('effect-fixture',{},30,operation_id=self.operation),backend=CountingBackend(complete=False))
        class Access:
            allowed=True
            def authorize(self,target,operation):
                if not self.allowed:
                    raise ValueError('permission_revoked')
            def authorize_release(self,target,operation,arguments):self.authorize(target,operation)
            def validate_closure(self,resource,acceptance):raise ValueError('accepted_change_evidence_unavailable')
        class Provider:
            intent_reconciliation_qualified=True
            calls=0
            observations=0
            def emit(self,intent,arguments):
                self.calls+=1
                raise TimeoutError('synthetic lost write response')
            def observe(self,intent):
                self.observations+=1
                return {'revision':'human-edit'}
        self.access,self.provider=Access(),Provider()
        self.effects=Effects(self.root,caller=self.caller,access=self.access,provider=self.provider,runtime=self.runtime)
        self.target={'site':'fixture-site','project':'TEST','resource':'1001'}
        self.arguments={'body':'fixture only'}

    def test_unknown_write_is_never_repeated_and_human_changes_are_preserved(self):
        eid=self.execution['execution_id']
        self.effects.intent(eid,self.operation,target=self.target,operation='comment',arguments=self.arguments,baseline='revision-1')
        self.assertEqual(self.effects.apply(eid,self.operation,arguments=self.arguments)['status'],'unknown')
        self.assertEqual(self.effects.apply(eid,self.operation,arguments=self.arguments)['status'],'unknown')
        self.assertEqual(self.provider.calls,1)
        current=self.effects.reconcile(eid,self.operation)
        self.assertEqual(current['conflict'],'intervening_human_change')
        self.assertEqual(current['outcome'],'unknown')
        self.assertEqual(self.provider.calls,1)
        self.access.allowed=False
        with self.assertRaisesRegex(ValueError,'permission_revoked'):
            self.effects.reconcile(eid,self.operation)
        self.assertEqual(self.provider.observations,1)

    def test_stable_operation_across_new_attempts_reuses_the_existing_intent(self):
        from getzilla import execution
        from tests.execution_contract_support import CountingBackend
        original=self.effects.intent(self.execution['execution_id'],self.operation,target=self.target,operation='comment',arguments=self.arguments,baseline='revision-1')
        later=execution.submit(self.root,self.caller,execution.SubmitRequest('next-attempt',{},30,operation_id=self.operation),backend=CountingBackend(complete=False))
        repeated=self.effects.intent(later['execution_id'],self.operation,target=self.target,operation='comment',arguments=self.arguments,baseline='revision-1')
        self.assertEqual(repeated['execution_id'],original['execution_id'])
        self.effects.apply(repeated['execution_id'],self.operation,arguments=self.arguments)
        self.effects.apply(repeated['execution_id'],self.operation,arguments=self.arguments)
        self.assertEqual(self.provider.calls,1)

    def test_dispatcher_target_and_fake_closure_claim_cannot_expand_scope(self):
        from getzilla_test_mcp.jira import Jira
        jira=Jira(site='fixture-site',project='TEST',resources=['1001'],manifest={
            'getIssue':{'class':'read','operation':'read'},'transition':{'class':'write','operation':'close'}},
            runtime=self.runtime,access=self.access,effects=self.effects)
        with self.assertRaisesRegex(ValueError,'jira_argument_schema_unqualified'):
            jira.normalize('getIssue',dict(self.target,issueId='outside'))
        nested={'operation':'executeWrite','arguments':{'operation':'transition','arguments':dict(self.target,site='outside')}}
        with self.assertRaisesRegex(ValueError,'jira_target_scope'):
            jira.normalize('executeWrite',nested)
        with self.assertRaisesRegex(ValueError,'accepted_change_evidence_unavailable'):
            jira.write('transition',self.target,execution_id=self.execution['execution_id'],operation_id=self.operation,baseline='revision-1',acceptance={'done':True,'merged':True})
        self.assertEqual(self.provider.calls,0)


class PayloadTests(unittest.TestCase):
    def test_T26_core_payload_and_engine_archive_exclude_mcp_implementation(self):
        from tests.test_optional_modules import installer
        import io
        import zipfile
        install=installer()
        entries=install.build_payload(ROOT,selection=install.PayloadSelection(()))
        self.assertFalse([entry.path for entry in entries if '/optional-modules/mcp-jira/' in entry.path or '/modules/mcp-jira/' in entry.path])
        core=[entry for entry in entries if entry.path.startswith('.getzilla/getzilla/')]
        archive=install.engine_archive_entry(core)
        with zipfile.ZipFile(io.BytesIO(archive.content)) as zipped:
            members=set(zipped.namelist())
            self.assertIn('getzilla/retrieval/transport.py',members)
            addon_roots=('optional-modules/mcp-jira/', 'modules/mcp-jira/',
                         '.getzilla/optional-modules/mcp-jira/', '.getzilla/modules/mcp-jira/')
            self.assertFalse([name for name in members if 'mcp-jira' in name or name.startswith(addon_roots)])
