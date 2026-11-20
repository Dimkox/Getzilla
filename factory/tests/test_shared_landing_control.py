"""Single-owner control storage and dispatch invariants. No provider network."""
from dataclasses import replace
from datetime import timedelta
import sqlite3
import unittest
from unittest.mock import patch

from factory.tests import test_landing_sqlite_store as sqlite_tests
source = sqlite_tests.source
from factory.tests import test_paid_admission as paid_tests
from getzilla_factory.landing_service import LandingJobRecord, LandingServiceError
from getzilla_factory.shared_landing_contracts import SharedControlBindingV1
from getzilla_factory.paid_admission import SHARED_DISPATCH_GUARD


class SharedBindingTests(unittest.TestCase):
    setUp = sqlite_tests.SQLiteLandingJobStoreTests.setUp
    store = sqlite_tests.SQLiteLandingJobStoreTests.store
    def binding(self):
        return SharedControlBindingV1('tenant-1','account','task','logical-task','a'*64,0,'b'*64,'e'*64,'c'*40,'d'*40)

    def test_atomic_binding_replay_conflicts_every_field_and_legacy_collision(self):
        store = self.store()
        item = source()
        record = LandingJobRecord(item,'accepted',None,None)
        binding = self.binding()
        first,created = store.create_or_replay(record,command_key=item.job_id,request_digest=item.input_digest,control_binding=binding)
        self.assertTrue(created)
        replay,created = store.create_or_replay(record,command_key=item.job_id,request_digest=item.input_digest,control_binding=binding)
        self.assertEqual(first,replay)
        self.assertFalse(created)
        for field,value in [('actor_id','other'),('account_id','other'),('task_id','other'),('control_task_id','other'),('parent_digest','f'*64),('ordinal',1),('profile_digest','f'*64),('credential_digest','f'*64),('source_head','f'*40),('source_tree','f'*40)]:
            with self.subTest(field=field), self.assertRaisesRegex(LandingServiceError,'idempotency_conflict'):
                store.create_or_replay(record,command_key=item.job_id,request_digest=item.input_digest,control_binding=replace(binding,**{field:value}))
        with self.assertRaisesRegex(LandingServiceError,'idempotency_conflict'):
            store.create_or_replay(record,command_key=item.job_id,request_digest=item.input_digest)
        self.assertEqual(1,store._connection.execute('SELECT count(*) FROM landing_commands').fetchone()[0])
        self.assertEqual(1,store._connection.execute('SELECT count(*) FROM shared_control_bindings').fetchone()[0])

    def test_v3_forward_upgrade_preserves_jobs_and_rejects_extra_legacy_tables(self):
        store = self.store()
        item = source()
        store.create_or_replay(LandingJobRecord(item,'accepted',None,None),command_key='old',request_digest=item.input_digest)
        path = store.database_path
        store.close()
        with sqlite3.connect(path) as db:
            db.execute('DROP TABLE shared_control_bindings')
            db.execute('DROP TABLE shared_control_clock')
            db.execute('PRAGMA user_version=3')
        upgraded = self.store(recovery_limit=0)
        self.assertEqual(item,upgraded.get(item.tenant_id,item.repository_id,item.job_id).source)
        self.assertEqual(4,upgraded._connection.execute('PRAGMA user_version').fetchone()[0])


class SharedDispatchTests(unittest.TestCase):
    setUp = paid_tests.PaidAdmissionTests.setUp
    def test_clock_highwater_survives_denied_expiry_and_restart(self):
        initial = self.now
        self.now += timedelta(seconds=301)
        with self.assertRaisesRegex(Exception,'paid_expired'):
            self.admission.reserve('qwen','qwen-plus','paid-inference','d'*64,50,20)
        self.now = initial
        with self.assertRaisesRegex(Exception,'clock_rollback'):
            self.admission.reserve('qwen','qwen-plus','paid-inference','d'*64,50,20)

    def test_dispatch_guard_runs_after_reserve_and_before_durable_dispatch(self):
        reservation = self.admission.reserve('qwen','qwen-plus','paid-inference','d'*64,50,20)
        calls=[]
        def reject(admission, input_digest, provider, model):
            calls.append((admission,input_digest,provider,model))
            raise ValueError('revoked')
        token=SHARED_DISPATCH_GUARD.set(reject)
        try:
            with self.assertRaisesRegex(ValueError,'revoked'):
                self.admission.dispatch(reservation,'a'*64,'d'*64,'qwen','qwen-plus')
        finally:
            SHARED_DISPATCH_GUARD.reset(token)
        self.assertEqual(1,len(calls))
        self.assertEqual('reserved',self.store.paid_audit('account')[0]['state'])


class SharedControlBoundaryTests(unittest.TestCase):
    """Real current-access policy; source/Factory execution qualifies in PG case."""
    def setUp(self):
        import base64,copy,json,tempfile
        from datetime import datetime,timezone,timedelta
        from pathlib import Path
        from fastapi.testclient import TestClient
        from factory.tests.test_access_authority import authority_fixture
        from getzilla_factory.access_authority import AccessAuthority
        from getzilla_factory.api import Authenticator,create_app
        from getzilla_factory.landing_renderer import TARGET_REPOSITORY_ID,TARGET_BASE_SHA,TARGET_BASE_TREE
        from getzilla_factory.landing_intake import PrivateLandingBlobStore
        from getzilla_factory.landing_sqlite_store import SQLiteLandingJobStore
        from getzilla_factory.landing_service import LandingApplicationService
        from getzilla_factory.landing_server import OwnedLandingRuntime
        from getzilla_factory.landing_http import HttpLandingProfile,HttpLandingNormalizer
        from getzilla_factory.landing_live_executors import qwen_landing_executor
        from getzilla_factory.paid_admission import PaidAccountV1,PaidTaskV1,PaidPriceV1,PaidExecutionAdmission
        from getzilla_factory.service import FactoryService
        from getzilla_factory.store import PostgresFactoryStore
        from getzilla_factory.shared_landing_control import SharedAuthorityControl,SharedLandingTask,install_shared_control_api
        from factory.tests.test_paid_admission import SCRATCH
        temporary=tempfile.TemporaryDirectory(dir=SCRATCH)
        self.addCleanup(temporary.cleanup)
        root=Path(temporary.name)
        control=root/'control';control.mkdir()
        self.now=datetime.now(timezone.utc)
        self.store=SQLiteLandingJobStore(root/'authority',repository_root=control,clock=lambda:self.now)
        self.addCleanup(self.store.close)
        self.blobs=PrivateLandingBlobStore(root/'blobs',repository_root=control)
        from getzilla_factory.landing_contracts import landing_digest
        profile=HttpLandingProfile.for_provider('qwen-intl',available=True)
        child='fo-'+landing_digest('landing-failover-child-v1',{'parent':'a'*64,'ordinal':0,'profile':profile.profile_digest})[:48]
        self.expected=self.blobs.accept(job_id=child,tenant_id='user-a',repository_id=TARGET_REPOSITORY_ID,
            exact_base_sha=TARGET_BASE_SHA,exact_base_tree=TARGET_BASE_TREE,site_id='therealaidarkfactory.online',media_kind='text',media_type='text/plain',chunks=(b'fixture',),received_at=self.now,expires_at=self.now+timedelta(days=1))
        path,payload,key=authority_fixture(root)
        for actor in payload['actors']:
            actor['scopes']+=['landing:submit','landing:read','task:read']
            actor['repositories']=[TARGET_REPOSITORY_ID]
            actor['projects']=[{'project_id':'project-a','repository_id':TARGET_REPOSITORY_ID}]
        payload['sources']=[dict(payload['sources'][0],repository_id=TARGET_REPOSITORY_ID)]
        payload['destinations']=[]
        path.write_text(json.dumps(payload))
        self.auth=Authenticator(AccessAuthority.load(path));self.access=payload
        self.admin=self.auth.access_session('Bearer synthetic-owned-credential-operator','factory:access-admin')
        profile=HttpLandingProfile.for_provider('qwen-intl',available=True)
        account=PaidAccountV1('user-a','account','tenant-a','scheduler','policy-v1',self.now.timestamp()-1,self.now.timestamp()+300,10**8,2,1,2)
        paid=PaidTaskV1('paid-child',TARGET_REPOSITORY_ID,'route',TARGET_BASE_SHA,TARGET_BASE_TREE,'c'*64,'loader',10**8,1,10**7,10**6,((profile.provider_id,profile.model_id,'paid-inference'),),self.expected.input_digest,self.now.timestamp()+300)
        self.store.install_paid_authority(account,paid,(PaidPriceV1(profile.provider_id,profile.model_id,'v1',1,1),))
        self.admission=PaidExecutionAdmission(self.store,'account','paid-child','loader','c'*64)
        executor=qwen_landing_executor(profile=profile,credential_loader=lambda:'synthetic-test-key',admission=self.admission)
        self.service=LandingApplicationService(self.store,self.blobs,HttpLandingNormalizer(profile,executor,source_preflight=lambda:None),profile_digest=profile.profile_digest,factory_service=FactoryService(PostgresFactoryStore('postgresql://unused-local-fixture')))
        self.control=SharedAuthorityControl(OwnedLandingRuntime(self.service,self.store),self.auth,(SharedLandingTask('user-a',self.admission,self.service,key('a'),'v1','logical',self.expected,__import__('hashlib').sha256(b'synthetic-test-key').hexdigest()),))
        app=create_app(None,self.auth,execution_enabled=False,landing_service=self.service,landing_only=True)
        install_shared_control_api(app,self.control)
        self.client=TestClient(app,raise_server_exceptions=False)
        self.addCleanup(self.client.close)
        self.headers={'Authorization':'Bearer synthetic-owned-credential-user-a','X-Repository-ID':TARGET_REPOSITORY_ID,'X-Shared-Task-ID':'logical','X-Expected-Profile-Digest':profile.profile_digest}
        self.document={'schema_version':1,'task_id':'logical','parent_digest':'a'*64,'ordinal':0,'profile_digest':profile.profile_digest,'source_head':TARGET_BASE_SHA,'source_tree':TARGET_BASE_TREE,'media_type':'text/plain','payload_base64':base64.b64encode(b'fixture').decode()}

    def assert_empty(self):
        self.assertEqual(0,self.store._connection.execute('SELECT count(*) FROM landing_jobs').fetchone()[0])
        self.assertEqual([],self.store.paid_audit('account'))

    def test_closed_malformed_fields_and_json_reject_before_persistence(self):
        for field,value in [('task_id',[]),('profile_digest',{}),('source_head',[]),('source_tree',None),('media_type',[]),('payload_base64',{}),('payload_base64','%%%'),('ordinal',True),('ordinal',5),('parent_digest',[])]:
            with self.subTest(field=field,value=value):
                response=self.client.post(f'/v1/shared-landing-control/jobs/{self.expected.job_id}',headers=self.headers,json={**self.document,field:value})
                self.assertIn(response.status_code,(403,409,422))
                self.assert_empty()
        for body in (b'{',b'{"schema_version":1,"schema_version":1}',b'[]'):
            response=self.client.post(f'/v1/shared-landing-control/jobs/{self.expected.job_id}',headers=self.headers,content=body)
            self.assertEqual(422,response.status_code)
            self.assert_empty()

    def test_same_uid_unauthorized_actor_and_revoked_source_are_denied(self):
        other={**self.headers,'Authorization':'Bearer synthetic-owned-credential-user-b'}
        self.assertEqual(403,self.client.post(f'/v1/shared-landing-control/jobs/{self.expected.job_id}',headers=other,json=self.document).status_code)
        self.access['revision']=2;self.access['groups'][0]['members']=[]
        self.auth.access_authority.update(self.admin,1,self.access)
        self.assertEqual(403,self.client.post(f'/v1/shared-landing-control/jobs/{self.expected.job_id}',headers=self.headers,json=self.document).status_code)
        self.assert_empty()

    def test_expired_disabled_clock_rollback_and_source_outage_fail_closed(self):
        from datetime import timedelta
        initial=self.now
        self.now+=timedelta(seconds=301)
        self.assertEqual(403,self.client.post(f'/v1/shared-landing-control/jobs/{self.expected.job_id}',headers=self.headers,json=self.document).status_code)
        self.now=initial
        self.assertEqual(503,self.client.post(f'/v1/shared-landing-control/jobs/{self.expected.job_id}',headers=self.headers,json=self.document).status_code)
        self.now=initial+timedelta(seconds=302)
        self.assert_empty()

    def test_changed_input_and_child_never_install_job_or_paid_authority(self):
        import base64
        response=self.client.post(f'/v1/shared-landing-control/jobs/{self.expected.job_id}',headers=self.headers,json={**self.document,'payload_base64':base64.b64encode(b'changed').decode()})
        self.assertEqual(409,response.status_code)
        self.assertEqual(403,self.client.post('/v1/shared-landing-control/jobs/other',headers=self.headers,json=self.document).status_code)
        self.assert_empty()

    def test_disabled_account_stale_access_credential_and_source_outage(self):
        with self.store._transaction():
            self.store._connection.execute("UPDATE paid_accounts SET disabled=1 WHERE account_id='account'")
        self.assertEqual(403,self.client.post(f'/v1/shared-landing-control/jobs/{self.expected.job_id}',headers=self.headers,json=self.document).status_code)
        with self.store._transaction():
            self.store._connection.execute("UPDATE paid_accounts SET disabled=0 WHERE account_id='account'")
        def outage():
            raise OSError('synthetic unavailable source')
        self.service._provider._source_preflight=outage
        self.assertEqual(503,self.client.post(f'/v1/shared-landing-control/jobs/{self.expected.job_id}',headers=self.headers,json=self.document).status_code)
        self.service._provider._source_preflight=lambda:None
        from pathlib import Path
        replacement=Path(self.access['actors'][0]['token_file']).with_name('rotated-access-token')
        replacement.write_text('new-synthetic-current-access-token');replacement.chmod(0o600)
        self.access['revision']=2;self.access['actors'][0]['credential_generation']=2
        self.access['actors'][0]['token_file']=str(replacement)
        self.auth.access_authority.update(self.admin,1,self.access)
        self.assertEqual(401,self.client.post(f'/v1/shared-landing-control/jobs/{self.expected.job_id}',headers=self.headers,json=self.document).status_code)
        self.assert_empty()

    def test_foreign_tenant_current_session_cannot_use_installed_paid_account(self):
        # The principal remains user-a. Only current tenant/source ownership moves.
        self.access['revision']=2
        for actor in self.access['actors']:
            actor['tenant_id']='tenant-b'
            actor['credential_generation']=2
        for source_item in self.access['sources']:
            source_item['key']['tenant']='tenant-b'
        for group in self.access['groups']:
            group['tenant_id']='tenant-b'
        self.auth.access_authority.update(self.admin,1,self.access)
        self.assertEqual(403,self.client.post(f'/v1/shared-landing-control/jobs/{self.expected.job_id}',headers=self.headers,json=self.document).status_code)
        self.assert_empty()


class SharedOwnerCrashTests(unittest.TestCase):
    def test_killed_owner_at_every_durable_cut_never_reissues_child(self):
        import subprocess,sys,tempfile
        from pathlib import Path
        from factory.tests.test_paid_admission import SCRATCH
        from getzilla_factory.landing_sqlite_store import SQLiteLandingJobStore
        for cut in ('before_accept','after_accept','after_reserve','after_dispatch'):
            with self.subTest(cut=cut),tempfile.TemporaryDirectory(dir=SCRATCH) as temporary:
                root=Path(temporary);(root/'control').mkdir()
                completed=subprocess.run([sys.executable,'-m','factory.tests.shared_store_crash_fixture',str(root),cut],capture_output=True,text=True,timeout=10)
                self.assertEqual(-9,completed.returncode,completed.stderr)
                store=SQLiteLandingJobStore(root/'authority',repository_root=root/'control')
                try:
                    item=source()
                    if cut=='before_accept':
                        self.assertIsNone(store.find(item.tenant_id,item.repository_id,item.job_id))
                    else:
                        binding=SharedControlBindingV1(item.tenant_id,'account','task','logical','a'*64,0,'b'*64,'e'*64,item.exact_base_sha,item.exact_base_tree)
                        record,created=store.create_or_replay(LandingJobRecord(item,'accepted',None,None),command_key=item.job_id,request_digest=item.input_digest,control_binding=binding)
                        self.assertFalse(created)
                        self.assertEqual('needs_human',record.state)
                    rows=store.paid_audit('account')
                    self.assertEqual(1 if cut in {'after_reserve','after_dispatch'} else 0,len(rows))
                    if rows:
                        self.assertEqual(70,rows[0]['cost_ceiling_micros'])
                        self.assertEqual('reserved' if cut=='after_reserve' else 'dispatching',rows[0]['state'])
                finally:
                    store.close()


class SharedCredentialPinTests(unittest.TestCase):
    setUp = SharedControlBoundaryTests.setUp
    assert_empty = SharedControlBoundaryTests.assert_empty
    def test_rotated_provider_credential_fails_before_accept_and_dispatch(self):
        loader=self.service._provider._executor._credential_loader
        loader._loader=lambda:'rotated-unapproved-key'
        self.assertEqual(403,self.client.post(f'/v1/shared-landing-control/jobs/{self.expected.job_id}',headers=self.headers,json=self.document).status_code)
        self.assert_empty()


class SharedUnknownTransportTests(unittest.TestCase):
    def test_lost_before_accept_is_unknown_get_only_and_never_falls_back(self):
        import subprocess,tempfile
        from pathlib import Path
        from factory.tests.test_landing_failover import configuration
        from factory.tests.test_landing_failover_transport import unix_responder,json_reply
        from getzilla_factory.landing_failover import FailoverCoordinator
        from getzilla_factory.landing_failover_config import FailoverConfig
        from getzilla_factory.landing_failover_contracts import backend_capability
        from getzilla_factory.landing_failover_journal import CallerJournal
        from getzilla_factory.landing_http import HttpLandingProfile
        common=Path(subprocess.check_output(['git','rev-parse','--git-common-dir'],text=True).strip()).resolve()
        runtime=common.parent/'.getzilla/runtime/tests';runtime.mkdir(mode=0o700,parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='ua-',dir=runtime) as temporary:
            document=configuration(Path(temporary),count=2)
            document.update(schema_version=2,shared_task_id='finite-task')
            token=Path(document['backends'][0]['token_file']);token.write_text('t'*32);token.chmod(0o600)
            document['backends'][1]['token_file']=str(token)
            config=FailoverConfig.from_dict(document)
            def respond(handler,method,target,headers):
                if target.endswith('/capability'):
                    profile=HttpLandingProfile.for_provider('qwen-intl',available=True)
                    json_reply(handler,backend_capability(profile,config.actor_id,config.repository_id,config.exact_base_sha,config.exact_base_tree))
                elif method=='POST':
                    handler.rfile.read(int(headers['content-length']))
                    # Transport-only fixture: the request is lost before any
                    # server acceptance. No authority or provider is installed.
                    return
                else:
                    json_reply(handler,{'detail':'absent child'},status=404)
            with unix_responder(config.backends[0].socket_path,respond) as server:
                with CallerJournal(config) as journal:
                    caller=FailoverCoordinator(config,journal)
                    result=caller.submit('unknown-child',b'brief','text/plain')
                    self.assertEqual(('needs_human','outcome_unknown'),(result['state'],result['reason']))
                    self.assertEqual(1,len(result['attempts']))
                    resumed=caller.resume('unknown-child')
                    self.assertEqual('outcome_unknown',resumed['reason'])
                    self.assertEqual(['GET','POST','GET','GET'],[item[0] for item in server.requests])


class SharedReviewedRegressionTests(unittest.TestCase):
    setUp = SharedControlBoundaryTests.setUp

    def test_observe_refuses_reconfigured_actual_paid_task_and_source(self):
        from getzilla_factory.paid_admission import PaidTaskV1,PaidAccountV1,PaidPriceV1,PaidExecutionAdmission
        from getzilla_factory.landing_contracts import strict_json_object,LandingInputV1
        key=next(iter(self.control.tasks));installed=self.control.tasks[key]
        bound=SharedControlBindingV1('user-a','account','paid-child','logical','a'*64,0,
            self.document['profile_digest'],installed.credential_digest,self.expected.exact_base_sha,self.expected.exact_base_tree)
        self.store.create_or_replay(LandingJobRecord(self.expected,'accepted',None,None),command_key=self.expected.job_id,request_digest=self.expected.input_digest,control_binding=bound)
        self.assertEqual(200,self.client.get(f'/v1/shared-landing-control/jobs/{self.expected.job_id}',headers=self.headers).status_code)
        account=PaidAccountV1(**strict_json_object(self.store._connection.execute("SELECT authority FROM paid_accounts").fetchone()[0]))
        task=PaidTaskV1(**strict_json_object(self.store._connection.execute("SELECT authority FROM paid_tasks").fetchone()[0]))
        price=PaidPriceV1(**strict_json_object(self.store._connection.execute("SELECT price FROM paid_prices").fetchone()[0]))
        replacement=replace(task,task_id='replacement-paid')
        self.store.install_paid_authority(account,replacement,(price,))
        new_admission=PaidExecutionAdmission(self.store,'account','replacement-paid','loader','c'*64)
        self.control.tasks[key]=replace(installed,admission=new_admission)
        self.assertEqual(403,self.client.get(f'/v1/shared-landing-control/jobs/{self.expected.job_id}',headers=self.headers).status_code)
        facts=self.expected.to_dict();facts.pop('input_digest');facts['job_id']='different-preapproved-child'
        self.control.tasks[key]=replace(installed,expected_source=LandingInputV1.from_facts(facts))
        self.assertEqual(403,self.client.get(f'/v1/shared-landing-control/jobs/{self.expected.job_id}',headers=self.headers).status_code)


class SharedClockReviewedRegressionTests(unittest.TestCase):
    setUp = paid_tests.PaidAdmissionTests.setUp

    def test_second_authority_observation_is_durable_before_expiry_denial(self):
        from getzilla_factory.paid_admission import PaidExecutionAdmission
        from getzilla_factory.landing_sqlite_store import SQLiteLandingJobStore
        initial=self.now
        future=initial+timedelta(seconds=301)
        ticks=iter((initial,future))
        self.store._clock=lambda:next(ticks)
        reservation=self.admission.reserve('qwen','qwen-plus','paid-inference','d'*64,50,20)
        with self.assertRaisesRegex(Exception,'paid_expired'):
            self.admission.dispatch(reservation,'a'*64,'d'*64,'qwen','qwen-plus')
        path=self.store.database_path;self.store.close()
        self.store=SQLiteLandingJobStore(path.parent,repository_root=__import__('pathlib').Path(self.tmp.name)/'repo',clock=lambda:initial)
        self.admission=PaidExecutionAdmission(self.store,'account','task','consumer-key','c'*64)
        with self.assertRaisesRegex(Exception,'clock_rollback'):
            self.admission.reserve('qwen','qwen-plus','paid-inference','e'*64,50,20)

    def test_failed_binding_conflict_retains_new_clock_highwater(self):
        item=source()
        record=LandingJobRecord(item,'accepted',None,None)
        binding=SharedControlBindingV1(item.tenant_id,'account','task','logical','a'*64,0,'b'*64,'e'*64,item.exact_base_sha,item.exact_base_tree)
        self.store.create_or_replay(record,command_key=item.job_id,request_digest=item.input_digest,control_binding=binding)
        initial=self.now;self.now+=timedelta(seconds=10)
        with self.assertRaisesRegex(Exception,'idempotency_conflict'):
            self.store.create_or_replay(record,command_key=item.job_id,request_digest=item.input_digest,control_binding=replace(binding,account_id='different'))
        self.now=initial
        with self.assertRaisesRegex(Exception,'clock_rollback'):
            self.store.create_or_replay(record,command_key=item.job_id,request_digest=item.input_digest,control_binding=binding)


class SharedAmbiguousReviewedRegressionTests(unittest.TestCase):
    def test_ambiguous_or_unknown_spend_receipt_never_authorizes_next_paid_child(self):
        import tempfile
        from pathlib import Path
        from factory.tests.test_landing_failover import configuration,ScriptedBackends
        from factory.tests.test_paid_admission import SCRATCH
        from getzilla_factory.landing_failover import FailoverCoordinator
        from getzilla_factory.landing_failover_config import FailoverConfig
        from getzilla_factory.landing_failover_journal import CallerJournal
        from getzilla_factory.landing_failover_transport import BackendAmbiguous
        for dropped in (False,True):
            with self.subTest(dropped=dropped),tempfile.TemporaryDirectory(dir=SCRATCH) as temporary:
                document=configuration(Path(temporary),count=2)
                document.update(schema_version=2,shared_task_id='logical')
                document['backends'][1]['token_file']=document['backends'][0]['token_file']
                config=FailoverConfig.from_dict(document)
                script=ScriptedBackends({'qwen-intl':'transport','grok-vision':'success'})
                def factory(backend,**kwargs):
                    client=script.factory(backend,**kwargs)
                    submit=client.submit
                    def ambiguous(*arguments):
                        submit(*arguments)
                        if dropped:
                            raise BackendAmbiguous('lost response')
                    client.submit=ambiguous
                    return client
                with CallerJournal(config) as journal:
                    caller=FailoverCoordinator(config,journal,backend_factory=factory)
                    result=caller.submit('ambiguous',b'brief','text/plain')
                    self.assertEqual(('needs_human','outcome_unknown'),(result['state'],result['reason']))
                    self.assertEqual(['qwen-intl'],script.calls)
                    self.assertEqual('outcome_unknown',caller.resume('ambiguous')['reason'])
                    self.assertEqual(['qwen-intl'],script.calls)
