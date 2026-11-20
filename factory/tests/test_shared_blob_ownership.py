"""Conflict cleanup cannot delete an existing owner's in-flight input."""
from dataclasses import replace
from datetime import timedelta
import hashlib
import unittest
from unittest.mock import patch

from factory.tests import test_shared_landing_control as fixtures
from getzilla_factory.landing_contracts import LandingInputV1
from getzilla_factory.landing_service import LandingJobRecord,LandingServiceError
from getzilla_factory.shared_landing_contracts import SharedControlBindingV1


class SharedBlobOwnershipTests(unittest.TestCase):
    setUp = fixtures.SharedControlBoundaryTests.setUp

    def binding(self, logical='logical'):
        installed=next(iter(self.control.tasks.values()))
        return SharedControlBindingV1('user-a','account','paid-child',logical,'a'*64,0,
            self.document['profile_digest'],installed.credential_digest,self.expected.exact_base_sha,self.expected.exact_base_tree)

    def seed(self,binding=None):
        record,_=self.store.create_or_replay(LandingJobRecord(self.expected,'accepted',None,None),
            command_key=self.expected.job_id,request_digest=self.expected.input_digest,control_binding=binding or self.binding())
        self.store.put(replace(record,state='normalizing'))

    def snapshot(self):
        tables=('landing_jobs','landing_commands','shared_control_bindings','paid_reservations')
        data={table:self.store._connection.execute('SELECT * FROM '+table).fetchall() for table in tables}
        path=self.blobs._root/(self.expected.quarantine_ref_digest+'.blob')
        info=path.stat()
        data['blob']=(info.st_dev,info.st_ino,info.st_mode,info.st_size,info.st_mtime_ns,hashlib.sha256(path.read_bytes()).hexdigest())
        data['registry']=dict(self.blobs._records)
        return data

    def submit(self,source=None,payload=b'fixture'):
        return self.service.submit(job_id=self.expected.job_id,repository_id=self.expected.repository_id,
            exact_base_sha=self.expected.exact_base_sha,exact_base_tree=self.expected.exact_base_tree,
            media_type='text/plain',chunks=(payload,),actor=self.auth.authenticate(self.headers['Authorization'],'landing:submit'),
            control_binding=self.binding(),control_source=source or self.expected)

    def test_conflicting_control_binding_preserves_existing_normalizing_input(self):
        self.seed(self.binding('prior-logical'));before=self.snapshot()
        response=self.client.post('/v1/shared-landing-control/jobs/'+self.expected.job_id,headers=self.headers,json=self.document)
        self.assertEqual(409,response.status_code)
        self.assertEqual(before,self.snapshot())

    def test_control_source_mismatch_preserves_borrowed_input(self):
        self.seed();before=self.snapshot()
        facts=self.expected.to_dict();facts.pop('input_digest')
        facts['received_at']=(self.expected.received_at+timedelta(seconds=1)).isoformat()
        different=LandingInputV1.from_facts(facts)
        with self.assertRaisesRegex(LandingServiceError,'shared_source_mismatch'):
            self.submit(source=different)
        self.assertEqual(before,self.snapshot())

    def test_mismatched_bytes_preserve_existing_input_and_durable_records(self):
        self.seed();before=self.snapshot()
        with self.assertRaises(LandingServiceError):
            self.submit(payload=b'changed input')
        self.assertEqual(before,self.snapshot())

    def test_store_failure_preserves_borrowed_input(self):
        self.seed();before=self.snapshot()
        with patch.object(self.store,'create_or_replay',side_effect=RuntimeError('synthetic store failure')):
            with self.assertRaisesRegex(RuntimeError,'synthetic store failure'):
                self.submit()
        self.assertEqual(before,self.snapshot())

    def test_store_failure_purges_new_intake_without_creating_authority(self):
        self.blobs.purge(self.expected,reason='rejected')
        with patch.object(self.store,'create_or_replay',side_effect=RuntimeError('synthetic store failure')):
            with self.assertRaisesRegex(RuntimeError,'synthetic store failure'):
                self.submit()
        self.assertEqual([],list(self.blobs._root.iterdir()))
        self.assertEqual({},self.blobs._records)
        for table in ('landing_jobs','landing_commands','shared_control_bindings','paid_reservations'):
            self.assertEqual(0,self.store._connection.execute('SELECT count(*) FROM '+table).fetchone()[0])

    def test_shared_profile_intake_waits_until_failed_owner_cleanup_finishes(self):
        import threading
        from getzilla_factory.landing_service import LandingApplicationService
        self.blobs.purge(self.expected,reason='rejected')
        second=LandingApplicationService(self.store,self.blobs,self.service._provider,
            profile_digest=self.service._profile_digest,factory_service=self.service._factory_service)
        first_entered=threading.Event();second_started=threading.Event();second_entered=threading.Event();release=threading.Event()
        original=self.store.create_or_replay
        calls=[];failures=[];results=[]
        def create(*arguments,**keywords):
            calls.append(1)
            if len(calls)==1:
                first_entered.set()
                if not release.wait(3):
                    raise RuntimeError('test release timeout')
                raise LandingServiceError('synthetic_store_failure',503,'synthetic failure')
            second_entered.set()
            self.assertEqual(b'fixture',self.blobs.read(self.expected,tenant_id=self.expected.tenant_id,repository_id=self.expected.repository_id,job_id=self.expected.job_id))
            return original(*arguments,**keywords)
        def submit(service,started=None):
            if started is not None:
                started.set()
            try:
                results.append(service.submit(job_id=self.expected.job_id,repository_id=self.expected.repository_id,
                    exact_base_sha=self.expected.exact_base_sha,exact_base_tree=self.expected.exact_base_tree,
                    media_type='text/plain',chunks=(b'fixture',),actor=self.auth.authenticate(self.headers['Authorization'],'landing:submit'),
                    control_binding=self.binding(),control_source=self.expected))
            except Exception as error:
                failures.append(str(error))
        with patch.object(self.store,'create_or_replay',side_effect=create),patch.object(second,'_process',side_effect=lambda record,actor:replace(record,state='needs_human',reason_code='synthetic_no_provider')):
            first=threading.Thread(target=submit,args=(self.service,));other=threading.Thread(target=submit,args=(second,second_started))
            first.start()
            try:
                self.assertTrue(first_entered.wait(2))
                other.start();self.assertTrue(second_started.wait(2))
                self.assertFalse(second_entered.wait(.1),'another profile borrowed intake before owner cleanup')
            finally:
                release.set();first.join(4)
                if other.ident is not None:
                    other.join(4)
        self.assertFalse(first.is_alive());self.assertFalse(other.is_alive())
        self.assertEqual(['synthetic_store_failure'],failures)
        self.assertEqual(1,len(results));self.assertTrue(results[0].created)
        self.assertEqual([],self.store.paid_audit('account'))
