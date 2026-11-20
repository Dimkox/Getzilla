"""Kill only this owned child at a named durable cut. No provider or network."""
from datetime import datetime,timezone
from pathlib import Path
import os
import signal
import sys
from factory.tests.test_landing_sqlite_store import source
from getzilla_factory.landing_sqlite_store import SQLiteLandingJobStore
from getzilla_factory.landing_service import LandingJobRecord
from getzilla_factory.paid_admission import PaidAccountV1,PaidTaskV1,PaidPriceV1,PaidExecutionAdmission
from getzilla_factory.shared_landing_contracts import SharedControlBindingV1


def main():
    root=Path(sys.argv[1]);cut=sys.argv[2]
    store=SQLiteLandingJobStore(root/'authority',repository_root=root/'control')
    item=source()
    now=datetime.now(timezone.utc).timestamp()
    account=PaidAccountV1('owner','account','tenant','scheduler','policy',now-1,now+300,10000,2,2,2)
    task=PaidTaskV1('task',item.repository_id,'route',item.exact_base_sha,item.exact_base_tree,'c'*64,'loader',10000,1,100,100,(('qwen','qwen-plus','paid-inference'),),item.input_digest,now+300)
    store.install_paid_authority(account,task,(PaidPriceV1('qwen','qwen-plus','v1',1,1),))
    if cut!='before_accept':
        binding=SharedControlBindingV1(item.tenant_id,'account','task','logical','a'*64,0,'b'*64,'e'*64,item.exact_base_sha,item.exact_base_tree)
        store.create_or_replay(LandingJobRecord(item,'accepted',None,None),command_key=item.job_id,request_digest=item.input_digest,control_binding=binding)
    if cut in {'after_reserve','after_dispatch'}:
        admission=PaidExecutionAdmission(store,'account','task','loader','c'*64)
        reservation=admission.reserve('qwen','qwen-plus','paid-inference','d'*64,50,20)
        if cut=='after_dispatch':
            admission.dispatch(reservation,item.input_digest,'d'*64,'qwen','qwen-plus')
    os.kill(os.getpid(),signal.SIGKILL)

if __name__=='__main__':
    main()
