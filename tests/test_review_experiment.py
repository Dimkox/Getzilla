import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'.getzilla'))
from getzilla.review_experiment import validate_protocol, review_admission, assess_experiment


def protocol():
    return {'version':1,'task_class':'docs-fix','procedure_version':'v1','frozen_at':100,'starts_at':200,'ends_at':400,'observation_ends_at':500,'owner':'owner','reviewer':'reviewer','review_minutes':60,'wip_limit':2,'budget_ref':'canonical-task-budget','budget_micros':10000,'minimum_savings_percent':10,'max_defects':0,'accepted_sources':['prior-accepted-task'],'expert_approval':{'actor':'expert','at':90,'procedure_version':'v1'},'inputs':{'scope':'v1','checks':'v1','tools':'v1','models':'v1','selection':'v1','schedule':'v1','randomization':'seed-record'},'backlog_size':20,'pairs':[{'pair':str(i),'control':'c'+str(i),'experiment':'e'+str(i),'basis':'same task class and size','order':['c'+str(i),'e'+str(i)]} for i in range(4)]}

class ContractTests(unittest.TestCase):
    def test_missing_stale_self_and_contaminated_procedure(self):
        validate_protocol(protocol())
        for change in ({'review_minutes':0},{'expert_approval':{'actor':'owner','at':90,'procedure_version':'v1'}},{'accepted_sources':['c0']},{'expert_approval':{'actor':'expert','at':201,'procedure_version':'old'}}):
            with self.assertRaises(ValueError): validate_protocol(protocol()|change)
        p=protocol(); del p['inputs']['checks']
        with self.assertRaises(ValueError):validate_protocol(p)
    def test_review_waiting_rework_and_unknown_consume_capacity(self):
        p=protocol()
        view={'as_of':200,'complete':True,'reviewer':'reviewer','available_minutes':60,'tasks':[{'task':'a','state':'waiting_review'},{'task':'b','state':'rework'}]}
        self.assertFalse(review_admission(p,view,now=201)['admit'])
        view['tasks']=[]
        self.assertTrue(review_admission(p,view,now=201)['admit'])
        for change in ({'as_of':100},{'complete':False},{'reviewer':'owner'},{'tasks':[{'task':'a','state':'unknown'}]}):
            self.assertFalse(review_admission(p,view|change,now=201)['admit'])
    def test_no_runs_unknown_and_failure_cannot_qualify(self):
        p=protocol()
        report=assess_experiment(p,{},as_of=600)
        self.assertEqual(report['decision'],'NOT_RUN')
        rows={name:{'actor':'human','decision':'unknown','candidate':'head','requirements':'v1','checks':True,'at':450,'defects':0} for pair in p['pairs'] for name in (pair['control'],pair['experiment'])}
        self.assertEqual(assess_experiment(p,rows,as_of=600)['decision'],'indeterminate')
        rows['c0']['decision']='rejected'
        rows['e0']['decision']='abandoned'
        report=assess_experiment(p,rows,as_of=600)
        self.assertEqual(report['assigned'],8)
        self.assertEqual(report['outcomes']['rejected'],1)
        self.assertEqual(report['outcomes']['abandoned'],1)
        self.assertIsNone(report['cost_per_accepted'])
    def test_self_stale_checks_and_incomplete_costs_block_go(self):
        p=protocol()
        rows={name:{'actor':'independent-human','decision':'accepted','candidate':'head','requirements':'v1','checks':True,'at':450,'defects':0} for pair in p['pairs'] for name in (pair['control'],pair['experiment'])}
        for change in ({'actor':'owner'},{'requirements':'old'},{'checks':False},{'decision':'revoked'}):
            changed=copy.deepcopy(rows);changed['e0'].update(change)
            self.assertNotEqual(assess_experiment(p,changed,as_of=600)['decision'],'broader_experiment')
        result=assess_experiment(p,rows,as_of=600)
        self.assertEqual(result['decision'],'indeterminate')
        self.assertIn('economics_unavailable',result['gaps'])
        self.assertEqual(result['qualification'],'supplied-contract-only')

class EconomicsBoundaryTests(unittest.TestCase):
    def test_canonical_reader_and_synthetic_pass_never_qualify(self):
        from unittest.mock import patch
        from getzilla.route_metrics import read_report
        p=protocol()
        rows={name:{'actor':'reviewer','decision':'accepted','candidate':'head','requirements':'v1','checks':True,'at':450,'defects':0} for pair in p['pairs'] for name in (pair['control'],pair['experiment'])}
        with patch('getzilla.review_experiment.route_metrics.read_report',return_value=read_report({})) as read:
            result=assess_experiment(p,rows,as_of=600,economics_queries={'control':{},'experiment':{}})
            self.assertEqual(read.call_count,2)
        self.assertEqual(result['decision'],'indeterminate')
        self.assertEqual(result['outcomes']['accepted'],8) # supplied assertions only
        self.assertIsNone(result['cost_per_accepted'])
        self.assertEqual(result['qualification'],'supplied-contract-only')
        rows['e0']['checks']=False
        self.assertEqual(assess_experiment(p,rows,as_of=600)['decision'],'stop')
    def test_oversized_unknown_states_duplicate_and_window(self):
        p=protocol()
        with self.assertRaises(ValueError):validate_protocol(p|{'task_class':'x'*70000})
        view={'as_of':200,'complete':True,'reviewer':'reviewer','available_minutes':60,'tasks':[{'task':'a','state':'active'},{'task':'a','state':'accepted'}]}
        self.assertFalse(review_admission(p,view,now=201)['admit'])
        rows={'c0':{'actor':'human','decision':'accepted','candidate':'head','requirements':'v1','checks':True,'at':450,'defects':1}}
        report=assess_experiment(p,rows,as_of=460)
        self.assertEqual(report['outcomes']['unknown'],7)
        self.assertIn('observation_window_incomplete',report['gaps'])
        self.assertEqual(report['decision'],'stop')
