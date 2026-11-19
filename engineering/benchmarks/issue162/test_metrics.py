"""Arithmetic controls use a tiny synthetic corpus, not new evaluation labels."""
import unittest
import numpy as np
import tiktoken
from benchmark import evaluate,dedup,Search,tokens
class MetricControls(unittest.TestCase):
    def setUp(self):
        self.chunks=[{'id':str(i),'function_id':f,'path':p,'text':'def x():\n    pass\n','symbol':s,'repository':'r','start':1,'end':2,'file_sha256':'0'*64} for i,(f,p,s) in enumerate([('f1','a.py','Known.run'),('f1','a.py','Known.run'),('f2','b.py','Other.stop')])]
        self.query={'qrels':[{'id':'f1','path':'a.py'},{'id':'f2','path':'b.py'}]}
    def test_function_dedup_and_recall(self):
        m=evaluate(self.query,[(0,3),(1,2),(2,1)],self.chunks,tiktoken.get_encoding('o200k_base'),2048)
        self.assertEqual(m['function_recall@1'],.5);self.assertEqual(m['function_recall@5'],1);self.assertEqual(m['file_recall@1'],.5);self.assertEqual(m['mrr@10'],1)
    def test_budget_is_hard(self):
        m=evaluate(self.query,[(0,3),(1,2),(2,1)],self.chunks,tiktoken.get_encoding('o200k_base'),1)
        self.assertEqual(m['budget_1_tokens'],0);self.assertEqual(m['budget_1_recall'],0)
    def test_windows_do_not_duplicate_context(self):
        codec=tiktoken.get_encoding('o200k_base')
        one=evaluate(self.query,[(0,3)],self.chunks,codec,2048)
        two=evaluate(self.query,[(0,3),(1,2)],self.chunks,codec,2048)
        self.assertEqual(one['budget_2048_tokens'],two['budget_2048_tokens'])
    def test_exact_symbols_do_not_expand(self):
        search=Search(self.chunks,np.array([[1,0],[1,0],[0,1]],dtype=np.float32))
        arms,_=search.query('Known.run',np.array([1,0],dtype=np.float32));self.assertEqual([i for i,_ in arms['exact_symbol']],[0,1])
        arms,_=search.query('perform a behavior',np.array([1,0],dtype=np.float32));self.assertEqual(arms['exact_symbol'],[])
    def test_identifier_split(self):self.assertIn('name',tokens('longName long_name'))
if __name__=='__main__':unittest.main()
