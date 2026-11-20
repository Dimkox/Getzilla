import ast
import importlib
from pathlib import Path
from types import SimpleNamespace
import unittest


class StudyLexicalTests(unittest.TestCase):
    def owner(self):
        try:
            return importlib.import_module('getzilla.retrieval.study_lexical')
        except ModuleNotFoundError:
            self.fail('fixed historical lexical study data plane missing')

    def test_original_ascii_camel_underscore_tokens_for_ru_and_mixed_are_exact(self):
        owner = self.owner()
        original = Path(__file__).resolve().parents[1] / 'engineering/benchmarks/issue162/benchmark.py'
        nodes = [node for node in ast.parse(original.read_text()).body
                 if isinstance(node, ast.FunctionDef) and node.name == 'tokens']
        namespace = {'re': __import__('re')}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), '<published-tokens>', 'exec'), namespace)
        for text in ('проверить loadXML_value42', 'foo.bar SSH_KEY 123', 'только русский текст'):
            with self.subTest(text=text):
                self.assertEqual(owner.tokens(text), namespace['tokens'](text))

    def test_fixed_exact_case_fqn_positive_scores_and_original_id_ties(self):
        owner = self.owner()
        windows = (SimpleNamespace(id='z', symbol='A.check', text='def check(value): pass'),
                   SimpleNamespace(id='a', symbol='A.check', text='def check(value): pass'))
        result = owner.LexicalIndex(windows).query('A.check')
        self.assertEqual([row[0] for row in result['exact_symbol']], ['a', 'z'])
        self.assertEqual(result['exact_symbol'][0][1], 3)
        self.assertEqual([row[0] for row in result['bm25']], ['a', 'z'])
        self.assertEqual(owner.LexicalIndex(windows).query('только русский')['bm25'], ())
