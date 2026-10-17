"""C02: unbounded paid loops in Python and n8n workflows are found statically; bounded ones are not."""
from __future__ import annotations

import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.cost_guard import diff_cost_findings, file_findings  # noqa: E402
from tests.branch_support import git  # noqa: E402


def kinds(path: str, source: str) -> list[str]:
    return sorted({item.kind for item in file_findings(path, textwrap.dedent(source).encode('utf-8'))})


def workflow(nodes, connections) -> str:
    return json.dumps({'name': 'wf', 'nodes': nodes, 'connections': connections})


def node(name, kind, **parameters):
    return {'name': name, 'type': kind, 'parameters': parameters}


def link(*targets):
    return {'main': [[{'node': target, 'type': 'main', 'index': 0} for target in targets]]}


OPENAI_NODE = '@n8n/n8n-nodes-langchain.openAi'


class PythonCostTests(unittest.TestCase):
    def test_while_true_around_sdk_call_is_unbounded(self) -> None:
        self.assertIn('UNBOUNDED_PAID_LOOP', kinds('gen.py', '''
            from openai import OpenAI
            client = OpenAI()
            while True:
                image = client.images.generate(prompt="cat")
                if looks_good(image):
                    break
        '''))

    def test_paid_helper_called_from_loop_is_unbounded(self) -> None:
        self.assertIn('UNBOUNDED_PAID_LOOP', kinds('gen.py', '''
            import replicate
            def render(prompt):
                return replicate.run("model", input={"prompt": prompt})
            def main():
                while not good_enough():
                    render("cat")
        '''))

    def test_raw_http_to_provider_host_in_loop_is_unbounded(self) -> None:
        self.assertIn('UNBOUNDED_PAID_LOOP', kinds('gen.py', '''
            import requests
            URL = "https://api.openai.com/v1/images/generations"
            while True:
                requests.post(URL, json={"prompt": "cat"})
        '''))

    def test_counter_and_range_bounds_are_accepted(self) -> None:
        bounded = '''
            from openai import OpenAI
            MAX_CALLS = 20
            client = OpenAI()
            attempts = 0
            while attempts < MAX_CALLS:
                attempts += 1
                client.images.generate(prompt="cat")
            for _ in range(MAX_CALLS):
                client.images.generate(prompt="dog")
            attempts = 0
            while True:
                attempts += 1
                if attempts > MAX_CALLS:
                    break
                client.images.generate(prompt="fish")
        '''
        self.assertEqual(kinds('gen.py', bounded), ['PAID_CALL'])

    def test_retry_without_stop_is_unbounded(self) -> None:
        self.assertIn('UNBOUNDED_RETRY', kinds('gen.py', '''
            import anthropic
            from tenacity import retry
            client = anthropic.Anthropic()
            @retry
            def ask():
                return client.messages.create(model="m", messages=[])
        '''))
        self.assertEqual(kinds('gen.py', '''
            import anthropic
            from tenacity import retry, stop_after_attempt
            client = anthropic.Anthropic()
            @retry(stop=stop_after_attempt(3))
            def ask():
                return client.messages.create(model="m", messages=[])
        '''), ['PAID_CALL'])

    def test_code_is_never_executed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / 'ran'
            kinds('evil.py', f'open({str(marker)!r}, "w").write("x")\nimport openai\nopenai.images.generate(prompt="x")\n')
            self.assertFalse(marker.exists())

    def test_other_languages_are_reported_not_analysed(self) -> None:
        self.assertEqual(kinds('gen.js', 'fetch("https://api.openai.com/v1/images", {method: "POST"})\n'),
                         ['UNANALYSED_PAID_CALL'])
        self.assertEqual(kinds('notes.js', 'console.log("hello")\n'), [])


class N8nCostTests(unittest.TestCase):
    def test_cycle_through_paid_node_without_counter_is_unbounded(self) -> None:
        source = workflow([node('Start', 'n8n-nodes-base.manualTrigger'), node('Generate', OPENAI_NODE),
                           node('Good?', 'n8n-nodes-base.if', conditions={'value': '={{$json.score > 0.9}}'})],
                          {'Start': link('Generate'), 'Generate': link('Good?'), 'Good?': link('Generate')})
        self.assertIn('UNBOUNDED_PAID_LOOP', kinds('flows/video.json', source))

    def test_counter_or_batch_loop_is_bounded(self) -> None:
        counted = workflow([node('Generate', OPENAI_NODE),
                            node('Retry?', 'n8n-nodes-base.if', conditions={'value': '={{$runIndex < 5}}'})],
                           {'Generate': link('Retry?'), 'Retry?': link('Generate')})
        batches = workflow([node('Batches', 'n8n-nodes-base.splitInBatches'), node('Generate', OPENAI_NODE)],
                           {'Batches': link('Generate'), 'Generate': link('Batches')})
        self.assertEqual(kinds('a.json', counted), ['PAID_CALL'])
        self.assertEqual(kinds('b.json', batches), ['PAID_CALL'])

    def test_http_node_to_provider_host_counts_as_paid(self) -> None:
        source = workflow([node('Call', 'n8n-nodes-base.httpRequest', url='https://api.klingai.com/v1/videos'),
                           node('Again', 'n8n-nodes-base.noOp')], {'Call': link('Again'), 'Again': link('Call')})
        self.assertIn('UNBOUNDED_PAID_LOOP', kinds('kling.json', source))

    def test_plain_json_is_ignored(self) -> None:
        self.assertEqual(kinds('package.json', '{"name": "x", "dependencies": {"openai": "4"}}'), [])


class DiffCostTests(unittest.TestCase):
    def test_only_changed_files_at_head_are_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            git(repo, 'init', '-q', '-b', 'main')
            (repo / 'old.py').write_text('import openai\nwhile True:\n    openai.images.generate(prompt="x")\n', encoding='utf-8')
            git(repo, 'add', '-A')
            git(repo, 'commit', '-q', '-m', 'old')
            base = git(repo, 'rev-parse', 'HEAD')
            (repo / 'new.py').write_text('import openai\nfor _ in range(3):\n    openai.images.generate(prompt="x")\n',
                                         encoding='utf-8')
            git(repo, 'add', '-A')
            git(repo, 'commit', '-q', '-m', 'new')
            findings = diff_cost_findings(repo, base, 'HEAD')
            self.assertEqual({(item.path, item.kind) for item in findings}, {('new.py', 'PAID_CALL')})


if __name__ == '__main__':
    unittest.main()
