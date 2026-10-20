"""#76: scheduled paid generation is default-deny without a scheduled-run budget; xAI is a paid provider."""
from __future__ import annotations

import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.cost_guard import CONTRACT_NAME, contract_problems, evaluate, file_findings, paid_run_resource  # noqa: E402
from getzilla.spec import validate_schema  # noqa: E402
from tests.branch_support import git  # noqa: E402

CONTRACT = {'schema_version': 'cost-contract-v1', 'provider': 'Gemini Veo', 'max_calls': 5, 'max_spend_usd_cents': 500,
            'stop_condition': 'stop after MAX_CALLS videos in one run', 'alert': 'email the owner above 5 USD',
            'limit_symbol': 'MAX_CALLS'}
SCHEDULED = textwrap.dedent('''
    import schedule
    from google import genai

    MAX_CALLS = 5
    client = genai.Client()

    def daily():
        for _ in range(MAX_CALLS):
            client.models.generate_videos(model="veo-3.1-fast-generate-preview", prompt="ad")

    schedule.every().day.do(daily)
''')
TEST = 'from gen import MAX_CALLS\n\ndef test_limit():\n    assert MAX_CALLS == 5\n'


def kinds(path: str, source: str) -> set[str]:
    return {item.kind for item in file_findings(path, textwrap.dedent(source).encode('utf-8'))}


class ScheduledPaidCallTests(unittest.TestCase):
    def test_schedulers_around_paid_calls_are_found(self) -> None:
        for scheduler in ('import schedule\nschedule.every(10).minutes.do(run)\n',
                          'from apscheduler.schedulers.blocking import BlockingScheduler\nBlockingScheduler().add_job(run, "interval", hours=1)\n',
                          'from celery.schedules import crontab\napp.conf.beat_schedule = {"gen": {"task": "gen", "schedule": crontab()}}\n'):
            with self.subTest(scheduler=scheduler.splitlines()[0]):
                source = 'import openai\n\ndef run():\n    openai.images.generate(prompt="x")\n' + scheduler
                self.assertIn('SCHEDULED_PAID_CALL', kinds('jobs.py', source))
        self.assertNotIn('SCHEDULED_PAID_CALL', kinds('once.py', 'import openai\nopenai.images.generate(prompt="x")\n'))
        self.assertNotIn('SCHEDULED_PAID_CALL', kinds('plain.py', 'import schedule\nschedule.every().day.do(print)\n'))

    def test_from_google_import_genai_is_a_paid_import(self) -> None:
        self.assertIn('PAID_CALL', kinds('veo.py', 'from google import genai\nclient = genai.Client()\n'
                                                   'client.models.generate_videos(prompt="ad")\n'))
        self.assertNotIn('PAID_CALL', kinds('auth.py', 'from google import auth\nauth.default()\n'))

    def test_xai_is_a_paid_provider(self) -> None:
        self.assertIn('PAID_CALL', kinds('grok.py', 'from xai_sdk import Client\nClient().chat.create(model="grok")\n'))
        self.assertIn('PAID_CALL', kinds('grok.py', 'import requests\nrequests.post("https://api.x.ai/v1/chat/completions")\n'))
        self.assertEqual(paid_run_resource('curl -s https://api.x.ai/v1/models'), 'api.x.ai')


class ScheduledBudgetTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name)
        git(self.repo, 'init', '-q', '-b', 'main')
        (self.repo / 'README.md').write_text('# x\n', encoding='utf-8')
        git(self.repo, 'add', '-A')
        git(self.repo, 'commit', '-q', '-m', 'base')
        self.base = git(self.repo, 'rev-parse', 'HEAD')
        self.package = self.repo / 'engineering' / 'changes' / 'c1'
        self.package.mkdir(parents=True)

    def report(self, contract: dict, mode: str = 'pr'):
        (self.repo / 'gen.py').write_text(SCHEDULED, encoding='utf-8')
        (self.repo / 'tests').mkdir(exist_ok=True)
        (self.repo / 'tests' / 'test_gen.py').write_text(TEST, encoding='utf-8')
        (self.package / CONTRACT_NAME).write_text(json.dumps(contract), encoding='utf-8')
        git(self.repo, 'add', '-A')
        git(self.repo, 'commit', '-q', '-m', 'scheduled generation')
        return evaluate(self.repo, None, mode, [self.base], 'HEAD', self.package)

    def test_scheduled_generation_needs_a_scheduled_run_budget(self) -> None:
        report = self.report(CONTRACT)
        self.assertEqual(report.status, 'fail')
        self.assertTrue(any(problem.startswith('COST_SCHEDULE_UNBOUNDED') for problem in report.problems), report.problems)

    def test_a_scheduled_run_budget_admits_it(self) -> None:
        report = self.report({**CONTRACT, 'max_scheduled_runs_per_day': 1})
        self.assertEqual(report.status, 'pass', report.problems)

    def test_the_scheduled_run_budget_is_validated_and_in_the_schema(self) -> None:
        for value in (0, -1, True, 1.5, '1'):
            with self.subTest(value=value):
                self.assertTrue(contract_problems({**CONTRACT, 'max_scheduled_runs_per_day': value}))
        self.assertEqual(contract_problems({**CONTRACT, 'max_scheduled_runs_per_day': 24}), [])
        schema = json.loads((ROOT / 'schemas' / 'cost-contract-v1.schema.json').read_text(encoding='utf-8'))
        validate_schema({**CONTRACT, 'max_scheduled_runs_per_day': 24}, schema)


if __name__ == '__main__':
    unittest.main()
