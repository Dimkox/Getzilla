"""Current native absence proofs may exclude Python discovery, never testlessness."""
import copy
from datetime import datetime, timezone
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'.getzilla'))
from getzilla import verification_plan as api
from getzilla.quality_gates import evaluate_quality_gate
from getzilla.util import tree_fingerprint


class NativePythonAbsenceTests(unittest.TestCase):
    def world(self, *, python=False, requested=None):
        owned = tempfile.TemporaryDirectory(prefix='owned-python-absence-')
        self.addCleanup(owned.cleanup)
        root = Path(owned.name)
        env = {key: value for key, value in os.environ.items() if key in ('PATH', 'SystemRoot', 'WINDIR')}
        env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=str(root/'absent-config'), HOME=str(root))
        subprocess.run(['git', '-c', 'init.templateDir=', 'init', '-q', str(root)], env=env, check=True, capture_output=True)
        if python:
            (root/'main.py').write_text('VALUE = 1\n', encoding='utf-8', newline='\n')
            subprocess.run(['git', 'add', 'main.py'], cwd=root, env=env, check=True, capture_output=True)
        rows = api._native_obligations(root, 'pr', {}, {}, files=[], profiles=requested, bases=[], documents=None)
        rows = [row for row in rows if row['check_id'] != 'known-vulnerabilities']
        plan = api.build_required_plan(root, mode='pr', context={}, source={'fingerprint': tree_fingerprint(root)},
                                       inventory={}, risk={}, selection={'requested_profiles': requested}, extra_obligations=rows)
        checks = []
        for row in rows:
            check = dict(name=row['check_id'], status='skip' if row['applicability']=='not_applicable' else 'pass',
                         summary='owned native structural result', details=[])
            api.bind_result(plan, check)
            checks.append(check)
        return plan, checks

    def decide(self, plan, checks, binding=None):
        def reject(*_args, **_kwargs):
            self.fail('native absence has no external data-source calls')
        return evaluate_quality_gate(mode='pr', checks=checks, required_plan=plan,
            current_binding=plan['binding'] if binding is None else binding,
            now_utc=datetime(2026, 11, 18, tzinfo=timezone.utc), data_source_validator=reject)

    def test_native_no_python_and_actual_bound_skips_admit(self):
        plan, checks = self.world()
        self.assertEqual(self.decide(plan, checks).status, 'pass')

    def test_missing_forged_stale_and_unbound_absence_still_refuse(self):
        plan, checks = self.world()
        for kind in ('missing-plan', 'malformed', 'malformed-binding', 'changed-binding', 'missing-skip',
                     'stale-skip', 'unbound-skip', 'missing-evidence', 'forged-evidence'):
            with self.subTest(kind=kind):
                current, observed, binding = copy.deepcopy(plan), copy.deepcopy(checks), copy.deepcopy(plan['binding'])
                if kind=='missing-plan':
                    current = None
                elif kind=='malformed':
                    current['digest'] = '0'*64
                elif kind=='malformed-binding':
                    current['binding'] = []
                elif kind=='changed-binding':
                    binding['source']['fingerprint'] = '0'*64
                elif kind=='missing-skip':
                    observed = [row for row in observed if row['name']!='coverage']
                elif kind in ('stale-skip', 'unbound-skip'):
                    row = next(row for row in observed if row['name']=='python-unittest')
                    if kind=='stale-skip':
                        row['details'][0]['plan_digest'] = '0'*64
                    else:
                        row['details'] = []
                else:
                    for row in current['obligations']:
                        if row['check_id']=='ruff':
                            row['evidence'] = {} if kind=='missing-evidence' else {'kind': 'unproved'}
                    current['digest'] = api.digest({key:value for key,value in current.items() if key!='digest'})
                    for row in observed:
                        row['details'] = []
                        api.bind_result(current, row)
                decision = self.decide(current, observed, binding)
                self.assertEqual(decision.status, 'fail')
                self.assertTrue(any(row['path']=='python-discovery' for row in decision.details), decision.details)

    def test_testless_real_python_and_explicit_python_cannot_use_absence(self):
        for python, requested in ((True, None), (False, ['python'])):
            with self.subTest(python=python, requested=requested):
                plan, checks = self.world(python=python, requested=requested)
                decision = self.decide(plan, checks)
                self.assertEqual(decision.status, 'fail')
                self.assertTrue(any(row['path']=='python-discovery' for row in decision.details), decision.details)
