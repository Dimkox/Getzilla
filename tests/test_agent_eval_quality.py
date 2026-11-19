"""Incident critic projections remain algorithm evidence, never human acceptance."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import shutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import agent_evals as ev  # noqa: E402


class ReviewQualityTests(unittest.TestCase):
    def setUp(self):
        runtime = ROOT / '.getzilla/runtime'
        runtime.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='quality-test-', dir=runtime)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = json.loads((ROOT / 'tests/fixtures/agent-evals/v1/manifest.json').read_text())
        self.manifest['cases'] = []
        self.outputs = {'schema_version': 1, 'outputs': []}
        self.study = {'schema_version': 1, 'manifest_sha256': '', 'cases': [], 'judgments': [], 'measurements': []}
        for pair in ('a', 'b'):
            for variant in ('faulty', 'clean'):
                name = pair + '-' + variant
                case = {'schema_version': 1, 'id': name, 'source': 'synthetic:154', 'input': {},
                        'assertions': [{'id': 'expected-finding', 'op': 'equals', 'path': ['finding'],
                                        'expected': 'detected' if variant == 'faulty' else 'clear'}]}
                sha = self.write(name + '.json', case)
                self.manifest['cases'].append({'id': name, 'path': name + '.json', 'sha256': sha})
                self.outputs['outputs'].append({'case_id': name, 'case_sha256': sha,
                                                'output': {'finding': 'detected' if variant == 'faulty' else 'clear'}})
                self.study['cases'].append({'id': name, 'pair': pair, 'family': 'one-incident', 'variant': variant,
                                           'incident': {'commit': 'a' * 40, 'path': 'engineering/incidents/example.md',
                                                        'sha256': 'b' * 64}, 'oracle_test': 'tests/test_agent_evals.py::oracle'})
                self.study['judgments'].append({'case_id': name, 'case_sha256': sha, 'recording_sha256': '',
                                               'status': 'synthetic', 'oracle_status': 'pass', 'evidence_sha256': 'c' * 64})
        self.save()

    def write(self, path, value):
        raw = (json.dumps(value, sort_keys=True) + '\n').encode()
        (self.root / path).write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def save(self):
        self.study['manifest_sha256'] = self.write('manifest.json', self.manifest)
        sha = self.write('outputs.json', self.outputs)
        for row in self.study['judgments']:
            row['recording_sha256'] = sha
        self.write('study.json', self.study)

    def run_quality(self):
        function = getattr(ev, 'review_quality', None)
        self.assertTrue(callable(function), 'existing evaluator needs the quality projection')
        return function(self.root, 'manifest.json', 'outputs.json', 'study.json')

    def test_paired_metrics_preserve_case_and_incident_denominators(self):
        self.outputs['outputs'][0]['output']['finding'] = 'clear'
        self.outputs['outputs'][3]['output']['finding'] = 'detected'
        self.save()
        report = self.run_quality()
        q = report['quality']
        self.assertEqual(q['counts'], {'TP': 1, 'FN': 1, 'FP': 1, 'TN': 1})
        self.assertEqual(q['planned'], {'cases': 4, 'faulty': 2, 'clean': 2, 'pairs': 2, 'incident_families': 1})
        self.assertEqual(q['rates'], {'precision': .5, 'recall': .5, 'false_positive_rate': .5})
        self.assertEqual(q['families'][0]['family'], 'one-incident')
        self.assertEqual(report['qualification'], 'algorithm-only-recorded-judgments')
        self.assertFalse(report['release_authority'])
        self.assertIsNone(report['runtime_detection_quality'])
        self.assertEqual(report['human_final_acceptance'], 'not_observed')

    def test_missing_disputed_and_failed_oracles_stay_unresolved(self):
        self.outputs['outputs'].pop()
        self.study['judgments'][0]['status'] = 'disputed'
        self.study['judgments'][1]['oracle_status'] = 'not_run'
        self.save()
        q = self.run_quality()['quality']
        self.assertEqual((q['planned']['cases'], q['resolved'], len(q['unresolved'])), (4, 1, 3))
        self.assertEqual(q['counts'], {'TP': 1, 'FN': 0, 'FP': 0, 'TN': 0})
        self.assertIsNone(q['rates']['false_positive_rate'])
        self.assertEqual(q['coverage'], .25)

    def test_case_recording_and_cohort_drift_are_not_graded(self):
        for field in ('case_sha256', 'recording_sha256'):
            with self.subTest(field=field):
                saved = deepcopy(self.study)
                self.study['judgments'][0][field] = '0' * 64
                self.write('study.json', self.study)
                self.assertEqual(self.run_quality()['quality']['resolved'], 3)
                self.study = saved
        self.study['manifest_sha256'] = '0' * 64
        self.write('study.json', self.study)
        self.assertEqual(self.run_quality()['quality']['status'], 'invalid')

    def test_pairs_must_be_closed_and_share_incident_identity(self):
        for mutate in ('missing-case', 'duplicate-pair-variant', 'incident-mismatch', 'family-alias'):
            with self.subTest(mutate=mutate):
                saved = deepcopy(self.study)
                if mutate == 'missing-case':
                    self.study['cases'].pop()
                elif mutate == 'duplicate-pair-variant':
                    self.study['cases'][1]['variant'] = 'faulty'
                elif mutate == 'incident-mismatch':
                    self.study['cases'][1]['incident']['sha256'] = '0' * 64
                else:
                    for row in self.study['cases'][2:]:
                        row['family'] = 'invented-independent-family'
                self.save()
                self.assertEqual(self.run_quality()['quality']['status'], 'invalid')
                self.study = saved

    def test_undeclared_payload_fields_and_self_claimed_approval_are_refused(self):
        for field in ('human_approved', 'independence', 'raw_prompt'):
            self.study[field] = 'caller claim is not evidence'
            self.write('study.json', self.study)
            report = self.run_quality()
            self.assertEqual(report['quality']['status'], 'invalid')
            self.assertNotIn('caller claim', json.dumps(report))
            self.study.pop(field)

    def test_unknown_or_malformed_finding_is_not_a_clean_negative(self):
        self.outputs['outputs'][1]['output'] = {'finding': 'unknown'}
        self.outputs['outputs'][3]['output'] = {'finding': True}
        self.save()
        q = self.run_quality()['quality']
        self.assertEqual((q['resolved'], q['counts']['TN']), (2, 0))
        self.assertIsNone(q['rates']['false_positive_rate'])

    def test_observed_cost_deduplicates_operations_and_keeps_unknown_currency(self):
        observed = {'operation_id': 'op1', 'stage': 'critic', 'seconds': 2, 'kind': 'observed',
                    'amount': 1.5, 'currency': 'USD', 'source_ref': 'synthetic:invoice1'}
        self.study['measurements'] = [observed, deepcopy(observed),
            {**observed, 'operation_id': 'op2', 'kind': 'reservation', 'amount': 7},
            {**observed, 'operation_id': 'op3', 'currency': None, 'amount': None}]
        self.save()
        m = self.run_quality()['quality']['measurements']
        self.assertEqual(m['observed_cost_by_currency'], {'USD': 1.5})
        self.assertEqual(m['unknown_cost_operations'], 2)
        self.assertIsNone(m['total_usd'])
        self.assertEqual(m['seconds_by_stage']['critic'], 6)
        self.assertIn('source_references', m)
        self.assertEqual(len(m['source_references']), 3)
        self.assertEqual(m['source_references'][0]['source_ref'], 'synthetic:invoice1')

    def test_conflicting_operation_or_extreme_number_is_invalid(self):
        row = {'operation_id': 'op', 'stage': 'critic', 'seconds': 1, 'kind': 'observed',
               'amount': 1, 'currency': 'USD', 'source_ref': 'synthetic:invoice'}
        for rows in ([row, {**row, 'amount': 2}], [{**row, 'seconds': 10**500}]):
            self.study['measurements'] = rows
            self.save()
            self.assertEqual(self.run_quality()['quality']['status'], 'invalid')

    def test_no_native_evidence_does_not_invent_independence(self):
        p = self.run_quality()['critic_provenance']
        self.assertEqual(p['independence'], 'unknown')
        self.assertEqual(p['author_history'], 'incomplete')
        self.assertIsNone(p['model_family'])
        self.assertEqual(p['blinding'], 'unknown')
        self.assertEqual(p['report_authorship'], 'not_attested')

    def test_same_existing_cli_exposes_quality_without_running_a_provider(self):
        command = [sys.executable, str(ROOT / 'scripts/getzilla_evals.py'), '--root', str(self.root),
                   'quality', '--manifest', 'manifest.json', '--outputs', 'outputs.json', '--study', 'study.json', '--json']
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['quality']['resolved'], 4)

    def test_quality_cli_honors_replay_timeout(self):
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/getzilla_evals.py'), '--root', str(self.root),
                                 'quality', '--manifest', 'manifest.json', '--outputs', 'outputs.json',
                                 '--study', 'study.json', '--timeout', '0', '--json'],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)['quality']['resolved'], 0)

    def test_quality_has_its_own_digest_and_family_counts(self):
        report = self.run_quality()
        self.assertEqual(report.get('quality_digest'), ev.digest(report['quality']))
        self.assertEqual(report['quality']['families'][0]['counts'], {'TP': 2, 'FN': 0, 'FP': 0, 'TN': 2})

    def test_native_instances_bind_report_but_cannot_prove_complete_independence(self):
        from getzilla.agent_lifecycle import start_agent, stop_agent
        from getzilla.continuity import context_binding
        from getzilla.state import get_active_route
        from tests._support import activate_owned_route
        from unittest.mock import patch
        self.enterContext(patch.dict(os.environ))
        for args in [('init', '-q'), ('config', 'user.name', 'Synthetic'),
                     ('config', 'user.email', 'synthetic@example.invalid')]:
            subprocess.run(['git', *args], cwd=self.root, check=True, capture_output=True)
        (self.root / '.gitignore').write_text('.getzilla/runtime/\n', encoding='utf-8')
        self.manifest['identities']['source']['commit'] = '0' * 40
        self.save()
        # Source identity belongs to the reviewed product, not the mutable external recording.
        for name in ['manifest.json', 'outputs.json', 'study.json', *[r['path'] for r in self.manifest['cases']]]:
            with (self.root / '.gitignore').open('a', encoding='utf-8') as handle:
                handle.write(name + '\n')
        subprocess.run(['git', 'add', '.gitignore'], cwd=self.root, check=True, capture_output=True)
        subprocess.run(['git', 'commit', '-qm', 'synthetic source'], cwd=self.root, check=True, capture_output=True)
        def git(*args):
            return subprocess.check_output(['git', *args], cwd=self.root, text=True).strip()
        self.manifest['identities']['source'] = {'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}')}
        self.save()
        route = {'route_id': 'synthetic154', 'risk': 'low', 'complexity': 'micro', 'write_agent': 'general_implementer',
                 'allowed_agents': ['general_implementer', 'code_reviewer'], 'review_agents': ['code_reviewer']}
        activate_owned_route(self.root, route)
        author = start_agent(self.root, 'author', 'general_implementer')
        stop_agent(self.root, 'author', 'general_implementer', generation=author['generation'], final=True)
        critic = start_agent(self.root, 'critic', 'code_reviewer')
        context = context_binding(self.root, get_active_route(self.root))['digest']
        path = '.getzilla/runtime/reviews/synthetic154/code-review.md'
        (self.root / path).parent.mkdir(parents=True)
        (self.root / path).write_text('Synthetic test report.\nreviewed-context-digest: ' + context + '\n', encoding='utf-8')
        observation = {'agent_id': 'critic', 'generation': critic['generation'], 'report': path, 'reviewed_context': context}
        report = ev.review_quality(self.root, 'manifest.json', 'outputs.json', 'study.json', observation=observation)
        self.assertEqual(report['quality']['status'], 'observed', report)
        native = report['critic_provenance']
        self.assertEqual(native['source_binding']['reviewed_commit'], self.manifest['identities']['source']['commit'])
        self.assertFalse(native['known_author_overlap'])
        self.assertEqual(native['independence'], 'unknown')
        bad = ev.review_quality(self.root, 'manifest.json', 'outputs.json', 'study.json',
                                observation={**observation, 'generation': 'foreign-generation'})
        self.assertIsNone(bad['critic_provenance']['source_binding'])
        (self.root / path).write_text('stale marker\n', encoding='utf-8')
        stale = ev.review_quality(self.root, 'manifest.json', 'outputs.json', 'study.json', observation=observation)
        self.assertEqual(stale['quality']['status'], 'invalid')

    def test_shipped_incident_cohort_is_paired_and_honestly_algorithm_only(self):
        base = 'tests/fixtures/agent-evals/incidents-v1/'
        self.assertTrue((ROOT / (base + 'study.json')).is_file(), 'versioned incident cohort is required')
        report = ev.review_quality(ROOT, base + 'manifest.json', base + 'outputs-control.json', base + 'study.json')
        self.assertEqual(report['quality']['planned'], {'cases': 10, 'faulty': 5, 'clean': 5, 'pairs': 5, 'incident_families': 3})
        self.assertEqual(report['quality']['counts'], {'TP': 5, 'FN': 0, 'FP': 0, 'TN': 5})
        self.assertEqual(report['qualification'], 'algorithm-only-recorded-judgments')
        self.assertEqual(report['critic_provenance']['independence'], 'unknown')
        self.assertIsNone(report['quality']['measurements']['total_usd'])

    def test_native_author_reused_as_critic_retains_overlap(self):
        # Exercise the real native association setup, then change only the recording's selected ID.
        self.test_native_instances_bind_report_but_cannot_prove_complete_independence()
        from getzilla.agent_lifecycle import start_agent
        from getzilla.continuity import context_binding
        from getzilla.state import get_active_route
        critic = start_agent(self.root, 'author', 'code_reviewer')
        context = context_binding(self.root, get_active_route(self.root))['digest']
        path = '.getzilla/runtime/reviews/synthetic154/code-review.md'
        (self.root / path).write_text('Synthetic report.\nreviewed-context-digest: ' + context + '\n', encoding='utf-8')
        report = ev.review_quality(self.root, 'manifest.json', 'outputs.json', 'study.json', observation={
            'agent_id': 'author', 'generation': critic['generation'], 'report': path, 'reviewed_context': context})
        self.assertTrue(report['critic_provenance']['known_author_overlap'])
        self.assertEqual(report['critic_provenance']['independence'], 'unknown')

    def test_native_observation_refuses_oversized_metadata_before_parse(self):
        self.test_native_instances_bind_report_but_cannot_prove_complete_independence()
        from getzilla.continuity import context_binding
        from getzilla.state import get_active_route
        context = context_binding(self.root, get_active_route(self.root))['digest']
        (self.root / '.getzilla/runtime/agent-state.json').write_text(' ' * (ev.MAX_BYTES + 1), encoding='utf-8')
        report = ev.review_quality(self.root, 'manifest.json', 'outputs.json', 'study.json', observation={
            'agent_id': 'critic', 'generation': 'synthetic', 'report': '.getzilla/runtime/reviews/synthetic154/code-review.md',
            'reviewed_context': context})
        self.assertEqual(report['quality']['status'], 'invalid')
        self.assertEqual(report['quality']['reason'], 'input_size_or_type')

    def test_incident_sha_oracle_resolves_exact_identity_and_rejects_invented_suffix(self):
        subprocess.run(['git', 'init', '-q'], cwd=self.root, check=True, capture_output=True)
        for key, value in [('user.name', 'Synthetic'), ('user.email', 'synthetic@example.invalid')]:
            subprocess.run(['git', 'config', key, value], cwd=self.root, check=True)
        subprocess.run(['git', 'add', '.'], cwd=self.root, check=True)
        subprocess.run(['git', 'commit', '-qm', 'synthetic'], cwd=self.root, check=True)
        exact = subprocess.check_output(['git', 'rev-parse', 'HEAD^{commit}'], cwd=self.root, text=True).strip()
        resolved = subprocess.check_output(['git', 'rev-parse', exact[:12] + '^{commit}'], cwd=self.root, text=True).strip()
        self.assertEqual(resolved, exact)
        invented = exact[:12] + ('0' if exact[12] != '0' else '1') + exact[13:]
        bad = subprocess.run(['git', 'cat-file', '-e', invented + '^{commit}'], cwd=self.root, capture_output=True)
        self.assertNotEqual(bad.returncode, 0)

    def test_incident_body_text_oracle_keeps_inert_shell_text_literal(self):
        body = 'Synthetic `literal` text with $(printf INERT) and UTF-8: café\n'
        path = self.root / 'body.txt'
        path.write_text(body, encoding='utf-8', newline='\n')
        child = 'import pathlib,sys;sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())'
        result = subprocess.run([sys.executable, '-c', child, str(path)], capture_output=True, timeout=10, check=True)
        self.assertEqual(result.stdout, body.encode('utf-8'))
        if os.name == 'posix':
            # An inert child shell demonstrates the historical interpretation fault.
            faulty = subprocess.run(['sh', '-c', 'printf "%s" "$(printf INERT)"'],
                                    capture_output=True, timeout=10, check=True)
            self.assertEqual(faulty.stdout, b'INERT')
            self.assertNotEqual(faulty.stdout, b'$(printf INERT)')

    def test_actual_managed_files_and_compressed_install_run_same_quality_cli(self):
        from scripts.install_into import PayloadSelection, materialize_new
        base = 'tests/fixtures/agent-evals/incidents-v1/'
        expected = hashlib.sha256((ROOT / '.getzilla/getzilla/agent_evals.py').read_bytes()).hexdigest()
        for compressed in (False, True):
            with self.subTest(compressed=compressed):
                target = self.root / ('archive' if compressed else 'files')
                materialize_new(ROOT, target, selection=PayloadSelection((), engine_archive=compressed))
                self.assertTrue((target / 'scripts/getzilla_evals.py').is_file())
                self.assertEqual((target / '.getzilla/getzilla.zip').is_file(), compressed)
                shutil.copytree(ROOT / base, target / base)
                result = subprocess.run([sys.executable, str(target / 'scripts/getzilla_evals.py'), 'quality',
                                         '--manifest', base + 'manifest.json', '--outputs', base + 'outputs-control.json',
                                         '--study', base + 'study.json', '--json'],
                                        cwd=target, capture_output=True, text=True, timeout=45)
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report['canonical']['identity']['runner_sha256'], expected)
                self.assertEqual(report['quality']['resolved'], 10)
                self.assertFalse(report['release_authority'])

    def test_runner_source_digest_refuses_unknown_loader_or_malformed_source(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        with patch.object(ev, '__loader__', SimpleNamespace(get_data=lambda path: b'untrusted loader')):
            with self.assertRaisesRegex(ev.EvalError, 'runner_source_unavailable'):
                ev._runner_digest()
        with patch.object(ev.__loader__, 'get_data', return_value=b'not valid python {'):
            with self.assertRaisesRegex(ev.EvalError, 'runner_source_unavailable'):
                ev._runner_digest()

    def test_bytecode_only_archive_has_typed_missing_source_refusal(self):
        import importlib.util
        from importlib import _bootstrap_external
        import zipfile
        stack = self.root / 'lean/.getzilla'
        package = stack / 'getzilla'
        package.mkdir(parents=True)
        (package / '__init__.py').write_bytes((ROOT / '.getzilla/getzilla/__init__.py').read_bytes())
        source = (ROOT / '.getzilla/getzilla/agent_evals.py').read_bytes()
        code = compile(source, 'getzilla/agent_evals.py', 'exec')
        pyc = _bootstrap_external._code_to_hash_pyc(code, importlib.util.source_hash(source), False)
        with zipfile.ZipFile(stack / 'getzilla.zip', 'w') as archive:
            archive.writestr('getzilla/agent_evals.pyc', pyc)
            archive.writestr('getzilla/fsx.py', (ROOT / '.getzilla/getzilla/fsx.py').read_bytes())
            archive.writestr('getzilla/agent_eval_authoring.py', (ROOT / '.getzilla/getzilla/agent_eval_authoring.py').read_bytes())
        child = ('import sys;sys.path.insert(0,sys.argv[1]);from getzilla import agent_evals as e\n'
                 'try:e._runner_digest()\n'
                 'except e.EvalError as x:print(str(x))\n'
                 'else:raise AssertionError("bytecode is not source proof")\n')
        result = subprocess.run([sys.executable, '-c', child, str(stack)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'runner_source_unavailable')


if __name__ == '__main__':
    unittest.main()
