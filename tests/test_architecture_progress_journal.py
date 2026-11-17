"""Owned diagnostic contexts expose actual work without granting evidence credit."""
import ast
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from getzilla import architecture_fitness as fitness
from getzilla import verification_journal as journal
from tests.test_batch_composition_joins import pure
from tests.test_queue_source_preparation_cache import resolve

ROOT = Path(__file__).resolve().parents[1]


class ArchitectureProgressTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory(prefix='owned-arch-journal-', dir=ROOT/'.getzilla/runtime/scratch')
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def test_library_without_active_sink_has_no_diagnostic_io_and_same_budget(self):
        with journal.activate(None), mock.patch.object(journal, 'Run', side_effect=AssertionError('library opened a journal')), pure():
            self.assertIsNone(journal.action_sink()[0])
            result, budget = resolve()
        self.assertEqual(result.state, 'not_queue')
        self.assertEqual((budget.ast_nodes, budget.logical_work), (17, 1))

    def test_locator_is_deterministic_private_and_reconstructable(self):
        private = 'outside/private-token.py'
        with pure():
            source = fitness._diagnostic_step('source-head-read', private)
            expected = hashlib.sha256((json.dumps(private, sort_keys=True, separators=(',', ':'), ensure_ascii=True)+'\n').encode()).hexdigest()[:16]
            self.assertEqual(source, 'arch-source-head-read-'+expected)
            demand = fitness._diagnostic_step('demand-head', ('module', 'owned'), (['first'], True))
            self.assertEqual(demand, fitness._diagnostic_step('demand-head', ('module', 'owned'), (['first'], True)))
            self.assertNotEqual(demand, fitness._diagnostic_step('demand-head', ('module', 'owned'), (['second'], True)))
            self.assertNotIn('first', demand)
            self.assertNotIn('private-token', source)
            self.assertIsNone(fitness._diagnostic_location(private))
            self.assertEqual(fitness._diagnostic_location('tests/owned.py'), ('tests/owned.py', 1))

    def test_actual_demand_span_is_recorded_without_changing_resolution(self):
        root = self.fixture()
        with journal.activate(None), redirect_stderr(io.StringIO()), journal.session(root, 'owned-architecture') as run:
            result, budget = resolve()
            raw = (run.path/run.writer.name).read_bytes()
            rows = [json.loads(line) for line in raw.splitlines()]
            demands = [row for row in rows if row.get('step', '').startswith('arch-demand-head-')]
            self.assertEqual([row['state'] for row in demands], ['start', 'end'])
            self.assertTrue(all('location' not in row for row in demands))
        self.assertEqual((result.state, budget.ast_nodes, budget.logical_work), ('not_queue', 17, 1))
        self.assertEqual(run.status, 'closed')

    def test_actual_source_reads_parses_and_classifications_have_reconstructable_steps(self):
        root = self.fixture()
        path, source = 'tests/owned.py', b'def owned(): return None\n'
        diff = SimpleNamespace(artifacts=[SimpleNamespace(path=path, status='added')])
        inventory = SimpleNamespace(tree=lambda _: ast.parse(source))
        empty = fitness._QueueResolutionCache((), (), {}, {})
        no_queue = fitness._QueueProvenanceResult('not_queue', 'no_queue_signal', ())
        def read(_root, _diff, selected, side):
            self.assertEqual((selected, side), (path, side))
            self.assertIn(side, ('head', 'base'))
            return source
        with mock.patch.object(fitness, '_queue_module_inventory', return_value=empty), \
                mock.patch.object(fitness, '_module_package', return_value=''), \
                mock.patch.object(fitness, 'read_diff_file', side_effect=read), \
                mock.patch.object(fitness, '_queue_signals', return_value=no_queue), \
                journal.activate(None), redirect_stderr(io.StringIO()), journal.session(root, 'owned-architecture') as run:
            result = fitness._new_queue_sources(root, diff, inventory, ())
            rows = [json.loads(line) for line in (run.path/run.writer.name).read_bytes().splitlines()]
        self.assertEqual(result.state, 'not_queue')
        for side in ('head', 'base'):
            for phase in ('read', 'parse', 'classify'):
                selected = [row for row in rows if row.get('step') == fitness._diagnostic_step('source-'+side+'-'+phase, path)]
                self.assertEqual([row['state'] for row in selected], ['start', 'end'])
                self.assertEqual(selected[0]['location'], {'path':path,'line':1})

    def test_actual_cli_opens_owned_session_and_stdout_stays_one_json_value(self):
        root = self.fixture()
        spec = importlib.util.spec_from_file_location('owned_architecture_cli', ROOT/'scripts/getzilla_architecture.py')
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        diff = SimpleNamespace(base_architecture_digest='a'*64, baseline_introduced=False,
            base_adoption_state='active', head_adoption_state='active', base_adoption_digest='b'*64,
            head_adoption_digest='c'*64, changed_paths=(), changes=(), artifacts=(), digest='d'*64,
            base_sha='1'*40, head_architecture_digest='e'*64, head_kind='commit',
            repository_inventory_digest='f'*64, head_sha='2'*40, _head_state=SimpleNamespace(snapshot=object()))
        report = SimpleNamespace(evidence_digest='a'*64, exemption_state='revoked', results=(), status='pass',
                                 required_scopes=(), escalation=None, post_risk='green', pre_risk='green', triggers=())
        stdout, stderr = io.StringIO(), io.StringIO()
        args = ['owned', '--root', str(root), 'fitness', '--base', '1'*40, '--head', '2'*40, '--json']
        with mock.patch.object(sys, 'argv', args), mock.patch.object(cli, 'diff_architecture', return_value=diff), \
                mock.patch.object(cli, 'evaluate_fitness', return_value=report), \
                journal.activate(None), redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(cli.main(), 0)
        self.assertEqual(json.loads(stdout.getvalue())['fitness_status'], 'pass')
        index = root/stderr.getvalue().strip().split('getzilla journal: ', 1)[1]
        self.assertEqual(json.loads(index.read_bytes())['status'], 'closed')
        raw = b''.join(p.read_bytes() for p in index.parent.glob('controller-*.jsonl'))
        rows = [json.loads(line) for line in raw.splitlines()]
        for step in ('arch-diff', 'arch-fitness'):
            self.assertEqual([row['state'] for row in rows if row.get('step') == step], ['start', 'end'])

    def test_actual_evaluator_records_every_category_and_preserves_single_calls(self):
        root = self.fixture()
        categories = {'_background_jobs':'background_job', '_change_separation':'change_separation',
            '_code_budget':'code_budget', '_contract_compatibility':'contract_compatibility',
            '_forbidden_edges':'forbidden_edge', '_governance_promotion':'governance_promotion',
            '_migration_safety':'migration_safety', '_module_boundaries':'module_boundary',
            '_network_clients':'network_client', '_production_imports':'production_import',
            '_secret_flows':'secret_flow', '_tenant_authorization':'tenant_authorization',
            '_workspace_trust':'workspace_trust'}
        diff = SimpleNamespace(changed_paths=(), head_architecture_digest='a'*64,
                               baseline_introduced=False, changes=())
        no_queue = fitness._QueueProvenanceResult('not_queue', 'no_queue_signal', ())
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(fitness, 'architecture_digests', return_value={'architecture_digest':'a'*64}))
            stack.enter_context(mock.patch.object(fitness, '_queue_source_roots', return_value=()))
            stack.enter_context(mock.patch.object(fitness, '_new_queue_sources', return_value=no_queue))
            stack.enter_context(mock.patch.object(fitness, '_bind_applicability_inventory', side_effect=lambda *args: args[-1]))
            stack.enter_context(mock.patch.object(fitness, '_risk', return_value=(None, 'green', ())))
            calls = [stack.enter_context(mock.patch.object(fitness, name, return_value=fitness._result(
                category, status='pass', predicate='owned logging fixture'))) for name, category in categories.items()]
            stack.enter_context(journal.activate(None))
            stack.enter_context(redirect_stderr(io.StringIO()))
            run = stack.enter_context(journal.session(root, 'owned-architecture'))
            report = fitness.evaluate_fitness(root, object(), diff, (), pre_risk='green')
            rows = [json.loads(line) for line in (run.path/run.writer.name).read_bytes().splitlines()]
        self.assertEqual(tuple(result.category for result in report.results), fitness.FITNESS_CATEGORIES)
        self.assertTrue(all(call.call_count == 1 for call in calls))
        phases = {row.get('step') for row in rows if row['state'] == 'start'}
        self.assertEqual(sum(step.startswith('arch-fitness-') for step in phases if step), 14)
        self.assertIn('arch-risk', phases)
        self.assertEqual(sum(step.startswith('arch-applicability-') for step in phases if step), 13)

    def test_error_text_and_private_locator_never_enter_diagnostic_bytes(self):
        root = self.fixture()
        error = ValueError('RAW-CREDENTIAL-SENTINEL')
        with journal.activate(None), redirect_stderr(io.StringIO()), journal.session(root, 'owned-architecture') as run:
            with self.assertRaises(ValueError) as raised:
                with journal.span(fitness._diagnostic_step('source-head-read', 'RAW-CREDENTIAL-SENTINEL'), stage='action'):
                    raise error
            self.assertIs(raised.exception, error)
        raw = b''.join(p.read_bytes() for p in run.path.iterdir() if p.suffix in {'.json', '.jsonl'})
        self.assertNotIn(b'RAW-CREDENTIAL-SENTINEL', raw)

    def test_rotation_keeps_the_current_active_span_in_owned_health(self):
        root = self.fixture()
        with journal.activate(None), redirect_stderr(io.StringIO()), journal.session(root, 'owned-architecture') as run:
            with journal.span('arch-source-head-owned', stage='action', location=('tests/owned.py', 1)):
                for _ in range(4096):
                    run.writer.emit('action', 'unknown', step='owned-rotation')
                    if run.writer.generation > journal.SEGMENTS:
                        break
                self.assertGreater(run.writer.generation, journal.SEGMENTS)
                health = json.loads((run.path/'controller.json').read_bytes())
                self.assertIn('active_span', health)
                self.assertEqual(health['active_span']['step'], 'arch-source-head-owned')
                self.assertEqual(health['active_span']['location'], {'path':'tests/owned.py','line':1})
                self.assertLessEqual((run.path/'controller.json').stat().st_size, 2048)
                segments = list(run.path.glob('controller-*.jsonl'))
                self.assertLessEqual(len(segments), 4)
                self.assertTrue(all(p.stat().st_size <= 128*1024 for p in segments))
        self.assertNotIn('active_span', json.loads((run.path/'controller.json').read_bytes()))

    def test_active_span_shape_is_closed_and_cannot_supply_freeform_data(self):
        with pure():
            for value in ({'stage':'action','step':'secret\nraw','invocation':1},
                          {'stage':'action','step':'arch-queue','invocation':True},
                          {'stage':'action','step':'arch-queue','invocation':1,'extra':'secret'}):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    journal._validated_active_span(value)
            for sequence, opened in ((0, 1), (1, 0)):
                with self.subTest(sequence=sequence, opened=opened), self.assertRaises(ValueError):
                    journal._retained_health({'sequence':sequence, 'open_spans':opened,
                        'active_span':{'stage':'action','step':'arch-queue','invocation':1}})

    def test_caught_refusal_uses_internal_capture_and_survives_later_progress(self):
        root = self.fixture()
        with journal.activate(None), redirect_stderr(io.StringIO()), journal.session(root, 'owned-architecture') as run:
            budget = fitness._QueueBudget('head')
            budget.enter('owned-request', module='owned.adapter')
            try:
                budget.check_depth(9, site='active')
            except fitness.ArchitectureError as error:
                captured = error._queue_refusal_capture
                error.queue_refusal.update(category='bytes', observed=0, active=['forged'])
                journal.queue_refusal(error)
            with journal.span('arch-later-progress', stage='action'):
                health = json.loads((run.path/'controller.json').read_bytes())
                self.assertIn('queue_refusal', health)
                detail = health['queue_refusal']
                self.assertEqual((detail['category'], detail['limit'], detail['observed']), ('depth', 8, 9))
                self.assertEqual(detail['active'], ['owned.adapter'])
                self.assertEqual(detail['capture_sha256'], hashlib.sha256(captured.payload.encode()).hexdigest())
                self.assertLessEqual(len(json.dumps(detail, separators=(',', ':')).encode()), 640)
            rows = [json.loads(line) for line in (run.path/run.writer.name).read_bytes().splitlines()]
            self.assertTrue(any(row.get('queue_refusal') == detail for row in rows))
            entries = journal.export_entries(root)
            summary = json.loads(dict(entries)['journal/index.json'])
            self.assertEqual(summary['actors'][0]['queue_refusal'], detail)

    def test_refusal_unknown_counts_and_witness_omission_are_explicit(self):
        root = self.fixture()
        with journal.activate(None), redirect_stderr(io.StringIO()), journal.session(root, 'owned-architecture') as run:
            budget = fitness._QueueBudget('base')
            for number in range(12):
                budget.enter('request-'+str(number), module='owned.'+str(number)+'x'*180)
            error = budget.refusal('owned unknown refusal', 'other', None, None, site='resolver')
            detail = json.loads((run.path/'controller.json').read_bytes())['queue_refusal']
            self.assertIsNone(detail['limit'])
            self.assertIsNone(detail['observed'])
            self.assertGreater(detail['active_omitted'], 0)
            self.assertEqual(len(detail['active'])+detail['active_omitted'], 12)
            self.assertEqual(detail['capture_sha256'], hashlib.sha256(error._queue_refusal_capture.payload.encode()).hexdigest())
            forged = dict(detail, observed=True)
            with self.assertRaises(ValueError):
                journal._validate_queue_refusal(forged)

    def test_public_or_wrong_owner_refusal_sidecar_is_not_provenance(self):
        root = self.fixture()
        with journal.activate(None), redirect_stderr(io.StringIO()), journal.session(root, 'owned-architecture') as run:
            budget = fitness._QueueBudget('head')
            genuine = budget.refusal('owned refusal', 'nodes', 10, 11)
            expected = json.loads((run.path/'controller.json').read_bytes())['queue_refusal']
            forged = fitness.ArchitectureError('owned refusal', code='limit')
            forged.queue_refusal = genuine.queue_refusal
            journal.queue_refusal(forged)
            forged._queue_refusal_capture = genuine._queue_refusal_capture
            journal.queue_refusal(forged)
            for field in ('message', 'payload'):
                genuine._queue_refusal_capture = genuine._queue_refusal_capture._replace(**{field:1})
                journal.queue_refusal(genuine)
            self.assertEqual(json.loads((run.path/'controller.json').read_bytes())['queue_refusal'], expected)
        with journal.activate(None), mock.patch.object(journal, 'Run', side_effect=AssertionError('inactive I/O')), pure():
            self.assertIsNone(journal.queue_refusal(genuine))

    def test_owned_child_abrupt_stop_retains_active_checkpoint_without_pass(self):
        root = self.fixture()
        source = '''import sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from getzilla import verification_journal as journal
from getzilla import architecture_fitness as fitness
root=Path(sys.argv[2])
with journal.session(root,'owned-architecture') as run:
 budget=fitness._QueueBudget('head')
 budget.enter('owned-request',module='owned.adapter')
 try:
  budget.check_depth(9,site='active')
 except fitness.ArchitectureError:
  pass
 for number in range(4096):
  run.writer.emit('action','unknown',step='owned-later-progress')
  if run.writer.generation>journal.SEGMENTS:
   break
 with journal.span('arch-demand-head-owned',stage='action',location=('tests/owned.py',1)):
  (root/'ready').write_text(run.relative_index)
  time.sleep(30)
'''
        process = subprocess.Popen([sys.executable, '-I', '-S', '-B', '-c', source, str(ROOT/'.getzilla'), str(root)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic()+5
            while not (root/'ready').is_file() and process.poll() is None and time.monotonic()<deadline:
                time.sleep(0.01)
            self.assertTrue((root/'ready').is_file())
            index = root/(root/'ready').read_text()
            process.terminate()
            process.communicate(timeout=5)
            health = json.loads((index.parent/'controller.json').read_bytes())
            self.assertEqual((health['queue_refusal']['category'],health['queue_refusal']['limit'],health['queue_refusal']['observed']), ('depth',8,9))
            self.assertEqual(health['queue_refusal']['active'], ['owned.adapter'])
            self.assertGreater(health['rotated'], 0)
            self.assertLessEqual(len(list(index.parent.glob('controller-*.jsonl'))), 4)
            self.assertLessEqual(len((index.parent/'controller.json').read_bytes()), 2048)
            self.assertEqual(health['active_span']['step'], 'arch-demand-head-owned')
            self.assertGreater(health['open_spans'], 0)
            self.assertEqual(json.loads(index.read_bytes())['status'], 'active')
            entries = journal.export_entries(root)
            summary = json.loads(dict(entries)['journal/index.json'])
            self.assertNotEqual(summary['status'], 'closed')
            self.assertEqual(summary['actors'][0]['active_span']['step'], 'arch-demand-head-owned')
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)
