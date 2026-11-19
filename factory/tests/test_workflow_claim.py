"""Controlled workflow admission fixtures do not qualify a production writer."""
import unittest
from copy import deepcopy

from getzilla_factory.workflow import WorkflowBoundary, WorkflowCandidate, WorkflowRejected
from getzilla_factory.contracts import canonical_digest


def snapshot():
    nodes = [dict(task_id=key, key=key, depends_on=deps, covers=['AC-001'],
                  files=[key + '.py'], interfaces=['api'], red=['test'], green=['test'],
                  enrichment_required=[], source_sha256='1' * 64, source_status='complete')
             for key, deps in [('a', []), ('b', ['a']), ('c', [])]]
    return dict(graph_digest='2' * 64, authority_digest='3' * 64, owner='worker',
                permission='allow', source_current=True, convergence='pass', nodes=nodes,
                bindings={'a': 'factory-a', 'b': 'factory-b', 'c': 'factory-c'}, accepted={},
                context={'goal': 'vertical change', 'specification': 'complete spec',
                         'decisions': [], 'requirements': {'AC-001': 'observable'},
                         'base_sha': '4' * 40, 'head_sha': '5' * 40,
                         'verification': ['test'], 'limits': {'full_task_seconds': 100}})


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.state = snapshot()
        self.boundary = WorkflowBoundary(lambda cursor: deepcopy(self.state))

    def test_chain_and_imported_checkbox(self):
        ready = self.boundary.ready(None)
        self.assertEqual(ready['ready'], ['a', 'c'])
        self.assertEqual(ready['blocked']['b'], ['dependency:a'])
        self.state['accepted']['a'] = self.boundary.acceptance_binding(self.state, 'a')
        self.assertEqual(self.boundary.ready(None)['ready'], ['b', 'c'])

    def test_stale_acceptance_does_not_unlock(self):
        self.state['accepted']['a'] = {'graph_digest': '0' * 64}
        self.assertEqual(self.boundary.ready(None)['blocked']['b'], ['stale-result:a'])

    def test_missing_self_cycle_and_permission_fail_closed(self):
        for mutate, reason in [
            (lambda s: s['nodes'][0].update(depends_on=['missing']), 'missing-dependency'),
            (lambda s: s['nodes'][0].update(depends_on=['a']), 'self-dependency'),
            (lambda s: s['nodes'][0].update(depends_on=['b']), 'cycle'),
            (lambda s: s.update(permission='unknown'), 'permission'),
            (lambda s: s.update(source_current=False), 'stale-source'),
            (lambda s: s.update(convergence='block'), 'requirements-conflict'),
        ]:
            with self.subTest(reason=reason):
                self.state = snapshot(); mutate(self.state)
                with self.assertRaisesRegex(WorkflowRejected, reason):
                    self.boundary.ready(None)

    def test_claim_reloads_owner_graph_and_prerequisites(self):
        candidate = self.boundary.candidate(None, 'a')
        self.boundary.validate(None, candidate, 'worker', 'factory-a')
        for field, value, reason in [('owner', 'handoff', 'owner'),
                                     ('graph_digest', 'f' * 64, 'stale-candidate'),
                                     ('permission', 'deny', 'permission')]:
            with self.subTest(field=field):
                old = self.state[field]; self.state[field] = value
                with self.assertRaisesRegex(WorkflowRejected, reason):
                    self.boundary.validate(None, candidate, 'worker', 'factory-a')
                self.state[field] = old

    def test_mandatory_scope_is_bounded_without_truncation(self):
        self.state['context']['specification'] = 'x' * 1_048_577
        with self.assertRaisesRegex(WorkflowRejected, 'scope-limit'):
            self.boundary.ready(None)
        self.state['context'] = {}
        with self.assertRaisesRegex(WorkflowRejected, 'scope-unavailable'):
            self.boundary.ready(None)

    def test_no_fallback_or_caller_selected_task_mapping(self):
        with self.assertRaisesRegex(WorkflowRejected, 'dependency'):
            self.boundary.candidate(None, 'b')
        candidate = self.boundary.candidate(None, 'a')
        with self.assertRaisesRegex(WorkflowRejected, 'task-mapping'):
            self.boundary.validate(None, candidate, 'worker', 'factory-c')


class NativeBoundaryTests(unittest.TestCase):
    def setUp(self):
        import json
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from datetime import datetime, timezone
        from getzilla import workflow_artifacts as artifacts
        from getzilla.spec import canonical_spec_digest
        from getzilla_factory.workflow import NativeWorkflowBoundary
        from getzilla_factory.contracts import TaskIntakeV1
        from factory.tests.test_contracts import valid_intake
        from tests.test_workflow_artifacts import WorkflowCompileTests

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        compiler = WorkflowCompileTests()
        compiler.artifacts = artifacts
        tasks = [dict(key=key, title='Observable ' + key, depends_on=deps,
                      covers=['AC-001', 'INV-001', 'FORBID-001'], files=[key + '.py'],
                      interfaces=['api'], red=['python3', '-m', 'unittest'],
                      green=['python3', '-m', 'unittest'], status='complete')
                 for key, deps in [('a', []), ('b', ['a']), ('c', [])]]
        self.root, bundle = compiler._root(self.temp.name, [('spec-kit', 'tasks', '.specify/specs/tasks.md',
            ''.join('<!-- AGB-TASK ' + json.dumps(task) + ' -->\n' for task in tasks))])
        self.route = dict(route_id='route', session_id='worker-01', write_agent='writer',
                          review_agents=['reviewer'], required_evidence=['verification'])
        runtime = self.root / '.getzilla/runtime'
        (runtime / 'active-route.json').write_text(json.dumps(self.route))
        (runtime / 'active-change.json').write_text(json.dumps(dict(change_id='change',
            path='.getzilla/runtime/changes/change')))
        self.graph = artifacts.compile_task_graph(self.root, 'change', bundle, self.route)
        artifacts.workflow_paths(self.root, 'change')['graph'].write_bytes(artifacts.canonical_json(self.graph))
        self.head_patch = patch('getzilla.util.git_head', return_value='3' * 40)
        self.head_patch.start(); self.addCleanup(self.head_patch.stop)
        self.session_patch = patch('getzilla.state.current_session', return_value=None)
        self.session_patch.start(); self.addCleanup(self.session_patch.stop)
        native = artifacts._load_native_spec(self.root, 'change')
        self.rows = []
        for i, node in enumerate(sorted(self.graph['tasks'], key=lambda node: node['key']), 1):
            body = valid_intake()
            body.update(source_type='api', source_id=NativeWorkflowBoundary.source_id('change', node['key']),
                        source_digest=self.graph['graph_digest'], route_id='route', change_id='change',
                        spec_digest=canonical_spec_digest(native), acceptance_ids=sorted(value for value in node['covers'] if value.startswith('AC-')))
            body['m0_authority']['observed_at'] = datetime.now(timezone.utc).isoformat()
            intake = TaskIntakeV1.from_dict(body)
            self.rows.append((f'00000000-0000-0000-0000-{i:012d}', 'queued', None, intake.to_dict()))
        self.cursor = NativeCursor(self.rows)
        self.boundary = NativeWorkflowBoundary(self.root, 'owner/repository', verify_authority=lambda c, i: True)

    def test_real_compile_converge_binding_and_current_result(self):
        self.assertEqual(self.boundary.ready(self.cursor)['ready'], ['a', 'c'])
        self.cursor.proofs[self.rows[0][0]] = ('a' * 64, 'b' * 64, 'c' * 64, 'run-a', 7)
        self.assertEqual(self.boundary.ready(self.cursor)['ready'], ['b', 'c'])
        state, _ = self.boundary._snapshot(self.cursor)
        self.assertEqual(state['accepted']['a']['evidence']['fence'], 7)
        self.assertEqual(state['context']['limits']['b']['wall_seconds'], 14400)
        self.assertIn('AGB-TASK', state['context']['source_documents'][0]['content'])
        from pathlib import Path
        proof_sql = (Path(__file__).resolve().parents[1] / 'src/getzilla_factory/resources/028_workflow_admission_evidence.sql').read_text()
        for binding in ('s.fence=r.fence', 's.owner_id=r.owner_id', 'w.task_packet_digest=p.packet_digest',
                        "v.body->>'decision'='pass'", 'FOR SHARE OF t,r'):
            self.assertIn(binding, proof_sql)

    def test_current_source_and_intent_and_owner_are_required(self):
        import json
        candidate = self.boundary.candidate(self.cursor, 'a')
        self.rows[0][3]['source_digest'] = '0' * 64
        with self.assertRaisesRegex(WorkflowRejected, 'stale-intent'):
            self.boundary.validate(self.cursor, candidate, 'worker-01', candidate.factory_task_id)
        self.rows[0][3]['source_digest'] = self.graph['graph_digest']
        self.route['session_id'] = 'new-owner'
        (self.root / '.getzilla/runtime/active-route.json').write_text(json.dumps(self.route))
        with self.assertRaisesRegex(WorkflowRejected, 'owner'):
            self.boundary.validate(self.cursor, candidate, 'worker-01', candidate.factory_task_id)

    def test_native_missing_cycle_self_and_unavailable_source(self):
        import json
        source = self.root / '.specify/specs/tasks.md'
        original = source.read_text()
        for dependency, reason in [('missing', 'native-dependency'), ('a', 'native-self-dependency'),
                                   ('b', 'native-cycle')]:
            tasks = [json.loads(line[len('<!-- AGB-TASK '):-len(' -->')]) for line in original.splitlines()]
            tasks[0]['depends_on'] = [dependency]
            source.write_text(''.join('<!-- AGB-TASK ' + json.dumps(task) + ' -->\n' for task in tasks))
            with self.subTest(reason=reason), self.assertRaisesRegex(WorkflowRejected, reason):
                self.boundary.ready(self.cursor)
        source.unlink()
        with self.assertRaisesRegex(WorkflowRejected, 'native-io'):
            self.boundary.ready(self.cursor)

    def test_native_current_permission_and_source_are_rechecked(self):
        candidate = self.boundary.candidate(self.cursor, 'a')
        self.boundary.verify_authority = lambda cursor, intake: False
        with self.assertRaisesRegex(WorkflowRejected, 'permission'):
            self.boundary.validate(self.cursor, candidate, 'worker-01', candidate.factory_task_id)
        self.boundary.verify_authority = lambda cursor, intake: True
        source = self.root / '.specify/specs/tasks.md'
        source.write_text(source.read_text() + '# changed source\n')
        with self.assertRaisesRegex(WorkflowRejected, 'stale-source'):
            self.boundary.validate(self.cursor, candidate, 'worker-01', candidate.factory_task_id)

    def test_cancelled_task_and_stale_result_are_not_done(self):
        self.cursor.old_results.add(self.rows[0][0])
        self.assertEqual(self.boundary.ready(self.cursor)['blocked']['b'], ['stale-result:a'])
        row = self.rows[0]
        self.rows[0] = (row[0], 'cancelled', row[2], row[3])
        with self.assertRaisesRegex(WorkflowRejected, 'task-cancelled'):
            self.boundary.ready(self.cursor)


class NativeCursor:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []
        self.proofs = {}
        self.old_results = set()
        self.one = None

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        if 'workflow_prerequisite_evidence_v1' in sql:
            proof = self.proofs.get(params[0])
            value = None
            if proof is not None:
                value = {'proof': dict(result_digest=proof[0], verdict_digest=proof[1],
                                       packet_digest=proof[2], run_id=proof[3], fence=proof[4])}
            elif params[0] in self.old_results:
                value = {'stale': True}
            self.one = (value,)

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.one


class ClaimCursor(NativeCursor):
    def __init__(self, rows):
        super().__init__(rows)
        self.last_sql = ''
        self.lease_count = 0
        self.deadline = None
        self.expiry = None

    def execute(self, sql, params=()):
        from datetime import datetime, timedelta, timezone
        super().execute(sql, params)
        self.last_sql = sql
        if 'capacity_eligible_repositories' in sql:
            pass
        elif 'FROM factory.tasks t WHERE' in sql:
            wanted = params[1]
            row = next((row for row in self.rows if row[0] == wanted and row[1] == 'queued'), None)
            self.deadline = datetime.now(timezone.utc) + timedelta(hours=1)
            self.one = (row[0], 'owner/repository', row[3]['intent_digest'], self.deadline, 2, row[1]) if row else None
        elif 'COALESCE(max(attempt_no)' in sql:
            self.one = (1,)
        elif 'INSERT INTO factory.lease_sequences' in sql:
            self.one = (1,)
        elif 'SELECT LEAST(clock_timestamp()' in sql:
            self.expiry = datetime.now(timezone.utc) + timedelta(minutes=5)
            self.one = (self.expiry,)
        elif 'INSERT INTO factory.runs' in sql:
            self.lease_count += 1
        elif 'SELECT factory.capacity_allocate' in sql:
            self.one = (True,)

    def fetchall(self):
        if 'capacity_eligible_repositories' in self.last_sql:
            return [('owner/repository',)]
        return self.rows


class AtomicClaimTests(NativeBoundaryTests):
    """Use the production claim implementation; replace only SQL transport."""
    def setUp(self):
        super().setUp()
        from contextlib import contextmanager
        from getzilla_factory.store import PostgresFactoryStore, FenceError
        from factory.tests.test_execution_service import FakeExecutionStore
        import threading
        test = self
        self.cursor = ClaimCursor(self.rows)

        class ControlledStore(PostgresFactoryStore):
            def __init__(self):
                super().__init__('controlled-fixture', workflow_boundary=test.boundary)
                self.calls, self.commands, self.packets = [], {}, {}
                self.start_error = None
                self.lock = threading.RLock()

            @contextmanager
            def _transaction(self):
                with self.lock:
                    yield test.cursor

            def _command_replay(self, cursor, key, actor, action, command):
                digest = canonical_digest(command)
                if key in self.commands:
                    old_digest, old_result = self.commands[key]
                    if old_digest != digest:
                        raise ValueError('idempotency mismatch')
                    return True, old_result, digest
                return False, None, digest

            def _record_command(self, cursor, key, actor, action, digest, correlation, result):
                if key:
                    self.commands[key] = (digest, result)

            def _is_killed(self, *args):
                return False

            def _apply_task_transition(self, cursor, task_id, current, target, command, **kwargs):
                for index, row in enumerate(test.rows):
                    if row[0] == task_id:
                        test.rows[index] = (row[0], target.value, kwargs['current_run_id'], row[3])

            def _event(self, *args, **kwargs):
                pass

            def _audit(self, *args, **kwargs):
                pass

            def _lock_grant(self, cursor, grant):
                row = next(row for row in test.rows if row[0] == grant.task_id)
                if row[1] != 'leased' or row[2] != grant.run_id or grant.fence != 1:
                    raise FenceError('stale or expired fence')

            def execution_material(self, grant, **kwargs):
                self._lock_grant(test.cursor, grant)
                row = next(row for row in test.rows if row[0] == grant.task_id)
                body = row[3]
                return dict(repository_id='owner/repository', legacy_intent_digest=body['intent_digest'],
                    route_id=body['route_id'], change_id=body['change_id'], exact_base_sha=body['exact_base_sha'],
                    exact_head_sha=body['governance']['exact_head_sha'], spec_digest=body['spec_digest'],
                    architecture_digest=body['architecture']['architecture_digest'],
                    governance_digest=body['governance']['governance_digest'], policy_digest=body['policy_digest'],
                    acceptance_ids=body['acceptance_ids'], limits=body['limits'],
                    deadline=test.cursor.deadline.isoformat())

            def start_execution(self, grant, packet, manifest, actor, **kwargs):
                self.packets[packet.packet_digest] = packet
                return FakeExecutionStore.start_execution(self, grant, packet, manifest, actor, **kwargs)

        self.store = ControlledStore()

    def _claim(self, candidate, key=None):
        from datetime import datetime, timezone
        from getzilla_factory.models import RunRole
        from getzilla_factory.service import FactoryService
        from factory.tests.test_execution_service import WORKER, trusted_registry, selection
        return FactoryService(self.store, execution_registry=trusted_registry()).claim_execution(
            owner=WORKER.actor_id, role=RunRole.WRITER, repositories=['owner/repository'], lease_seconds=300,
            selection=selection(), actor=WORKER, now=datetime.now(timezone.utc),
            idempotency_key=key, workflow_candidate=candidate)

    def test_compile_to_real_atomic_claim_and_packet(self):
        candidate = self.boundary.candidate(self.cursor, 'a')
        grant = self._claim(candidate, 'request-a')
        self.assertEqual(grant.lease.task_id, self.rows[0][0])
        self.assertEqual(self.cursor.lease_count, 1)
        packet = next(iter(self.store.packets.values()))
        self.assertEqual(packet.authority.spec_digest, self.rows[0][3]['spec_digest'])
        self.assertEqual(self.store.workflow_context(grant.lease)['graph']['graph_digest'], self.graph['graph_digest'])
        self.assertEqual(self._claim(candidate, 'request-a'), grant)
        self.assertEqual(len(self.store.packets), 1)
        self.assertEqual(self.cursor.lease_count, 1)

    def test_stale_owner_and_graph_refuse_before_lease(self):
        import json
        candidate = self.boundary.candidate(self.cursor, 'a')
        self.route['session_id'] = 'handoff'
        (self.root / '.getzilla/runtime/active-route.json').write_text(json.dumps(self.route))
        with self.assertRaisesRegex(WorkflowRejected, 'owner'):
            self._claim(candidate)
        self.assertEqual(self.cursor.lease_count, 0)

    def test_competing_claims_create_one_lease(self):
        from concurrent.futures import ThreadPoolExecutor
        candidate = self.boundary.candidate(self.cursor, 'a')
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self._claim(candidate), range(2)))
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertEqual(self.cursor.lease_count, 1)

    def test_replay_after_cancellation_and_stale_fence_refuse(self):
        from dataclasses import replace
        from getzilla_factory.store import FenceError
        candidate = self.boundary.candidate(self.cursor, 'a')
        grant = self._claim(candidate, 'request-a')
        with self.assertRaises(FenceError):
            self.store.workflow_context(replace(grant.lease, fence=0))
        row = self.rows[0]
        self.rows[0] = (row[0], 'cancelled', row[2], row[3])
        with self.assertRaisesRegex(WorkflowRejected, 'task-cancelled'):
            self._claim(candidate, 'request-a')
        self.assertEqual(self.cursor.lease_count, 1)


class WorkflowApiTests(unittest.TestCase):
    def test_ready_exposes_only_candidate_and_claim_rejects_added_done_bits(self):
        from fastapi.testclient import TestClient
        from getzilla_factory.api import Authenticator, create_app
        from factory.tests.test_api import FakeService
        from factory.tests.test_execution_service import WORKER, selection
        service = FakeService()
        candidate = WorkflowCandidate('a', '00000000-0000-0000-0000-000000000001', 'a' * 64)
        service.workflow_ready = lambda **kwargs: candidate
        client = TestClient(create_app(service, Authenticator({'fixture-token': WORKER})))
        headers = {'Authorization': 'Bearer fixture-token', 'Idempotency-Key': 'workflow-request',
                   'X-Correlation-ID': 'workflow-request'}
        response = client.post('/v2/workflow/ready', json={'node_key': 'a'}, headers=headers)
        self.assertEqual(response.json(), candidate.to_dict())
        payload = dict(selection(), role='writer', repositories=['owner/repository'], lease_seconds=60,
                       workflow_candidate=response.json())
        self.assertEqual(client.post('/v2/execution/claims', json=payload, headers=headers).status_code, 200)
        self.assertEqual(service.calls[-1][1]['workflow_candidate'], candidate)
        payload['workflow_candidate']['done'] = True
        self.assertEqual(client.post('/v2/execution/claims', json=payload, headers=headers).status_code, 422)
        self.assertEqual(client.post('/v2/workflow/ready', json={'accepted': ['a']}, headers=headers).status_code, 422)
