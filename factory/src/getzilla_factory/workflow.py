"""Workflow admission at the existing Factory transaction boundary.

The installed loader is a trusted host port, not request data. It must compile,
validate and converge current native sources, lock mutable authority and accepted
result rows with the supplied transaction cursor, and retain those locks until
commit. Imported status and model output are never accepted result evidence.
"""
from dataclasses import dataclass
from contextlib import contextmanager
from collections.abc import Callable, Mapping

from .contracts import canonical_digest


class WorkflowRejected(ValueError):
    pass


@dataclass(frozen=True)
class WorkflowCandidate:
    node_key: str
    factory_task_id: str
    snapshot_digest: str

    def to_dict(self):
        return dict(node_key=self.node_key, factory_task_id=self.factory_task_id,
                    snapshot_digest=self.snapshot_digest)


class WorkflowBoundary:
    MAX_SCOPE_BYTES = 1_048_576

    def __init__(self, load_current: Callable):
        self._load_current = load_current

    @staticmethod
    def acceptance_binding(state, key):
        node = next(node for node in state['nodes'] if node['key'] == key)
        return dict(graph_digest=state['graph_digest'], authority_digest=state['authority_digest'],
                    source_sha256=node['source_sha256'], factory_task_id=state['bindings'][key])

    def _snapshot(self, cursor):
        state = self._load_current(cursor)
        required = {'graph_digest', 'authority_digest', 'owner', 'permission', 'source_current',
                    'convergence', 'nodes', 'bindings', 'accepted', 'context'}
        if not isinstance(state, Mapping) or set(state) != required:
            raise WorkflowRejected('snapshot-unavailable')
        if state['permission'] != 'allow':
            raise WorkflowRejected('permission')
        if state['source_current'] is not True:
            raise WorkflowRejected('stale-source')
        if state['convergence'] != 'pass':
            raise WorkflowRejected('requirements-conflict')
        for field in ('graph_digest', 'authority_digest'):
            value = state[field]
            if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
                raise WorkflowRejected('snapshot-digest')
        nodes = state['nodes']
        if not isinstance(nodes, list) or len(nodes) > 500 or not nodes:
            raise WorkflowRejected('graph-limit')
        try:
            by_key = {node['key']: node for node in nodes}
            if len(by_key) != len(nodes) or set(state['bindings']) != set(by_key):
                raise WorkflowRejected('task-mapping')
            if len(set(state['bindings'].values())) != len(nodes):
                raise WorkflowRejected('task-mapping')
            dependencies = {key: set(node['depends_on']) for key, node in by_key.items()}
            for key, values in dependencies.items():
                if key in values:
                    raise WorkflowRejected('self-dependency')
                if values - set(by_key):
                    raise WorkflowRejected('missing-dependency')
            remaining = dict(dependencies)
            while remaining:
                ready = {key for key, values in remaining.items() if not values}
                if not ready:
                    raise WorkflowRejected('cycle')
                remaining = {key: values - ready for key, values in remaining.items() if key not in ready}
        except (KeyError, TypeError) as exc:
            raise WorkflowRejected('graph-invalid') from exc
        context = state['context']
        mandatory = {'goal', 'specification', 'decisions', 'requirements', 'base_sha', 'head_sha',
                     'verification', 'limits'}
        if not isinstance(context, dict) or not mandatory <= set(context) or any(
            not context[field] for field in mandatory - {'decisions'}
        ):
            raise WorkflowRejected('scope-unavailable')
        # Measure before digesting; do not truncate mandatory requirements or estimates.
        import json
        if len(json.dumps(context, ensure_ascii=True).encode()) > self.MAX_SCOPE_BYTES:
            raise WorkflowRejected('scope-limit')
        if not isinstance(state['accepted'], dict) or set(state['accepted']) - set(by_key):
            raise WorkflowRejected('result-binding')
        return state, by_key

    def _accepted_current(self, state, key):
        record = state['accepted'].get(key)
        expected = self.acceptance_binding(state, key)
        return isinstance(record, dict) and {field: record.get(field) for field in expected} == expected

    def _ready(self, state, nodes):
        ready, blocked = [], {}
        for key, node in sorted(nodes.items()):
            if self._accepted_current(state, key):
                continue
            reasons = []
            if node.get('enrichment_required') or not any(value.startswith('AC-') for value in node.get('covers', [])):
                reasons.append('enrichment-required')
            if any(not node.get(field) for field in ('files', 'interfaces', 'red', 'green')):
                reasons.append('enrichment-required')
            if set(node.get('covers', [])) - set(state['context']['requirements']):
                reasons.append('requirements-conflict')
            for dependency in sorted(node['depends_on']):
                accepted = state['accepted'].get(dependency)
                if not self._accepted_current(state, dependency):
                    reasons.append(('stale-result:' if accepted is not None else 'dependency:') + dependency)
            if reasons:
                blocked[key] = sorted(set(reasons))
            else:
                ready.append(key)
        return dict(ready=ready, blocked=blocked, snapshot_digest=canonical_digest(state))

    def ready(self, cursor):
        state, nodes = self._snapshot(cursor)
        return self._ready(state, nodes)

    def candidate(self, cursor, key):
        state, nodes = self._snapshot(cursor)
        result = self._ready(state, nodes)
        if key not in result['ready']:
            raise WorkflowRejected(','.join(result['blocked'].get(key, ['node-unavailable'])))
        return WorkflowCandidate(key, state['bindings'][key], result['snapshot_digest'])

    def validate(self, cursor, candidate, owner, task_id):
        if not isinstance(candidate, WorkflowCandidate):
            raise WorkflowRejected('candidate-invalid')
        state, nodes = self._snapshot(cursor)
        if state['owner'] != owner:
            raise WorkflowRejected('owner')
        if state['bindings'].get(candidate.node_key) != task_id or candidate.factory_task_id != task_id:
            raise WorkflowRejected('task-mapping')
        result = self._ready(state, nodes)
        if result['snapshot_digest'] != candidate.snapshot_digest:
            raise WorkflowRejected('stale-candidate')
        if candidate.node_key not in result['ready']:
            raise WorkflowRejected('node-unavailable')
        return state['context']


class NativeWorkflowBoundary(WorkflowBoundary):
    """Production adapter for native sources and existing persisted Factory evidence.

    Mapping lives in accepted_intents, using the ordinary intake identity and
    supersession rules. No separate workflow task or result ledger is created.
    """

    def __init__(self, root, repository_id, *, verify_authority):
        from pathlib import Path
        self.root = Path(root).resolve(strict=True)
        self.repository_id = repository_id
        self.verify_authority = verify_authority
        super().__init__(self._load_native)

    @contextmanager
    def locked(self):
        try:
            from getzilla.state import task_transition
            from getzilla import workflow_artifacts as artifacts
        except ImportError as exc:
            raise WorkflowRejected('native-runtime-unavailable') from exc
        with task_transition(self.root):
            try:
                change = artifacts.load_runtime_authority(self.root, 'change')['change_id']
                descriptor, directory = artifacts._acquire_cas_lock(self.root, change, 'task-graph.json')
            except artifacts.WorkflowArtifactError as exc:
                raise WorkflowRejected('native-' + exc.code) from exc
            try:
                yield
            finally:
                artifacts.fsx.unlock_file(descriptor)
                import os
                os.close(descriptor)
                artifacts.fsx.close_dir(directory)

    @staticmethod
    def source_id(change_id, node_key):
        value = f'workflow:v1:{change_id}:{node_key}'
        if len(value) > 128:
            raise WorkflowRejected('identity-limit')
        return value

    def _load_native(self, cursor):
        import json
        from getzilla import workflow_artifacts as artifacts
        from getzilla.spec import canonical_spec_digest
        from getzilla.util import git_head
        from .contracts import TaskIntakeV1

        try:
            route = artifacts.load_runtime_authority(self.root, 'route')
            from getzilla.continuity import scope_gaps
            if scope_gaps(self.root, route):
                raise WorkflowRejected('scope-sync-required')
            change = artifacts.load_runtime_authority(self.root, 'change')['change_id']
            native = artifacts._load_native_spec(self.root, change)
            paths = artifacts.workflow_paths(self.root, change)
            bundle = artifacts.load_source_manifest(self.root, paths['manifest'])
            graph = artifacts.compile_task_graph(self.root, change, bundle, route)
            head = git_head(self.root)
            authority = dict(route=route, spec_digest=canonical_spec_digest(native), head_sha=head)
            authority_digest = canonical_digest(authority)
            report = artifacts.converge(
                self.root, change, bundle, graph, route,
                current_fingerprint=authority_digest,
                # Native/imported status never grants execution completion here.
                receipt_errors=['Factory semantic acceptance is required per node'],
            )
            stored = artifacts._load_stored(self.root, paths['graph'])
            if stored != graph:
                raise WorkflowRejected('stale-source')
        except WorkflowRejected:
            raise
        except artifacts.WorkflowArtifactError as exc:
            raise WorkflowRejected('native-' + exc.code) from exc
        except (ValueError, OSError, KeyError, TypeError) as exc:
            raise WorkflowRejected('native-source-unavailable') from exc
        if not head or not route.get('session_id') or route.get('status') in {'cancelled', 'complete', 'completed', 'released', 'archived'}:
            raise WorkflowRejected('owner-unavailable')
        nodes = graph['tasks']
        key_by_id = {node['task_id']: node['key'] for node in nodes}
        nodes = [dict(node, depends_on=[key_by_id[value] for value in node['depends_on']]) for node in nodes]
        if any(not any(value.startswith('AC-') for value in node['covers']) for node in nodes):
            raise WorkflowRejected('enrichment-required:AC-coverage')
        bindings, accepted, limits = {}, {}, {}
        source_ids = {node['key']: self.source_id(change, node['key']) for node in nodes}
        # Use precisely the intake lock key. Replacement cannot race admission.
        for source_id in sorted(source_ids.values()):
            cursor.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',
                           (f'{self.repository_id}\x1fapi\x1f{source_id}',))
        cursor.execute('''SELECT t.task_id,t.state,t.current_run_id,i.body
            FROM factory.tasks t JOIN factory.accepted_intents i ON i.intent_id=t.intent_id
            WHERE t.repository_id=%s AND i.source_type='api' AND i.source_id=ANY(%s)
            AND t.generation=(SELECT max(newer.generation) FROM factory.tasks newer
                WHERE newer.repository_id=t.repository_id AND newer.source_type=t.source_type
                AND newer.source_id=t.source_id)
            ORDER BY t.task_id FOR UPDATE OF t''', (self.repository_id, sorted(source_ids.values())))
        rows = cursor.fetchall()
        by_source = {}
        for task_id, task_state, run_id, body in rows:
            body = json.loads(body) if isinstance(body, str) else body
            if body['source_id'] in by_source:
                raise WorkflowRejected('task-mapping')
            by_source[body['source_id']] = (str(task_id), task_state, run_id, body)
        permission = 'allow'
        for node in nodes:
            row = by_source.get(source_ids[node['key']])
            if row is None:
                raise WorkflowRejected('task-mapping-unavailable')
            task_id, task_state, run_id, body = row
            if task_state in {'cancelled', 'superseded', 'dead'}:
                raise WorkflowRejected('task-cancelled')
            if (body['source_digest'] != graph['graph_digest'] or body['route_id'] != route['route_id']
                    or body['change_id'] != change or body['spec_digest'] != authority['spec_digest']
                    or body['governance']['exact_head_sha'] != head
                    or sorted(body['acceptance_ids']) != sorted(value for value in node['covers'] if value.startswith('AC-'))):
                raise WorkflowRejected('stale-intent')
            intake_data = {key: value for key, value in body.items()
                           if key not in {'intent_digest', 'idempotency_key'}}
            intake_data['m0_authority'] = {key: value for key, value in intake_data['m0_authority'].items() if value is not None}
            try:
                from datetime import datetime
                observed = intake_data['m0_authority'].get('observed_at')
                # Reparse immutable intake at its recorded observation time. Current
                # revocation/expiry is checked by the existing locked DB function.
                at = datetime.fromisoformat(observed.replace('Z', '+00:00')) if observed else None
                intake = TaskIntakeV1.from_dict(intake_data, now=at)
            except ValueError as exc:
                raise WorkflowRejected('permission') from exc
            if (intake.intent_digest != body['intent_digest']
                    or not self.verify_authority(cursor, intake)):
                permission = 'deny'
            bindings[node['key']] = task_id
            limits[node['key']] = body['limits']
        context = dict(workflow_context_version=1, graph_digest=graph['graph_digest'],
                       authority_digest=authority_digest, goal=native.get('objective'), specification=native,
                       decisions=native.get('decisions', []),
                       requirements={item['id']: item for group in ('acceptance_criteria', 'invariants', 'forbidden_outcomes')
                                     for item in native.get(group, [])},
                       base_sha={node['key']: by_source[source_ids[node['key']]][3]['exact_base_sha'] for node in nodes},
                       head_sha=head, verification={node['key']: dict(red=node['red'], green=node['green']) for node in nodes},
                       limits=limits, graph=graph,
                       sources=bundle.to_dict(),
                       source_documents=[dict(identity=source.to_dict(), content=source.content) for source in bundle.sources])
        state = dict(graph_digest=graph['graph_digest'], authority_digest=authority_digest,
                     owner=route['session_id'], permission=permission, source_current=True,
                     convergence=report['status'], nodes=nodes, bindings=bindings, accepted=accepted,
                     context=context)
        for node in nodes:
            task_id, _, run_id, _ = by_source[source_ids[node['key']]]
            # A current, fenced completed result plus deterministic semantic pass is
            # acceptance. A terminal proposal or external phase alone cannot pass.
            cursor.execute('SELECT factory.workflow_prerequisite_evidence_v1(%s,%s,%s,%s,%s)',
                           (task_id, self.repository_id, graph['graph_digest'], authority['spec_digest'], head))
            value = cursor.fetchone()[0]
            if isinstance(value, str):
                value = json.loads(value)
            if value is not None and 'proof' in value:
                accepted[node['key']] = dict(self.acceptance_binding(state, node['key']), evidence=value['proof'])
            elif value is not None and value.get('stale') is True:
                accepted[node['key']] = {'stale': True}
        context['dependency_evidence'] = dict(accepted)
        context['factory_bindings'] = dict(bindings)
        context['intent_digests'] = {node['key']: by_source[source_ids[node['key']]][3]['intent_digest'] for node in nodes}
        return state
