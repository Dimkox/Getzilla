"""G09: impact attaches to an existing workflow task graph; required verification is never narrowed."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.code_graph.architecture_bindings import architecture_impact, bind_architecture  # noqa: E402
from getzilla.code_graph.impact import calculate_impact  # noqa: E402
from getzilla.code_graph.models import GraphError  # noqa: E402
from getzilla.code_graph.task_bindings import (  # noqa: E402
    bind_task_impact, compact_task_packet, resolve_evidence_refs,
)
from getzilla.workflow_artifacts import digest_without, validate_task_graph  # noqa: E402
from tests.code_graph_support import FOLDER, generation  # noqa: E402
from tests.test_code_graph_architecture_bindings import MODEL  # noqa: E402

FILES = {'core/calc.py': 'def add():\n    pass\n', 'svc/api.py': 'from core.calc import add\ndef handle():\n    add()\n',
         'web/app.js': 'x()\n'}
TASK_ID = 'TASK-0123456789ab'


def task_graph() -> dict:
    graph = {'schema_version': 1, 'change_id': '20261016-code-graph', 'source_manifest_digest': 'a' * 64,
             'write_agent': 'integration_implementer', 'review_agents': ['code_reviewer'],
             'tasks': [{'task_id': TASK_ID, 'key': 'calc', 'title': 'Calc', 'depends_on': [], 'covers': ['AC-001'],
                        'files': ['core/calc.py'], 'interfaces': ['add()'],
                        'red': ['python3', '-m', 'unittest', 'tests.test_calc'],
                        'green': ['python3', '-m', 'unittest', 'tests.test_calc'], 'source_status': 'pending',
                        'enrichment_required': [], 'source_sha256': 'b' * 64}],
             'graph_digest': ''}
    graph['graph_digest'] = digest_without(graph, 'graph_digest')
    return graph


class TaskBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.graph = generation(FILES)
        self.impact = calculate_impact(self.graph, self.graph, ['core/calc.py'])
        self.policy = {'baseline': dict(FOLDER, **{key: None for key in
                                                   ('object_format', 'commit_oid', 'tree_oid', 'working_set_digest')}),
                       'change_id': '20261016-code-graph', 'required_verification': ['review']}
        self.policy['baseline']['source_kind'] = 'folder'

    def bind(self, artifact=None, policy=None, **kwargs):
        return bind_task_impact(self.impact, artifact or task_graph(), policy or self.policy, task_id=TASK_ID,
                                commit='c' * 40, **kwargs)

    def test_task_code_commit_links_validate_existing_schema(self) -> None:
        artifact = task_graph()
        validate_task_graph(artifact)
        attachment = self.bind(artifact)
        self.assertEqual((attachment.task_id, attachment.commit, attachment.generation_id),
                         (TASK_ID, 'c' * 40, self.graph.generation_id))
        self.assertEqual(attachment.task_files_affected, ('core/calc.py',))
        self.assertEqual(attachment.affected_outside_task, ('svc/api.py',))
        self.assertEqual(attachment.graph_digest, artifact['graph_digest'])

    def test_foreign_baseline_attachment_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy['baseline']['source_digest'] = '9' * 64
        with self.assertRaises(GraphError) as caught:
            self.bind(policy=policy)
        self.assertEqual(caught.exception.reason_code, 'FOREIGN_BASELINE')

    def test_workflow_identity_mismatch_blocks(self) -> None:
        with self.assertRaises(GraphError):
            self.bind(policy={**self.policy, 'change_id': '20261016-other'})
        tampered = task_graph()
        tampered['tasks'][0]['title'] = 'Changed'
        with self.assertRaises(GraphError) as caught:
            self.bind(tampered)
        self.assertEqual(caught.exception.reason_code, 'TASK_GRAPH_DIGEST_MISMATCH')

    def test_unknown_graph_preserves_required_verification(self) -> None:
        attachment = self.bind()
        self.assertFalse(self.impact.complete)  # web/app.js is not analysed
        for required in ('review', 'security_checks', 'full_test_suite',
                         'task_green: python3 -m unittest tests.test_calc'):
            self.assertIn(required, attachment.required_verification)
        self.assertIn('UNSUPPORTED_LANGUAGE:web/app.js:javascript', attachment.diagnostics)

    def test_attachment_does_not_mutate_policy_or_route(self) -> None:
        artifact, policy = task_graph(), copy.deepcopy(self.policy)
        before_artifact, before_policy = copy.deepcopy(artifact), copy.deepcopy(policy)
        self.bind(artifact, policy)
        self.assertEqual((artifact, policy), (before_artifact, before_policy))

    def test_compact_task_packet_resolves_evidence_refs(self) -> None:
        bindings = bind_architecture(self.graph, MODEL)
        attachment = self.bind(architecture=architecture_impact(self.impact, bindings, MODEL))
        packet = compact_task_packet(attachment)
        resolved = resolve_evidence_refs(packet, attachment.evidence)
        self.assertEqual(resolved['impact'], self.impact.to_dict())
        self.assertIn('NODE-CORE', resolved['architecture_impact']['components'])
        with self.assertRaises(GraphError):
            resolve_evidence_refs(packet, {})


if __name__ == '__main__':
    unittest.main()
