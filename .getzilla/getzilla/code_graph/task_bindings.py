"""Attach code impact to an existing workflow task graph without changing it or the route.

The task graph is validated by the existing `workflow_artifacts.validate_task_graph` and its own
`graph_digest`; the attachment is a separate record that references the graph, the task, the
commit, the graph generation, the impact report and the architecture impact by digest. Its
required verification is the policy's list plus everything an incomplete impact demands; an
incomplete graph never removes a required test or review.
"""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping

from ..workflow_artifacts import digest_without, validate_task_graph
from .architecture_bindings import ArchitectureImpactReport
from .models import GraphError, ImpactReport


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()


@dataclass(frozen=True)
class TaskImpactAttachment:
    change_id: str
    graph_digest: str
    task_id: str
    commit: str
    generation_id: str
    impact_digest: str
    architecture_impact_digest: str | None
    task_files_affected: tuple[str, ...]
    affected_outside_task: tuple[str, ...]
    components: tuple[str, ...]
    required_verification: tuple[str, ...]
    diagnostics: tuple[str, ...] = ()
    evidence: Mapping[str, Mapping[str, Any]] = field(default_factory=dict, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {'schema_version': 'getzilla-task-impact-attachment-v1', 'change_id': self.change_id,
                'graph_digest': self.graph_digest, 'task_id': self.task_id, 'commit': self.commit,
                'generation_id': self.generation_id, 'impact_digest': self.impact_digest,
                'architecture_impact_digest': self.architecture_impact_digest,
                'task_files_affected': list(self.task_files_affected),
                'affected_outside_task': list(self.affected_outside_task), 'components': list(self.components),
                'required_verification': list(self.required_verification), 'diagnostics': list(self.diagnostics)}

    @property
    def digest(self) -> str:
        return _digest(self.to_dict())


def bind_task_impact(impact: ImpactReport, task_artifact: Mapping[str, Any], policy: Mapping[str, Any], *,
                     task_id: str, commit: str, architecture: ArchitectureImpactReport | None = None) -> TaskImpactAttachment:
    """policy: {'baseline': source identity dict, 'change_id', 'graph_digest', 'required_verification': [...]}."""
    original = copy.deepcopy(task_artifact)
    validate_task_graph(task_artifact)
    if task_artifact['graph_digest'] != digest_without(dict(task_artifact), 'graph_digest'):
        raise GraphError('TASK_GRAPH_DIGEST_MISMATCH')
    if dict(impact.source_identity) != dict(policy.get('baseline') or {}):
        raise GraphError('FOREIGN_BASELINE', 'impact was computed for another source baseline')
    for key in ('change_id', 'graph_digest'):
        if policy.get(key) is not None and policy[key] != task_artifact[key]:
            raise GraphError('WORKFLOW_IDENTITY_MISMATCH', key)
    task = next((item for item in task_artifact['tasks'] if item['task_id'] == task_id), None)
    if task is None:
        raise GraphError('TASK_NOT_IN_GRAPH', task_id)
    required = list(dict.fromkeys([*policy.get('required_verification', []), *impact.required_checks,
                                   'task_green: ' + ' '.join(task['green'])]))
    diagnostics = []
    if not impact.complete:
        diagnostics.extend(impact.gaps)
        required.append('full_test_suite')
    files = set(task['files'])
    attachment = TaskImpactAttachment(
        task_artifact['change_id'], task_artifact['graph_digest'], task_id, commit, impact.current_generation,
        _digest(impact.to_dict()), None if architecture is None else _digest(architecture.to_dict()),
        tuple(sorted(files & set(impact.affected_files))), tuple(sorted(set(impact.affected_files) - files)),
        () if architecture is None else architecture.components, tuple(dict.fromkeys(required)), tuple(diagnostics),
        {_digest(impact.to_dict()): impact.to_dict(), **({} if architecture is None else
                                             {_digest(architecture.to_dict()): architecture.to_dict()})})
    if task_artifact != original:
        raise GraphError('TASK_ARTIFACT_MUTATED')
    return attachment


def compact_task_packet(attachment: TaskImpactAttachment) -> dict[str, Any]:
    """Small packet for an agent: identities and evidence references instead of the full reports."""
    return {'task_id': attachment.task_id, 'commit': attachment.commit, 'attachment': attachment.digest,
            'required_verification': list(attachment.required_verification),
            'evidence_refs': {'impact': f'sha256:{attachment.impact_digest}',
                              **({'architecture_impact': f'sha256:{attachment.architecture_impact_digest}'}
                                 if attachment.architecture_impact_digest else {})}}


def resolve_evidence_refs(packet: Mapping[str, Any], store: Mapping[str, Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    resolved = {}
    for name, ref in packet['evidence_refs'].items():
        digest = ref.removeprefix('sha256:')
        record = store.get(digest)
        if record is None or _digest(record) != digest:
            raise GraphError('EVIDENCE_REF_UNRESOLVED', name)
        resolved[name] = record
    return resolved
