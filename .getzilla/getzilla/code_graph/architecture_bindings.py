"""Bind code files and symbols to declared architecture nodes; an extra evidence source, never a rewrite.

The contract is the existing `architecture/system.yaml` (`nodes[].repository_paths`, exact files or
directory prefixes) and `architecture/rules.yaml`, loaded by `getzilla.architecture.load_architecture`.
The most specific declared path wins; equally specific matches from different nodes stay unknown.
Bindings record the digest of the architecture source they were made from and are refused for any
other version. The model and rules are only read.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping

from .models import GraphError, GraphGeneration, ImpactReport

PATH_RULE_FIELDS = ('source_prefixes', 'path_prefixes', 'implementation_prefixes', 'trust_ci_prefixes',
                    'forbidden_dependency_prefixes')
NODE_TYPE_RULE_FIELDS = ('node_types',)
TRUST_RULE_FIELDS = ('from_trust_domains', 'to_trust_domains', 'allowed_trust_domains')


def architecture_digest(system: Mapping[str, Any], rules: Mapping[str, Any]) -> str:
    payload = json.dumps({'system': system, 'rules': rules}, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def _model(architecture: Any) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    if hasattr(architecture, 'system') and hasattr(architecture, 'rules'):
        return architecture.system, architecture.rules
    return architecture['system'], architecture['rules']


@dataclass(frozen=True)
class ArchitectureBindings:
    architecture_id: str
    architecture_digest: str
    generation_id: str
    files: Mapping[str, str | None]  # path -> node id (None: unbound or ambiguous)
    ambiguous: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    def node_of(self, path: str) -> str | None:
        return self.files.get(path)

    def to_dict(self) -> dict[str, Any]:
        return {'schema_version': 'getzilla-architecture-bindings-v1', 'architecture_id': self.architecture_id,
                'architecture_digest': self.architecture_digest, 'generation_id': self.generation_id,
                'files': dict(sorted(self.files.items())),
                'ambiguous': {path: list(nodes) for path, nodes in sorted(self.ambiguous.items())},
                'evidence_kind': 'declared_intent_matched_to_actual_paths'}


def _match_length(path: str, declared: str) -> int | None:
    declared = declared.rstrip('/')
    if path == declared:
        return len(declared) + 1  # an exact file beats a directory of the same length
    if path.startswith(declared + '/'):
        return len(declared)
    return None


def bind_architecture(graph: GraphGeneration, architecture_model: Any) -> ArchitectureBindings:
    system, rules = _model(architecture_model)
    files: dict[str, str | None] = {}
    ambiguous: dict[str, tuple[str, ...]] = {}
    for node in graph.files:
        best: dict[int, set[str]] = {}
        for declared_node in system.get('nodes', []):
            for declared in declared_node.get('repository_paths', []):
                length = _match_length(node.path, declared)
                if length is not None:
                    best.setdefault(length, set()).add(declared_node['id'])
        if not best:
            files[node.path] = None
            continue
        winners = best[max(best)]
        if len(winners) == 1:
            files[node.path] = next(iter(winners))
        else:
            files[node.path] = None
            ambiguous[node.path] = tuple(sorted(winners))
    return ArchitectureBindings(system.get('architecture_id', ''), architecture_digest(system, rules),
                                graph.generation_id, files, ambiguous)


@dataclass(frozen=True)
class ArchitectureImpactReport:
    architecture_digest: str
    components: tuple[str, ...]
    unbound_files: tuple[str, ...]
    ambiguous_files: tuple[str, ...]
    rules: tuple[str, ...]
    reasons: Mapping[str, tuple[str, ...]]

    def to_dict(self) -> dict[str, Any]:
        return {'schema_version': 'getzilla-architecture-impact-v1', 'architecture_digest': self.architecture_digest,
                'components': list(self.components), 'unbound_files': list(self.unbound_files),
                'ambiguous_files': list(self.ambiguous_files), 'rules': list(self.rules),
                'reasons': {key: list(value) for key, value in sorted(self.reasons.items())}}


def _prefix_hit(path: str, prefixes: Any) -> bool:
    return any(path == prefix or path.startswith(prefix.rstrip('/') + '/') for prefix in prefixes or [])


def architecture_impact(impact: ImpactReport, bindings: ArchitectureBindings, architecture_model: Any) -> ArchitectureImpactReport:
    system, rules = _model(architecture_model)
    digest = architecture_digest(system, rules)
    if digest != bindings.architecture_digest:
        raise GraphError('ARCHITECTURE_SOURCE_CHANGED', 'bindings were made from another architecture version')
    if impact.current_generation != bindings.generation_id:
        raise GraphError('BINDINGS_FOR_OTHER_GENERATION')
    nodes = {node['id']: node for node in system.get('nodes', [])}
    components, unbound, ambiguous = set(), [], []
    for path in impact.affected_files:
        node = bindings.node_of(path)
        if node is not None:
            components.add(node)
        elif path in bindings.ambiguous:
            ambiguous.append(path)
        else:
            unbound.append(path)
    types = {nodes[node].get('type') for node in components if node in nodes}
    domains = {nodes[node].get('trust_domain') for node in components if node in nodes}
    hits: dict[str, set[str]] = {}
    for collection, entries in rules.items():
        if not isinstance(entries, list):
            continue
        for rule in entries:
            if not isinstance(rule, Mapping) or 'id' not in rule:
                continue
            why = set()
            if any(_prefix_hit(path, rule.get(name)) for name in PATH_RULE_FIELDS for path in impact.affected_files):
                why.add('PATH_IN_RULE_SCOPE')
            if any(kind in (rule.get(name) or []) for name in NODE_TYPE_RULE_FIELDS for kind in types):
                why.add('COMPONENT_TYPE_IN_RULE_SCOPE')
            if any(domain in (rule.get(name) or []) for name in TRUST_RULE_FIELDS for domain in domains):
                why.add('TRUST_DOMAIN_IN_RULE_SCOPE')
            if why:
                hits[rule['id']] = why | {f'COLLECTION:{collection}'}
    return ArchitectureImpactReport(digest, tuple(sorted(components)), tuple(sorted(unbound)), tuple(sorted(ambiguous)),
                                    tuple(sorted(hits)), {key: tuple(sorted(value)) for key, value in hits.items()})
