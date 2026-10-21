"""Exact-head diff risk: what the change touches, independent of how the prompt was worded.

`classify_diff` reads the changed paths between two commits with read-only Git, applies the path
rules in `.getzilla/config/diff-risk-rules.json`, binds changed code to the architecture model
(restricted data classifications and secret-holding nodes are high risk), and follows one hop of
exact Python imports and calls in the head tree: a helper whose direct dependents live in a
high-risk path is at least medium. The result raises a route's risk and never lowers it. The
`trivial` profile is offered only when every change is admitted prose and nothing is unknown.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Mapping

from .project_ingestion import _git

RULES_SCHEMA = 'diff-risk-rules-v1'
DEFAULT_RULES = Path(__file__).resolve().parents[1] / 'config' / 'diff-risk-rules.json'
ORDER = {'low': 0, 'medium': 1, 'high': 2}
MAX_GRAPH_FILES = 5000


class DiffRiskError(ValueError):
    pass


@lru_cache(maxsize=512)
def _glob(pattern: str) -> re.Pattern[str]:
    out, index = [], 0
    while index < len(pattern):
        if pattern.startswith('**/', index):
            out.append('(?:.*/)?')
            index += 3
        elif pattern.startswith('**', index):
            out.append('.*')
            index += 2
        elif pattern[index] == '*':
            out.append('[^/]*')
            index += 1
        elif pattern[index] == '?':
            out.append('[^/]')
            index += 1
        else:
            out.append(re.escape(pattern[index]))
            index += 1
    return re.compile(''.join(out) + r'\Z')


def matches(path: str, patterns: Iterable[str]) -> bool:
    lowered = path.lower()
    return any(_glob(pattern.lower()).match(lowered) for pattern in patterns)


def load_rules(path: Path = DEFAULT_RULES) -> dict[str, Any]:
    return parse_rules(path.read_bytes())


def parse_rules(content: bytes) -> dict[str, Any]:
    """Validate captured rules without consulting module-relative defaults."""
    data = json.loads(content)
    if data.get('schema_version') != RULES_SCHEMA:
        raise DiffRiskError('unknown diff risk rules schema')
    for rule in data.get('rules', []):
        if rule.get('risk') not in ('high', 'medium') or not rule.get('id') or not rule.get('paths'):
            raise DiffRiskError(f"invalid rule {rule.get('id')!r}")
    trivial = data.get('trivial') or {}
    if not trivial.get('allow') or not isinstance(data.get('tests'), list):
        raise DiffRiskError('rules need trivial.allow and tests')
    return data


@dataclass(frozen=True)
class Change:
    status: str  # A, M, D, R, C, T
    path: str
    old_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {'status': self.status, 'path': self.path, 'old_path': self.old_path}


@dataclass(frozen=True)
class DiffRisk:
    base: str | None
    head: str
    tree: str
    risk: str
    profile_candidate: str  # trivial, standard, full
    reasons: tuple[Mapping[str, str], ...]
    changed: tuple[Change, ...]
    gaps: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    rules_digest: str = ''
    details: Mapping[str, Any] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        return not self.gaps

    def to_dict(self) -> dict[str, Any]:
        return {'schema_version': 'diff-risk-v1', 'base': self.base, 'head': self.head, 'tree': self.tree,
                'risk': self.risk, 'profile_candidate': self.profile_candidate,
                'reasons': [dict(reason) for reason in self.reasons],
                'changed': [change.to_dict() for change in self.changed],
                'coverage': {'complete': self.complete, 'gaps': list(self.gaps)}, 'notes': list(self.notes),
                'rules_digest': self.rules_digest}


def _out(root: Path, *args: str) -> str:
    return _git(root, *args).stdout.decode('utf-8', 'surrogateescape').strip()


def changed_paths(root: Path, base: str | None, head: str) -> list[Change]:
    if base is None:
        base = _empty_tree(root)  # root commit: everything in it is a change
    raw = _git(root, 'diff', '--name-status', '-z', '-M', '--no-ext-diff', base, head).stdout
    fields = raw.decode('utf-8', 'surrogateescape').split('\0')
    changes, index = [], 0
    while index < len(fields) and fields[index]:
        status = fields[index][0]
        if status in 'RC':
            changes.append(Change(status, fields[index + 2], fields[index + 1]))
            index += 3
        else:
            changes.append(Change(status, fields[index + 1]))
            index += 2
    return changes


def _empty_tree(root: Path) -> str:
    import subprocess
    from .project_ingestion import _env
    result = subprocess.run(['git', '-C', str(root), 'hash-object', '-t', 'tree', '--stdin'], input=b'',
                            capture_output=True, check=True, env=_env())
    return result.stdout.decode().strip()


def _restricted_nodes(system: Mapping[str, Any], rules: Mapping[str, Any]) -> dict[str, str]:
    restricted_classes: set[str] = set()
    for policy in rules.get('tenant_authorization_policies', []) or []:
        restricted_classes.update(policy.get('data_classifications') or [])
    found = {}
    for node in system.get('nodes', []) or []:
        if node.get('data_classification') in restricted_classes:
            found[node['id']] = f"data classification {node['data_classification']}"
        elif node.get('secrets'):
            found[node['id']] = 'holds secrets'
    return found


def _node_for(path: str, system: Mapping[str, Any]) -> str | None:
    best: dict[int, set[str]] = {}
    for node in system.get('nodes', []) or []:
        for declared in node.get('repository_paths', []) or []:
            declared = declared.rstrip('/')
            if path == declared:
                best.setdefault(len(declared) + 1, set()).add(node['id'])
            elif path.startswith(declared + '/'):
                best.setdefault(len(declared), set()).add(node['id'])
    if not best:
        return None
    winners = best[max(best)]
    return next(iter(winners)) if len(winners) == 1 else None


def _head_python(root: Path, head: str) -> dict[str, bytes]:
    import subprocess
    from .project_ingestion import _env
    listing = _git(root, 'ls-tree', '-r', '-z', '--full-tree', head).stdout.split(b'\0')
    blobs = []
    for line in listing:
        if not line:
            continue
        meta, _, name = line.partition(b'\t')
        mode, kind, oid = meta.split()
        path = name.decode('utf-8', 'surrogateescape')
        if kind == b'blob' and mode in (b'100644', b'100755') and path.endswith('.py'):
            blobs.append((path, oid.decode()))
    if len(blobs) > MAX_GRAPH_FILES:
        raise DiffRiskError('IMPACT_SCOPE_TOO_LARGE')
    if not blobs:
        return {}
    batch = subprocess.run(['git', '-C', str(root), 'cat-file', '--batch'], input=''.join(f'{oid}\n' for _, oid in blobs).encode(),
                           capture_output=True, check=True, env=_env()).stdout
    contents, offset = {}, 0
    for path, _ in blobs:
        header_end = batch.index(b'\n', offset)
        size = int(batch[offset:header_end].split()[2])
        contents[path] = batch[header_end + 1:header_end + 1 + size]
        offset = header_end + 1 + size + 1
    return contents


def _one_hop_dependents(contents: Mapping[str, bytes], changed: set[str], tree: str) -> tuple[dict[str, set[str]], list[str]]:
    from .code_graph.builder import build_generation
    from .code_graph.models import GraphConfig, make_graph_input
    graph = build_generation(make_graph_input({'source_kind': 'local_git', 'source_digest': tree}, dict(contents),
                                              GraphConfig()))
    dependents: dict[str, set[str]] = {}
    for edge in graph.imports:
        if edge.resolution == 'internal' and edge.target_file in changed and edge.source_file not in changed:
            dependents.setdefault(edge.target_file, set()).add(edge.source_file)
    for edge in graph.calls:
        if edge.resolution != 'exact':
            continue
        caller_file = edge.caller.split(':', 1)[1].split('::', 1)[0]
        for target in edge.targets:
            target_file = target.split(':', 1)[1].split('::', 1)[0]
            if target_file in changed and caller_file not in changed:
                dependents.setdefault(target_file, set()).add(caller_file)
    gaps = [f'PARSE_INCOMPLETE:{path}' for path, _ in graph.coverage.incomplete if path in changed]
    return dependents, gaps


def classify_diff(root: Path, base: str | None, head: str, *, rules: Mapping[str, Any] | None = None,
                  architecture: Any = None, follow_imports: bool = True) -> DiffRisk:
    root = Path(root)
    rules_data = dict(rules) if rules is not None else load_rules()
    digest = hashlib.sha256(json.dumps(rules_data, sort_keys=True).encode('utf-8')).hexdigest()
    head_oid = _out(root, 'rev-parse', '--verify', f'{head}^{{commit}}')
    tree = _out(root, 'rev-parse', f'{head_oid}^{{tree}}')
    base_oid = None if base is None else _out(root, 'rev-parse', '--verify', f'{base}^{{commit}}')
    changes = changed_paths(root, base_oid, head_oid)
    trivial = rules_data['trivial']
    tests = rules_data['tests']
    reasons: list[dict[str, str]] = []
    gaps: list[str] = []
    notes: list[str] = []

    def prose(path: str) -> bool:
        return matches(path, trivial['allow']) and not matches(path, trivial.get('deny', []))

    def add(rule: str, path: str, risk: str) -> None:
        entry = {'rule': rule, 'path': path, 'risk': risk}
        if entry not in reasons:
            reasons.append(entry)

    code_paths: set[str] = set()
    for change in changes:
        for path in filter(None, (change.path, change.old_path)):
            if prose(path):
                continue
            code_paths.add(path)
            for rule in rules_data.get('rules', []):
                if matches(path, rule['paths']):
                    add(rule['id'], path, rule['risk'])
        if change.status == 'D' and matches(change.path, tests):
            add('TEST_REMOVED', change.path, 'high')
        if change.status == 'R' and change.old_path and matches(change.old_path, tests) and not matches(change.path, tests):
            add('TEST_REMOVED', change.old_path, 'high')
    test_changes = [c for c in changes if c.status != 'D' and matches(c.path, tests)]
    non_test_code = [p for p in code_paths if not matches(p, tests)]
    if test_changes and not non_test_code:
        for change in test_changes:
            add('TESTS_CHANGED_WITHOUT_CODE', change.path, 'medium')

    model = architecture
    if model is None and (root / 'architecture' / 'system.yaml').is_file():
        try:
            from .architecture import load_architecture
            model = load_architecture(root)
        except Exception as error:  # noqa: BLE001 - an unreadable model is a coverage gap, not a crash
            gaps.append(f'ARCHITECTURE_MODEL_UNREADABLE:{type(error).__name__}')
    if model is None:
        notes.append('ARCHITECTURE_MODEL_ABSENT')
    else:
        system = model.system if hasattr(model, 'system') else model['system']
        arch_rules = model.rules if hasattr(model, 'rules') else model['rules']
        restricted = _restricted_nodes(system, arch_rules)
        for path in sorted(code_paths):
            node = _node_for(path, system)
            if node in restricted:
                add(f'ARCHITECTURE_RESTRICTED_NODE:{node}', path, 'high')

    changed_python = {c.path for c in changes if c.status != 'D' and c.path.endswith('.py') and not prose(c.path)}
    if follow_imports and changed_python:
        try:
            contents = _head_python(root, head_oid)
            dependents, parse_gaps = _one_hop_dependents(contents, changed_python, tree)
            gaps.extend(parse_gaps)
            for target, users in sorted(dependents.items()):
                for user in sorted(users):
                    hits = [rule['id'] for rule in rules_data.get('rules', [])
                            if rule['risk'] == 'high' and matches(user, rule['paths'])]
                    if hits:
                        add(f'DEPENDENT_IN_HIGH_RISK_PATH:{hits[0]}:{user}', target, 'medium')
        except DiffRiskError as error:
            gaps.append(str(error))

    risk = 'low'
    for reason in reasons:
        if ORDER[reason['risk']] > ORDER[risk]:
            risk = reason['risk']
    if not changes:
        notes.append('EMPTY_DIFF')
    if risk == 'high':
        profile = 'full'
    elif changes and risk == 'low' and not gaps and all(prose(c.path) and (c.old_path is None or prose(c.old_path))
                                                        for c in changes):
        profile = 'trivial'
    else:
        profile = 'standard'
    return DiffRisk(base_oid, head_oid, tree, risk, profile, tuple(reasons), tuple(changes), tuple(gaps), tuple(notes),
                    digest)
